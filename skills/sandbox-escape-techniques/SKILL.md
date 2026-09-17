---
name: sandbox-escape-techniques
description: Escaping process sandboxes and containers. Use after achieving code execution inside a confined process and needing the host — Chrome renderer-to-browser via Mojo, seccomp-bpf analysis and bypass, Linux namespace and capability escapes, Docker and Kubernetes breakout, macOS sandbox and XPC, Windows token and integrity levels, Electron contextIsolation, kernel LPE as the universal escape.
---

# SKILL: Sandbox & Container Escape

You have code execution inside a confined process. This decides how to get out. Getting the initial execution is `browser-exploitation-v8`, `exploit-dev`, or a web/app finding; the kernel bug that many escapes end in is `kernel-exploitation`.

Use only on targets you are authorized to attack. Escapes cross a trust boundary onto the host — confirm the engagement covers the host, not only the sandboxed component, before you run one.

## Discipline

**Enumerate the actual policy before choosing a technique.** Sandboxes differ enormously in what they permit, and the fastest escape is nearly always through something explicitly allowed rather than through a memory-corruption bug. Read the filter, the profile, the capability set, and the mounted filesystem first.

**An escape is proven by an effect outside the sandbox.** A file written to the host, a process spawned in the host namespace, `id` from outside the container. "This ioctl is reachable, which could lead to escape" is a hypothesis.

**Name the boundary you crossed.** Renderer→browser, container→host, sandbox→kernel, and low→medium integrity are different findings with different severities. Be precise.

## Enumerate First

```bash
# what am I?
cat /proc/self/status | grep -E 'Seccomp|CapEff|CapBnd|NoNewPrivs|Uid|Gid'
capsh --decode=$(grep CapEff /proc/self/status | cut -f2)
cat /proc/self/uid_map /proc/self/gid_map      # user namespace?
ls -l /proc/self/ns/                            # which namespaces, and are they shared?
cat /proc/self/mountinfo                        # what's mounted, and rw?
cat /proc/self/attr/current                     # SELinux/AppArmor label
mount | grep -E 'proc|sys|cgroup|docker.sock'
ls -la /dev                                     # device nodes = weak isolation
cat /proc/1/cgroup                              # container runtime fingerprint
```

```bash
seccomp-tools dump ./binary          # dump the BPF filter of a local binary
# in-process: /proc/self/status Seccomp: 0 none | 1 strict | 2 filter
```

| Question | Tells you |
|---|---|
| Which syscalls does the filter allow? | Whether you need a kernel bug at all |
| Which namespaces are **not** unshared? | A shared PID/net/mount namespace is a direct path out |
| What capabilities remain? | `CAP_SYS_ADMIN`, `CAP_SYS_MODULE`, `CAP_SYS_PTRACE` are each an escape on their own |
| Which filesystem paths are writable? | Policy files, sockets, host mounts |
| Which IPC endpoints are reachable? | The main browser/service escape surface |
| Is `no_new_privs` set? | Whether setuid paths help |

## Chrome / Browser: Renderer → Browser

The renderer is heavily sandboxed (seccomp-bpf + namespaces on Linux, restricted token + Win32k lockdown on Windows, `.sb` profile on macOS) and holds no privileges of its own. It talks to the privileged browser process over **Mojo IPC**. The escape is therefore almost always a bug in a Mojo interface, not a bug in the sandbox mechanism.

| Surface | What to look for |
|---|---|
| **Mojo interfaces exposed to the renderer** | An interface bound in the browser process that a compromised renderer should not reach. Enumerate the `.mojom` files and the binder registries |
| **Missing origin/capability checks** | The browser trusts a renderer-supplied origin, URL, file path, or frame ID. Renderers are compromised in this threat model — every such value is attacker-controlled |
| **Memory corruption in the browser process** | UAF in a Mojo message handler, bad deserialization of a mojom struct |
| **GPU / network / utility processes** | Less-sandboxed helpers; a bug there is a stepping stone |
| **Downloads, file pickers, drag & drop** | Paths that legitimately touch the filesystem on the renderer's behalf |
| **Kernel LPE from inside the sandbox** | The universal escape — anything the seccomp filter still permits (`kernel-exploitation`) |

The design assumption is "the renderer is malicious", so any browser-process code path that validates something the renderer told it is a bug. That framing finds more than fuzzing.

### Electron and Node

A completely different picture, and usually far worse:

| Setting | Risk |
|---|---|
| `nodeIntegration: true` | XSS in the renderer is **immediate system RCE** — `require('child_process')` |
| `contextIsolation: false` | Preload-script and Electron internals reachable from page JS → prototype pollution into RCE |
| `sandbox: false` | No OS sandbox on the renderer at all |
| Overbroad `preload` API surface | A poorly-scoped `contextBridge` function (file read, shell open, IPC passthrough) is the escape |
| `webSecurity: false`, `allowRunningInsecureContent` | Turns an ordinary web bug into a local one |
| Unvalidated `ipcRenderer.send` handlers | The main process acts on renderer-supplied paths/commands |

Check `webPreferences` in the app source (`app.asar` — `npx asar extract app.asar out/`) before anything else. Most Electron findings are configuration, not memory corruption.

## seccomp-bpf Bypass

A seccomp filter is a program; read it and look for what it forgot.

```bash
seccomp-tools dump ./binary
```

| Weakness | Bypass |
|---|---|
| Filter doesn't check the architecture | Enter via the **x32 ABI** (`__X32_SYSCALL_BIT`, `0x40000000`) or 32-bit `int 0x80` — different syscall numbers hit the same kernel functionality |
| `execve` blocked, `execveat` allowed | Same effect, different number. Also `open` vs `openat` vs `openat2`, `fork` vs `clone` vs `clone3` |
| `io_uring` allowed | **The big one.** Operations are performed by kernel workers, not syscalls — file and network I/O outside the filter's view. Most modern sandboxes block it outright for this reason |
| `ptrace` allowed | Attach to a less-confined process and inject |
| `process_vm_readv`/`writev` allowed | Write into another process's memory |
| `sendmsg`/`recvmsg` allowed on a unix socket | Pass file descriptors (`SCM_RIGHTS`) in or out of the sandbox |
| `mmap` with `PROT_EXEC` allowed | Load a second-stage payload |
| `prctl` allowed | Modify the process's own state |
| Filter allows a syscall with a dangerous flag | Argument checks in BPF cannot dereference pointers — only scalar args are checkable, so flags in a struct are unchecked |
| Only `execve` blocked | **ORW**: `open`/`read`/`write` the flag or a host file directly (see `stack-overflow-and-rop` advanced reference for ORW chains) |

The structural limitation to exploit: **BPF filters cannot follow pointers.** Anything passed in a struct is invisible to the filter.

## Linux Namespace & Container Escape

| Condition | Escape |
|---|---|
| `/var/run/docker.sock` mounted | Full host control — create a privileged container mounting `/` |
| `--privileged` | All capabilities + device access — mount the host disk (`/dev/sda`) directly |
| `CAP_SYS_ADMIN` | `mount`, and historically the `cgroup` `release_agent` trick (patched, but check) |
| `CAP_SYS_MODULE` | `insmod` a kernel module — instant host root |
| `CAP_SYS_PTRACE` + shared PID namespace | Inject into a host process |
| `CAP_DAC_READ_SEARCH` | `open_by_handle_at` brute force (Shocker) → read any host file |
| Host PID namespace shared | `/proc/<host pid>/root` reaches the host filesystem |
| Host network namespace | Reach services bound to localhost on the host (kubelet, metadata, etcd) |
| Writable `/proc/sys/kernel/core_pattern` | Crash a process → kernel runs your command as root |
| Writable host path mounted (`/etc`, `/root`, a cron dir) | Persist and escalate |
| Device node for the host disk in `/dev` | Mount or read it raw |
| Kubernetes: overly permissive ServiceAccount | Create a privileged pod; read the token at `/var/run/secrets/kubernetes.io/serviceaccount/` |
| Nothing above applies | Kernel LPE — a container shares the host kernel (`kernel-exploitation`) |

A container is a *policy*, not a boundary in the way a VM is. Enumerate what the policy actually forbids; usually something has been left open.

## macOS

| Surface | Notes |
|---|---|
| **Sandbox profiles (`.sb`)** | SBPL rules; look for permissive `(allow file-write*)` globs, or `(allow mach-lookup)` to a service that does privileged work |
| **XPC services** | The main escape route. A service that fails to validate its client (code signature, entitlements, audit token) will act on your behalf. Look for `NSXPCConnection` without `setCodeSigningRequirement`, or use of the deprecated PID-based validation (PID reuse) |
| **Mach ports** | Port-name confusion, sending to a port you shouldn't hold |
| **Entitlements** | `codesign -d --entitlements - /path/app` — a helper with `com.apple.security.cs.disable-library-validation` or `allow-dyld-environment-variables` is a target |
| **Launch services / login items** | Persistence and privilege transitions |
| **TCC** | Escaping into a process that already has Full Disk Access is often more useful than escaping the sandbox itself |

## Windows

| Mechanism | Escape surface |
|---|---|
| **Restricted token / low integrity** | Find an object with a weak DACL writable from low IL; named pipes and shared sections are classic |
| **Win32k lockdown** | If disabled for the process, the huge `win32k.sys` surface is back |
| **ALPC / RPC** | A privileged service accepting calls from a low-IL client without proper impersonation checks |
| **COM** | Auto-elevating and out-of-process COM servers |
| **Job objects / AppContainer capabilities** | Enumerate granted capabilities; a network or filesystem capability may be enough |
| **ACG / CIG** | Blocks new executable pages and unsigned DLL loads — pushes you to ROP/data-only, not a boundary itself |
| **Kernel LPE** | Same universal answer as Linux |

## Policy File Manipulation

Whenever the sandbox's own configuration is reachable and writable, that is the escape — no memory corruption needed:

- Seccomp/AppArmor/SELinux policy files editable by the confined user.
- A sandbox helper binary or its `LD_PRELOAD`/`LD_LIBRARY_PATH` environment reachable.
- A profile path chosen from a config file you can write.
- Container runtime config (`daemon.json`, pod spec, `docker-compose.yml`) in a writable repo that CI applies.
- Anything the sandbox reads *at startup* that you can influence before the next restart.

Check writability of every configuration path you find in the enumeration step before assuming you need a bug.

## Verification

Demonstrate the crossing, minimally and non-destructively:

```bash
# from a container
touch /host-root-marker            # only if a host path is mounted — say what you touched
nsenter -t 1 -m -u -i -n -p -- id  # host namespace, if you got there
# from a renderer
# spawn a benign process, or read a file the sandbox forbids
```

Prefer `id`, a timestamped marker file in `/tmp`, or a read of a file the sandbox should deny. Record exactly what you created so it can be cleaned up, and clean it up (`reverse-shell-techniques` covers artefact cleanup discipline).

## Failure Triage

| Symptom | Cause | Fix |
|---|---|---|
| Syscall returns `EPERM`/process killed with `SIGSYS` | seccomp denied it | Dump the filter; find an allowed equivalent |
| `execve` blocked | Common seccomp policy | `execveat`, or ORW instead of exec |
| Escape works locally, not in the target | Different policy/profile version | Re-enumerate on the target; never assume the same filter |
| `nsenter`/`mount` returns `EPERM` | Missing `CAP_SYS_ADMIN` | Check `CapEff`; look for a different route |
| `docker.sock` present but access denied | Group/permission | Check `id` and the socket's mode before concluding |
| Kernel exploit panics the box | Wrong kernel version/offsets | `kernel-exploitation`; work in a snapshot VM |
| Mojo/XPC call rejected | Client validation is present | That interface is not the bug — enumerate others |
| Electron `require` undefined | `contextIsolation` on | Look at the `preload` bridge surface instead |

## Related Skills

`kernel-exploitation` (the universal escape) · `browser-exploitation-v8` (getting renderer execution first) · `exploit-dev` · `arbitrary-write-to-rce` · `reverse-shell-techniques` (post-escape session and cleanup) · `recon-for-sec` (host and service enumeration once you are out).
