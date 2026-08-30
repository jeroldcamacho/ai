---
name: anti-debugging-techniques
description: Detecting and defeating anti-debugging, anti-instrumentation, and anti-VM checks in binaries. Use when a target crashes, exits, hangs, or silently changes behaviour under a debugger — ptrace self-attach, /proc TracerPid, rdtsc and clock timing, int3 and code-checksum scanning, hardware-breakpoint (DR register) detection, SIGTRAP handler tricks, Windows PEB/NtQueryInformationProcess/ThreadHideFromDebugger, CPUID hypervisor and sandbox artefact checks, and Frida/instrumentation detection. Covers locating the check, then choosing between patching, LD_PRELOAD stubs, debugger-side spoofing, and emulation.
---

# SKILL: Anti-Debugging Detection & Bypass

Owns the **anti-analysis check catalog and its bypasses**. Debugger operation and crash triage are `dynamic-verification`; unpacking and code transformations are `code-obfuscation-deobfuscation`; the tool syntax for locating checks is `re-tools`.

Use only on targets you are authorized to analyze.

## Discipline

**Confirm you are being detected before you start bypassing.** A binary that behaves differently under GDB may be reading `LINES`/`COLUMNS` from the debugger's environment, not running an anti-debug check. Establish the difference first:

```bash
./target < input > /tmp/clean.out 2>&1; echo "clean rc=$?"
env -i ./target < input > /tmp/envless.out 2>&1; echo "env -i rc=$?"
gdb -batch -ex run --args ./target < input > /tmp/dbg.out 2>&1; echo "gdb rc=$?"
diff /tmp/clean.out /tmp/dbg.out
```

If `env -i` alone changes the behaviour, it is the environment, not anti-debug. This distinction saves hours.

**Find the check, don't fight the symptom.** Bypassing blindly (patching every `ptrace`) breaks binaries that use `ptrace` legitimately. Locate the specific comparison, then neutralise that one.

**Prefer the least invasive bypass.** An `LD_PRELOAD` stub or a debugger-side register write leaves the binary intact and is trivially reversible; a patched binary is a new artefact you must track and hash separately.

## Locating the Check

With `strace`/`ltrace` this is usually a two-minute job:

```bash
strace -f -e trace=ptrace,prctl,personality ./target 2>&1 | head        # self-attach, dumpable
strace -f -e trace=openat ./target 2>&1 | grep -E 'proc/(self|[0-9]+)/(status|stat|maps|cmdline)'
ltrace -f ./target 2>&1 | grep -iE 'ptrace|getenv|fork|time|clock'
```

Statically:

```bash
rabin2 -i ./target | grep -iE 'ptrace|prctl|personality|sysconf'
rg -a 'TracerPid|/proc/self/status|/proc/self/maps|LD_PRELOAD' ./target    # strings in the binary
rizin -qc 'aaa; axt sym.imp.ptrace; /x 0f31' ./target                       # xrefs + rdtsc opcodes
```

`/x 0f31` finds `rdtsc`; `/x 0f01f9` finds `rdtscp`. In Ghidra, `get_xrefs_to` on the `ptrace` import and a byte search for the same opcodes (`re-tools`).

## Linux Checks

| Check | How it works | Bypass |
|---|---|---|
| **`ptrace(PTRACE_TRACEME)`** | Only one tracer allowed; a second call fails if a debugger is attached | `LD_PRELOAD` stub returning 0; or in GDB, break `ptrace` and `set $rax = 0` |
| **`/proc/self/status` → `TracerPid`** | Non-zero when traced. The single most common check | Patch the parse; or `LD_PRELOAD` an `open`/`read` shim rewriting the line |
| **`getppid()` / parent name** | Parent is `gdb`, `strace`, `lldb` | Patch the comparison; or launch via a wrapper so the parent looks ordinary |
| **`rdtsc` / `clock_gettime` deltas** | Single-stepping is orders of magnitude slower | Patch the threshold compare; avoid single-stepping — use breakpoints and `continue` |
| **Code checksum / int3 scan** | Hashes its own `.text`, or scans for `0xCC` | Use **hardware** breakpoints (`hbreak`) — they leave no `0xCC` |
| **Hardware breakpoint detection** | Reads DR0–DR3 via `ptrace(PTRACE_PEEKUSER)` on a forked child, or from `ucontext` in a signal handler | Use software breakpoints instead, or patch the DR read |
| **`SIGTRAP` handler trick** | Installs a handler, executes `int3`; under a debugger the debugger eats the trap and the handler never runs | `handle SIGTRAP nostop noprint pass` in GDB |
| **`prctl(PR_SET_DUMPABLE, 0)`** | Blocks attach and core dumps | `LD_PRELOAD` stub; or attach before it runs |
| **`personality(ADDR_NO_RANDOMIZE)`** | Detects the debugger disabling ASLR | `set disable-randomization off` in GDB |
| **`LD_PRELOAD` detection** | Reads `/proc/self/maps` or `environ` for injected objects | Inject via `ptrace` instead of `LD_PRELOAD`, or patch the check |
| **Child-traces-parent** | `fork()`s and has the child `PTRACE_ATTACH` the parent, occupying the tracer slot | `set follow-fork-mode child`, or patch the `fork` |

The classic one-file bypass, still the fastest for most CTF and many real binaries:

```c
/* gcc -shared -fPIC noptrace.c -o noptrace.so && LD_PRELOAD=./noptrace.so gdb ./target */
#include <sys/ptrace.h>
long ptrace(int request, ...) { return 0; }
```

## Windows Checks

| Check | Bypass |
|---|---|
| `IsDebuggerPresent`, `CheckRemoteDebuggerPresent` | Patch `PEB->BeingDebugged` (byte at `PEB+0x02`) to 0 |
| `PEB->NtGlobalFlag` (`+0x68` x86 / `+0xBC` x64) | Clear the heap-debug bits (`0x70`) |
| Heap flags (`Flags`, `ForceFlags`) | Normalise them |
| `NtQueryInformationProcess` — `ProcessDebugPort` (7), `ProcessDebugObjectHandle` (0x1E), `ProcessDebugFlags` (0x1F) | Hook and return the clean values |
| `NtSetInformationThread(ThreadHideFromDebugger=0x11)` | Detaches the debugger from thread events — hook it to a no-op |
| `int 2Dh`, `ICEBP` (`0xF1`), `CloseHandle` on an invalid handle | Exception-based; handle the exception in the debugger |
| `OutputDebugString` + `GetLastError` | Legacy; hook it |
| Timing (`RDTSC`, `GetTickCount`, `QueryPerformanceCounter`) | Patch the threshold |
| Anti-attach (`DbgUiRemoteBreakin` patched) | Attach with a debugger that injects differently, or restore the function |

**ScyllaHide** handles nearly all of these as an x64dbg/IDA plugin — reach for it before hand-patching on Windows.

## VM and Sandbox Detection

Common in malware; also in commercial protectors.

| Check | Bypass |
|---|---|
| `CPUID` leaf 1, ECX bit 31 (hypervisor present) | Patch the check; some hypervisors can mask the bit |
| `CPUID` leaf `0x40000000` vendor string (`KVMKVMKVM`, `VMwareVMware`, `Microsoft Hv`) | Patch, or configure the hypervisor to spoof |
| DMI/SMBIOS strings (`dmidecode`, registry) | Change the VM's advertised board/vendor strings |
| MAC OUI (VMware `00:0C:29`, VirtualBox `08:00:27`) | Set a plausible MAC |
| Device names (`/dev/vboxguest`, `vmci`), guest-additions processes | Uninstall guest additions |
| Low core count / RAM / disk size | Provision realistically |
| No user artefacts — empty recent files, no mouse movement, uptime near zero | Age the image; simulate activity |

Where possible, analyse in an environment that is genuinely not a VM (bare-metal lab), or use full-system emulation and accept that some checks will fire.

## Instrumentation Detection (Frida & friends)

Increasingly the real obstacle on mobile and hardened desktop targets:

- Default `frida-server` port **27042**, and the process name itself.
- `/proc/self/maps` scanned for `frida-agent`, `gum-js-loop`, `gmain` thread names.
- Inline-hook detection: the function prologue no longer matches the on-disk bytes.
- `ptrace(PTRACE_TRACEME)` on itself to occupy the tracer slot and block attach.

Countermeasures: rename and re-port `frida-server`, use `frida-gadget` embedded in the app instead of attaching, hook the detection functions themselves early, or fall back to static patching. Mobile specifics — including SSL pinning interaction — are `android-pentesting-tricks`, `ios-pentesting-tricks`, and `mobile-ssl-pinning-bypass`.

## Choosing a Bypass

| Situation | Approach |
|---|---|
| One or two checks, source of the check known | `LD_PRELOAD` stub or GDB-side register write — non-invasive, reversible |
| Many checks, scattered | Patch the binary once (`objcopy`/LIEF/rizin `w` command), keep the original hash on record |
| Check is in a packed/encrypted region | Unpack first (`code-obfuscation-deobfuscation`) — patching packed bytes achieves nothing |
| Timing checks defeat single-stepping | Breakpoints + `continue` only; never `stepi` through a timed region |
| Self-checksumming code | Hardware breakpoints; or patch after the checksum runs; or emulate |
| Anti-debug is the whole point (protector) | Emulate under QEMU or angr instead of debugging (`symbolic-execution-tools`) |

When patching, record the original bytes and the exact offsets so the change is documented and reversible:

```bash
rizin -w -qc 's 0x1234; wx 9090; q' ./target       # record before/after bytes in your notes
```

## Failure Triage

| Symptom | Cause | Fix |
|---|---|---|
| Runs standalone, exits instantly under GDB | `PTRACE_TRACEME` or `TracerPid` | `LD_PRELOAD` stub; confirm with `strace -e trace=ptrace` |
| Behaviour differs but no anti-debug found | Environment (`LINES`, `COLUMNS`, `_`), or stack-layout shift | Compare against `env -i`; never hardcode a GDB-observed stack address |
| Works with breakpoints, dies when single-stepping | Timing check | Breakpoints + `continue`; patch the delta compare |
| Breakpoint silently never hits | Code is packed/rewritten at runtime, or checksum restored the byte | Break after unpacking; use `hbreak` |
| Debugger detaches mid-run (Windows) | `ThreadHideFromDebugger` | ScyllaHide, or hook `NtSetInformationThread` |
| Bypass works, program still misbehaves | Multiple independent checks | Enumerate all of them — `strace` the whole run, don't stop at the first |
| Patch applied but no effect | Patched a copy, or the region is re-decrypted at runtime | Verify the byte at runtime in the debugger, not on disk |

## Related Skills

`dynamic-verification` (debugger operation, crash triage) · `code-obfuscation-deobfuscation` (packers, obfuscation on top of anti-debug) · `symbolic-execution-tools` (emulate instead of debug) · `re-tools` (locating checks in a stripped binary) · `vm-and-bytecode-reverse` (protector VMs) · `android-pentesting-tricks` / `ios-pentesting-tricks` / `mobile-ssl-pinning-bypass` (mobile instrumentation detection).
