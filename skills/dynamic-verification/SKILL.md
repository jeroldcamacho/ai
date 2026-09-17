---
name: dynamic-verification
description: Debugger command reference and crash triage for runtime verification with GDB, LLDB, pwndbg/gef/PEDA, or the rizin/radare2 debugger. Use when debugging a binary, analyzing a SIGSEGV or SIGABRT, triaging crash exploitability, tracing input through a program, proving a UAF, or confirming a static hypothesis at runtime.
---

# SKILL: Dynamic Verification & Crash Triage

Static analysis proposes; the debugger decides. Verify every important hypothesis with runtime evidence.

## Debugger Syntax Discipline

**GDB, LLDB, pwndbg/gef/PEDA, and the rizin/radare2 debugger are different interfaces — never fire one debugger's syntax at another.**

Detect what's in front of you first:
- Prompt prefix: `pwndbg>` / `gef>` / `gdb-peda$` → GDB + plugin
- `(lldb)` → LLDB
- `(gdb)` → vanilla GDB
- Shell: `command -v gdb lldb`

**A plugin is a script, not a PATH binary** — `command -v pwndbg` failing proves nothing, and with no `~/.gdbinit` GDB starts vanilla even when plugins are installed. Check the install roots, then load one explicitly per invocation:

```bash
ls -d ~/pwndbg ~/gef ~/peda /opt/pwndbg /usr/share/pwndbg 2>/dev/null   # look before concluding
gdb -ex 'source ~/pwndbg/gdbinit.py' ./binary        # pwndbg
gdb -ex 'source ~/gef/gef.py' ./binary               # gef
```

**Confirm it actually loaded** — a plugin can be present but broken, and the failure is quiet: `source` raises, GDB continues, and the plugin's commands are simply absent. A successful load prints a banner (pwndbg: "loaded N pwndbg commands"; gef: "GEF for linux ready"). Verify with a plugin-only command (`checksec`, `vmmap`) rather than trusting the absence of an error.

`ModuleNotFoundError: No module named 'six.moves'` on a plugin is worth one minute, not an afternoon: it means a **vendored** `six` older than 1.16 is shadowing the system copy. Old six registers its meta-path importer with `find_module`, which Python 3.12 removed. Overwrite the vendored file with the system one and clear the stale `__pycache__`:

```bash
cp /usr/lib/python3/dist-packages/six.py <plugin>/lib/six.py && rm -rf <plugin>/lib/__pycache__
```

SyntaxWarnings about invalid escape sequences from an older plugin are cosmetic — they go to stderr and do not stop it working.

With no working plugin, everything below still holds via vanilla GDB plus pwntools on the shell for offsets and packing.

## GDB ↔ LLDB Command Mapping

| Task | GDB | LLDB |
|---|---|---|
| Break at function / address | `break main` / `break *0x401000` | `breakpoint set --name main` / `breakpoint set --address 0x401000` (`b main` / `b 0x401000`) |
| Conditional breakpoint | `break *0x401000 if $rax==0` | `b -a 0x401000 -c '$rax == 0'` |
| Step / step-over instruction | `stepi` / `nexti` | `thread step-inst` / `thread step-inst-over` |
| Step out of function | `finish` | `thread step-out` |
| Registers read / write | `info registers` / `set $rax = 0` | `register read` / `register write rax 0` |
| Examine stack (8-byte words) | `x/16xg $rsp` | `memory read --size 8 --count 16 $rsp` |
| Disassemble at PC | `x/10i $rip` | `disassemble --pc --count 10` |
| Locals / args | `info locals` / `info args` | `frame variable` |
| Watchpoint on address | `watch *(long*)addr` | `watchpoint set expression -- (long*)addr` |
| Memory mappings / ASLR slide | `info proc mappings` | `image list` (+ `target modules dump sections`) |
| Identify function at PC | `bt`, `x/i $pc` | `image lookup -a $pc` |
| Force return from call | `return 0` | `thread return 0` |
| Follow fork | `set follow-fork-mode child` | `settings set target.process.follow-fork-mode child` |

## Plugin-Only Commands (pwndbg / gef / PEDA)

`checksec`, `cyclic`, `vmmap`, `telescope`, `heap`, `arena`, `pattern_create`/`pattern_offset` are **plugin** commands — they fail in vanilla GDB and don't exist in LLDB.

- `cyclic` → pwndbg
- `pattern_create` / `pattern_offset` → PEDA

Without a plugin, or in LLDB, generate offset patterns via pwntools on the shell:

```bash
python3 -c "from pwn import *; print(cyclic(256))"
python3 -c "from pwn import *; print(cyclic_find(0x61616166))"
```

## rizin/radare2 Built-in Debugger

Launch: `rizin -d ./binary` (or `r2 -d`). Use when GDB/LLDB are unavailable or for remote targets (`r2 -d gdb://host:1234` wraps gdbserver).

**Not GDB** — don't mix `db`/`dc`/`dr` with `break`/`continue`/`info registers`.

| Task | Command |
|---|---|
| Set breakpoint | `db 0xaddr` |
| Continue | `dc` |
| Step into / step over | `ds` / `dso` |
| Registers | `dr` |
| Memory at RSP | `px @ rsp` |
| Memory maps | `dmm` |
| Backtrace | `dbt` |

## Windows Targets

x64dbg/WinDbg syntax: `bp`, `g`, `p`, `t`, `dd addr`. Only relevant for PE/Windows targets.

## Crash Triage Workflow

Crashes arrive from manual PoCs or fuzz campaigns (see the `fuzzing-triage` skill for generation and dedup). For each crash:

1. **Reproduce**: `run < crash_input` (or feed via stdin/argv as the program expects).
2. **Capture state**: `bt`, `info registers`, `x/i $pc` (faulting instruction), `x/16xg $rsp` (stack).
3. **Classify**:
   - `SIGSEGV` on **write** → likely buffer overflow
   - `SIGSEGV` on **read** from a controlled address → info leak or UAF
   - `SIGABRT` → heap corruption caught by the allocator
4. **Check control**: is `$rip` (or the faulting target address) attacker-influenced? A controlled PC or write address is the exploit primitive — prove it with a cyclic pattern.

## Input Tracing

Break at `read`/`recv`/`fgets`; log the buffer (`$rdi`) and size (`$rdx`); `finish`, then inspect what landed (`x/s $rax`). Follow the buffer forward to the sink.

## UAF / Double-Free Proof

Break on `free`, note the address, then `watch *(long*)freed_addr` to catch any post-free access. Track repeated `free` of the same address for double-free.

## Heap Inspection

Breakpoint `malloc`/`free`, log size + short backtrace (`bt 3`) per call to reconstruct allocation patterns.

pwndbg/gef expose the allocator state directly — use these rather than reading chunk headers by hand:

```
pwndbg> heap          # chunk walk        pwndbg> bins     # every bin
pwndbg> vis 20        # visual dump, shows overlaps at a glance
pwndbg> tcache        # tcache struct     pwndbg> arena
gef>    heap chunks ; heap bins
```

Snapshot `vis` at every stage of a heap chain; a chain that "randomly fails" is almost always one un-modelled allocation. Bin semantics and the glibc version gates are `heap-exploitation`.

## Stack Overflow Offset

Break before/after the vulnerable copy. Saved RIP lives at `$rbp+8` (x86-64): `x/xg $rbp+8`. Compute distance from buffer base to saved RIP. Confirm with a cyclic pattern at the crash.

## Format String Verification

Probe with `%x.%x.%x.%x`. Break at `printf`, inspect `x/s $rdi` and following args. Count `%x` outputs to find your input's stack offset. Automated offset discovery and the write primitive are `format-string-exploitation`.

## Kernel and Engine Targets

Different debuggers, same discipline:

- **Kernel**: `qemu -s` + `gdb ./vmlinux -ex 'target remote :1234'`; `add-symbol-file mod.ko <base from /sys/module/*/sections/.text>`. Develop with `nokaslr`, then re-enable mitigations one at a time. See `kernel-exploitation`.
- **V8/d8**: `%DebugPrint(obj)` and `%SystemBreak()` to correlate JS state with memory; `source tools/gdbinit` then `job <addr>`. See `browser-exploitation-v8`.
- **Sanitizers beat debuggers** when you have source: an ASan/UBSan/MSan report names the bug class and both stack traces immediately. Reach for the debugger for what the sanitizer cannot tell you — control of the faulting value.

## Anti-Debug Bypass

Quick unblock: break `ptrace` (or `sysctl` on macOS) and force success — GDB `set $rax = 0`, LLDB `thread return 0`. Prefer hardware breakpoints (`hbreak`) near timing-sensitive or self-checksumming code, since they leave no `0xCC` to find.

Before bypassing, confirm you are actually being detected: a binary that behaves differently under GDB is often reacting to the debugger's *environment*, not to an anti-debug check. Compare against `env -i ./target`. The full check catalog and per-technique bypasses are `anti-debugging-techniques`.

## Discipline

- Plan breakpoints from static analysis *before* `run`.
- Always kill debug sessions when done.
- Never hardcode an address seen only under GDB — the debugger's environment shifts the stack. Test with `env -i`, or leak the address at runtime (`binary-protection-bypass`).
- If the program forks, set follow-fork mode deliberately (use the mapping table above for GDB vs LLDB syntax).
