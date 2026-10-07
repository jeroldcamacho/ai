---
name: pe-and-macho-analysis
description: Reverse engineering Windows PE/COFF and macOS Mach-O binaries — the container, hardening flags, import tables and sink lists that differ from ELF. Use when the target is a .exe, .dll, .sys driver, Mach-O executable, dylib, or fat binary, or when Phase 0's readelf/checksec/ldd sequence returns nothing because the target is not an ELF.
---

# SKILL: PE and Mach-O — the other containers

Phase 0 and the sink sweep are written in `readelf`/`checksec`/`ldd`, which parse **exactly one format**. The methodology is unchanged on Windows and macOS; only the commands and the sink table change.

**Get the format right first — `file` is enough.** This is the load-bearing warning: running ELF tools on a PE gets you **silence, not an error**, and silence reads like "nothing there". A `checksec` that prints nothing on a `.exe` is not a finding about the binary's hardening; it is a finding about your tooling. Record the format as your first observation.

```bash
file "$B"     # PE32+ executable (console) x86-64 / Mach-O 64-bit executable arm64 / ELF...
```

Binary Ninja (`binaryninja-mcp`) handles all three containers natively and stays the default — `bn_binary_view_info` reports the real `viewType` (`PE`, `Mach-O`, `ELF`, `Raw`), which is an independent confirmation of `file`. The commands below are for triage on the shell, where they are faster.

## Windows PE / COFF

```bash
file "$B"                                  # format, subsystem, arch
objdump -f "$B"                            # format, arch, entry point
objdump -p "$B"                            # headers, sections, DLL imports + exports
objdump -x "$B" | grep -A100 'DLL Name'    # the import table, DLL by DLL
rabin2 -I "$B"; rabin2 -i "$B"; rabin2 -E "$B"   # identity / imports / exports
strings -a -n 5 -el "$B"                   # PE is full of UTF-16 — always run -el too
```

`lief` parses PE fully (in the `vr` venv per the tool inventory — `~/.local/venvs/vr/bin/python3`):

```python
import lief
b = lief.parse("sample.exe")
print(b.header.machine, hex(b.optional_header.dll_characteristics))
print([f"{i.name}!{e.name}" for i in b.imports for e in i.entries][:40])
print([s.name for s in b.sections], b.has_signature)
```

### Hardening lives in `DLL_CHARACTERISTICS`, not program headers

`checksec` is ELF-shaped and will not tell you this. Read the flags directly — every later exploitation decision depends on them, exactly as the mitigation-assessment rule requires:

| Flag | Means | Consequence when absent |
|---|---|---|
| `DYNAMIC_BASE` | ASLR | fixed image base — everything is at a known address |
| `NX_COMPAT` | DEP | the stack and heap are executable |
| `GUARD_CF` | Control Flow Guard | indirect-call targets are not validated |
| `NO_SEH` / SafeSEH | exception-handler validation | on x86, SEH overwrite is live — technique and its SEHOP/x64 gates in `windows-exploitation` |
| `HIGH_ENTROPY_VA` | 64-bit ASLR | low-entropy base, cheaper to brute-force |
| `__security_cookie` / `__security_check_cookie` (symbols, not a flag) | `/GS` stack cookies | same role as `__stack_chk_fail` |

### What differs from ELF, and will trip you if you assume otherwise

- **Imports are `DLL!function` pairs**, and may be **by ordinal with no name at all** — resolve the ordinal against that DLL's export table, or you lose the semantics the sink sweep depends on.
- **Delay-loaded imports are a second table.** A program that "does not import `CreateProcessW`" may delay-load it. Check both before claiming an import is absent.
- **Dynamic resolution is the norm, not a packing tell.** `LoadLibrary` + `GetProcAddress` with runtime-built strings hides the whole attack surface from the static import table. When the import table looks suspiciously clean, this is usually why — not obfuscation. An "empty" sink sweep here is *not reviewed*, not *clean*.
- **The interesting entry points are not just `main`.** `DllMain`, exported functions, service entry points, and — for a `.sys` driver — **`DriverEntry` and its IOCTL dispatch table**, which is the entire attack surface of a kernel target and the Windows analogue of the ioctl surface in `kernel-exploitation`.
- **The Win32 API is the sink table.** Re-derive the sink list in Win32 terms: `CopyMemory`/`RtlCopyMemory`, `lstrcpy` vs `StringCchCopy`, `CreateProcess` **with an unquoted path**, `WinExec`, `ShellExecute`, `system`, `RegSetValue`, `CreateFile` with a user-controlled name, `RpcServerRegisterIf`, `CreateNamedPipe`, `MultiByteToWideChar` with a miscomputed size.
- **`.rsrc` carries real content** — embedded executables, configs, manifests. The manifest's `requestedExecutionLevel` tells you the privilege the program requests, which sets the threat model.
- **An Authenticode signature is not a safety property.** It identifies a signer. `has_signature` is not a mitigation.

## Mach-O

```bash
file "$B"; lipo -info "$B"                 # fat/universal binary? thin it first
lipo -thin arm64 "$B" -output "$B.arm64"
otool -hv "$B"                             # header and flags (PIE, TWOLEVEL)
otool -L "$B"                              # linked dylibs
otool -l "$B" | less                       # load commands — the real structure
nm -u "$B"                                 # undefined symbols = imports (the sink gate)
codesign -dvvv --entitlements - "$B"       # entitlements: the privilege surface
```

- **Thin a fat binary before anything else.** Every downstream tool, decompiler included, will otherwise analyse whichever slice it picks first — **and will not tell you which**. An analysis of the wrong slice is an analysis of a different program.
- **`readelf` cannot parse it.** Use `otool`/`nm`, `rabin2`, `lief`, or Binary Ninja.
- **Entitlements are the attack surface** for anything sandboxed or privileged. `com.apple.security.cs.*`, `get-task-allow`, keychain and IPC entitlements decide what a bug in the process is actually worth — they belong in the Threat Model field, not as an afterthought.
- **ObjC/Swift dispatch is dynamic.** `objc_msgSend` means the call graph is **not** in the disassembly. Recover selectors from `__objc_selrefs` / `__objc_classlist` before concluding a function is unreachable — "no xrefs" on a Mach-O is a statement about static references only.
- **Apple AArch64 passes varargs on the stack**, which is the single most common source of wrong findings in decompiled Mach-O. Treat any format-string or varargs reasoning from Pseudo C as a hypothesis until checked in disassembly.

## Coverage honesty on non-ELF targets

Say which container you analysed, and do not let an ELF-shaped tool's silence become an implied clean result. Three statements that are each fine, and must not be confused:

- *reviewed* — the format's own tooling ran and returned a verdict;
- *not reviewed* — the ELF tool returned nothing because the target is not an ELF, or the import table was hidden behind `GetProcAddress`/`objc_msgSend`;
- *out of scope* — the container was not in the engagement.

## Cross-references

- Default disassembler, which handles all three containers → `binaryninja-mcp`
- Triage sequence and the rizin/radare2 command set → `re-tools`
- Mitigation assessment before technique selection → `binary-protection-bypass`
- Windows driver IOCTL surface, as the analogue of the Linux ioctl surface → `kernel-exploitation`
- Mobile-side Mach-O, entitlements, and pinning → `ios-pentesting-tricks`
- Bug classes and sinks, to be re-derived in Win32/ObjC terms → `bug-class-catalog`, `c-cpp-review`

*PE/Mach-O container specifics adapted from the REx-skill `SKILL-RE` reference (github.com/tihanyin/REx-skill, §22), reconciled with this agent's Binary Ninja default and coverage conventions.*
