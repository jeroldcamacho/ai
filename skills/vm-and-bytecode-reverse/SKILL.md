---
name: vm-and-bytecode-reverse
description: Reversing virtual-machine protections and managed bytecode. Use when a binary dispatches through a handler table over a bytecode blob (VMProtect, Themida/CodeVirtualizer, custom VMs) — locating the dispatcher and VPC, recovering the handler semantics and instruction set, lifting bytecode back to readable form — or when the target is managed bytecode rather than native code: Python .pyc, Java .class and Android DEX, .NET IL, WebAssembly, Lua, and Ruby/PHP opcodes, including decompiler recovery, obfuscated-name handling, and bytecode-level patching.
---

# SKILL: VM & Bytecode Reversing

Two related problems, both "the CPU you are reading is not the CPU that runs it":

1. **VM protection** — native code replaced by a custom interpreter over a private instruction set.
2. **Managed bytecode** — the program ships as bytecode for a documented runtime.

Native obfuscation that isn't a VM is `code-obfuscation-deobfuscation`; solver work is `symbolic-execution-tools`; disassembler syntax is `re-tools`.

Use only on targets you are authorized to analyze.

## Discipline

**Confirm it is a VM before committing.** VM reversing is the most expensive technique in RE — days, not hours. Flattening and heavy junk code look similar at a glance and cost far less to undo. Check the triage table in `code-obfuscation-deobfuscation` first.

**Ask whether you need the VM at all.** You usually want one specific thing: a key check, a decryption routine, a protocol. Often you can get it by tracing the VM's *effects* — its memory writes and syscalls — without ever recovering the instruction set. Recover the ISA only when you need the algorithm itself.

**Recovered semantics are a hypothesis.** A reconstructed handler table is proven when your re-implementation reproduces the original's output on the same inputs. Diff them.

## Part 1 — VM Protection

### Recognising it

| Sign | Detail |
|---|---|
| Central dispatch loop | Fetch a byte/word, index a table, jump — repeatedly |
| Handler table | An array of code pointers, each handler small and ending by returning to the dispatcher |
| Virtual PC | A register or memory slot incremented by each handler |
| Virtual context | A block of memory acting as the VM's registers, often pushed at entry |
| A large opaque data blob | The bytecode itself — high entropy, no strings, referenced only by the dispatcher |
| Section names `.vmp0`, `.vmp1`, `.themida`, `.winlice` | Commercial protector |

```bash
rizin -qc 'aaa; afl~[0]' ./target | wc -l      # many tiny functions of similar size = handlers
rizin -qc 'aaa; /r sym.dispatcher' ./target
```

The tell is structural: dozens of short functions with near-identical prologues and epilogues, all reachable only from one loop.

### Recovery workflow

1. **Find the dispatcher.** The block executed most often in a trace. Instrument with a hit counter (`perf`, a Frida/Pin trace, or a Unicorn emulation loop) and the dispatcher is the top entry by a wide margin.
2. **Find the VPC and the virtual context.** The value the dispatcher reads to index the table is the opcode; whatever advances monotonically is the VPC. The context is the memory block the handlers read and write instead of using real registers.
3. **Enumerate the handler table.** Read it statically from the dispatcher's indexing, or dynamically by logging every dispatch target.
4. **Recover each handler's semantics.** Small and self-contained, so **symbolic execution is ideal** here: emulate the handler on symbolic context values and read out the resulting expression — that expression *is* the instruction's meaning. This is the highest-value application of `symbolic-execution-tools` in RE.
5. **Build a disassembler** for the recovered ISA — a Python script mapping opcode bytes to your recovered semantics.
6. **Lift and simplify.** Translate the bytecode to a readable IR (or to pseudo-C) and let dead-code elimination and constant folding clean it up.

### Shortcuts worth trying first

- **Trace the effects.** Log memory writes and syscalls during execution; frequently the algorithm is visible in the data flow without decoding a single opcode.
- **Attack the boundary.** VM'd code must eventually call real APIs and touch real buffers. Breakpoint those and read the plaintext there.
- **Devirtualise only the hot path.** Recover the handlers your target function actually uses — commonly a fraction of the full table.
- **Check for a known protector.** VMProtect and Themida have published research and, for some versions, existing devirtualisation tooling. Identify the version before writing your own.

## Part 2 — Managed Bytecode

Far cheaper: the instruction set is documented and decompilers exist.

| Runtime | Format | Tools | Notes |
|---|---|---|---|
| **Python** | `.pyc`, frozen, PyInstaller | `pycdc`/`decompyle++`, `uncompyle6`, `xdis`, `pyinstxtractor` | Decompilers lag new versions — fall back to `dis` on the code object, which always works |
| **Java** | `.class`, `.jar` | `jadx`, `CFR`, `procyon`, `Fernflower`, `javap -c` | Recovery is usually near-source |
| **Android** | `.dex`, `.odex`, `.vdex` | `jadx`, `apktool`, `baksmali`/`smali`, `dex2jar` | smali for patch-and-rebuild; see `android-pentesting-tricks` |
| **.NET** | CIL/MSIL | `ILSpy`, `dnSpyEx`, `de4dot`, `monodis` | `de4dot` first — it unpacks most commodity .NET obfuscators |
| **WebAssembly** | `.wasm` | `wasm2wat`, `wabt`, `wasm-decompile`, Ghidra WASM loader | Increasingly common in browser targets; see `browser-exploitation-v8` |
| **Lua** | `.luac` | `unluac`, `luadec` | Common in games and embedded UIs |
| **PHP** | opcache/bytecode | `php -d opcache...`, `vld` | Also encoders like ionCube/Zend Guard |
| **Ruby** | YARV | `RubyVM::InstructionSequence.disasm` | |
| **Erlang/BEAM** | `.beam` | `beam_disasm` | |

### Python bytecode specifics

The most common of these in practice:

```bash
python3 -c "import dis, marshal, importlib.util, sys;
f=open('mod.pyc','rb'); f.read(16); dis.dis(marshal.load(f))"    # header is 16 bytes on 3.7+
pyinstxtractor.py app.exe          # PyInstaller bundle -> .pyc files
pycdc mod.pyc                      # decompile
```

When the decompiler fails — new Python version, or deliberately corrupted bytecode — `dis` on the unmarshalled code object still works, and reading disassembly is entirely tractable for a single function. Deobfuscation of the *names* (`l1lllI1l`) is a separate, mechanical renaming pass.

### Obfuscated managed code

Renaming obfuscators (ProGuard, R8, .NET obfuscators) strip meaning but not structure:

- Recover semantics from **string constants, API calls, and control flow**, not identifiers.
- `de4dot` (.NET) and matching-based deobfuscators restore many names automatically.
- For Android, library code can be re-identified by method-signature matching against known AARs.
- String encryption in managed code is defeated the same way as native: breakpoint or invoke the decryptor and dump the results — and in a managed runtime you can usually just *call* the decryption method directly from a debugger or a small harness.

### Patching managed bytecode

Far easier than native patching, and often the fastest route to a working PoC:

```bash
apktool d app.apk -o out && $EDITOR out/smali/.../Check.smali && apktool b out -o patched.apk
# then re-sign — an unsigned APK will not install
```

`.NET`: edit IL in dnSpyEx and save the assembly. `Java`: recompile the decompiled source, or edit with a bytecode editor when recompilation fails.

## Failure Triage

| Symptom | Cause | Fix |
|---|---|---|
| Handlers all look identical | Handler bodies are themselves obfuscated | Simplify each with an IR/solver pass first |
| Dispatcher not obvious in the trace | Multiple nested VMs, or a threaded interpreter | Count basic-block hits; look for the block with the highest count |
| Recovered ISA gives wrong results | Missed a flags/side-effect in a handler | Symbolically diff your model against the handler for all inputs |
| Bytecode blob is encrypted at rest | Decrypted per-block at runtime | Dump the blob from memory after decryption |
| `uncompyle6`/`pycdc` errors out | Unsupported Python version, or anti-decompile bytecode | Use `dis` on the code object |
| Decompiled Java won't recompile | Decompiler artefacts | Patch at bytecode/smali level instead |
| APK installs but crashes after patching | Not re-signed, or signature check in-app | Re-sign; look for integrity checks (`android-pentesting-tricks`) |
| Devirtualisation is taking days | Scope too broad | Recover only the handlers on your target path |

## Related Skills

`code-obfuscation-deobfuscation` (deciding it's a VM; native obfuscation) · `symbolic-execution-tools` (recovering handler semantics — the key technique) · `re-tools` (tracing, disassembly) · `dynamic-verification` (breakpoints at the VM boundary) · `android-pentesting-tricks` / `ios-pentesting-tricks` (mobile bytecode) · `browser-exploitation-v8` (WASM and JS engine bytecode).
