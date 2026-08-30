---
name: re-tools
description: Reverse engineering command reference for binary analysis. Use when reverse engineering binaries or firmware, disassembling, decompiling, doing binary triage, sink-first import sweeps, stripped-binary recovery, crypto constant identification, binary diffing, or symbolic execution with angr. Covers rizin/radare2 vs Ghidra (ghidra-mcp) syntax equivalents, axt/afl/pdg/izz commands, and RE workflows, and routes to the depth skills for anti-debugging, obfuscation and packing, VM/bytecode protection, and symbolic execution.
---

# SKILL: Reverse Engineering Tools

Reference for binary RE workflows, tool syntax, and command equivalents.

## Tool Selection

- **Ghidra** — via `ghidra-mcp` + HexStrike `ghidra_analysis`. Best for decompilation and large binaries.
- **rizin/radare2** — same letter-command syntax; rizin is a fork. Use whichever is installed: `command -v rizin radare2`. Commands below apply to both; substitute `rizin`/`rz-bin`/`rz-asm`/`rzpipe` ↔ `radare2`/`rabin2`/`rasm2`/`r2pipe`.
- **objdump** — fallback disassembly; no decompilation.
- **HexStrike wrappers** — `gdb_analyze`, `gdb_peda_debug`, `radare2_analyze`, `objdump_analyze` execute CLI tools non-interactively with logging; pass command batches, not interactive sessions.

## Syntax Discipline

**rizin/radare2 commands only work inside rizin/radare2.** They are not valid in Ghidra.

When using Ghidra via `ghidra-mcp`, use its named tools:

| rizin/radare2 | Ghidra MCP equivalent |
|---|---|
| `axt @ sym.imp.X` | `search_functions` + `get_xrefs_to` on the import thunk |
| `afn name @ addr` | `rename_function_by_address` |
| `pdg @ addr` | `decompile_function` |
| `afl` | `list_functions` |
| `izz` | `list_strings` / `search_strings` |

**`pdg` requires the rz-ghidra (rizin) or r2ghidra (radare2) plugin.** Without it, fall back to `pdc` (rizin) or `pdd` (radare2).

## Standard Analysis Sequence

Always run `aaa` before any analysis commands (`afl`, `axt`, `pdg`, etc.).

```
aaa          # analyze all (auto-analysis)
afl          # list functions
iI           # binary info (arch, bits, stripped, etc.)
iS           # sections
ii           # imports
iE           # exports
ie           # entry points
il           # linked libraries
izz          # all strings (including non-null-terminated)
```

## Agent-Efficient Output

- Append `j` for JSON on most commands (`aflj`, `axtj`, `iIj`) — parse programmatically instead of scraping text.
- `pds @ addr` / `pdsf @ addr` — summary disassembly (calls + strings, + jumps): cheap orientation before committing to a full `pdg` decompile.
- `axf @ addr` — xrefs *from* an address (what it calls/references); complement of `axt`.
- Addressing: commands accept `@ <addr>` inline (`0x...`, `sym.main`, `entry0`) — no persistent seek needed in one-shot shells.
- Cut noise with internal grep: `afl~main`, `izz~http`, `iz~pass`.

## Triage Commands

```bash
file ./binary                        # format, arch, bits, stripped
checksec --file=./binary             # mitigations
rabin2 -I ./binary                   # same as iI in rizin
strings -a ./binary | grep -E '...' # interesting strings
ldd ./binary                         # linked libraries
```

## Sink-First Binary Sweep

Find callers of dangerous imports, decompile each, trace data backwards to input:

```
axt @ sym.imp.strcpy
axt @ sym.imp.gets
axt @ sym.imp.sprintf
axt @ sym.imp.system
axt @ sym.imp.popen
axt @ sym.imp.printf
axt @ sym.imp.memcpy
axt @ sym.imp.read
axt @ sym.imp.recv
```

For each caller address returned: `pdg @ <addr>` (or `pdc` without rz-ghidra).

**Format-string check**: for every `printf`-family callsite, is the first argument user-controlled (`printf(user)` instead of `printf("%s", user)`)?

**Buffer-overflow shape**: fixed-size stack buffer fed by unbounded or oversized copy — `char buf[64]; strcpy(buf, input);` or `char buf[64]; read(fd, buf, 0x200);`. For every copy into a fixed buffer: is the input length validated before the copy?

## Stripped Binary Recovery

Finding `main` from `entry0`:
- **ELF x86-64**: first argument to `__libc_start_main` is `main` → look for value in RDI at the call.
- **PE**: look for the call right after `GetCommandLine`/`GetModuleHandle`.
- Rename: `afn main @ <addr>`

Identify non-libc functions by xrefs from strings and imports.

## Crypto Constant Identification

```
/x 6a09e667    # SHA-256 initial hash value
/x 67452301    # MD5 initial hash value
/x 01234567    # DES
pxw 256 @ addr # inspect S-box / lookup tables
```

XOR/shift-dense loops with entropy hotspots → likely crypto.

## Protocol & Format Recovery

Infer message layouts, length fields, checksums, and state machines from disassembly and traffic captures; rebuild grammars to drive fuzzing (see the `fuzzing-triage` skill).

## Firmware Analysis

1. Unpack with Binwalk (`binwalk -Me`), then identify the filesystem type before choosing an extractor.
2. Extract filesystems: squashfs, ubifs, cramfs, Android OTA `payload.bin`, Intel HEX for MCU targets.
3. Recover hardcoded credentials/keys/endpoints.
4. Audit extracted services and binaries for standard bug classes.
5. Emulate with QEMU/FirmAE-style setups when dynamic analysis is needed.

## Binary Diffing (Patch Analysis)

```
aaa && afl    # run on both builds
```

Diff function lists; decompile changed functions side by side. The patch points at the bug.

## Malware Triage

Static + behavioral analysis, C2/config extraction, IOC generation. Analyze safely — isolated environment, no execution on host.

## Anti-Analysis Handling

Triage which transformation you are facing, then go to the depth skill — the methods do not transfer between them:

| Observation | Skill |
|---|---|
| Exits/misbehaves under a debugger; `ptrace`, `rdtsc`, `TracerPid` | `anti-debugging-techniques` |
| Packed, high entropy, no imports/strings; flattened CFG; MBA; junk code | `code-obfuscation-deobfuscation` |
| Dispatch loop over a handler table and a bytecode blob; `.pyc`/`.class`/`.dex`/IL/wasm | `vm-and-bytecode-reverse` |

Always unpack before deep analysis — breakpoints, patches, and decompilation on packed bytes achieve nothing.

## Symbolic Execution

Reach for a solver when the path from hypothesis to proof is **computational** — keygen math, CRC/checksum constants, path predicates, opaque-predicate proofs — rather than something you could read. Prefer a scripted solution over staring at disassembly for pure computation.

It is the wrong tool for "what does this program do". Technique depth — angr/claripy/z3/Triton, path-explosion control, hooks and SimProcedures, and how to read `unsat` correctly — is the `symbolic-execution-tools` skill.

**Python environment**: `angr`, `z3-solver`, `claripy`, and `lief` live in an isolated venv at `~/.local/venvs/vr` (the system Python is externally-managed — PEP 668 blocks even `pip install --user`). `pwntools`, `capstone`, `pyelftools`, and `python-can` *are* importable from the system `python3`; `angr` and `z3` are not. Run angr/z3/LIEF scripts with `~/.local/venvs/vr/bin/python3 script.py`, or set the shebang to that interpreter — plain `python3 -c "import angr"` will raise `ModuleNotFoundError`. The venv's `bin/` is also symlinked into `~/.local/bin` for its CLI entry points (`angr`, `z3`, `ropper`, `patchelf`, `asm`/`disasm`/`shellcraft`/`cyclic`/etc. from pwntools).
