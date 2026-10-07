---
name: re-tools
description: Reverse engineering command reference for binary analysis. Use when reverse engineering a binary or firmware, disassembling, decompiling, doing binary triage, sink-first import sweeps, stripped-binary recovery, DWARF debug-info recovery, recovering bundled library versions, crypto constant identification, or binary diffing. Covers rizin/radare2, Binary Ninja, and Ghidra equivalents, and routes to the depth skill for each analysis obstacle.
---

# SKILL: Reverse Engineering Tools

Reference for binary RE workflows, tool syntax, and command equivalents.

## Tool Selection

- **Binary Ninja — the default.** Via `binaryninja-mcp` (`mcp__binaryninja__bn_*`). Best decompilation, and the only tool here with a queryable IL stack (LLIL/MLIL/HLIL + SSA) — read MLIL SSA for backward taint. GUI must be running; no headless, no debugger, no bulk/batch tools.
- **Ghidra — the secondary.** Via `ghidra-mcp` + HexStrike `ghidra_analysis`. Use it for what Binary Ninja's MCP lacks: bulk xrefs, batch decompilation, scripted dataflow, headless runs, and very large binaries.
- **rizin/radare2** — same letter-command syntax; rizin is a fork. Use whichever is installed: `command -v rizin radare2`. Commands below apply to both; substitute `rizin`/`rz-bin`/`rz-asm`/`rzpipe` ↔ `radare2`/`rabin2`/`rasm2`/`r2pipe`.
- **objdump** — fallback disassembly; no decompilation. **On this host it is x86-only** (`objdump --help` → `supported architectures: i386 i386:x86-64 …`). On ARM/AArch64/MIPS firmware it emits **no output and no error**, which reads like "nothing there" — verify with `objdump --help` before trusting a quiet result. Foreign-arch fallback here is `rz-asm -a arm -b 64 -d` / `rizin -a <arch> -b <bits>` or capstone in system python (both verified working); `llvm-objdump` is installed but rejects GNU's `-b binary`.
- **Specialist tools — verified availability on this host, per GINGER's detect-before-assume rule.** **Present**: `binwalk` (firmware carving), `ikdasm` (.NET IL), `qemu-*-static` (foreign-arch emulation, aarch64/arm/mips/… installed), AFL++ at `/usr/local/bin` with its `LD_PRELOAD` libs at `/usr/local/lib/afl/`. **Absent — install before planning around them, do not assume**: `qiling` (emulate firmware with a faked filesystem/syscall layer — invaluable for MIPS/ARM services, but a wrong environment model produces confident nonsense) · `floss` (recovers *obfuscated*/stack-constructed strings `strings` misses) · `diffoscope` (recursive diff of two builds/firmware images) · `radamsa` (dumb mutation fuzzer for a first pass) · `retdec` (third decompiler opinion when Binary Ninja and Ghidra disagree) · `GoReSym` (names from a stripped Go binary) · `hexyl` (use `xxd` instead). Re-check with `command -v`; availability drifts.
- **HexStrike wrappers** — `gdb_analyze`, `gdb_peda_debug`, `radare2_analyze`, `objdump_analyze` execute CLI tools non-interactively with logging; pass command batches, not interactive sessions.

## Syntax Discipline

**rizin/radare2 commands only work inside rizin/radare2.** They are not valid in Binary Ninja or Ghidra — those take named MCP tools:

| rizin/radare2 | Binary Ninja MCP (default) | Ghidra MCP (secondary) |
|---|---|---|
| `axt @ sym.imp.X` | `bn_function_callers` (callsites) / `bn_function_xrefs_to` | `search_functions` + `get_xrefs_to` on the import thunk |
| `axt @ <data addr>` | `bn_data_xrefs_to` | `get_xrefs_to` |
| `afn name @ addr` | `bn_symbol_rename` | `rename_function_by_address` |
| `pdg @ addr` | `bn_function_decompile` | `decompile_function` |
| `pdf @ addr` | `bn_function_disassembly` | `disassemble_function` |
| *(no equivalent)* | `bn_function_il` — `mlil` + `ssa` for taint | *(no equivalent)* |
| `afl` | `bn_function_list` / `bn_function_search` | `list_functions` |
| `izz` | `bn_string_list` | `list_strings` / `search_strings` |
| `ii` | `bn_import_list` | `list_imports` |
| `afvs` | `bn_function_stack_layout` | the `data` group |
| *(N calls)* | *(no bulk tool — one call per function)* | `get_bulk_xrefs`, `batch_decompile` |

Binary Ninja `function` arguments take a start-address expression: hex (`0x401000`), a symbol, or a BN expression.

**`pdg` requires the rz-ghidra (rizin) or r2ghidra (radare2) plugin.** Without it, fall back to `pdc` (rizin) or `pdd` (radare2).

## Identify First — container, then language

Both of these decide *which* methodology applies, and getting either wrong wastes the whole engagement. Run before any analysis command.

### Container magic — note the ones NOT at offset 0

```bash
file "$F"; binwalk "$F"; xxd -l 128 "$F"   # hexyl is not installed here; xxd is
```

| Bytes | Format | Offset |
|---|---|---|
| `7F 45 4C 46` (`\x7FELF`) | ELF | 0 |
| `4D 5A` (`MZ`) | PE / DOS | 0, real PE header at the `e_lfanew` offset |
| `FE ED FA CE` / `CF` | Mach-O 32 / 64-bit | 0 |
| `CA FE BA BE` | Mach-O **fat** — also Java `.class` | 0 |
| `50 4B 03 04` (`PK`) | ZIP — **and** jar/apk/docx/xlsx | 0 |
| `1F 8B 08` · `42 5A 68` · `FD 37 7A 58 5A` · `28 B5 2F FD` | gzip · bzip2 · xz · zstd | 0 |
| `hsqs` / `sqsh` | **SquashFS** (LE / BE) | 0 |
| `UBI#` | **UBIFS** | 0 |
| `75 73 74 61 72` (`ustar`) | tar | **257** |
| `43 44 30 30 31` (`CD001`) | ISO 9660 | **32769** |
| `\0asm` | WebAssembly | 0 |

A magic match at a non-zero offset is why a bare `file` on a firmware image says `data`. That is not "unknown format" — it is "look further in".

### Language tells — do not carry the C checklist onto a Go or Rust binary

Identify from `.comment`, runtime symbols, or panic strings. **This is the highest-leverage early decision**: run a memory-safety checklist over a Go or Rust binary and you will find nothing while missing the logic and concurrency bugs that are actually there.

| Language | Tells | What actually goes wrong |
|---|---|---|
| **Go** | `go.buildid`, `runtime.` symbols, huge static binary | data races, nil-map writes, `unsafe`, integer overflow in `make()` sizes, path handling. Memory safety is mostly *not* the seam. `GoReSym` recovers names |
| **Rust** | `_ZN` mangling, `core::panicking`, `unwrap` strings | `unsafe` blocks, FFI boundaries, release-build integer wrap, logic, deserialisation → `rust-security-audit` |
| **C++** | vtables, RTTI, `_ZNSt`, STL patterns | lifetime UAF, vtable corruption, iterator invalidation, exception paths |
| **Swift/ObjC** | `_$s` mangling, `objc_msgSend` | force-unwrap, ObjC bridging, IPC entitlements → `pe-and-macho-analysis` |
| **JVM** | `.class` / dex | deserialisation, reflection, traversal, injection — **not** memory safety. Decompiles near-perfectly: use a decompiler, not a disassembler |
| **.NET** | `MZ` + CLR header, `mscoree`, `#~` metadata stream | near-perfect decompilation (ILSpy/dnSpy/`ikdasm`); deserialisation, reflection, P-Invoke, secrets in IL literals |
| **Python (frozen)** | PyInstaller/`py2exe` markers, `PYZ`/`MEIPASS`, embedded zip | not a native RE problem — extract the archive, decompile the `.pyc`, read the source |
| **Node / Electron** | `app.asar`, V8 `.jsc` snapshots | unpack the asar and read the JS; the native seam is addons and IPC |
| **WebAssembly** | `\0asm` | linear-memory bounds are enforced, so overflows corrupt *within* the sandbox; the seams are host imports and integer arithmetic |

Managed bytecode depth → `vm-and-bytecode-reverse`.

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

## DWARF Debug Info — Free Ground Truth

Before treating a binary as stripped, **check whether it carries debug info**. A binary with DWARF
hands you real function names, parameter types, struct layouts, and line numbers — every one of
which is a fact rather than a decompiler guess, and struct field offsets are exactly what an
overflow analysis needs.

```bash
readelf -S ./binary | rg '\.debug_'          # does it have any? .debug_info is the one that matters
file ./binary | rg -o 'with debug_info|not stripped|stripped'
llvm-dwarfdump --version                      # installed at /usr/bin/llvm-dwarfdump

llvm-dwarfdump --debug-info ./binary | head -80
llvm-dwarfdump --name='parse_header' --show-children ./binary     # exhaustive DIE-name search
llvm-dwarfdump --find='parse_header' ./binary                     # fast, via accelerator tables
llvm-dwarfdump --lookup=0x401230 ./binary                         # which DIE covers this address
llvm-dwarfdump --debug-line ./binary | rg '0x00000000004012'       # address → source line
llvm-dwarfdump --statistics ./binary                              # debug-info quality, as JSON
llvm-dwarfdump --verify ./binary                                  # structural integrity
```

`--find` uses the accelerator tables — fast but **not exhaustive**; fall back to `--name` when it
misses. Struct layouts come from the type DIE's children:
`llvm-dwarfdump --name='struct packet_hdr' --show-children` gives every member with its
`DW_AT_data_member_location` offset, which beats reconstructing the struct from decompiled
arithmetic.

Pitfalls that produce wrong conclusions:

- **An unused type is not in DWARF at all.** Compilers elide debug info for types with no
  instance, so `--name='some_struct'` returning nothing does **not** mean the struct is absent
  from the source. Verified: a `struct hdr` with no variable of that type yields **0**
  `DW_TAG_structure_type`; give it one instance and it appears, as does
  `-fno-eliminate-unused-debug-types` on the original. When a struct you can see in the source is
  missing from DWARF, this — not a stripped binary — is usually why.

- **Attributes are optional.** A DIE may omit `DW_AT_name`, `DW_AT_type`, or its ranges. Absence is
  not a fact about the program.
- **Attribute indirection.** A DIE's attributes may live on the DIE referenced by its
  `DW_AT_abstract_origin` (an inlined instance) or `DW_AT_specification` (an out-of-line
  definition). **Resolve the chain before concluding data is absent.**
- **Type chains.** Qualifiers and modifiers (`DW_TAG_const_type`, `DW_TAG_pointer_type`,
  `DW_TAG_volatile_type`) wrap the underlying type — walk `DW_AT_type` links to reach the base type
  and its real size.
- **macOS.** A linked Mach-O executable carries **no** DWARF: it stays in the `.o` files until
  `dsymutil` collects it into a `.dSYM` bundle. Point the tool at the dSYM or the objects, not the
  executable.
- **Two `dwarfdump`s exist** — libdwarf's and LLVM's — with different options, and a bare
  `dwarfdump` may be either. Check `dwarfdump --version`; the flags above are LLVM's. Only
  `llvm-dwarfdump` is installed here.
- **Old DWARF versions** read the same apart from surface forms: in v2, member offsets appear as
  location expressions (`DW_OP_plus_uconst`) and linkage names as `DW_AT_MIPS_linkage_name`. A
  current compiler emitting old DWARF means the build passed `-gdwarf-N` explicitly — gcc records
  its flags in `DW_AT_producer`, so the pin is often readable right there; clang's producer string
  carries no flags.

Escalate from grep pipelines to a script once the query is structural — "every parameter of type
`float *`", "every struct with a trailing zero-length array". `pyelftools` (Python, ELF-only) is
the default for one-off work; `gimli` (Rust), `libdwarf` (C), and Go's `debug/dwarf` for anything
long-lived. `readelf --debug-dump=info --dwarf-depth=2` is the fallback when no dwarfdump exists.

Also worth knowing for diffing: `llvm-dwarfdump --statistics` across two builds catches debug-info
regressions, and line tables make a binary diff readable in *source* terms — which turns a
`radiff2` function list into "the fix added a bounds check at parser.c:142".

## Recovering Bundled Library Versions

A statically linked or vendored library appears in no manifest, so dependency tooling cannot see
it — but it usually announces itself in the binary. This is how a supply-chain finding gets made
against a shipped artifact (`supply-chain-audit`).

```bash
strings -a ./binary | rg -i '([0-9]+\.[0-9]+\.[0-9]+)' | rg -i \
  'zlib|libpng|sqlite|openssl|libcurl|expat|libjpeg|freetype|pcre|lua|xml2|zstd|brotli|nghttp2|boring'
strings -a ./binary | rg -x 'OpenSSL [0-9].*'          # OpenSSL prints its own banner
strings -a ./binary | rg -i 'sqlite3? [0-9]|3\.[0-9]{2}\.[0-9]'
rg -a 'ZLIB_VERSION|PNG_LIBPNG_VER_STRING|SQLITE_VERSION|EXPAT_VERSION|LIBXML_DOTTED' ./binary
nm -C ./binary 2>/dev/null | rg -i 'version|_v[0-9]'   # exported version symbols, if not stripped
readelf -p .comment ./binary                            # compiler and sometimes distro build id
file ./binary; readelf -nW ./binary | rg -i 'build.?id' # Build-ID for symbol-server lookup
```

Where the version string is absent, fall back to **fingerprinting**: a library's distinctive
constant tables and error-message sets are version-discriminating. Match a recovered function
against a known build of the same library (`radiff2 -C`, BinDiff) and the closest match dates the
bundled copy. DWARF, if present, is faster and exact — `llvm-dwarfdump --debug-info | rg
DW_AT_producer` gives the compiler, and `DW_AT_comp_dir` plus source paths often leak the exact
upstream version directory.

Then treat the recovered version as a dependency: advisory sweep it, and check whether the
vulnerable path is reachable rather than reporting the version match alone.

## Crypto Constant Identification

```
/x 6a09e667    # SHA-256 initial hash value
/x 67452301    # MD5 initial hash value
/x 01234567    # DES
pxw 256 @ addr # inspect S-box / lookup tables
```

XOR/shift-dense loops with entropy hotspots → likely crypto.

## Protocol & Format Recovery

Infer message layouts, length fields, checksums, and state machines from disassembly and traffic
captures; rebuild grammars to drive fuzzing. Recovered structure feeds two things directly: the
**seed corpus and dictionary** (`fuzzing-harness-design`) and the **magic-value and checksum
locations** that decide whether the fuzzer needs a patch to get past them. Struct offsets recovered
from DWARF, where present, are ground truth for this.

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

Static + behavioral analysis, C2/config extraction, IOC generation. Analyze safely — isolated
environment, no execution on host. `yara` is installed at `/usr/bin/yara` for turning a recovered
constant, string set, or code stub into a detection rule; keep atoms long and specific (a 4-byte
atom on a common pattern scans the whole corpus) and test any rule against benign samples before
claiming a detection.

## Anti-Analysis Handling

Triage which transformation you are facing, then go to the depth skill — the methods do not transfer between them:

| Observation | Skill |
|---|---|
| Exits/misbehaves under a debugger; `ptrace`, `rdtsc`, `TracerPid` | `anti-debugging-techniques` |
| Packed, high entropy, no imports/strings; flattened CFG; MBA; junk code | `code-obfuscation-deobfuscation` |
| Dispatch loop over a handler table and a bytecode blob; `.pyc`/`.class`/`.dex`/IL/wasm | `vm-and-bytecode-reverse` |

Always unpack before deep analysis — breakpoints, patches, and decompilation on packed bytes achieve nothing.

## Binary-Only Variant Hunting

Once a bug is confirmed at one call site, sweep the others in the same binary before writing up:
`axt @ sym.imp.<sink>` gives every caller, and each one is a candidate for the same mistake. The
method — root-cause statement, expansion axes, calibrate on the known instance first — is
`variant-analysis`; it applies unchanged to binaries, with `axt`/`get_bulk_xrefs` in place of grep.

## Symbolic Execution

Reach for a solver when the path from hypothesis to proof is **computational** — keygen math, CRC/checksum constants, path predicates, opaque-predicate proofs — rather than something you could read. Prefer a scripted solution over staring at disassembly for pure computation.

It is the wrong tool for "what does this program do". Technique depth — angr/claripy/z3/Triton, path-explosion control, hooks and SimProcedures, and how to read `unsat` correctly — is the `symbolic-execution-tools` skill.

**Python environment**: `angr`, `z3-solver`, `claripy`, and `lief` live in an isolated venv at `~/.local/venvs/vr` (the system Python is externally-managed — PEP 668 blocks even `pip install --user`). `pwntools`, `capstone`, `pyelftools`, and `python-can` *are* importable from the system `python3`; `angr` and `z3` are not. Run angr/z3/LIEF scripts with `~/.local/venvs/vr/bin/python3 script.py`, or set the shebang to that interpreter — plain `python3 -c "import angr"` will raise `ModuleNotFoundError`. The venv's `bin/` is also symlinked into `~/.local/bin` for its CLI entry points (`angr`, `z3`, `ropper`, `patchelf`, `asm`/`disasm`/`shellcraft`/`cyclic`/etc. from pwntools).
