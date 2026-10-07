---
name: reading-decompiled-code
description: Reading decompiler and disassembler output without drawing wrong conclusions — signedness of comparisons per architecture, compiler runtime helpers in stripped binaries, lossy varargs, the CWE-134 false-positive trap, instruction side effects, and discharging bounds claims. Use when a bug claim rests on reconstructed C, when a bounds check's signedness decides the vulnerability, or when a stripped binary's arithmetic must be identified by shape.
---

# SKILL: Reading decompiled code honestly

The decompiler is a lossy summary. **Treating its output as source is the most common source of wrong findings** — which makes this skill a refutation tool as much as a discovery one. Every claim below is about the gap between what the pseudo-C says and what the bytes do.

Applies to Binary Ninja Pseudo C, HLIL, and Ghidra's decompiler alike; their failure modes differ, so record which produced a reading (`binaryninja-mcp` ownership rules).

## Read the disassembly for signedness — always

Whether a bound is a **signed or unsigned** compare *is* frequently the whole vulnerability, and the C rendering blurs it. A signed compare against a length lets a negative value pass a `<= max` check. This table is the bridge from "signedness matters" to actually reading it:

| Arch | Signed | Unsigned |
|---|---|---|
| x86 / x86-64 | `jl` `jg` `jle` `jge` | `jb` `ja` `jbe` `jae` |
| AArch64 | `b.lt` `b.gt` `b.le` `b.ge` | `b.lo` `b.hi` `b.ls` `b.hs` |
| MIPS | `slt` `slti` | `sltu` `sltiu` |
| RISC-V | `blt` `bge` | `bltu` `bgeu` |
| PowerPC | `cmpw` `cmpwi` | `cmplw` `cmplwi` |

**PowerPC deserves care**: the `l` marks the *unsigned* form, and the branch that follows (`bge`/`blt`) reads identically after either comparison — so the comparison instruction, not the branch, carries the signedness.

**Verified on real firmware** (ARM64 Linux kernel Image, 870,882 instructions decoded via capstone): all eight AArch64 forms occur in quantity — signed `b.lt` 806 / `b.gt` 1210 / `b.le` 1829 / `b.ge` 404, unsigned `b.lo` 1320 / `b.hi` 4394 / `b.ls` 3526 / `b.hs` 1130. **Unsigned outnumbered signed ~2.4:1**, so a signed compare guarding a length is the minority case and worth flagging when you see one. Narrowing loads in the same sample: sign-extending `ldrsw`/`ldrsh`/`ldrsb` = 934, zero-extending `ldrh`/`ldrb` = 18,497 — 934 places where the extension decides the program and the C shows nothing.

**Tooling — GNU `objdump` on this host is x86-only** (`supported architectures: i386 i386:x86-64 …`; no ARM, AArch64, or MIPS). For foreign-architecture firmware it produces *no output and no error*, which reads exactly like "nothing there". Use instead:

```bash
rz-asm -a arm -b 64 -d "e10300aa"          # rizin: verified working for arm64
rizin -a arm -b 64 -qc 'pd 40' ./blob      # or radare2 equivalents
python3 -c 'from capstone import *; ...'    # capstone 5.0.7, system python — verified
```

`llvm-objdump` is present but does **not** accept GNU's `-b binary`. A raw blob (kernel `Image`, firmware payload) also has no ELF container, so a plain `objdump -d` yields one "file format binary" line — see `re-tools` for the container branch.

**MIPS branch delay slots**: the instruction after a branch executes whether or not the branch is taken. When the C shows an ordering that makes no sense, this is usually why.

**Sign vs zero extension on narrowing loads** is invisible in C. A sign-extending load of a 16-bit length into a 32-bit register is a different program from a zero-extending one. In Binary Ninja, read `llil` — extension is explicit there.

## Compiler runtime helpers — the arithmetic hides in an unnamed function

On targets whose ISA lacks an instruction for an operation — 64-bit division nearly everywhere on 32-bit targets, integer division on ARM profiles without `idiv` — the compiler calls into `libgcc`/`compiler-rt` instead. In a stripped firmware binary that helper is an unnamed `sub_xxxx`, and it is frequently the **only** place the operation occurs in the entire program. Recognise it by **shape**, not name:

| Shape | Likely helper |
|---|---|
| four integer params, returns a 64-bit pair, **first branch tests two against zero**, then saturates to `INT_MIN`/`INT_MAX` | 64-bit divide/modulo — `__divdi3`, `__udivdi3`, `__moddi3`, `__aeabi_ldivmod` |
| two integer params, same zero test | 32-bit divide — `__udivsi3`, `__aeabi_uidiv` |
| a rolled byte/word loop with no symbol, where a copy should be | inlined `memcpy`/`memset` — the length argument is still the question |

**A helper that calls `raise` is signalling, not aborting.** Where division is a library call rather than a trapping instruction, the zero check is explicit and raises `SIGFPE` in software — so `raise` reached from an arithmetic helper points at **CWE-369 divide-by-zero**, not the generic "abort path" an import table suggests. Conversely, where the ISA traps division in hardware there is no call at all, so **absence of `raise` rules nothing out.** Ask what a signal-raising function is *for* before classifying it.

`bn_function_stack_layout` and `bn_function_prototype_get` help identify these by parameter shape; once identified, `bn_function_callers` gives you every divisor in the program to check.

## Lossy reconstruction — what gets silently dropped

- **Variadic arguments and the computation producing them.** Systematic on Mach-O AArch64 (Apple passes varargs on the stack; the stores get dead-code-eliminated). The shape: a function decompiles to two `printf` calls and some constant stores, while the disassembly holds the hash computation, the `umull`/`lsr` modulo, and the `cbz` guarding an `sdiv` — the entire divide-by-zero question. **Never conclude "this function does almost nothing" from a short decompilation.**
- **Inlining** fuses functions so the guard and the sink appear unrelated.
- **Rolled-up SIMD copies** look like loops with wrong bounds.
- **Spurious aliasing** — two `local_`/`var_` names that are one variable; `undefined` stack slots.
- **Instruction side effects** — condition flags, implicit register writes, addressing-mode effects. The mnemonic understates what the instruction does.

## The CWE-134 trap — a specific false positive to refuse

A `printf`/`__printf_chk` whose format string has **more conversion specifiers than the decompiler shows arguments** is **almost never** a format-string bug. Two far likelier causes:

1. GCC's `-fipa-ra` lets a call reuse a register the caller already loaded — the argument is present but invisible at the call site;
2. the stack-vararg loss above.

**Claim CWE-134 only when the format pointer itself is attacker-derived** and you can trace input into the first argument. "The decompiler rendered `printf` with a missing argument" is not that. This belongs in `false-positive-refutation`'s gate list for any format-string candidate.

## Ordering — three different things, routinely conflated

- **Compiler scheduling** — instruction order need not match source order. Expected; read no intent into it.
- **Weak memory ordering** — in concurrent code the observed order depends on the model; x86-TSO is strong, ARM and POWER are weak. Read the barriers. **This is where real ordering bugs live.**
- **Speculative execution** — only relevant to transient-execution side channels. CPU out-of-order execution is architecturally transparent and is *not* what "out of order" should mean in a finding.

## Discharging a bounds claim

A bounds claim is an **agenda item, not a detector output**. For each candidate, write the claim as algebra and discharge it explicitly — this is the "write out the algebra" requirement in the Sanitizer Analysis field:

- State it: *"`len` at `0x401230` can exceed `sizeof(buf)` = 0x88."*
- Enumerate every check on the path and what each actually constrains — including the **signedness** of each, per the table above.
- Discharge: proved safe (say which check and why it is sufficient), proved unsafe (give the triggering value), or **undischarged** (say what is missing). Undischarged is a legitimate third state and must not be silently filed as either.
- **Signedness decides more of these than anything else.** A check that bounds `len <= 0x88` with a *signed* compare does not bound `len = -1`.
- Where the argument gets long, a harness beats an argument: extract the function and test the boundary values directly.

**When a tool and the bytes conflict, the bytes win.** Cross-check the decompilation against the disassembly, and one tool against another.

## Cross-references

- IL levels, and why MLIL SSA answers "where did this value come from" → `binaryninja-mcp`
- Mach-O varargs and container-specific traps → `pe-and-macho-analysis`
- The gate this skill feeds, especially for CWE-134 → `false-positive-refutation`
- Integer and signedness bug classes → `bug-class-catalog`, `c-cpp-review`
- Making a bounds question a runtime answer instead of an argument → `sanitizers-and-coverage`, `fuzzing-harness-design`
- Answering reachability when reading runs out → `symbolic-execution-tools`

*Signedness table, helper-shape recognition, and the CWE-134 trap adapted from the REx-skill `SKILL-RE` reference (github.com/tihanyin/REx-skill, §7–8, §31).*
