---
name: code-obfuscation-deobfuscation
description: Recognising and undoing code obfuscation and packing in native binaries. Use when a binary is packed, its decompilation is unreadable, or strings and imports are absent — UPX and custom packers, OEP finding and import reconstruction, control-flow flattening, opaque predicates, MBA, string encryption, self-modifying code.
---

# SKILL: Obfuscation & Deobfuscation

Owns **code transformations and how to undo them**. Anti-debug checks are `anti-debugging-techniques`; VM-based protection and managed bytecode are `vm-and-bytecode-reverse`; solver-driven simplification is `symbolic-execution-tools`; disassembler syntax is `re-tools`.

Use only on targets you are authorized to analyze. Analyse malware in an isolated environment; never execute it on your host.

## Discipline

**Identify the transformation before attacking it.** "Obfuscated" is not a diagnosis. Packing, flattening, MBA, and a VM interpreter each need a different method, and applying the wrong one wastes the most time in this whole domain.

**Deobfuscate only what blocks your question.** Full recovery of a protected binary is a research project. If you need one function's algorithm, recover that function. Scope creep here is the norm and it is expensive.

**Verify the recovered logic against the original.** A simplified expression or a rewritten CFG is a hypothesis until the two produce identical outputs on the same inputs. Emulate or execute both and diff — this is the only honest proof that your deobfuscation is faithful.

## Triage: Which Transformation?

| Observation | Likely transformation |
|---|---|
| High entropy section, few imports, tiny `.text`, big `.data` | **Packer** |
| Section names `UPX0`/`UPX1`, `.aspack`, `.themida`, `.vmp0` | Named packer/protector |
| Entry point immediately `pusha`/`pushad` then a loop writing memory | Packer stub |
| One giant function, `switch` on a state variable, all blocks at one level | **Control-flow flattening** |
| Conditionals that always take one branch but aren't optimised away | **Opaque predicates** |
| Long chains of `xor`/`add`/`and`/`neg` computing something trivial | **MBA** |
| Strings absent at rest, appear in memory at runtime | String encryption |
| Imports resolved by hash at runtime, `GetProcAddress`-style loops | API hashing |
| Small handler functions, indexed dispatch loop, a "bytecode" blob | **VM protection** → `vm-and-bytecode-reverse` |
| Code bytes change during execution | Self-modifying code |

```bash
binwalk -E ./target                 # entropy graph — flat high entropy = packed/encrypted
rabin2 -I ./target                  # "static", "stripped", canary, packer hints
rabin2 -S ./target                  # section names, sizes, entropy
rabin2 -i ./target | wc -l          # a handful of imports on a large binary = resolved at runtime
rizin -qc 'aaa; afl' ./target | wc -l
```

## Unpacking

**Always unpack before anything else.** Analysing packed bytes — patching, breakpointing, decompiling — produces nothing.

```bash
upx -d -o unpacked ./target         # try the obvious first; works surprisingly often
```

For custom packers, the generic dump-at-OEP workflow:

1. **Find the OEP.** The stub decompresses, then transfers control. Break on the transition: a hardware breakpoint on the unpacked region turning executable (`mprotect`/`VirtualProtect`), a `hbreak` on the destination, or run until the stub's final `jmp`/`ret` into freshly written memory.
2. **Dump the image** from memory once decompression finishes.
3. **Reconstruct imports** — the IAT is rebuilt at runtime; a dump without it is unusable. (Windows: Scylla/ImpRec. Linux: rebuild from the resolved GOT.)
4. **Fix section headers** so the dump loads in a disassembler.

```
gdb> catch syscall mprotect          # Linux: watch for the region turning executable
gdb> hbreak *<unpacked_region>       # hardware bp — no 0xCC for the stub to find
gdb> dump memory out.bin 0x400000 0x500000
```

Use **hardware** breakpoints throughout: packer stubs commonly checksum their own code and will notice `0xCC` (`anti-debugging-techniques`).

Emulation is the alternative when the stub resists debugging — run it under QEMU or Unicorn and snapshot memory at OEP.

## Control-Flow Flattening

The dispatcher pattern: every basic block returns to a central `switch`, which selects the next block from a state variable. The real CFG is hidden in the state transitions.

Recovery:

1. Identify the **state variable** and the dispatcher block.
2. Enumerate the real blocks (the `switch` cases).
3. For each block, determine the state value it writes — that edge is the real successor.
4. Rebuild the CFG from those edges.

When the state transition is computed rather than constant, a symbolic execution pass over each block recovers the next-state expression — this is where `symbolic-execution-tools` earns its place. In IDA, the **D-810** plugin automates flattening removal on the microcode level; **miasm** and **Triton** do the same programmatically.

## Opaque Predicates

Conditions whose outcome is fixed but not obvious to the compiler — `(x*x + x) % 2 == 0` is always true, `7*y*y - 1 == z*z` never has integer solutions.

Defeat them by asking a solver whether the other branch is reachable:

```python
import z3
x = z3.BitVec('x', 32)
s = z3.Solver(); s.add((x*x + x) % 2 != 0)
print(s.check())        # unsat -> the branch is dead, prune it
```

Prune every branch the solver proves unreachable, then re-run the disassembler's CFG analysis. Dead code often collapses dramatically once the predicates are gone.

## Mixed Boolean Arithmetic

Arithmetic identities expand a simple operation into a long chain — `x + y` becomes `(x ^ y) + 2*(x & y)`, and so on for dozens of terms.

| Method | Tool |
|---|---|
| Pattern rewriting against a rule set | `msynth`, `SSPAM`, custom peephole rules |
| Program synthesis from I/O behaviour | `msynth`, `QSynthesis` — treat the expression as a black box, synthesise an equivalent |
| Solver-assisted simplification | z3 `simplify`, plus equivalence checking |
| Symbolic expression simplification | Triton's AST simplifier, miasm's expression engine |

The synthesis approach is the most robust against unseen identities: sample the expression's outputs over its inputs, then search for the smallest expression matching that behaviour. Always **verify equivalence** with a solver before trusting a synthesised replacement.

## String and API Encryption

Strings decrypt on demand; imports resolve by hash. Both are routine and both have a cheap dynamic answer.

- **Dynamic**: breakpoint the decryption routine, let the program decrypt for you, and dump the plaintext at each call. One breakpoint recovers every string.
- **Static**: identify the routine, reimplement it in Python, and sweep the encrypted blob offline. Necessary when execution isn't possible.
- **API hashing**: recover the hash algorithm (usually a small rolling hash over the name), then brute-force it against exported-name lists from the relevant DLLs/SOs to rebuild the import table.

Emulating just the decryption function — with Unicorn, or angr with everything else stubbed out — is often the fastest route when the routine is self-contained.

## Junk Code, Dead Code, Instruction Substitution

Semantic no-ops inserted to defeat pattern matching and inflate the disassembly: `push`/`pop` pairs, `xchg` round-trips, arithmetic that cancels, unreachable blocks behind opaque predicates, and single instructions replaced with equivalent sequences.

Approach: normalise, don't read. Lift to an IR (miasm, Triton, VEX via angr, or Binary Ninja/IDA microcode), let the IR's own dead-code elimination and constant folding run, then read the simplified output. This is what a compiler optimiser does, and reusing one beats manual cleanup.

## Choosing a Method

| Transformation | First choice | Fallback |
|---|---|---|
| Packing | Unpack + dump at OEP | Emulate the stub |
| Flattening | D-810 / IR-level pass | Per-block symbolic next-state recovery |
| Opaque predicates | Solver-prove branch unreachable | Dynamic tracing shows the taken branch |
| MBA | Program synthesis | Rule-based rewriting |
| String/API encryption | Breakpoint the decryptor at runtime | Reimplement it statically |
| Junk/substitution | IR lifting + optimiser | Manual peephole |
| VM protection | `vm-and-bytecode-reverse` | — |
| Self-modifying | Dump after modification | Emulate and snapshot |

## Failure Triage

| Symptom | Cause | Fix |
|---|---|---|
| Dump won't load in the disassembler | Imports/sections not reconstructed | Rebuild the IAT and fix headers before analysis |
| Breakpoint never hits | Region still packed at that point | Break later — after `mprotect`/`VirtualProtect` |
| Patch reverts during execution | Self-checksumming or re-decryption | Patch after the check, or emulate |
| Decompiler output is one huge function | Flattening | Recover the CFG before reading |
| Simplified expression gives wrong results | Rewrite rule wasn't equivalence-checked | Verify with z3 over the full input domain |
| Symbolic simplification never terminates | Path explosion in the obfuscated region | Bound the scope to one block; see `symbolic-execution-tools` |
| Handlers look like a dispatch table | It's a VM, not flattening | `vm-and-bytecode-reverse` |
| Unpacked binary still has no strings | Second-stage packing, or strings encrypted separately | Re-triage entropy on the dump |

## Related Skills

`vm-and-bytecode-reverse` (VM protectors, managed bytecode) · `symbolic-execution-tools` (solver-driven simplification, next-state recovery) · `anti-debugging-techniques` (checks guarding the packer stub) · `re-tools` (disassembler commands, entropy triage) · `dynamic-verification` (breakpoints, memory dumps) · `cve-patch-analysis` (diffing recovered code against a known version).
