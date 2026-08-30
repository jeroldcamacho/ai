---
name: symbolic-execution-tools
description: Symbolic and concolic execution for reverse engineering and vulnerability research. Use when a question is computational rather than readable — solving a licence check or keygen, finding input that reaches a target address, recovering a next-state expression from obfuscated code, or proving a branch unreachable — with angr, claripy, z3, Triton, or Manticore. Covers when symbolic execution is the wrong tool, controlling path explosion with hooks, SimProcedures, veritesting and state pruning, symbolising only the bytes that matter, and reading unsat/timeout results correctly.
---

# SKILL: Symbolic Execution

Owns **solver-driven analysis**: angr/claripy/z3/Triton depth, path-explosion control, and result interpretation. The one-off angr snippet and the local Python environment are in `re-tools`; deobfuscation strategy is `code-obfuscation-deobfuscation`; runtime proof of a crash is `dynamic-verification`.

Use only on targets you are authorized to analyze.

## Discipline

**Symbolic execution is a computation tool, not a reading tool.** It pays off when the answer is a *value* — an input, a key, a constraint solution. It does not pay off for "what does this program do"; that is disassembly and dynamic tracing, and reaching for a solver there wastes hours.

**Decide the budget before you start.** Symbolic execution either finishes in seconds or runs forever. Set a wall-clock limit and a state cap up front; when it blows through them, the answer is to change the approach, not to wait longer.

**A solver result is evidence about the model, not the program.** `unsat` means *your constraints* had no solution — which is equally consistent with a wrong memory model, an over-constrained input, or a missing library stub. Always execute the concrete input the solver hands you against the real binary and confirm it does what you claimed.

## When To Use It — and When Not

| Use it | Don't |
|---|---|
| Find input reaching address X | Understand overall program behaviour |
| Solve a licence/keygen/serial check | Explore a large network-facing binary end to end |
| Recover a CRC/hash/encoding constant | Anything with heavy crypto (the solver cannot invert a real hash) |
| Prove a branch unreachable (opaque predicate) | Loop-heavy parsers with unbounded input |
| Recover next-state expressions in flattened code | Code dominated by syscalls/IO you'd have to model |
| Generate a seed that reaches deep coverage | Bulk bug-finding — fuzzing is far cheaper (`fuzzing-triage`) |

The honest heuristic: if the interesting logic is under ~10k instructions and mostly arithmetic and comparisons, symbolic execution wins. Otherwise fuzz, or trace concretely and only symbolise a slice.

## Environment

angr, claripy, z3, and lief live in the isolated venv documented in `re-tools`:

```bash
~/.local/venvs/vr/bin/python3 solve.py          # plain python3 has no angr
```

## angr — the standard shape

```python
import angr, claripy, logging
logging.getLogger('angr').setLevel('ERROR')

proj = angr.Project('./target', auto_load_libs=False)   # auto_load_libs=False is almost always right

flag = claripy.BVS('flag', 8 * 32)                       # symbolise ONLY the input that matters
state = proj.factory.entry_state(stdin=flag)
for b in flag.chop(8):                                   # constrain the alphabet — huge speedup
    state.solver.add(claripy.Or(b >= 0x20, b == 0))
    state.solver.add(b <= 0x7e)

simgr = proj.factory.simulation_manager(state)
simgr.explore(find=0x401337, avoid=[0x401300, 0x4012f0])

if simgr.found:
    print(simgr.found[0].solver.eval(flag, cast_to=bytes))
else:
    print('no path found', simgr.errored[:3])
```

Three choices in that snippet account for most of the difference between "solves in 4 seconds" and "runs all night":

1. **`auto_load_libs=False`** — otherwise angr symbolically executes libc and drowns.
2. **Symbolise the minimum.** Symbolising a whole 4 KB buffer when the check reads 16 bytes is the most common self-inflicted path explosion.
3. **Constrain the input domain.** Printable-ASCII constraints prune enormous swathes of the state space.

Give `avoid` real addresses — the "wrong password" branch, `exit`, error handlers. Avoiding is usually cheaper than finding.

## Controlling Path Explosion

| Technique | What it does |
|---|---|
| **Hooks / SimProcedures** | Replace a function with a Python model — essential for `printf`, custom hash, or anything with a loop you don't care about |
| **`blank_state(addr=...)`** | Start mid-program instead of at the entry, skipping initialisation entirely |
| **Veritesting** (`simgr = proj.factory.simgr(state, veritesting=True)`) | Merges states across branches — very effective on branchy, loop-free code |
| **`LoopSeer`** (`simgr.use_technique(angr.exploration_techniques.LoopSeer(bound=10))`) | Bounds loop iterations |
| **`DFS`** | Keeps memory flat when breadth explodes |
| **`Explorer` with `num_find`** | Stop at the first solution |
| **Manual pruning** | `simgr.move(from_stash='active', to_stash='deadended', filter_func=...)` |
| **Concrete-to-symbolic slicing** | Run concretely to a point, then symbolise from there |

```python
class FakeCheck(angr.SimProcedure):
    def run(self, buf, length):
        return claripy.BVV(1, 32)          # pretend it succeeded
proj.hook_symbol('expensive_check', FakeCheck())

proj.hook(0x401200, lambda s: None, length=5)   # skip 5 bytes of instructions entirely
```

Hooking is the single highest-leverage technique. When a run stalls, find the function it is stuck in (`simgr.active[0].history.bbl_addrs`) and hook it.

## Using z3 Directly

For a pure constraint problem, skip angr entirely — it is far faster and easier to debug:

```python
import z3
a, b = z3.BitVecs('a b', 32)
s = z3.Solver()
s.add(a ^ 0xdeadbeef == b, b + a == 0x1337, a > 0)
print(s.check(), s.model() if s.check() == z3.sat else '')
```

Use z3 for: opaque-predicate proofs, checksum/CRC inversion, offset arithmetic, verifying that a synthesised expression is equivalent to the original (`code-obfuscation-deobfuscation`). Use `z3.BitVec`, not `Int` — machine arithmetic wraps, and `Int` will give you answers the CPU never would.

## Concolic Execution — Triton and Manticore

Concrete execution drives the path; symbolic state is collected alongside. Better than pure symbolic when the program has heavy IO, syscalls, or environment interaction you would otherwise have to model.

| Tool | Best at |
|---|---|
| **Triton** | Instruction-level symbolic state, expression simplification, deobfuscation passes, taint. The usual choice for MBA and flattening work |
| **Manticore** | Whole-binary and EVM analysis, scriptable state exploration |
| **angr concrete mode** | Mixing a real process (via GDB) with symbolic state |
| **Unicorn** (via angr's engine) | Fast concrete emulation of a slice; not a solver, but pairs with one |

Typical Triton use in RE: emulate one obfuscated function, collect the symbolic expression for its output, simplify, and read the recovered semantics — no path exploration at all.

## Interpreting Results

| Result | Means | Do |
|---|---|---|
| `sat` + model | A solution exists **for your model** | Run the concrete input against the real binary — always |
| `unsat` | No solution under your constraints | Suspect over-constraint or a bad model before concluding the branch is dead |
| `unknown` / timeout | Solver gave up | Simplify constraints; reduce symbolic width; split the query |
| Empty `found`, non-empty `errored` | Unsupported instruction, unmodelled syscall, or a memory error | Inspect `simgr.errored[0].error`; hook the offending function |
| `found` state but wrong output concretely | Model diverged from reality (libc, environment, uninitialised memory) | Re-run with the real libc, or symbolise less |

`state.solver.eval(x, cast_to=bytes)` gives one solution; `eval_upto(x, 10, cast_to=bytes)` shows whether the answer is unique — worth checking before reporting a "the" key.

## Failure Triage

| Symptom | Cause | Fix |
|---|---|---|
| Runs forever, memory climbs | Path explosion | Hook expensive functions; `LoopSeer`; DFS; symbolise fewer bytes |
| Stuck inside libc | `auto_load_libs=True` | Set it `False`; hook what you need |
| "Unsupported syscall" | Unmodelled environment | `SimProcedure` for it, or start from a `blank_state` past it |
| Solution is garbage bytes | Input domain unconstrained | Add printable/length constraints |
| Works on the sample, not the real binary | Different libc, or uninitialised memory assumed zero | `add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY}` deliberately, and note it |
| z3 hangs on a hash | Solvers cannot invert cryptographic hashes | Brute force or attack the algorithm, not the solver |
| `unsat` on a branch you saw execute | Over-constrained, or wrong start state | Re-derive constraints; verify with a concrete trace |

## Related Skills

`re-tools` (disassembly, the venv path) · `code-obfuscation-deobfuscation` (what to point the solver at) · `vm-and-bytecode-reverse` (recovering VM handler semantics) · `anti-debugging-techniques` (emulate instead of debug) · `fuzzing-triage` (cheaper for bulk bug-finding) · `exploit-dev` (offset and constraint math in exploits).
