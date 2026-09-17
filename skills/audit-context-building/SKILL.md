---
name: audit-context-building
description: Understand unfamiliar code before hunting bugs in it — what each function assumes, guarantees, and depends on. Use at the start of an audit, threat model, or architecture review, or when earlier findings could not be judged because nobody had mapped the assumptions. Produces no verdicts or severities.
---

# SKILL: Audit Context Building

Build understanding, not verdicts. This runs **before** hunting, and feeds it.

The output is a per-function record and a dossier of what spans them. The single most valuable
thing it produces is the list of **assumptions marked `nothing found`** — places where the code
counts on something being true and nothing anywhere makes it true. That list is the hunting
phase's work queue, and it is not obtainable by grepping for sinks.

## When to Use

At the start of an audit, threat model, or architecture review on unfamiliar code. Also when an
earlier pass produced findings nobody could judge, because no one had mapped how the system fits
together — a `memcpy` with an unbounded length is a finding or a non-finding depending entirely on
a caller contract, and that contract is what this phase establishes.

Not worth the tokens on code you already understand, or on a single function you can simply read.

## When NOT to Use

**Do not name vulnerabilities, suggest fixes, write PoCs, or rate severity here.** Those belong to
the hunting phase, which runs next and with the whole picture in hand. When the code counts on
something and nothing checks it, record that plainly and move on; whether it matters is decided
later, by `c-cpp-review` / `rust-security-audit` / `source-audit`, and adjudicated by
`false-positive-refutation`.

Crossing that line is the failure mode of this phase. A record that says "this is a heap overflow"
has stopped building context and started guessing, and it poisons the hunting phase by anchoring
it on one hypothesis.

## The Rule That Matters Most: Follow the Calls

Whether a function is correct almost always depends on something another function does, and **you
cannot see that from the caller alone.** A limit looks enforced because the value came back from a
function whose *name* suggests it was checked.

So: read the function being called. Follow **every path** through it, not only the one that
succeeds. Say what makes each assumption true. When nothing does, use those words — `nothing
found`. Every claim cites a line, or becomes an open question.

The corollary is that a function you cannot read is a **black box**, and must be recorded as one
rather than guessed at: a third-party library with no vendored source, a syscall, a `dlopen`'d
plugin, an FFI callee, an external contract, a decompiled function whose source is absent. Name
the boundary; do not invent its behaviour.

## The Record Format

One record per function. Six slots, and every claim carries a `file:line`.

```
## <function> — <file:line>

**Purpose** — one or two sentences: what it is for, in the caller's terms.

**Invariants** — what must always be true here, each with the line that establishes it.
  - `len <= sizeof(buf)` — enforced at parse.c:88
  - `state != NULL` on entry — nothing found

**Assumptions** — what it takes on faith about its inputs, its globals, or its environment,
  each with whatever establishes it, or `nothing found`.
  - hdr->count matches the number of records that follow — nothing found
  - fd is open and non-blocking — set by accept_conn() at net.c:212

**Guarantees** — what a correct caller may rely on afterwards, per exit path. Enumerate the
  error exits separately: "returns -1 with *out untouched" is a different guarantee from
  "returns -1 with *out freed but not NULLed".

**Calls out to** — each callee and what this function needs from it. Mark black boxes.
  - validate_hdr() @ hdr.c:40 — needs it to reject count > MAX. Verified: it does, line 51.
  - EVP_DecryptUpdate() — black box (OpenSSL, not vendored)

**Open questions** — what is still unclear. An honest list here beats a confident answer
  that turns out to be wrong.
```

Two slots do the real work:

- **Assumptions marked `nothing found`.** Hand these straight to the hunting phase.
- **Open questions.** Carry them forward rather than closing them out.

Where two records disagree, **quote both** rather than quietly reconciling them. That
disagreement is a fact about the code, not a flaw in the analysis — and it is very often where the
bug is.

## Dossier: What Spans the Functions

Beyond per-function records, record the cross-cutting picture:

- **Entry points and who can reach each** — remote unauth / remote auth / local user / local root /
  same-process / another tenant. This ranking is the audit plan.
- **Trust boundaries**, marked explicitly: network↔process, process↔kernel (ioctl/syscall),
  user↔root (setuid/IPC/D-Bus/service), tenant↔tenant, plugin↔host, deserializer↔object graph.
- **Rules that span several functions** — the invariant on a shared struct field, the locking
  discipline, the "always call `init` before `use`" contract, the ownership convention for a
  pointer passed across a module.
- **Lifecycle of the long-lived state** — for each field of the main state struct: every writer,
  every reader, and what the field's rule is at each. This is the input to the invariant audit
  that finds bugs no class label surfaces.
- **Where the complicated parts cluster** — the functions with the most callers, the deepest call
  chains, the most branches. Complexity is where understanding runs out, and where bugs live.
- **What did not get read**, and why.

## Per-Target Notes

The format is the same whatever the target. What changes is what fills each slot, and what counts
as a call you cannot see inside.

**C and C++.** Assumptions are mostly about buffer sizes, ownership, and initialisation — and they
are usually *unwritten*, because C has no way to express them. `malloc` does not zero, so
"initialised by the caller" is an assumption; manual lifetime means "the caller still owns this
after the error return" is an assumption. **Macros are calls you cannot see**: a function-like
macro is textual and untypechecked, so its assumptions are invisible at the expansion site.
Conditional compilation forks the code you are reading — record which `#ifdef` configuration your
records describe.

**Rust.** Most assumptions are *enforced by the type system*, which makes the ones that are not
stand out sharply — and they cluster in exactly one place: the `// SAFETY:` obligations of `unsafe`
blocks. Read every one and ask whether the safe code above it actually establishes what the
comment claims. A missing or hand-waving `// SAFETY:` comment is an assumption marked `nothing
found`. FFI callees and trait impls supplied by the *caller* (a hostile `impl Read`) are the black
boxes.

**Decompiled and firmware targets.** A function with no source is a black box, full stop — record
what its call sites imply about it and stop. Decompiler output invents variables, guesses
signatures, mis-sizes stack buffers, and drops overflow-relevant arithmetic, so an "invariant"
read out of pseudo-C is an open question until confirmed in the disassembly. Record addresses
alongside names, so the record survives a re-analysis that renames things.

**Services and web backends.** Assumptions are about the request shape, the session state, and
what a middleware layer already did. "Authenticated by the time this handler runs" is the single
most common assumption worth checking against the actual route registration; framework
auto-escaping and ORM parameterisation are assumptions about a black box.

## Cost Control

The analysis is long, and this phase is worth nothing if the context needed to *use* it is gone by
the time it finishes. Two rules:

1. **Do not read the whole tree.** Rank entry points by attacker reachability first, then build
   records along those paths only. A dossier covering the remote-unauth path completely is worth
   more than a shallow one covering everything.
2. **Write records to disk, not to context.** Keep a file per function (or one file per module)
   and keep only the index, the `nothing found` assumptions, and the open questions in working
   memory. Read a function's file back when you need its detail. When the target is large enough
   that this matters, dispatch per-function analysis as separate focused tasks with concrete
   locations and questions — never "analyze everything" — and verify what comes back before
   recording it.

Stop when the records answer the question the audit is actually about. Full comprehension of a
large codebase is a research project, not an audit phase; say in the report what you did not map.

## Handing Off

The hunting phase consumes three things:

| Artifact | Consumed by |
|---|---|
| Ranked entry points + trust boundaries | `source-audit` Phase B, as the audit plan |
| `nothing found` assumptions | `c-cpp-review` / `rust-security-audit` — each is a candidate hypothesis with the missing check already named |
| State-struct field lifecycle | the invariant audit (`state-field-invariant` in `c-cpp-review`) |
| Open questions | carried into the report's coverage section, unresolved and labelled |

A record whose assumptions are all established is a **negative result worth keeping** — it stops
the hunting phase re-deriving the same contract.

## Cross-references

- Attack-surface enumeration commands and the coverage ledger → `source-audit`
- C/C++ per-unit review questions once context exists → `c-cpp-review`
- Rust safe/unsafe boundary and `// SAFETY:` review → `rust-security-audit`
- Judging a candidate the hunting phase produced → `false-positive-refutation`
- Reconstructing a black box you have only as a binary → `re-tools`
- Footgun APIs and unenforced-by-design contracts → `sharp-edges-and-insecure-defaults`
