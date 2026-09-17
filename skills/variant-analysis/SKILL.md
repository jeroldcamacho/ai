---
name: variant-analysis
description: Find the other instances of a bug already found. Use right after a vulnerability or bad pattern turns up and the question becomes where else it occurs, when generalizing one instance into a reusable CodeQL or Semgrep query, or when a patch fixed one call site and may have missed siblings. Not for initial discovery.
---

# SKILL: Variant Analysis

One bug is rarely alone. One root cause usually has several manifestations, and **they are rarely
in the module where you found the first one**. This skill turns a confirmed finding into the set
of its siblings, and into a query that keeps finding them.

Run it after every confirmed finding, before writing up. Not for initial discovery — that is
`source-audit`, `c-cpp-review`, `rust-security-audit`.

## Why Variants Exist (this predicts *where*)

1. **Developer habits** — the same person writes similar code and makes similar errors. Cluster:
   the files that author touched (`git log --format='%an' -- <path>`).
2. **Copy-paste propagation** — boilerplate spreads a bug. Cluster: sibling files, other protocol
   handlers, the other three drivers in the same directory.
3. **API misuse patterns** — a complex API invites consistent misunderstanding. Cluster: **every
   call site of that API, anywhere in the tree**, including vendored copies.
4. **Framework idioms** — framework patterns create predictable shapes. Cluster: every route,
   every handler, every subclass.
5. **Incomplete fixes** — the bug was fixed in one place and missed elsewhere. Cluster: the other
   callers the patch did not touch. This is the highest-yield case in N-day work.

Knowing *why* a variant exists tells you where to look. A copy-paste bug clusters in siblings; an
API-misuse bug clusters at call sites and ignores directory structure entirely.

## Step 1 — Extract the Root Cause

Ask four questions before writing any pattern:

1. **What operation is dangerous?** (`system()`, `memcpy`, raw SQL, an authorization check)
2. **What data makes it dangerous?** (user-controlled input, a null, an attacker-chosen size)
3. **What is missing?** (sanitization, a bounds check, canonicalisation, a null guard)
4. **What context enables it?** (an error path, a specific caller, an unauthenticated state)

Then write the statement:

> This vulnerability exists because **[untrusted data]** reaches **[dangerous operation]**
> without **[required protection]**.

Examples: "attacker-controlled size reaches `malloc()` without an overflow check"; "an untrusted
path reaches `open()` without canonicalisation"; "a length field is stored into state without
being checked against the buffer bound".

**That statement is the search pattern.** Everything below expands it.

For a logic bug with no data flow, state the **violated invariant** instead: "this function must
return false for unauthenticated callers, and it returns true when both IDs are null."

## Step 2 — Enumerate the Expansion Axes

A single root cause manifests several ways. List them all *before* searching. Each axis will be
searched independently, so each must be **independently searchable** (naming concrete identifiers
or constructs, not a theme like "authorization problems"), **non-overlapping**, and
**grounded** — its leads must exist in *this* codebase. Grep the identifiers before claiming them;
a plausible-sounding name that does not appear produces an axis that searches hard and finds
nothing.

1. **Semantically related identifiers.** If the bug involves one name, every name playing the same
   role is in scope: `isAuthenticated` → also `isActive`, `isAdmin`, `isVerified`, `isLoggedIn`;
   `userId` → also `ownerId`, `creatorId`, `authorId`; `content_length` → also `payload_len`,
   `body_size`, `nbytes`.
2. **Other shapes of the same mistake.** Inverted conditions; the wrong default on a fall-through
   path; `or` where `and` was meant; the check applied to a normalized copy while the raw value is
   used; the bound re-derived rather than reused.
3. **Data-type edge cases.** Null/None/undefined on *both* sides of a comparison; empty string vs
   null; zero vs null; empty collections; boundary values at the type limits; signed vs unsigned.
4. **Documentation/code mismatch.** A function whose behaviour contradicts its own name or
   docstring. Search for functions named with `deny`, `restrict`, `block`, `forbid`, `check`,
   `validate`, `is_safe` and confirm the return value means what the name says.
5. **The sink family, not the sink.** `system` → also `popen`, `execl`, `execlp`, `execvp`,
   `posix_spawnp`, `CreateProcess`. `strcpy` → also `strcat`, `sprintf`, `stpcpy`. One API is
   never the whole family.
6. **Vendored and duplicated copies.** `cargo tree --duplicates`, a second copy of the library
   under `third_party/`, a forked file with local edits. The same bug, twice, with different fix
   status.

## Step 3 — Create an Exact Match (calibration, not search)

Write a pattern that matches **only** the known instance, and confirm it hits.

```bash
rg 'SELECT \* FROM users WHERE id=" \+ request\.args\.get'      # 1 match, 0 FP
```

**A pattern that matches nothing means you have misunderstood the bug**, and every search built on
it is calibrated against the wrong code. This step costs a minute and saves the whole hunt.

## Step 4 — Climb the Abstraction Ladder, One Rung at a Time

| Level | What changes | Typical matches | FP rate | Finds |
|---|---|---|---|---|
| 0 | nothing — the literal code | 1 | none | calibration |
| 1 | variable names → metavariables | 3–5 | low | copy-paste variants |
| 2 | surrounding structure generalised | 10–30 | medium | pattern variants |
| 3 | abstracted to the security property (taint mode) | 50–100+ | high | comprehensive coverage |

Pick the level from the goal: verifying one fix → 0; hunting copy-paste → 1; auditing a component
→ 2; full assessment → 3.

**Never generalize more than one element at a time.**

```
BAD:  exact code ─────────────────────────────────► fully abstract pattern
GOOD: exact code → abstract var1 → abstract var2 → abstract the operation
```

Each step: make **one** change, run it, read **all** the new matches, decide whether the FP rate
is still acceptable, then continue or revert. Jumping straight to level 3 produces a pile of
results with no way to attribute the noise to any one abstraction.

Decision points:

- **Abstract this variable name?** Yes if a different name could carry the same bug. No if the name
  itself is the semantic constraint you are relying on.
- **Abstract this literal?** Yes if any value triggers the bug. No if only specific values are
  dangerous.
- **Use `...` wildcards?** Yes if argument position does not matter. No if only one position is a
  sink.
- **Add taint tracking?** Yes if you need to prove data actually flows source→sink. No if the
  presence of the pattern is already sufficient evidence.

**Run every search against the entire codebase root**, not the directory the original bug lived
in. A bug in `api/handlers/` with a variant in `utils/auth.py` is the normal case. **Narrow scope
is the single most common reason a variant hunt finds nothing.**

## Step 5 — Tool Selection

| Situation | Tool | Why |
|---|---|---|
| Recon, surface sweep | `rg` | seconds, zero setup |
| C/C++ shape with scope ("buffer here, copy there") | `weggli` | syntax-aware, understands scope |
| Iterating the ladder, multi-language | Semgrep | easy syntax, no build, taint mode |
| Proving cross-function flow | CodeQL | true interprocedural dataflow |
| Cross-function on C/C++ **with no working build** | joern | CPG without compiling |

Tool loyalty is an anti-pattern. "I only use CodeQL" costs you the fast passes that tell you where
to aim it. Verified installed here: `rg`, `weggli`, `semgrep`, `joern`, and `codeql` at
`~/codeql/codeql/codeql` (not on `PATH` — invoke it by full path or check for it there before
concluding it is missing).

```bash
# Rung 1–2, portable
semgrep -e 'memcpy($DST, $SRC, $LEN)' --lang=c .
weggli '{ $n = _; not: $n < _; memcpy(_, _, $n); }' .

# Rung 3 — taint, the reusable artifact
cat > /tmp/variant.yaml <<'YAML'
rules:
  - id: tainted-len-to-copy
    languages: [c]
    severity: WARNING
    message: attacker-controlled length reaches a memory copy
    mode: taint
    pattern-sources:
      - pattern: recv(...)
      - pattern: read(...)
    pattern-sinks:
      - pattern: memcpy($D, $S, $LEN)
    pattern-sanitizers:
      - pattern: $LEN = MIN(...)
YAML
semgrep --config /tmp/variant.yaml .
```

## Step 6 — Triage: Argue Against Each Candidate

The snippet alone is never enough. Read the surrounding function, the callers, and the type of
every value, then look **specifically for the thing that makes it safe**:

- a guard earlier in the function, or in a decorator/middleware/wrapper
- a sanitizer, validator, or parameterised API between source and sink
- a type constraint making the dangerous value unreachable
- a caller set that never supplies attacker-controlled input

A candidate survives only if you looked for these and did not find them. Then establish:
**reachable** (a path from an external entry point), **controllable** (the attacker can influence
the value), **unprotected** (the protection named in the root cause is genuinely absent *here*).

Note what is **not** a refutation: **having no callers.** Code nothing reaches today is still
unprotected code, and a variant hunt is exactly the search that finds it before a caller arrives.
Report it at lower severity, and say what would make it reachable — do not refute it as dead.

Edge cases that hide real variants, because normal-path reasoning misses them:

- **Null-equality bypass.** If *both* sides of a comparison can be null at once, the comparison
  succeeds for the wrong reason: `order.owner_id == current_user.id` with both `None` passes for a
  user who owns nothing. Ask what values each side can hold, whether both can be null
  simultaneously, and who can cause that.
- **Documentation/code mismatch.** A function that does the opposite of what its name claims makes
  **every one of its callers** a potential finding, even where the call site looks correct.
- Unauthenticated and anonymous callers; empty string vs null; zero vs null; empty collections;
  boundary values at the type limits.

Attach a **severity** to every verdict, including informational ones, and keep it separate from
**confidence** (severity = impact if real; confidence = how sure you are it is real). Do not
suppress minor findings — filtering happens downstream where the full set is visible, and a
finding you decline to mention is a finding nobody sees.

**Record every false positive with the reason it was safe.** Grouped by reason, these become the
report's FP table, and they are what lets you refine the pattern instead of re-triaging the same
matches. Run survivors through `false-positive-refutation` before filing.

## Step 7 — Write It Up, Including the Failures

The deliverable is three things:

1. **The variant table** — location, verdict, severity, confidence, and the reason for each
   rejection.
2. **The final query**, with the rung it sits on and its measured FP rate on this tree. This is
   the reusable artifact; a variant hunt that leaves no query behind will be re-run by hand next
   time.
3. **The patterns that failed**, and why. "Level 2 with `...` in the length position matched 400
   sites, 380 of them constant-bounded" tells the next person which rung to stop at.

Add a **CI rule** so the class cannot regress: the Semgrep YAML (or the CodeQL query, with its
`.qls` suite reference) checked in next to the fix.

## What Makes Hunts Fail

1. **Narrow scope** — searching only the module the original bug was in.
2. **Pattern too specific** — searching one attribute and missing the family around it.
3. **One vulnerability class** — chasing a single manifestation of the root cause.
4. **Happy-path testing** — never trying the null, empty, and boundary cases.
5. **Generalizing too fast** — abstracting several elements at once, so noise cannot be attributed
   to any one of them.
6. **Stopping at the first clean rung** — a level-1 sweep that finds nothing is not evidence there
   are no variants; it is evidence there are no *copy-paste* variants.

## Cross-references

- Where the original finding came from → `source-audit`, `c-cpp-review`, `rust-security-audit`
- Refuting each candidate before filing → `false-positive-refutation`
- Rule authoring, taint mode, and test-first rule discipline → `semgrep`
- CodeQL database and suite discipline → `source-audit`
- Reading a vendor patch to get the root cause in the first place → `cve-patch-analysis`
- Vendored duplicate copies of a vulnerable library → `supply-chain-audit`
- Binary-only variant hunting (other callers of the same import) → `re-tools`
