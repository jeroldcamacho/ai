---
name: source-audit
description: Whole-codebase static audit methodology and interprocedural taint tooling. Use when auditing a source tree, mapping attack surface across a large repo, tracing taint across file boundaries, choosing between grep, weggli, Semgrep, CodeQL and joern, writing dataflow queries, running language SAST, resolving SARIF severity, or triaging noisy SAST output into ranked reachable findings.
---

# SKILL: Source Code Audit & Interprocedural Taint

How to audit a source tree you did not write. This skill covers **getting from "here is a 400k-line repo" to "here is a ranked list of reachable source→sink paths."**

Core discipline: an audit is a *coverage* exercise, not a scanning exercise. Track what you have looked at, not just what you found.

It sits in the middle of a five-stage pipeline; skipping either end is what produces audits nobody can act on:

```
audit-context-building → source-audit → c-cpp-review / rust-security-audit → false-positive-refutation → variant-analysis
   (what does the           (where is the      (what is wrong with            (is this real?)          (where else?)
    code assume?)            attack surface?)   this specific unit?)
```

- **Before**: `audit-context-building` establishes what each function assumes and guarantees. A `memcpy` with an unbounded length is a finding or a non-finding depending entirely on a caller contract, and that contract is what the context phase produces.
- **Per-language depth**: `c-cpp-review` for the C/C++ class catalog and per-unit review questions; `rust-security-audit` for the safe/unsafe boundary; `bug-class-catalog` for class→primitive mapping; `code-security` for per-CWE secure/vulnerable examples; `semgrep` for rule authoring; `llm-security` for LLM apps and agents.
- **After**: `false-positive-refutation` is the mandatory gate before anything is filed, and `variant-analysis` runs on every confirmed finding before write-up.

## Phase A — Build the Map (time-boxed)

Never read a function body before you know the shape of the tree.

```bash
tokei . || cloc .                       # languages + LOC, tells you which tooling applies
ls -1 | head -50                        # top-level layout
fd -t f -e md -d 2 . | head             # READMEs, ARCHITECTURE, SECURITY.md
git log --oneline -15                   # what's active
git log --format='%an' | sort | uniq -c | sort -rn | head   # who owns what
```

Build system → tells you what actually ships and how to get a compile database:

| Build file | Compile DB command |
|---|---|
| `CMakeLists.txt` | `cmake -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON` |
| `Makefile` | `bear -- make` (or `compiledb make`) |
| `meson.build` | `meson setup build` (emits `compile_commands.json`) |
| `package.json` / `go.mod` / `pom.xml` / `requirements.txt` | native SAST covers it; note the dependency manifest |

Record as **observations**: languages, build system, whether it builds, sanitizer support, which directories are third-party/vendored (audit those *last* unless the target is an N-day — see the `cve-patch-analysis` skill).

## Phase B — Attack Surface Enumeration

Enumerate entry points *before* sinks. A sink that no attacker can reach is not a finding.

```bash
# Network / IPC listeners
rg -n --no-heading '\b(bind|listen|accept|recvfrom|recvmsg|socket)\s*\(' -g '!test*'
rg -n 'AF_UNIX|SOCK_(STREAM|DGRAM)|ioctl|DeviceIoControl|dbus_|grpc\.'

# HTTP route surfaces
rg -n '@(app|router|bp)\.(route|get|post|put|delete)|app\.(get|post|use)\(|@(Get|Post|RequestMapping)'
rg -n 'http\.HandleFunc|mux\.Handle|Route::|routes\.rb'

# Process boundaries / privileged surfaces
rg -n 'setuid|setgid|seteuid|CAP_|SUID|sudo|polkit|SYSTEM\('
rg -n 'main\s*\(\s*int\s+argc|argparse|clap::|flag\.(String|Int)|getenv'

# Deserialization + file parsers
rg -n 'pickle\.loads|yaml\.load\(|ObjectInputStream|unserialize|Marshal\.load|BinaryFormatter'
rg -n 'fopen|mmap|fread|ReadFile|ParseFrom|json_?[Dd]ecode|XmlReader'
```

For each entry point record: **who can reach it** (remote unauth / remote auth / local user / local root / same-process), and the **format** of the data it accepts. Rank by reachability. This ranking is the audit plan — everything downstream is spent in that order.

Trust boundaries to mark explicitly: network↔process, process↔kernel (ioctl/syscall), user↔root (setuid/IPC/D-Bus/service), tenant↔tenant, plugin/extension↔host, deserializer↔object graph.

## Phase C — Tool Selection

Escalate only as far as the question requires. Cheap tools first.

| Tool | Best at | Cost | Interprocedural? |
|---|---|---|---|
| `rg`/grep | sink inventory, string/constant hunting | seconds | no |
| `weggli` | C/C++ **syntax-aware** patterns (buffer + copy in same scope) | seconds | no |
| Semgrep | multi-language patterns, taint mode, custom rules, CI | minutes | limited (intra-file) |
| CodeQL | true interprocedural dataflow, path queries, variant hunting | 10min–hours (needs build) | **yes** |
| joern | C/C++ CPG queries **without a working build** | minutes | **yes** |
| Language SAST | cheap language-idiomatic baseline | minutes | varies |

Rule of thumb: `rg` to inventory sinks → `weggli`/Semgrep to shrink the candidate set → CodeQL or joern to prove reachability across files → debugger to prove it at runtime (`dynamic-verification` skill).

### weggli — C/C++ syntax-aware sweeps

```bash
weggli '{ char $buf[_]; strcpy($buf, _); }' ./src              # stack buf + unbounded copy
weggli '{ $len = _; memcpy(_, _, $len); }' ./src                # copy with a variable length
weggli -u '{ malloc($n * _); }' ./src                           # unique matches: mul in alloc size
weggli '{ free($p); not: $p = _; _($p); }' ./src                # use after free in one scope
weggli '$fn(_);' -R '$fn=^(system|popen|execl|execlp)$' ./src    # exec sinks by regex
```

`not:` (must-not-occur) and `_` (wildcard) are what make weggli beat grep — it understands scope, so "buffer declared here, copied into there" is one query.

### CodeQL — interprocedural proof

`codeql` is installed at **`~/codeql/codeql/codeql`** and is *not* on `PATH` — invoke it by full
path, or check for it there before concluding it is missing.

**The CLI being installed does not mean the queries are.** Verified here: only `javascript-*` packs
are present, so a C/C++ run dies with `The QL pack 'codeql/cpp-queries' ... cannot be found` —
*after* you have paid for the database build. Check the packs **first**, and download the ones you
need (network required):

```bash
CQL=~/codeql/codeql/codeql
$CQL resolve packs 2>&1 | rg -i 'queries'      # what is actually available
ls ~/.codeql/packages/codeql                    # per-language packs on disk
$CQL pack download codeql/cpp-queries           # then the language you need
$CQL pack download trailofbits/cpp-queries      # extra coverage the stock suite misses
```

```bash
CQL=~/codeql/codeql/codeql
$CQL database create db --language=cpp --command="make -j$(nproc)"
$CQL database create db --language=python --source-root .          # no build needed
$CQL database analyze db suite.qls --format=sarif-latest --output=results.sarif
$CQL query run -d db custom.ql                                     # single custom query
```

Five rules that decide whether a CodeQL run means anything. Each of them fails **silently**, which
is why they are worth stating:

1. **A database that builds is not automatically a good database.** A cached or no-op build
   extracts almost nothing while reporting success. Check the file count against the source tree
   before analysing: `$CQL database print-baseline db`, and
   `$CQL resolve database --format=json db | jq '.languages, .sourceLocationPrefix'`. **Zero
   findings and a database that extracted nothing are the same output** — distinguish them.
2. **Never pass pack names to `database analyze`.** Each pack's `defaultSuiteFile` applies hidden
   filters that can silently resolve to zero queries. Always generate an explicit `.qls` and verify
   it resolves to a non-zero count:

   ```bash
   cat > suite.qls <<'QLS'
   - import: codeql-suites/cpp-security-and-quality.qls
     from: codeql/cpp-queries
   - import: codeql-suites/cpp-security-experimental.qls
     from: codeql/cpp-queries
   QLS
   $CQL resolve queries suite.qls | wc -l      # must be > 0 and roughly what you expect;
   #   a single line is usually the fatal 'QL pack cannot be found' error, not a query
   ```

3. **`security-and-quality` is not the broadest suite** — it excludes every `experimental/` query
   path. For a full sweep import `security-experimental` as well; the delta is 1–52 queries
   depending on the language. And `security-extended` is the *baseline*, not the ceiling: check
   whether Trail of Bits and Community query packs exist for the language
   (`$CQL pack download trailofbits/cpp-queries`) before claiming coverage.
4. **Data extensions catch what the shipped models miss.** Even Django, Spring and Express projects
   wrap request parsing, database calls and shell execution in project-specific helpers that no
   shipped model knows about — so taint stops at the wrapper and the query finds nothing. Enumerate
   the project's own wrappers, then model them:

   ```yaml
   # extensions/custom-sources.model.yml
   extensions:
     - addsTo:
         pack: codeql/cpp-all
         extensible: sourceModel
       data:
         - ["", "read_client_input", "", "", "ReturnValue", "remote", "manual"]
   ```
   Pass with `--model-packs` / `--additional-packs`. Either create extensions or **explicitly record
   that you skipped them, with the justification** — a taint query with no project models is a
   coverage hole, not a clean result.
5. **`--build-mode=none` on a compiled language produces severely incomplete analysis.** Use it only
   as a last resort, and label the results as partial. On macOS Apple Silicon, exit code **137** is
   an `arm64e`/`arm64` toolchain mismatch, not a build failure — fix the toolchain before
   downgrading the build mode.

Custom taint query template (new dataflow API — `tainted length reaches memcpy`):

```ql
/**
 * @name Tainted length flows to memcpy
 * @kind path-problem
 * @problem.severity error
 * @id cpp/tainted-memcpy-len
 */
import cpp
import semmle.code.cpp.dataflow.new.TaintTracking
import semmle.code.cpp.security.FlowSources
import TaintedLen::PathGraph

module TaintedLenConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof FlowSource }
  predicate isSink(DataFlow::Node n) {
    exists(FunctionCall fc |
      fc.getTarget().hasGlobalOrStdName(["memcpy", "memmove", "strncpy"]) and
      n.asExpr() = fc.getArgument(2)
    )
  }
}
module TaintedLen = TaintTracking::Global<TaintedLenConfig>;

from TaintedLen::PathNode src, TaintedLen::PathNode sink
where TaintedLen::flowPath(src, sink)
select sink.getNode(), src, sink, "Attacker-controlled length from $@ reaches a copy.",
  src.getNode(), "this source"
```

Swap `import cpp` for `python`/`java`/`javascript`/`go` and the sink predicate for that language's dangerous call. Start from the shipped `codeql/<lang>-queries` suite, then narrow — writing a query from scratch before reading the stock suite output wastes the build.

**When the build is broken and CodeQL is out of reach**, use joern.

### joern — CPG queries with no build

```bash
joern-parse /path/to/src -o cpg.bin
joern
```
```scala
importCpg("cpg.bin")
cpg.method.name("memcpy").callIn.l                    // every memcpy call site
val src = cpg.call.name("recv|read|fgets|getenv").inAssignment.target
val snk = cpg.call.name("memcpy").argument.order(3)
snk.reachableByFlows(src).p                            // printed dataflow paths
cpg.method.name("main").callee.name.l                  // outgoing call graph
cpg.call.name("system|popen|execve").argument.order(1).reachableByFlows(src).p
```

### Language SAST baselines

```bash
scan-build make                 # clang static analyzer (C/C++)
clang-tidy -checks='clang-analyzer-*,bugprone-*,cert-*' -p build src/*.c
cppcheck --enable=all --inconclusive --std=c11 src/
infer run -- make               # Facebook Infer: null deref, leaks, races
bandit -r . -ll                 # Python
~/go/bin/gosec ./...            # Go
brakeman -A                     # Ruby on Rails
psalm --taint-analysis          # PHP
dotnet tool run security-scan   # .NET
```

**Availability in this environment** (regenerate with `./ginger-setup.sh --verify-tools`, which probes every one of these and verifies it *runs*): `scan-build`, `clang-tidy` and `cppcheck` are on `PATH` at `/usr/bin`; `bandit`, `brakeman` and `infer` (v1.3.0) are under `~/.local/bin`, and `gosec` plus `govulncheck` (v1.7.0, which does real symbol reachability) are under `~/go/bin` — **neither directory is reliably on the default `PATH`**, so all five look absent to `command -v` and are not. Invoke them by full path rather than concluding they are missing. `psalm`'s `.phar` is present at `~/.local/opt/psalm/psalm.phar` and **prints its version fine, then dies on the first real file** with `Call to undefined function mb_strcut` — the PHP CLI has no `mbstring` (`dom` and `simplexml` are both present, so that is not the cause). One package fixes it: `sudo apt install php8.4-mbstring`. Until then treat psalm as **missing** and fall back to Semgrep's PHP ruleset (`semgrep --config p/php`), which has working taint rules for the injection classes — what you lose is psalm's interprocedural `--taint-analysis`, so a cross-file PHP path needs hand-walking. psalm is also the standing example of why a `--version` probe is not a functional one. Verify each *runs* before relying on it, and fall back to the C/C++ chain (weggli → CodeQL/joern) or Semgrep's language rulesets when one is absent.

Treat all of these as **hypothesis generators**, never as findings.

## Phase D — Backward Taint by Hand

Automation gives candidates; you prove the path. For each candidate sink, walk *backwards*:

1. **Sink** — record `file:line`, the exact expression, and which argument is dangerous.
2. **Who calls this function?** — `rg -n '\bfunc_name\s*\('` or `cpg.method.name("f").caller.name.l`. Repeat until you hit an entry point from Phase B or run out of callers (dead code → reject).
3. **At each frame, ask three questions**:
   - Is the value still attacker-controlled here, or was it replaced by a constant/lookup?
   - What checks were applied between here and the sink? Record each one.
   - Can the check be defeated? (signed/unsigned, truncation, TOCTOU, encoding, `int` vs `size_t`, check-on-copy-not-original)
4. **Sanitizer verdict** — sufficient / bypassable-with-<technique> / absent. A "bypassable" verdict needs a concrete input, not a hunch.
5. **Classify** the class + primitive via `bug-class-catalog`, then hand off to `dynamic-verification` for runtime proof.

Write the chain down in one line per frame — `recv() @ net.c:412 → parse_hdr() @ hdr.c:88 (len is int16, no check) → memcpy() @ buf.c:31` — so the path survives context loss and reads straight into the finding report.

## Phase E — SAST Triage

A 900-finding SARIF is not a result. Reduce it in this order:

1. **Drop the unreachable** — anything in `test/`, `example/`, `fuzz/`, build scripts, or code not compiled into the shipped artifact. Confirm with the build system, not the path name.
2. **Deduplicate** — group by (rule id, sink function, sink file). One bug reported five times is one bug.
3. **Bucket by source trust** — attacker-controlled > config-file > developer-supplied constant. Findings whose source is a literal die here.
4. **Bucket by primitive** — memory write / exec / auth bypass / info leak > everything else. Impact ranks the queue, not tool severity.
5. **Spot-check the tool** — manually verify 3–5 findings per rule. If a rule is wrong 3 times, drop the whole rule and record why.
6. **Record rejections with reasons** — a rejected candidate you can't re-litigate is worth as much as a confirmed one.

```bash
# Quick SARIF triage without a viewer
jq -r '.runs[].results[] | [.ruleId, .locations[0].physicalLocation.artifactLocation.uri,
  .locations[0].physicalLocation.region.startLine] | @tsv' results.sarif \
  | sort | uniq -c | sort -rn | head -40
```

### Severity is not always on the result

**`result.level` is optional, and CodeQL omits it on every result** — severity lives on the *rule*
as `defaultConfiguration.level` and the result inherits it. Read `result.level` directly and a
CodeQL run scores as clean however many errors it found. This is how a severity gate exits 0 on a
failing repo, and it is the single most common SARIF-handling bug.

Resolve severity in this order (SARIF 2.1.0 §3.27.10):

1. a `kind` other than `"fail"` (a pass/notApplicable record) → `"none"`
2. `result.level`, when present
3. the matched rule's `defaultConfiguration.level` — join `ruleIndex` into
   `runs[].tool.driver.rules[]`, or match `ruleId` against `rules[].id` when the tool omits
   `ruleIndex`
4. `"warning"`, the SARIF default

```bash
# Correct severity resolution, and a count per level. Verified against a mixed
# CodeQL-style SARIF (level on the result, level only on the rule, and neither).
jq -r '
  def lvl($rules): . as $r
    | if ($r.kind // "fail") != "fail" then "none"
      elif $r.level then $r.level
      else ( ($r.ruleIndex // null) as $i
             | if $i != null and ($rules[$i]? != null)
               then $rules[$i].defaultConfiguration.level
               else ([$rules[]? | select(.id == $r.ruleId)][0]?.defaultConfiguration.level) end
             // "warning" ) end;
  .runs[] | (.tool.driver.rules // []) as $rules | .results[]
  | [ (. | lvl($rules)), .ruleId,
      .locations[0].physicalLocation.artifactLocation.uri,
      .locations[0].physicalLocation.region.startLine ] | @tsv' results.sarif \
  | sort -u | tee triage.tsv | cut -f1 | sort | uniq -c

# Merge several tools, dedup on (rule, file, line)
jq -s '{version:"2.1.0", runs:[.[].runs[]]}' cq.sarif semgrep.sarif > merged.sarif
```

For **cross-run tracking** — "is this new in this PR?" — match on `partialFingerprints` /
`fingerprints`, never on the path: tools report different roots (`/repo/src/x.c` vs `src/x.c` vs
`/github/workspace/src/x.c`) and path-based matching silently reports every finding as new. When a
tool emits no fingerprints, synthesise one from `(ruleId, relative path, code snippet)` — not from
the line number, which every edit above it shifts.

## Coverage Bookkeeping

Keep a running table so the audit is auditable. Report it even when incomplete — a partial audit with known boundaries beats a "complete" one nobody can check.

Three distinctions the table must preserve, because collapsing them is how a report implies
completeness it does not have:

| Status | Means | Who should look next |
|---|---|---|
| **reviewed, no findings** | a method was applied and answered the question | nobody |
| **not reviewed** | nothing looked at it | a human — name it explicitly |
| **out of scope** | excluded by configuration or platform (Windows classes on a POSIX build, `LOCAL_UNPRIVILEGED` classes under a `REMOTE` threat model) | nobody, but say *why* |

A coverage figure with no denominator is not a figure. "37 of 41 functions reachable from
`handle_packet`" is checkable; "62% coverage" is not. Where the target can run, back the claim with
a measured number (`sanitizers-and-coverage`) rather than an impression.

| Entry point | Reachability | Reviewed | Method | Result |
|---|---|---|---|---|
| `handle_packet()` net.c:88 | remote unauth | yes | manual + CodeQL | 1 confirmed OOB write |
| `parse_config()` cfg.c:12 | local admin | yes | weggli sweep | no findings |
| `plugin_load()` plug.c:200 | local user | **no** | — | out of time — unreviewed |

## Language Audit Focus (where to look, not what to find)

- **C/C++** — every `memcpy`/`alloca`/pointer-arith site near a parser; `int`↔`size_t` conversions; error paths that `free` and continue; `realloc` returning NULL; macro-hidden lengths.
- **Rust** — every `unsafe` block (`rg -n 'unsafe\s*\{'`), FFI boundaries, `from_raw`, `transmute`, `get_unchecked`, and panics on attacker input (DoS).
- **Go** — slice reslicing with attacker indices, `unsafe.Pointer`, goroutine data races, `exec.Command` with shell wrappers, `filepath.Join` without `Clean`+prefix check.
- **Java/Kotlin** — deserialization gadget entry (`readObject`, Jackson polymorphic types), JNI boundaries, XXE-capable parsers, reflection driven by input, SpEL/OGNL.
- **Python** — `subprocess(shell=True)`, `pickle`/`yaml.load`, format-string `.format` on user templates, C extensions, `eval`/`exec`, path joins.
- **JS/TS** — prototype pollution merge helpers, `child_process`, template/`vm` sandboxes, deserializers, SSRF in server fetches.
- **PHP** — `unserialize` gadget chains, dynamic `include`, variable functions `$$x`/`$f()`, type juggling in auth comparisons.

## Cross-references

- **Before this skill**: establishing what the code assumes → `audit-context-building`
- **Per-language depth**: `c-cpp-review` (C/C++ class catalog, per-unit review questions, unit ledger); `rust-security-audit` (safe/unsafe boundary, panic-DoS, FFI)
- **After a candidate**: the mandatory refutation gate → `false-positive-refutation`
- **After a confirmed finding**: the other instances of the same root cause → `variant-analysis`
- Bug classes, CWEs, exploit primitives → `bug-class-catalog`
- Per-CWE vulnerable/secure examples, 28 rule files → `code-security`
- Semgrep rule authoring, test-first discipline, taint mode → `semgrep`
- LLM/agent-specific sinks and sources → `llm-security`
- Runtime proof of a traced path → `dynamic-verification`
- Turning an unreachable-looking path into a crash → `fuzzing-harness-design`, then `fuzzing-triage`
- Measuring whether the testing reached what you audited → `sanitizers-and-coverage`
- Known-CVE targets, patch diffing → `cve-patch-analysis`
- Third-party and vendored dependencies in the tree → `supply-chain-audit`
- Timing channels and secrets left in memory in crypto code → `crypto-side-channel-audit`
- Footgun APIs and fail-open defaults rather than outright bugs → `sharp-edges-and-insecure-defaults`
