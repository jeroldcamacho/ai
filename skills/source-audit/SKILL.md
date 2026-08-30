---
name: source-audit
description: Whole-codebase static audit methodology and interprocedural taint tooling for vulnerability research. Use when auditing a source tree for vulnerabilities, mapping attack surface across a large repo, tracing tainted data across function/file boundaries, building a call graph, choosing between grep/weggli/Semgrep/CodeQL/joern, writing CodeQL or joern dataflow queries, running language SAST (clang analyzer, cppcheck, bandit, gosec, brakeman, psalm), or triaging and de-duplicating noisy SAST output into ranked, reachable findings.
---

# SKILL: Source Code Audit & Interprocedural Taint

How to audit a source tree you did not write. Bug *classes* live in the `bug-class-catalog` skill; secure-coding rules and per-CWE examples live in the `code-security` skill; single-file pattern scanning lives in the `semgrep` skill. This skill covers the part in between: **getting from "here is a 400k-line repo" to "here is a ranked list of reachable source→sink paths."**

Core discipline: an audit is a *coverage* exercise, not a scanning exercise. Track what you have looked at, not just what you found.

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

```bash
codeql database create db --language=cpp --command="make -j$(nproc)"
codeql database create db --language=python --source-root .      # no build needed
codeql database analyze db codeql/cpp-queries:codeql-suites/cpp-security-extended.qls \
  --format=sarif-latest --output=results.sarif
codeql query run -d db custom.ql                                  # single custom query
```

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
gosec ./...                     # Go
brakeman -A                     # Ruby on Rails
psalm --taint-analysis          # PHP
dotnet tool run security-scan   # .NET
```

**Availability in this environment**: `bandit`, `gosec`, `brakeman` are installed and ready. `scan-build`, `clang-tidy`, `cppcheck`, `infer`, and `psalm` (its `.phar` is present at `~/.local/opt/psalm/psalm.phar` but the PHP CLI is missing the `dom`/`simplexml` extensions it requires) all need root (`apt install cppcheck clang-tidy clang-tools php-xml`, or a multi-GB LLVM release tarball for the first two) — `command -v` each before relying on it, and fall back to the C/C++ chain (weggli → CodeQL/joern) or Semgrep's language rulesets when they're absent.

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

## Coverage Bookkeeping

Keep a running table so the audit is auditable. Report it even when incomplete — a partial audit with known boundaries beats a "complete" one nobody can check.

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

- Bug classes, CWEs, exploit primitives → `bug-class-catalog`
- Per-CWE vulnerable/secure examples, 28 rule files → `code-security`
- Semgrep rule authoring and taint mode → `semgrep`
- LLM/agent-specific sinks and sources → `llm-security`
- Runtime proof of a traced path → `dynamic-verification`
- Turning an unreachable-looking path into a crash → `fuzzing-triage`
- Known-CVE targets, patch diffing, variant sweeps → `cve-patch-analysis`
