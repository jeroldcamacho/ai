---
name: semgrep
description: Run Semgrep scans and author custom detection rules with test-first discipline and taint mode. IMPORTANT: also use when asked to 'scan for bugs', 'find vulnerabilities', 'static analysis', 'lint for security' or 'audit this code' without naming Semgrep. Covers rule authoring constraints, porting a rule to another language, and where Semgrep sits in the escalation ladder.
---

# Semgrep Static Analysis

Fast, pattern-based static analysis for security scanning and custom rule creation.

## MCP Tools Available

If Semgrep MCP tools are available in your environment, prefer them for scanning:

- **`semgrep_scan`** — Scan code files for security vulnerabilities using built-in rulesets. Pass absolute file paths and an optional config (e.g., `p/security-audit`, `auto`).
- **`semgrep_scan_with_custom_rule`** — Scan code with a custom YAML rule you've written. Pass code content inline along with the rule.
- **`semgrep_findings`** — Fetch existing findings from the Semgrep AppSec Platform for a repository.
- **`semgrep_rule_schema`** — Get the full schema for writing Semgrep rules.
- **`get_supported_languages`** — List all languages Semgrep supports.

When MCP tools aren't available, fall back to the CLI commands below.

## When to Use Semgrep

**Ideal scenarios:**
- Quick security scans (minutes, not hours)
- Pattern-based bug and vulnerability detection
- Enforcing coding standards and best practices
- Finding known vulnerability patterns (OWASP, CWE)
- Creating custom detection rules for your codebase
- Data flow analysis with taint mode

## Installation (CLI)

```bash
# pip (recommended)
python3 -m pip install semgrep

# Homebrew
brew install semgrep

# Docker
docker run --rm -v "${PWD}:/src" semgrep/semgrep semgrep --config auto /src
```

---

# Part 1: Running Scans

## Quick Scan

```bash
semgrep --config auto .                    # Auto-detect rules
```

## Using Rulesets

```bash
semgrep --config p/<RULESET> .             # Single ruleset
semgrep --config p/security-audit --config p/trailofbits .  # Multiple
```

| Ruleset | Description |
|---------|-------------|
| `p/default` | General security and code quality |
| `p/security-audit` | Comprehensive security rules |
| `p/owasp-top-ten` | OWASP Top 10 vulnerabilities |
| `p/cwe-top-25` | CWE Top 25 vulnerabilities |
| `p/trailofbits` | Trail of Bits security rules |
| `p/python` | Python-specific |
| `p/javascript` | JavaScript-specific |
| `p/golang` | Go-specific |

## Output Formats

```bash
semgrep --config p/security-audit --sarif -o results.sarif .   # SARIF
semgrep --config p/security-audit --json -o results.json .     # JSON
```

## Scan Specific Paths

```bash
semgrep --config p/python app.py           # Single file
semgrep --config p/javascript src/         # Directory
semgrep --config auto --include='**/test/**' .  # Include tests
```

## Configuration

### .semgrepignore

```
tests/fixtures/
**/testdata/
generated/
vendor/
node_modules/
```

### Suppress False Positives

```python
password = get_from_vault()  # nosemgrep: hardcoded-password
dangerous_but_safe()  # nosemgrep
```

---

# Part 2: Creating Custom Rules

## When to Create Custom Rules

- Detecting project-specific vulnerability patterns
- Enforcing internal coding standards
- Building security checks for custom frameworks
- Creating taint-mode rules for data flow analysis

## Approach Selection

| Approach | Use When |
|----------|----------|
| **Taint mode** | Data flows from untrusted source to dangerous sink (injection vulnerabilities) |
| **Pattern matching** | Syntactic patterns without data flow requirements (deprecated APIs, hardcoded values) |

**Prioritize taint mode** for injection vulnerabilities. Pattern matching alone can't distinguish between `eval(user_input)` (vulnerable) and `eval("safe_literal")` (safe).

## Quick Start: Pattern Matching

```yaml
rules:
  - id: hardcoded-password
    languages: [python]
    message: "Hardcoded password detected: $PASSWORD"
    severity: ERROR
    pattern: password = "$PASSWORD"
```

## Quick Start: Taint Mode

```yaml
rules:
  - id: command-injection
    languages: [python]
    message: User input flows to command execution
    severity: ERROR
    mode: taint
    pattern-sources:
      - pattern: request.args.get(...)
      - pattern: request.form[...]
    pattern-sinks:
      - pattern: os.system(...)
      - pattern: subprocess.call($CMD, shell=True, ...)
    pattern-sanitizers:
      - pattern: shlex.quote(...)
```

## Pattern Syntax Quick Reference

| Syntax | Description | Example |
|--------|-------------|---------|
| `...` | Match anything | `func(...)` |
| `$VAR` | Capture metavariable | `$FUNC($INPUT)` |
| `<... ...>` | Deep expression match | `<... user_input ...>` |

| Operator | Description |
|----------|-------------|
| `pattern` | Match exact pattern |
| `patterns` | All must match (AND) |
| `pattern-either` | Any matches (OR) |
| `pattern-not` | Exclude matches |
| `pattern-inside` | Match only inside context |
| `pattern-not-inside` | Match only outside context |
| `metavariable-regex` | Regex on captured value |

## Testing Rules

**Test-first is mandatory.** Create test files with annotations:

```python
# test_rule.py
def test_vulnerable():
    user_input = request.args.get("id")
    # ruleid: my-rule-id
    cursor.execute("SELECT * FROM users WHERE id = " + user_input)

def test_safe():
    user_input = request.args.get("id")
    # ok: my-rule-id
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_input,))
```

Run tests:
```bash
semgrep --test --config rule.yaml test-file
```

## Command Reference

| Task | Command |
|------|---------|
| Run tests | `semgrep --test --config rule.yaml test-file` |
| Validate YAML | `semgrep --validate --config rule.yaml` |
| Dump AST | `semgrep --dump-ast -l <lang> <file>` |
| Debug taint flow | `semgrep --dataflow-traces -f rule.yaml file` |

## Rule Creation Workflow

1. **Analyze the problem** - Understand the bug pattern, determine taint vs pattern approach
2. **Create test cases first** - Write `ruleid:` and `ok:` annotations before the rule
3. **Analyze AST** - Run `semgrep --dump-ast` to understand code structure
4. **Write the rule** - Start simple, iterate
5. **Test until 100% pass** - No "missed lines" or "incorrect lines"
6. **Optimize patterns** - Remove redundancies only after tests pass

**Output structure:**
```
<rule-id>/
├── <rule-id>.yaml     # Semgrep rule
└── <rule-id>.<ext>    # Test file
```

## Rule Authoring Constraints

Non-negotiable, because each one produces a rule that looks fine and quietly does not work:

- **One YAML file, one rule.** Combining rules in a file makes `semgrep --test` unable to attribute
  a failure, and makes the rule un-reusable.
- **100% test pass, not "most tests pass."** A rule with one failing test is a rule with an unknown
  false-positive or false-negative rate.
- **`todoruleid:` and `todook:` are forbidden.** They mark a rule as knowingly incomplete and then
  ship it as if it were done. Fix the rule or delete the case.
- **Never `languages: generic`** when targeting a specific language. Generic mode matches text, not
  syntax, and its false-positive rate on real code makes the rule worse than grep.
- **Prefer taint mode for anything with a data flow.** `eval($X)` matches both `eval(user_input)`
  and `eval("literal")`; taint mode only fires when untrusted data actually reaches the sink. It is
  fine to switch back to pattern matching if taint does not propagate as expected — the goal is a
  working rule, not loyalty to a mode.
- **Optimize last.** Write correct patterns, get the tests green, *then* simplify — and re-run the
  tests after each simplification.

## Porting a Rule to Another Language

A rule that catches a bug in Python usually has a sibling bug in the project's Go or JS. Porting is
test-driven, same as authoring:

1. **Write the target-language test file first** — the vulnerable case *and* the safe cases, using
   that language's idioms rather than a transliteration of the source language's.
2. **Dump the AST** in the target language (`semgrep --dump-ast -l go bad.go`). The equivalent
   construct is often shaped differently: Python's `subprocess.run(..., shell=True)` maps to Go's
   `exec.Command("sh", "-c", ...)`, not to `exec.Command`.
3. **Re-derive the source and sink lists** for the target language. The taint *shape* ports; the
   source and sink names never do.
4. **Test to 100%**, then compare the match count on a real tree against the original rule's. A
   port that fires far more or far less than the original is usually matching the wrong construct.

## Detailed References

**Official Semgrep Documentation:**
- [Rule Syntax](https://semgrep.dev/docs/writing-rules/rule-syntax) - Complete YAML structure, operators, and options
- [Rule Schema](https://github.com/semgrep/semgrep-interfaces/blob/main/rule_schema_v1.yaml) - Full JSON schema specification

**Local References:**
- [Workflow Guide](references/workflow.md) - Complete step-by-step rule creation process
- [Quick Reference](references/quick-reference.md) - Pattern operators and taint components

## Anti-Patterns to Avoid

**Too broad:**
```yaml
# BAD: Matches any function call
pattern: $FUNC(...)

# GOOD: Specific dangerous function
pattern: eval(...)
```

**Missing safe cases:**
```python
# BAD: Only tests vulnerable case
# ruleid: my-rule
dangerous(user_input)

# GOOD: Include safe cases
# ruleid: my-rule
dangerous(user_input)

# ok: my-rule
dangerous(sanitize(user_input))
```

## Rationalizations to Reject

| Shortcut | Why It's Wrong |
|----------|----------------|
| "Semgrep found nothing, code is clean" | Semgrep is pattern-based; can't track complex cross-function data flow |
| "The pattern looks complete" | Untested rules have hidden false positives/negatives |
| "It matches the vulnerable case" | Matching vulnerabilities is half the job; verify safe cases don't match |
| "Taint mode is overkill" | For injection vulnerabilities, taint mode gives better precision |
| "One test case is enough" | Include edge cases: different coding styles, sanitized inputs, safe alternatives |
| "It matches, so it's a finding" | A Semgrep hit is a hypothesis. It becomes a candidate after a backward taint walk, and a finding after `false-positive-refutation` |
| "I'll mark the hard case `todoruleid` and move on" | That ships a rule with a known blind spot and no record of it |
| "`languages: generic` will catch more" | It catches more *text*. Precision collapses and the rule gets ignored |

## Where Semgrep Sits

Semgrep is the middle rung of the escalation ladder — cheap, multi-language, no build required,
**intra-file** taint only. Escalate past it when you need to prove a path across files:

| Need | Tool |
|---|---|
| Sink inventory, string hunting | `rg` |
| C/C++ shape with scope awareness | `weggli` |
| Multi-language patterns, taint, CI, custom rules | **Semgrep** |
| True interprocedural dataflow, path queries | CodeQL (`source-audit`) |
| Interprocedural C/C++ with no working build | joern (`source-audit`) |

## Cross-references

- Escalating past Semgrep, CodeQL suite discipline, SARIF severity resolution → `source-audit`
- Turning one confirmed bug into a rule for its whole pattern family (abstraction ladder) → `variant-analysis`
- Refuting a hit before it enters a report → `false-positive-refutation`
- Per-CWE vulnerable/secure examples to build test cases from → `code-security`
- Language-specific class semantics the rule should encode → `c-cpp-review`, `rust-security-audit`
- Encoding a CVE's root cause as a regression rule → `cve-patch-analysis`

---

# CI/CD Integration

## GitHub Actions

```yaml
name: Semgrep

on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: '0 0 1 * *'

jobs:
  semgrep:
    runs-on: ubuntu-latest
    container:
      image: returntocorp/semgrep

    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Run Semgrep
        run: |
          if [ "${{ github.event_name }}" = "pull_request" ]; then
            semgrep ci --baseline-commit ${{ github.event.pull_request.base.sha }}
          else
            semgrep ci
          fi
        env:
          SEMGREP_RULES: >-
            p/security-audit
            p/owasp-top-ten
            p/trailofbits
```

---

# Resources

**Rule Writing:**
- Rule Syntax: https://semgrep.dev/docs/writing-rules/rule-syntax
- Pattern Syntax: https://semgrep.dev/docs/writing-rules/pattern-syntax
- Rule Schema: https://github.com/semgrep/semgrep-interfaces/blob/main/rule_schema_v1.yaml

**General:**
- Registry: https://semgrep.dev/explore
- Playground: https://semgrep.dev/playground
- Docs: https://semgrep.dev/docs/
- Trail of Bits Rules: https://github.com/trailofbits/semgrep-rules
