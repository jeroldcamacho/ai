---
name: supply-chain-audit
description: Audit a project's dependencies for supply-chain risk across npm, PyPI, Go, Cargo and Maven. Use when assessing third-party or dependency risk, deciding whether a vulnerable package is actually reachable, or checking for abandoned upstreams, publisher concentration, install scripts, typosquats and vendored copies.
---

# SKILL: Supply Chain Audit

Two questions, and they are not the same:

1. **Does this project depend on something with a known vulnerability?** — mechanical, and
   answerable from manifests and advisory databases.
2. **Is the vulnerable code reachable from this project's attack surface?** — the part that decides
   whether it is a finding, and the part tools cannot answer.

A dependency audit that answers only the first produces a list of CVEs, most of which do not
matter, and buries the two that do.

Out of scope: license compliance; scanning the target's own source (that is `source-audit`);
whether the project installs or builds. This audit works from the dependency list alone and
**never installs, builds, or executes anything** from the tree under review — treat a dependency's
`postinstall` as hostile code you are *reading*, not running.

## Two Rules That Keep It Honest

- **Unavailable data is never evidence of risk, and never evidence of safety.** Every criterion
  resolves to *assessed-clean*, *assessed-flagged*, or **unassessable, with the reason**. PyPI
  publishes no maintainer ACL; Go has no central registry. Those rows say what could not be known.
- **An absent measurement is never a clean verdict.** "No advisories" means "none among what was
  assessed" — so the coverage count bounds every claim in the report and must be stated next to
  it. Dropping the unassessable rows because they would confuse the reader converts partial
  coverage into a clean bill of health, which is the failure this whole discipline exists to
  prevent.

Do not estimate maintainer counts, download volumes, staleness, or CVE history from memory or from
a repository page. Repository *contributors* and registry *publish rights* are different
populations — a package with fifty GitHub contributors can have one person who can push to the
registry, and that one person is the supply-chain risk. Measure it or mark it unassessable.

## Phase 1 — Establish the Dependency Set

Confirm the manifests exist before auditing anything; if the ecosystem is not one you can parse,
say it is unsupported rather than improvising.

```bash
ls package.json package-lock.json npm-shrinkwrap.json yarn.lock pnpm-lock.yaml \
   pyproject.toml requirements*.txt uv.lock poetry.lock Pipfile.lock \
   go.mod go.sum Cargo.toml Cargo.lock pom.xml build.gradle* 2>/dev/null
```

**Manifest vs lockfile is a real distinction, and it changes what a version claim means.** A
manifest range (`^1.2.3`) checked against the latest release is a different assertion from a
lockfile-resolved exact version. Keep the label:

| File | What it gives you |
|---|---|
| `package-lock.json`, `npm-shrinkwrap.json`, `uv.lock`, `Cargo.lock`, `go.sum`, `poetry.lock`, `Pipfile.lock` | exact resolved versions, and the **full transitive tree** |
| `package.json`, `pyproject.toml`, `requirements.txt`, `Cargo.toml`, `pom.xml` | declared ranges and direct dependencies only |
| `go.mod` (1.17+) | direct **and** indirect, with versions |

Then enumerate, direct and transitive separately — most advisories land transitively, and most
*actionable* ones land directly:

```bash
npm ls --all --json 2>/dev/null | jq -r '..|.version? // empty' | wc -l
npm ls --depth=0
cargo tree ; cargo tree --duplicates          # duplicates = two copies of the same bugs
go list -m all ; go list -deps ./...
uv pip list  # or: pip list --format=json
mvn dependency:tree -DoutputType=text
```

Also enumerate what the tooling will *not* find:

- **Vendored source.** `third_party/`, `vendor/`, `deps/`, `external/`, a single copied `.c` file.
  These carry the upstream's bugs with none of its patches and appear in no manifest.
  `rg -l 'Copyright.*(zlib|libpng|expat|sqlite|libjpeg|openssl|curl)' --glob '!*.md'` finds the
  common ones; so does looking for a `VERSION`, `CHANGES`, or amalgamation header.
- **Statically linked libraries** in a shipped binary. `strings ./binary | rg -i 'zlib |sqlite
  3\.|openssl|libpng|expat_'` recovers many version banners; `nm -C` and build-id lookups help.
- **Bundled runtimes** — an Electron app's Chromium and Node, a Python app's shipped interpreter, a
  JVM in a container image. Usually the largest and stalest attack surface in the whole project.
- **Build- and dev-time dependencies.** They execute on developer machines and in CI, often with
  credentials. Compromise there is a compromise of the release pipeline.

## Phase 2 — Advisory Sweep

```bash
npm audit --json                          # or: npm audit --omit=dev
~/go/bin/osv-scanner scan source -r .     # multi-ecosystem, reads lockfiles directly
~/go/bin/govulncheck ./...                # Go: real symbol reachability, unlike the others
~/.local/bin/pip-audit -r requirements.txt  # PyPI
~/.local/bin/grype dir:.                    # filesystem/image oriented
~/.cargo/bin/cargo-audit audit              # Cargo advisories (cargo-deny is usually absent)
```

**Verified availability here — regenerate with `./ginger-setup.sh --verify-tools`. This is exactly the case the `command -v` rule warns about** —
`~/go/bin` is not on the default `PATH`, so these three look absent and are not:

| Tool | Location |
|---|---|
| **`osv-scanner`** 2.5.1 — multi-ecosystem, reads lockfiles directly | `~/go/bin/osv-scanner` |
| **`govulncheck`** v1.7.0 — Go, with real symbol reachability | `~/go/bin/govulncheck` |
| **`grype`** 0.117.0 — filesystem/image scan, also reads lockfiles | `~/.local/bin/grype` |
| **`pip-audit`** 2.10.1 — PyPI, from a requirements file or an installed env | `~/.local/bin/pip-audit` |
| **`cargo-audit`** — Cargo, against `Cargo.lock` | `~/.cargo/bin/cargo-audit` (off `PATH`) |
| `npm` (so `npm audit`), `pnpm`, `trivy` | on `PATH` |

`cargo-deny` is the usual absence — its licence/ban/source checks have no substitute, but for
advisories alone `cargo audit` covers it. Reach for `osv-scanner` first generally: it covers PyPI,
Cargo, npm, Go and Maven lockfiles in one pass. Where a tool is missing, query the OSV API
directly
(`https://api.osv.dev/v1/query` takes a `{"package":{"name":..,"ecosystem":..},"version":..}` body)
or use `WebSearch`/`WebFetch` against GHSA and the vendor advisory — and say in the report which
method produced the coverage number.

**`govulncheck` is the outlier worth knowing**: it reports only advisories whose vulnerable
*symbols* your code actually calls, which is the reachability question already answered for Go.
Everything else reports version matches.

### Verify the scanner actually parsed something

The principle at the top of this skill — *an absent measurement is never a clean verdict* — has a
concrete failure mode worth checking on every run. `osv-scanner` **needs a lockfile**; given only
a `package.json` it parses nothing, and it **exits 0**:

```
$ osv-scanner scan source -r .          # package.json only, lodash 4.17.11 (has advisories)
End status: 1 dirs visited, 2 inodes visited, 0 Extract calls, 70µs elapsed
No package sources found, --help for usage information.
$ echo $?
0
```

It does say so — but a CI gate or wrapper reading `$?` reads that as "no vulnerabilities". Add the
lockfile and the same command reports **23 vulnerabilities across 4 packages in 2 ecosystems**.

So before repeating any clean verdict, confirm the run measured something:

```bash
osv-scanner scan source -r . --verbosity=info 2>&1 | tee scan.log
rg -q 'No package sources found' scan.log && echo "SCANNED NOTHING — not a clean result"
rg -o '[0-9]+ Extract calls' scan.log        # 0 Extract calls = nothing was parsed
```

The same question applies to every scanner: `npm audit` needs a lockfile, `pip-audit -r` needs the
requirements file to pin versions, and `grype dir:.` warns `no explicit name and version provided
for directory source` and derives an artifact ID from the path — usable, but say so. Report the
count of packages assessed next to the finding count, always.

## Phase 3 — The Reachability Question

This is the phase that separates a useful report from a CVE list. For each advisory, in order:

1. **Is the vulnerable version actually the resolved one?** Manifest range vs lockfile — and check
   whether a transitive constraint pinned it lower than the range suggests.
2. **Is the vulnerable *code path* imported at all?** A CVE in a package's CLI entry point does not
   affect a project that imports only its parsing function. `rg -n "require\(['\"]pkg|from pkg
   import|use pkg::|\"pkg/"` finds what is imported; then check whether the specific vulnerable
   symbol is among it.
3. **Is that path reachable from an attacker-controlled entry point?** Cross-reference against the
   ranked entry-point table from `source-audit`. A deserialization CVE in a library used only to
   parse a developer-supplied config at build time is not remotely exploitable.
4. **Does the project's own code satisfy the precondition?** Many advisories require a specific
   option, a specific input format, or a feature flag. Check whether it is set. In Cargo,
   `cargo tree -e features` matters — a feature flag can turn on the vulnerable code, or turn on
   `unsafe`.
5. **Is there a compensating control?** An upstream size limit, a WAF rule, a sandboxed worker.
   Note it, and note whether it is a primary control or defense-in-depth
   (`false-positive-refutation`, gate 6).

Then classify: **exploitable** (reachable from attacker input, precondition met), **latent** (the
code is present and unpatched but nothing reaches it today — a real finding at lower severity,
because a caller can arrive), or **not applicable** (with the reason). Never report a version match
as a vulnerability without saying which of these it is.

## Phase 4 — Non-Advisory Risk

An abandoned dependency with no CVEs is often a bigger risk than a patched one with three.

| Criterion | How to measure it | Why it matters |
|---|---|---|
| **Abandoned / archived upstream** | last release date; repository archived flag; open-issue age | no advisory will ever be filed, and no patch will ever ship. The most under-reported risk in any dependency audit |
| **Publisher concentration** (npm) | `npm owner ls <pkg>` — registry publish rights, **not** repo contributors | one compromised account publishes to everyone |
| **Install-time script execution** | `jq '.scripts | keys' package.json` on each dependency; `preinstall`/`install`/`postinstall`; `setup.py` executing code at build; a Cargo `build.rs`; a Go `//go:generate` | code runs on developer machines and in CI at install time, before any review |
| **Typosquat / dependency confusion** | is a name one edit away from a popular package? does an internal-looking package resolve from the *public* registry? is a scope missing? | the classic active attack, and it is checked by reading names, not by scanning |
| **Recent maintainer change** | ownership transfer, a first release after a long gap, a sudden new maintainer | the shape of every recent npm account takeover |
| **Unpinned or floating versions** | `latest`, `*`, `^` on a critical dependency, a git branch reference, no lockfile committed | the build is not reproducible, so what you audited is not what ships |
| **Integrity verification** | lockfile `integrity` hashes present? `go.sum` complete? `--frozen-lockfile` in CI? | without it a registry compromise is undetectable |
| **Duplicate versions** | `cargo tree --duplicates`, `npm ls --all` | two copies means fixing one leaves the other |
| **Transitive depth and count** | total package count | not a finding by itself, but it is the honest denominator for every coverage claim |

For install scripts, the specific mitigation to assess is whether `npm ci --ignore-scripts` (or
`--ignore-scripts` in `.npmrc`, or `uv sync --no-build-isolation` decisions, or a vendored
prebuilt) is viable **for this project's build** — several native packages genuinely need their
install script, so the answer is project-specific and belongs in the report as a judgment, not a
blanket recommendation.

## Phase 5 — Report

Structure it so a reader can act, and so every claim carries its boundary:

1. **Coverage table first.** Ecosystems parsed; lockfiles read vs absent; dependency count assessed
   vs total; which criteria were **unassessable** and why. Every later claim is bounded by this.
2. **Exploitable findings** — advisory, resolved version, the reachability argument, the fix
   version, and whether the upgrade is a patch or a major bump (that cost is the difference between
   a fix that happens and one that does not).
3. **Latent findings** — present, unpatched, currently unreachable; say what would make them
   reachable.
4. **Non-advisory risk** — abandonment, publisher concentration, install scripts, unpinned
   versions, with the measured datum behind each.
5. **What the collector could not know**, kept separate and not deleted.

Quote measured figures verbatim; do not re-derive, round, or embellish them. Label your own
additions — an upgrade path, a replacement candidate, a priority ordering — as **judgment**, not
measurement, and verify a suggested replacement actually exists in the registry before naming it.

Register: state the finding, the datum behind it, and the action. "Upgrading to 1.19.0 clears all
25 advisories" beats "it is recommended that axios be upgraded". A recommendation names the action
and its cost, never a culprit.

## Rationalizations to Reject

- **"No findings, so the dependencies are safe."** Read the coverage table. On PyPI and Go, several
  criteria are structurally unassessable.
- **"It has a CVE, so it is a finding."** Reachability decides. Phase 3 exists for this.
- **"The vulnerable version is in the tree, so we are affected."** Which *resolved* version, and is
  the vulnerable symbol imported?
- **"The unassessable rows would confuse the reader."** They are the boundary of every claim.
- **"The version is probably close enough."** A range checked at latest-release and a
  lockfile-resolved version are different claims. Keep the label.
- **"`npm audit` covers it."** It covers the npm registry's advisory data for what the lockfile
  resolves. Not vendored source, not statically linked libraries, not the bundled Chromium.
- **"Dev dependencies do not matter."** They execute in CI, with credentials.
- **"I will just run the install script to see what it does."** No. Read it.

## Cross-references

- Tracing an advisory to its fix commit and reconstructing the bug → `cve-patch-analysis`
- Auditing the vendored copy's source once you have found it → `c-cpp-review`, `rust-security-audit`
- Deciding whether the vulnerable path is reachable from an entry point → `source-audit`
- Dismissing an advisory defensibly → `false-positive-refutation` (brocards 3, 6, 7)
- Vendored duplicates of the same vulnerable library → `variant-analysis`
- Version banners in a shipped binary with no manifest → `re-tools`
- Dangerous-by-default configuration in a dependency → `sharp-edges-and-insecure-defaults`
