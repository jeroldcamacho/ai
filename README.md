## GINGER and ALPHA

- **GINGER** — vulnerability researcher, reverse engineer and exploit developer. Binaries, source trees and firmware. Proves findings with runtime evidence and refutes them before filing.
- **ALPHA** — mobile application penetration tester. Android and iOS, the app on the device and the backend it talks to.

Agent definitions in `agents/`, their 50 skills in `skills/`, toolchain provisioning in `setup.sh`.

### Install

Claude Code reads agents from `~/.claude/agents/` and skills from `~/.claude/skills/`:

```sh
git clone https://github.com/jeroldcamacho/ai && cd ai
mkdir -p ~/.claude/agents ~/.claude/skills
cp agents/*.md ~/.claude/agents/
cp -r skills/*  ~/.claude/skills/
cp setup.sh     ~/.claude/ && chmod +x ~/.claude/setup.sh

~/.claude/setup.sh --agent=ginger --install-deps   # or --agent=alpha
```

`setup.sh` sits one level above `agents/` and `skills/` in both layouts, and finds them relative to itself — so it reads the repo's trees from the repo root, and `~/.claude/agents` plus `~/.claude/skills` once installed. The agents appear as `ginger` and `alpha` on the next Claude Code start.

### setup.sh

```
./setup.sh                            help
./setup.sh --agent=X --install-deps   install that agent's tier
./setup.sh --agent=X --verify-tools   execute every tool, report what is
                                      installed / off-PATH / aliased / broken
./setup.sh --agent=X --write          regenerate the tool-inventory table in
                                      that agent's own file
./setup.sh --selftest                 check the docs against the script
./setup.sh --new-engagement NAME      scaffold the three ledger logs
```

`--agent` is `ginger`, `alpha` or `all`, and is **required** by the first three — deliberately no default, since either guess provisions or skips the wrong tier.

Detection does not rely on `command -v` — GDB plugins are sourced scripts, gem and cargo binaries install off `PATH`, venv modules are invisible to the system interpreter, and snaps live only in `/snap/bin`. Every tool is verified by **executing** it; one that runs but fails on real input counts as missing.

`--selftest` checks the docs against the script: every `setup.sh` command they quote must still parse, and every tool they invoke must be tracked by some install tier.

### GINGER — 39 skills

| Group | Skill | What it covers |
|---|---|---|
| **Workflow** | `source-audit` | whole-tree audit, tool escalation, interprocedural taint, CodeQL/joern |
| | `exploit-dev` | technique selection and exploitation routing |
| | `bug-class-catalog` | class → CWE → primitive, per-language sink patterns |
| **Source audit** | `audit-context-building` | what each function assumes and guarantees, before hunting |
| | `c-cpp-review` | C/C++ review with a coverage ledger |
| | `rust-security-audit` | safe/unsafe boundary, panic-DoS, FFI, trait contracts |
| | `crypto-side-channel-audit` | timing channels, known-attack vectors, secrets left in memory |
| | `supply-chain-audit` | dependency risk and reachability across five ecosystems |
| | `sharp-edges-and-insecure-defaults` | footgun APIs, fail-open defaults, off switches |
| | `cve-patch-analysis` | n-day research from a patch or diff |
| | `semgrep` | scanning and custom rule authoring, taint mode |
| | `false-positive-refutation` | **the gate before filing** — TRUE/FALSE POSITIVE with evidence |
| | `variant-analysis` | **after every confirmed finding** — where else does it occur |
| **Verification** | `sanitizers-and-coverage` | instrumented builds; what testing actually reached |
| | `fuzzing-harness-design` | writing the harness; getting past checksums and magic values |
| | `fuzzing-triage` | running campaigns, dedup, when a campaign is done |
| | `dynamic-verification` | debuggers, crash triage, proving it at runtime |
| | `symbolic-execution-tools` | angr/z3 when the question is a *value* |
| **Reverse engineering** | `binaryninja-mcp` | live Binary Ninja over MCP — **the default** |
| | `ghidra-mcp` | secondary: bulk xrefs, batch decompile, scripting, headless |
| | `re-tools` | RE command reference and triage sequence |
| | `reading-decompiled-code` | what decompiler output does and does not prove |
| | `pe-and-macho-analysis` | PE/COFF and Mach-O, where ELF tooling goes silent |
| | `anti-debugging-techniques` | targets that behave differently under a debugger |
| | `code-obfuscation-deobfuscation` | packers, flattening, MBA, encrypted strings |
| | `vm-and-bytecode-reverse` | VM protections; `.pyc`, `.class`, DEX, .NET IL, wasm |
| **Exploitation** | `binary-protection-bypass` | **first** — mitigations, leaks, what a technique needs |
| | `stack-overflow-and-rop` | saved-RIP control, ROP/SROP/ret2libc |
| | `heap-exploitation` | UAF, double free, tcache/fastbin, House-of family |
| | `format-string-exploitation` | CWE-134, `%n` writes, GOT overwrite |
| | `arbitrary-write-to-rce` | turning a write primitive into execution |
| | `kernel-exploitation` | module/ioctl/syscall, LPE, SMEP/SMAP/KPTI |
| | `windows-exploitation` | SEH, Windows heap, WinDbg, token stealing |
| | `browser-exploitation-v8` | JIT bugs, addrof/fakeobj, the V8 sandbox |
| | `sandbox-escape-techniques` | renderer, seccomp, namespaces, container breakout |
| **Specialist** | `code-security` | per-CWE vulnerable and secure examples |
| | `llm-security` | OWASP LLM Top 10 — agents, RAG, tool-using apps |
| | `cmdi-command-injection` | shell metacharacters, blind and OOB injection, filter bypass |
| | `reverse-shell-techniques` | after execution — sessions, PTY, transfer, cleanup |

### ALPHA — 11 skills

| Group | Skill | What it covers |
|---|---|---|
| **Device** | `android-pentesting-tricks` | exported components, WebView, intents, root detection, Play Integrity, tapjacking, backup extraction |
| | `ios-pentesting-tricks` | keychain, URL schemes, Universal Links, runtime manipulation, ATS |
| | `mobile-ssl-pinning-bypass` | certificate, public-key and SPKI pinning — React Native, Flutter, Xamarin |
| **Backend** | `api-auth-and-jwt-abuse` | bearer tokens, API keys, claim trust, rate-limit bypass |
| | `jwt-oauth-token-attacks` | algorithm confusion, key handling, token forgery |
| | `oauth-oidc-misconfiguration` | redirect URI, state, nonce, PKCE, account binding |
| | `api-authorization-and-bola` | BOLA, BFLA, method abuse, hidden writable fields |
| | `authbypass-authentication-flaws` | login, password reset, MFA, enumeration, lockout |
| | `path-traversal-lfi` | content providers, FileProvider, download and include paths |
| | `deserialization-insecure` | intent extras, Java/PHP/Python objects |
| | `graphql-and-hidden-parameters` | introspection, batching, undocumented fields |

ALPHA also uses the shared skills: `anti-debugging-techniques` for on-device Frida and root detection, `vm-and-bytecode-reverse` for DEX, `pe-and-macho-analysis` for Mach-O, plus `cmdi-command-injection`, `reverse-shell-techniques`, `code-security`, `llm-security` and `false-positive-refutation`.

Reversing an artefact is GINGER's; assessing an installed app is ALPHA's — GINGER reverses the DEX, ALPHA assesses the APK on the device. Each hands the other what it owns, and each routing table names the other. Web-specific classes (XSS, CSRF, SSRF, SQLi, SSTI, CORS, SAML) are out of scope for both, by construction.

### Credits

[reagent](https://github.com/criticic/reagent) · [hack skills](https://github.com/yaklang/hack-skills) · [agent-studio](https://github.com/oimiragieo/agent-studio) · [REx-skill](https://github.com/tihanyin/REx-skill)
