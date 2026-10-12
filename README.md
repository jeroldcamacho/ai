## GINGER and ALPHA

Two security agents and the 50 skills they route to.

- **GINGER** — vulnerability researcher, reverse engineer and exploit developer. Binaries, source trees and firmware. Proves findings with runtime evidence and refutes them before filing.
- **ALPHA** — mobile application penetration tester. Android and iOS, the app on the device and the backend it talks to.

`agents/GINGER.md` and `agents/ALPHA.md` are the agent definitions; `skills/` carries the skills. `agents/setup.sh` provisions and audits the toolchain.

### Install

Claude Code reads agents from `~/.claude/agents/` and skills from `~/.claude/skills/`:

```sh
git clone https://github.com/jeroldcamacho/ai && cd ai
mkdir -p ~/.claude/agents ~/.claude/skills
cp agents/GINGER.md agents/ALPHA.md agents/setup.sh ~/.claude/agents/
cp -r skills/* ~/.claude/skills/
chmod +x ~/.claude/agents/setup.sh

~/.claude/agents/setup.sh --agent=ginger --install-deps   # or --agent=alpha
```

The agents appear as `ginger` and `alpha` on the next Claude Code start. `setup.sh` finds the skills beside itself, so it audits `~/.claude/skills` once installed and the repo's own `skills/` when run from a checkout.

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

`--agent` is `ginger`, `alpha` or `all`, and is **required** by the first three. There is no default: `all` would provision a mobile stack onto a box that may only ever do binary RE, and `ginger` would silently skip what an alpha run came for.

Detection does not rely on `command -v`. GDB plugins are sourced scripts that never appear on `PATH`, Ruby and Cargo binaries install outside it, venv modules are invisible to the system interpreter, and a snap's entry point lives only in `/snap/bin`. Every tool is verified by **executing** it, and one that runs but fails on real input counts as missing.

`--selftest` checks two things nothing else does: that every `setup.sh` command quoted in the agent and skill docs still parses against the current flags, and that every tool those docs invoke is tracked by some install tier. Both have caught real drift — a rename, a removed flag, and a newly required one.

### GINGER — 39 skills

**Source audit — 10** · audit-context-building · c-cpp-review · rust-security-audit · crypto-side-channel-audit · supply-chain-audit · sharp-edges-and-insecure-defaults · cve-patch-analysis · semgrep · false-positive-refutation (the gate before filing) · variant-analysis (after every confirmed finding)

**Verification — 5** · sanitizers-and-coverage · fuzzing-harness-design · fuzzing-triage · dynamic-verification · symbolic-execution-tools

**Reverse engineering — 8** · binaryninja-mcp (live Binary Ninja over MCP — the default) · ghidra-mcp (secondary: bulk xrefs, batch decompile, scripting, headless) · reading-decompiled-code · pe-and-macho-analysis · re-tools · anti-debugging-techniques · code-obfuscation-deobfuscation · vm-and-bytecode-reverse

**Exploitation — 9** · binary-protection-bypass (first, before any technique) · stack-overflow-and-rop · heap-exploitation · format-string-exploitation · arbitrary-write-to-rce · kernel-exploitation · windows-exploitation · browser-exploitation-v8 · sandbox-escape-techniques

**Core workflow — 3** · exploit-dev · source-audit · bug-class-catalog

**Specialist — 4** · code-security · llm-security · reverse-shell-techniques · cmdi-command-injection

### ALPHA — 11 skills

**Device — 3** · android-pentesting-tricks (exported components, WebView, intents, root detection, Play Integrity, tapjacking, backup extraction) · ios-pentesting-tricks (keychain, URL schemes, Universal Links, runtime manipulation, ATS) · mobile-ssl-pinning-bypass (certificate, public-key and SPKI pinning, including React Native, Flutter and Xamarin)

**Backend — 8** · api-auth-and-jwt-abuse · jwt-oauth-token-attacks · oauth-oidc-misconfiguration · api-authorization-and-bola · authbypass-authentication-flaws · path-traversal-lfi · deserialization-insecure · graphql-and-hidden-parameters

ALPHA also uses the shared skills — `anti-debugging-techniques` for on-device Frida and root detection, `vm-and-bytecode-reverse` for DEX, `pe-and-macho-analysis` for Mach-O, plus `cmdi-command-injection`, `reverse-shell-techniques`, `code-security`, `llm-security` and `false-positive-refutation`.

### Where the boundary sits

Reversing an artefact is GINGER's; assessing an installed app is ALPHA's. GINGER reverses the DEX, ALPHA assesses the APK on the device. ALPHA hands native libraries, memory corruption, firmware, cryptographic review and CVE diffing back to GINGER; GINGER hands installed mobile apps to ALPHA. Each agent's routing table names the other.

Web-specific classes (XSS, CSRF, SSRF, SQLi, SSTI, CORS, SAML) are **out of scope by construction** for both — a deliberate choice stated in the routing tables rather than left as a dangling reference.

### Evidence discipline

Both agents run the same ledger: three append-only logs — `observations.md` (raw facts, each with the tool that produced it), `hypotheses.md` (the single candidate ledger; findings and rejections are views over it), `coverage.md` (one verdict per entry point). Nothing is edited; state changes are new lines and the latest line for an ID wins. `./setup.sh --new-engagement <target>` scaffolds them outside the target tree.

A rejection is a deliverable. A coverage number needs its denominator. A clean result says which of three things it is — reviewed and clean, not reviewed, or out of scope — because collapsing them is the most common way an audit lies.

### Credits

[reagent](https://github.com/criticic/reagent) · [hack skills](https://github.com/yaklang/hack-skills) · [agent-studio](https://github.com/oimiragieo/agent-studio)

Skills vendored from hack-skills carry a provenance comment naming the source and date; cross-links to skills not shipped here were removed rather than left dangling.
