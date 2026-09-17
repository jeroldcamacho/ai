## GINGER

Hardcore vulnerability researcher, reverse engineer, and exploit developer — proves findings with runtime evidence and refutes them before filing.

`agents/GINGER.md` is the agent definition; `skills/` carries the 34 skills it routes to. `agents/ginger-setup.sh` installs the toolchain (`--check` to audit only, `--all` for the optional extras, `--verify-tools --write` to regenerate the tool-inventory table in `GINGER.md`).

**Source audit depth — 10**

- audit-context-building (assumptions before verdicts)
- c-cpp-review
- rust-security-audit
- crypto-side-channel-audit
- supply-chain-audit
- sharp-edges-and-insecure-defaults
- cve-patch-analysis
- semgrep
- false-positive-refutation (the gate before filing)
- variant-analysis (after every confirmed finding)

**Verification depth — 5**

- sanitizers-and-coverage
- fuzzing-harness-design
- fuzzing-triage
- dynamic-verification (debuggers, crash triage)
- symbolic-execution-tools

**Reverse engineering depth — 4**

- anti-debugging-techniques
- code-obfuscation-deobfuscation
- vm-and-bytecode-reverse
- ghidra-mcp (live Ghidra over MCP)

**Exploitation depth — 8 (the pwn set)**

- stack-overflow-and-rop
- heap-exploitation
- format-string-exploitation
- arbitrary-write-to-rce
- binary-protection-bypass
- kernel-exploitation
- browser-exploitation-v8
- sandbox-escape-techniques

**Core workflow — 4**

- re-tools (RE command reference + RE routing)
- exploit-dev (technique selection + exploitation routing)
- source-audit (whole-codebase audit + taint tooling)
- bug-class-catalog (CWE → primitive)

**Specialist — 3**

- code-security
- llm-security
- reverse-shell-techniques

Web and mobile skills referenced as cross-domain hand-offs (`injection-checking`, `auth-sec`, `api-sec`, `recon-for-sec`, and the mobile set) belong to sibling agents and are not shipped here.

[reagent](https://github.com/criticic/reagent), [hack skills](https://github.com/yaklang/hack-skills), [agent-studio](https://github.com/oimiragieo/agent-studio)
