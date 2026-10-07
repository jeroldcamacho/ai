## GINGER

Hardcore vulnerability researcher, reverse engineer, and exploit developer — proves findings with runtime evidence and refutes them before filing.

`agents/GINGER.md` is the agent definition; `skills/` carries the 38 skills it routes to. `agents/ginger-setup.sh` installs the toolchain (`--check` to audit only, `--all` for the optional extras, `--verify-tools --write` to regenerate the tool-inventory table in `GINGER.md`).

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

**Reverse engineering depth — 8**

- binaryninja-mcp (live Binary Ninja over MCP — the default)
- ghidra-mcp (secondary: bulk xrefs, batch decompile, scripting, headless)
- reading-decompiled-code (what decompiler output does and doesn't prove)
- pe-and-macho-analysis (PE/COFF and Mach-O, where ELF tooling goes quiet)
- re-tools (RE command reference + RE routing)
- anti-debugging-techniques
- code-obfuscation-deobfuscation
- vm-and-bytecode-reverse

**Exploitation depth — 9**

- binary-protection-bypass (first, before any technique)
- stack-overflow-and-rop
- heap-exploitation
- format-string-exploitation
- arbitrary-write-to-rce
- kernel-exploitation
- windows-exploitation (SEH, Windows heap, WinDbg, token stealing)
- browser-exploitation-v8
- sandbox-escape-techniques

**Core workflow — 3**

- exploit-dev (technique selection + exploitation routing)
- source-audit (whole-codebase audit + taint tooling)
- bug-class-catalog (CWE → primitive)

**Specialist — 3**

- code-security
- llm-security
- reverse-shell-techniques

Web and mobile skills referenced as cross-domain hand-offs (`injection-checking`, `auth-sec`, `api-sec`, `recon-for-sec`) belong to sibling agents and are not shipped here.

[reagent](https://github.com/criticic/reagent), [hack skills](https://github.com/yaklang/hack-skills), [agent-studio](https://github.com/oimiragieo/agent-studio)
