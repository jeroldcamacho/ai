---
name: ghidra-mcp
description: Drive Ghidra through the live MCP bridge (mcp__ghidra__*). Use when reverse engineering a binary with Ghidra — attaching to an instance, decompiling a call chain, bulk cross-referencing dangerous imports, following a value with dataflow, or naming a database as an audit progresses.
---

# SKILL: Ghidra via MCP

Ghidra is available as live MCP tools (`mcp__ghidra__*`) from the `ghidra` server — a bridge that speaks HTTP to the GhidraMCP plugin inside a **running Ghidra instance** (default `http://127.0.0.1:8089`). It is not headless-by-magic: if no Ghidra is up or no program is loaded, every tool returns `{"error":"No program loaded."}`.

**Attach before analyzing** — never assume state:

1. `list_instances` → which Ghidra instances the bridge can see; `connect_instance` to pick one when there are several.
2. `get_metadata` → confirms a program is loaded and tells you the binary, arch, and base address you are actually looking at. If it errors, stop and fix the attachment before drawing conclusions.
3. `import_file` to load a target the instance doesn't have yet — then let auto-analysis finish before reading results (`analysis_status`).
4. `list_tool_groups` / `load_tool_group` — only `listing`, `function`, and `program` load by default. Load `analysis`, `data`, or `debugger` when you need them; `search_tools` / `check_tools` find a tool by capability instead of guessing names.

**Use it for the map and the decompilation, not for triage.** Initial triage stays on the shell (`file`, `checksec`, `izz`, `rabin2`) — faster, and needs no GUI. Reach for Ghidra when you need readable C and cross-references:

- Attack surface: `list_functions`, `list_imports`, `list_exports`, `list_segments`, `search_functions_enhanced`, `list_strings` / `search_strings`.
- Sink sweep: `get_xrefs_to` on each dangerous import (`get_bulk_xrefs` for a whole sink list in one call — prefer it over N single calls).
- Backward taint: `decompile_function` per frame (`batch_decompile` for a call chain, `force_decompile` when the decompiler bails), `get_function_xrefs` / `analyze_call_graph` / `analyze_api_call_chains` to walk callers, `analyze_dataflow` to follow a value, `disassemble_function` when the pseudo-C hides the actual instruction.
- Structure/field questions: the `data` group; raw bytes via `read_memory`, `search_byte_patterns`, `search_instructions`. Where DWARF is present, prefer it — real field offsets beat inferred ones.

**Write-back is allowed and encouraged** — this bridge has full write access, and a named/commented database is how a multi-hour audit stays coherent. `rename_function`, `set_plate_comment`, and `set_decompiler_comment` as you confirm what a function does; record the address in your observations so a finding is reproducible from the raw binary too. Do not rename or comment in a database you were not asked to modify, and never `run_ghidra_script` / `run_script_inline` with unreviewed code.

**Decompilation is a hypothesis generator, not evidence.** Ghidra's C is a lossy reconstruction: it invents variables, guesses signatures, mis-sizes stack buffers, and drops overflow-relevant arithmetic. A bug seen only in pseudo-C stays a hypothesis until you confirm it in the disassembly *and* — where the target can run — at runtime. Ghidra being unreachable (no GUI, headless box, connection refused) is the common case, not the exception. Fall back in this order: rizin/radare2 `pdg` (needs the rz-ghidra / r2ghidra plugin) → `pdc`/`pdf` → `objdump -d`. Say in the report which tool produced the reconstruction, because their failure modes differ.

## Cross-references

- Command syntax, the rizin/radare2 ↔ Ghidra equivalence table, triage sequence → `re-tools`
- DWARF, where present, beats every inferred struct layout → `re-tools`
- The obstacle blocking your analysis (packing, anti-debug, a VM) → `re-tools` routing table
- Sink sweep and backward taint methodology the tool calls serve → `source-audit`
- Turning a recovered function into a bug → `c-cpp-review`, `bug-class-catalog`
