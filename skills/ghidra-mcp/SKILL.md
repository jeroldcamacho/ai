---
name: ghidra-mcp
description: Drive Ghidra through the live MCP bridge (mcp__ghidra__*). Secondary RE tool behind binaryninja-mcp — use when Binary Ninja is unavailable, or for what its MCP server lacks: bulk cross-referencing dangerous imports, batch decompiling a call chain, scripted dataflow, headless runs, and very large binaries.
---

# SKILL: Ghidra via MCP

**Ghidra is the secondary RE tool here; Binary Ninja (`binaryninja-mcp`) is the default.** Reach for Ghidra when Binary Ninja is down, or for the capabilities its MCP server does not have: bulk xrefs (`get_bulk_xrefs`), batch decompilation (`batch_decompile`), scripted dataflow (`analyze_dataflow`, `analyze_call_graph`), a debugger group, and headless operation. For ordinary decompilation and backward taint, prefer Binary Ninja's MLIL SSA.

**If Binary Ninja owns this program, you are being entered for one bulk query and then exited.** In that mode the write-back guidance below is suspended — do not rename, retype, or comment here, because annotations split across two databases are worse than none. Carry **addresses** in and out, never names: Ghidra's auto-names (`FUN_00401357`) will not match Binary Ninja's (`sub_401357`), and any name assigned in the other tool does not exist here. Confirm the image base and load options match before treating addresses as comparable, verify same-function identity by entry address plus one distinguishing feature, and record that the reconstruction you carry back came from **Ghidra's decompiler** — its failure modes differ from Binary Ninja's, and the claim inherits them. Ghidra owns the program only when it is the sole tool in use (Binary Ninja unavailable, or a headless run).

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

**Write-back is allowed and encouraged _only when Ghidra owns the program_** (see the ownership rule above — if Binary Ninja owns it, write nothing here). When Ghidra is the sole tool in use, this bridge has full write access, and a named/commented database is how a multi-hour audit stays coherent. `rename_function`, `set_plate_comment`, and `set_decompiler_comment` as you confirm what a function does; record the address in your observations so a finding is reproducible from the raw binary too. Do not rename or comment in a database you were not asked to modify, and never `run_ghidra_script` / `run_script_inline` with unreviewed code.

**Decompilation is a hypothesis generator, not evidence.** Ghidra's C is a lossy reconstruction: it invents variables, guesses signatures, mis-sizes stack buffers, and drops overflow-relevant arithmetic. A bug seen only in pseudo-C stays a hypothesis until you confirm it in the disassembly *and* — where the target can run — at runtime. Ghidra being unreachable (no GUI, headless box, connection refused) is the common case, not the exception. Fall back in this order: rizin/radare2 `pdg` (needs the rz-ghidra / r2ghidra plugin) → `pdc`/`pdf` → `objdump -d`. Say in the report which tool produced the reconstruction, because their failure modes differ.

## Headless — the mode the MCP bridge cannot give you

Headless is one of the few reasons to prefer Ghidra outright, and it needs no GUI or bridge. The flags that matter:

```bash
$GHIDRA/support/analyzeHeadless <proj_dir> <proj_name> \
  -import ./target            # or -process <name> to reuse an imported program
  -scriptPath ./scripts -preScript Pre.java -postScript Export.py \
  -noanalysis                 # skip auto-analysis when the script does its own
  -readOnly                   # do not save changes back to the project
  -okToDelete                 # allow -deleteProject / overwrite
```

- `-postScript` runs **after** auto-analysis — that is where export and bulk queries belong; `-preScript` runs before it, for load-time fixes.
- `-readOnly` is the right default when Binary Ninja owns the program (see the ownership rule above): it makes accidental write-back impossible.
- **PyGhidra / Jython API**, the calls actually needed for a bulk export: `getInstructionAt` / `getInstructionAfter`, `getDefinedData`, `getDataAt`, `getGlobalSymbols`, `getBlocks`, `createLabel`, and `currentProgram.getMemory()`. Decompilation goes through `DecompInterface`.
- Headless is also how a whole-program scripted dataflow or patch-diff sweep runs without holding a GUI open for hours — the case where Ghidra genuinely beats the default.

## Cross-references

- Command syntax, the rizin/radare2 ↔ Ghidra equivalence table, triage sequence → `re-tools`
- DWARF, where present, beats every inferred struct layout → `re-tools`
- The obstacle blocking your analysis (packing, anti-debug, a VM) → `re-tools` routing table
- Sink sweep and backward taint methodology the tool calls serve → `source-audit`
- Turning a recovered function into a bug → `c-cpp-review`, `bug-class-catalog`
