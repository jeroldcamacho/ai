---
name: binaryninja-mcp
description: Drive Binary Ninja through the live MCP server (mcp__binaryninja__bn_*). Default tool for reverse engineering a binary — attaching to a binary view, decompiling a call chain, reading MLIL/HLIL SSA for backward taint, cross-referencing dangerous imports, recovering stack layouts and struct types, or naming a database as an audit progresses.
---

# SKILL: Binary Ninja via MCP

**This is the default RE tool for this agent.** Binary Ninja is available as live MCP tools (`mcp__binaryninja__bn_*`) from the `binaryninja` server — the **official in-UI MCP server** (`binaryninja_ui_mcp`), not a third-party plugin. Verified local setup:

| Fact | Value |
|---|---|
| Endpoint | `http://127.0.0.1:24642/mcp` (streamable HTTP), authorization **disabled** |
| Binary Ninja | 6.0.10601 **Personal**, `/opt/binaryninja/binaryninja` |
| Server | `binaryninja_ui_mcp` 0.1.0 — **75 tools, all exposed at once** |
| Tool groups | none — no `load_tool_group` step, unlike the Ghidra bridge |

It is **not headless**. The server lives inside the running GUI, so with no Binary Ninja up the tools are unreachable. This is a Personal license — treat standalone headless scripting (`import binaryninja`) as unavailable unless you verify the license permits it; the MCP path is the UI server regardless.

## Attach before analyzing — never assume state

The single most important gotcha, straight from the server's own instructions: **a file opened by hand in the Binary Ninja UI is not automatically active for MCP.** Skipping this step is how you end up analyzing the wrong program, or a `Raw` view of the right one.

1. `bn_open_item_list` → which files/databases/projects Binary Ninja knows about (opaque handles: `item_1`, …). `bn_open_item_open` with a `path` to load a target it doesn't have; `bn_project_file_list` / `bn_project_file_open` for items inside a project.
2. `bn_binary_view_list` → the views. **One item usually yields several views** — a real ELF/PE view *and* a `Raw` view. Confirm `created`, `active`, and `recommended` before trusting anything.
3. `bn_binary_view_set_active` with the intended `binaryView` handle — this also creates the view if it is available but not yet created.
4. `bn_binary_view_get_active` / `bn_binary_view_info` → confirms arch, platform, address size, start/end, entry point. `bn_binary_view_triage` for a compact read-only summary. If these disagree with the binary you think you are looking at, stop and fix the attachment rather than drawing conclusions.
5. `bn_analysis_status` → analysis state and progress. Let it finish before reading results; `bn_analysis_update_and_wait` to force and block, `bn_analysis_update` for async, `bn_analysis_abort` to stop runaway work.

**A failed attach is the most likely operational failure here** — there is no headless mode and the server sits on a fixed port inside a GUI that may not be running. **Stop and fix the attachment rather than drawing conclusions from an error.** Never work around it, and never treat an error response as a fact about the binary.

**Check `truncated` on every list result.** Responses are markdown tables with YAML front matter carrying `offset`, `limit`, `count`, `total`, `nextOffset`, `truncated`. A truncated list silently understates coverage — page with `offset`/`nextOffset` until `truncated: false`, or your "swept all imports" claim has an unstated denominator. This is a coverage-honesty requirement, not a convenience.

## Use it for the map and the reconstruction, not for triage

Initial triage stays on the shell (`file`, `checksec`, `izz`, `rabin2`) — faster, and needs no GUI. Reach for Binary Ninja when you need readable C, ILs, and cross-references.

- **Attack surface**: `bn_function_list`, `bn_function_search`, `bn_import_list`, `bn_export_list`, `bn_entry_point_list`, `bn_string_list`, `bn_section_list`, `bn_segment_list`, `bn_symbol_list` / `bn_symbol_list_at`, `bn_relocation_list`.
- **Sink sweep**: `bn_function_callers` on each dangerous import (callsites that call it), `bn_function_xrefs_to` for non-call code references, `bn_data_xrefs_to` / `bn_data_xrefs_from` for data references to a buffer, table, or config address, `bn_type_xrefs_to` for everything touching a named type.
- **Backward taint**: `bn_function_decompile` (Pseudo C) per frame, `bn_function_il` for the IL levels, `bn_function_callers` / `bn_function_callees` to walk the chain, `bn_function_basic_blocks` for control-flow edges when a check's reachability is the question, `bn_function_disassembly` when the pseudo-C hides the actual instruction.
- **Bounds and overflow math**: `bn_function_stack_layout` gives the real stack variables and their offsets — this is what turns "a `strcpy` into a stack buffer" into the actual distance to the saved return address. `bn_function_prototype_get` / `bn_variable_list` for signatures and locals. `bn_function_complexity` to rank which parsers deserve the time.
- **Structure/field questions**: `bn_type_list`, `bn_type_search`, `bn_type_info`, `bn_data_at`, `bn_data_variable_list`. Raw bytes via `bn_memory_read`. Where DWARF is present, prefer it — real field offsets beat inferred ones.

## The IL stack is the reason this is the default

Ghidra gives you one lossy C reconstruction. `bn_function_il` gives you four rungs plus SSA (`level`: `lifted` | `llil` | `mlil` | `hlil`, default `hlil`; `ssa: true` on all but `lifted`). Use the rung that answers the question:

- **HLIL** — closest to the decompiled C, best for "what does this function do".
- **MLIL + `ssa: true`** — **the single best view for backward taint.** SSA gives every value one definition, so "where did this size come from" is a lookup instead of a guess. When you need to prove a length reaches a `memcpy` unvalidated, read MLIL SSA, not Pseudo C.
- **LLIL** — architecture-normalized semantics; use when flags, partial-register writes, or exact arithmetic width decide the bug.
- **Lifted / `bn_function_disassembly`** — ground truth. Any bug claim ends here.

`function` parameters take a **start address expression**: hex (`0x401000`), a symbol, or a Binary Ninja expression. Pass `arch` only to disambiguate functions sharing a start address. Decompile/IL/disassembly output paginates with `offset`/`limit` (max 1000 lines).

## Honest limitations vs the Ghidra bridge

Know these before planning a wide sweep — they change the call budget, and pretending otherwise produces a half-finished audit:

- **No bulk or batch tools.** There is no equivalent of `get_bulk_xrefs` or `batch_decompile`. Every xref lookup and every decompilation is one function per call. A 20-import sink sweep is 20+ calls — budget for it, or delegate the sweep to a subagent with the import list.
- **No dataflow or call-graph analysis tool.** No `analyze_dataflow`, no `analyze_call_graph`, no `analyze_api_call_chains`. You walk the chain yourself with `bn_function_callers`/`bn_function_callees` — and MLIL SSA is the compensation, which is a fair trade but is manual.
- **No script execution.** Nothing like `run_ghidra_script`. No custom queries — which also means no arbitrary-code footgun.
- **No debugger.** The Ghidra bridge has a debugger group; this server has none. All dynamic verification stays on GDB/pwndbg per `dynamic-verification`. Static-only here, always.

When a task needs bulk xrefs, scripted dataflow, or a headless run, that is the case for falling back to Ghidra (`ghidra-mcp`) or rizin — not a reason to narrow the question.

**The 75 tool schemas are a standing context cost.** They stay in context for the whole engagement, alongside depth skills and accumulating decompiled C. Load depth skills sequentially and release them when their phase is done; page decompilation and IL with `offset`/`limit` one function at a time rather than dumping whole programs; and keep engagement state in files, because compaction here is likely rather than remote.

## One tool owns the program

Binary Ninja is the owner for the engagement. Ghidra is **entered for a specific bulk query and exited** — never run as a parallel workspace. Two disassemblers mean two independent analysis states, and mixing them corrupts notes silently, which is the worst way for them to be wrong.

- **Carry addresses across, never names.** Auto-names differ (`sub_401357` vs `FUN_00401357`), and a name *you* assigned exists only where you assigned it. The address is the only shared identifier — and check that image base and load options match, or the addresses are not comparable either.
- **Never write back to both.** Renames, prototypes, types, and comments go only into the owning tool. A half-annotated second database is worse than a bare one, because it reads as authoritative.
- **Re-derive across the boundary, don't remember.** What you know as `parse_header` here is an unnamed address there. Confirm same-function identity — entry address plus one distinguishing feature — before acting on what you read.
- **Record the producing tool with every fact**, as you go. Pseudo C, MLIL SSA, Ghidra's decompiler, and raw disassembly do not carry equal weight, and the distinction is unrecoverable later.

## Write-back is allowed and encouraged

A named, commented, typed database is how a multi-hour audit stays coherent — and Binary Ninja's type system is the strongest part of this toolset.

- Names: `bn_symbol_rename`, `bn_symbol_define`, `bn_variable_rename`, `bn_function_prototype_set`, `bn_type_rename`.
- Comments: `bn_comment_set` / `bn_comment_get` / `bn_comment_delete`.
- Types: `bn_type_parse` (parse C without defining), `bn_type_define`, `bn_type_struct_create` / `bn_type_struct_modify`, `bn_type_union_*`, `bn_type_enum_*`, `bn_variable_set_type`, `bn_data_variable_define`. Recovering a real struct converts guessed offsets into named fields across every function that touches it — do this early on a parser.
- Also mutating: `bn_calling_convention_set`, `bn_section_create`/`_modify`/`_delete`, `bn_data_variable_undefine`, `bn_symbol_undefine`, `bn_type_delete`, `bn_open_item_close`, `bn_open_item_save`.

Rules: **record the address in your observations** alongside any name you assign, so a finding stays reproducible from the raw binary by someone without your database. Do not rename, retype, or comment in a database you were not asked to modify. Mutations refresh analysis automatically — but after a batch that skipped updates, call `bn_analysis_update_and_wait` before reading results. Prefer `bn_type_parse` to preview before `bn_type_define` commits.

## Decompilation is a hypothesis generator, not evidence

Binary Ninja's Pseudo C is a lossy reconstruction: it invents variables, guesses signatures, mis-sizes stack buffers, and can drop overflow-relevant arithmetic. It is *better* than Ghidra's at some of this and worse at others — the failure modes differ, which is precisely why the tool that produced a reconstruction belongs in the report. A bug seen only in pseudo-C stays a hypothesis until confirmed in MLIL/disassembly *and* — where the target can run — at runtime.

**Fallback order when the GUI is down or the answer needs something this server lacks:** Binary Ninja MCP → `ghidra-mcp` (bulk xrefs, scripting, headless) → rizin/radare2 `pdg` (needs rz-ghidra / r2ghidra) → `pdc`/`pdf` → `objdump -d`. Binary Ninja being unreachable is an ordinary occurrence, not an exception — say in the report which tool produced the reconstruction.

## Cross-references

- Command syntax, the rizin/radare2 ↔ GUI-tool equivalence table, triage sequence → `re-tools`
- DWARF, where present, beats every inferred struct layout → `re-tools`
- The obstacle blocking your analysis (packing, anti-debug, a VM) → `re-tools` routing table
- Sink sweep and backward taint methodology the tool calls serve → `source-audit`
- Turning a recovered function into a bug → `c-cpp-review`, `bug-class-catalog`
- Runtime confirmation, which this server cannot do → `dynamic-verification`
- The secondary bridge, and when to prefer it → `ghidra-mcp`
