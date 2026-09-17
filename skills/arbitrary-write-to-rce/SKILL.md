---
name: arbitrary-write-to-rce
description: Converting a write primitive into code execution. Use when you already control "write value V to address A" — from a heap, format string, OOB, or type-confusion bug — and need a target. Covers which targets survive Full RELRO and glibc 2.34+, and how to trigger each.
---

# SKILL: Arbitrary Write → RCE

The conversion step. You have a write; this decides **what to overwrite and how to make the process reach it**. Getting the write is `heap-exploitation`, `format-string-exploitation`, or `stack-overflow-and-rop`; assessing the mitigations that rule targets in or out is `binary-protection-bypass`.

Use only on targets you are authorized to attack.

## Discipline

**Characterise your primitive before you shop for targets.** Most wasted effort here comes from picking a famous technique that your primitive cannot actually service. Answer all six:

| Question | Why it matters |
|---|---|
| **Where** — arbitrary address, or relative to a known base? | Relative writes rule out most libc targets |
| **What** — any value, or constrained (heap pointer only, small ints, non-null)? | The largebin attack writes a heap pointer you don't choose |
| **How wide** — 1, 2, 4, 8 bytes? | 1-byte writes → partial overwrite only |
| **How many times** — one shot, or a loop? | One shot forces a target that is *already* about to be used |
| **Do you also have a read?** | No read means no leak means only non-randomised targets |
| **How does the process end** — `exit`, `return`, loop, or crash? | Determines which triggers are even reachable |

**Then pick the shortest path to an observable effect.** A data-only overwrite that flips an auth boolean is a better finding than a half-working FSOP chain, and it survives CFI.

**It is not proven until it runs.** Show the `id` output or the observed effect. "Overwriting `__free_hook` would give a shell" is a hypothesis, and on modern glibc it is a false one.

## Target Selection

Work down this table; the first row whose preconditions you meet is almost always the right answer.

| Target | Preconditions | Trigger | Status |
|---|---|---|---|
| **GOT entry** | Partial RELRO | Next call to that function | Best case — 1 write, no leak needed if you aim at PLT-reachable code |
| **`printf@got` → `system`** | Partial RELRO, program prints a controlled buffer | Next `printf(buf)` | Elegant: arg1 is already your data |
| **`free@got` → `system`** | Partial RELRO, program frees a controlled buffer | Next `free(buf)` where buf holds `/bin/sh` | Same trick, heap flavour |
| **Application function pointer / C++ vtable** | Know the object address | Whatever calls the method | Ignores RELRO entirely; often overlooked |
| **Saved return address** | Stack address leak | Function returns | Turns the write into a full ROP chain |
| **`__exit_funcs`** | Handle PTR_MANGLE | `exit()` | Alive on current glibc |
| **`_IO_FILE` vtable (FSOP)** | libc leak, write into a FILE struct | Any stream flush, `puts`, `exit` | Alive — the main Full-RELRO answer |
| **`.fini_array`** | No PIE, Partial RELRO | Program exit | Simple when the binary is non-PIE |
| **`tls_dtor_list`** | libc leak, PTR_MANGLE | `exit()` | Alive, mangled |
| **`__malloc_hook` / `__free_hook`** | **glibc < 2.34 only** | `malloc`/`free` | **Dead on modern systems** |
| **`link_map` / `_dl_fini`** | Partial RELRO, no PIE or leaked | Exit | Fiddly; last resort |
| **Kernel: `modprobe_path`, `core_pattern`** | Kernel write primitive | Execute an unknown-format binary / crash | See `kernel-exploitation` |
| **Data-only** (uid, auth flag, path, size field) | Know the variable | Normal program flow | Most reliable; CFI-proof |

### The hooks are gone — check first

```python
libc = ELF('./libc.so.6')
'__free_hook' in libc.sym            # False on glibc >= 2.34
```

glibc 2.34 stopped calling `__malloc_hook`, `__free_hook`, `__realloc_hook`, and `__memalign_hook`. On Ubuntu 22.04+, Debian 12+, Fedora 35+, writing `system` there succeeds and then does **nothing**. Every "heap exploitation tutorial" ending in `__free_hook` is pre-2.34. Confirm the version (`heap-exploitation` has the version-gate table) before planning around them.

## GOT Overwrite

The cheapest conversion, and the reason `checksec`'s RELRO line is the first thing you read.

```python
# one write, and the very next call to puts() goes to win()
fmt.write(elf.got['puts'], elf.sym['win'])
```

Choose a function the program calls **after** your write and **with an argument you control**. That second property is what turns "redirect execution" into "execute a command":

```
free(buf)   → system(buf)      buf holds "/bin/sh"
printf(buf) → system(buf)      buf holds "/bin/sh"
puts(str)   → system(str)      str is your string
strlen(s)   → system(s)
atoi(s)     → system(s)        common in menu-driven CTF binaries
```

Under **Full RELRO** the GOT is mapped read-only after startup (`readelf -d ./binary | grep BIND_NOW`) — every row below exists because of that.

## `_IO_FILE` / FSOP

The workhorse under Full RELRO. `FILE` structs (`stdout`, `stderr`, `stdin`, and anything from `fopen`) carry a **vtable pointer**; stream operations dispatch through it. Corrupt a FILE struct and the next flush calls your pointer.

`exit()` flushes all streams, and so does `puts`/`printf` — so the trigger is usually already in the program.

**Since glibc 2.24, `_IO_validate_vtable` requires the vtable pointer to land inside the `__libc_IO_vtables` section**, so you cannot simply point it at your heap. The modern techniques all work *within* that constraint by pointing at a **legitimate** vtable whose handlers then dispatch through a field you control:

| Technique | Idea | Needs |
|---|---|---|
| **House of Apple 2** | Point the vtable at `_IO_wfile_jumps`; `_IO_wfile_overflow` dereferences `_wide_data->_wide_vtable`, which is **not** validated | Control of a FILE struct + libc leak |
| **House of Cat** | `_IO_wfile_jumps` variant reaching `_IO_wdoallocbuf` → `setcontext`-style call with a controlled register | Same |
| **House of Apple 3 / Husk** | Variants through `_IO_wstrn_jumps` and friends | Same |
| **`_IO_list_all` chain (House of Orange)** | Forge a whole FILE and link it into `_IO_list_all` so exit-time flush walks into it | A write of a heap pointer — pairs perfectly with the **largebin attack** |

The high-value payoff is that several of these paths reach a call with **`rdx` pointing at your controlled struct**, which is exactly what `setcontext` wants.

## `setcontext` — one gadget, all registers

```
setcontext+61 (glibc <= 2.28):   loads every register from [rdi + offset]
setcontext+61 (glibc >= 2.29):   the same, but from [rdx + offset]
```

Modern glibc uses **`rdx`**, which is why the `_IO_FILE` paths above are so useful — they hand you a call with `rdx` under your control. Point `rdx` at a fake `ucontext` and you get `rsp`, `rip`, and every argument register in one shot: a stack pivot and a full ROP chain from a single write.

Verify the exact offset in your libc (`disassemble setcontext`) rather than trusting `+61` — it moves between versions and architectures.

## Exit Handlers

`exit()` walks `__exit_funcs`, a list of `atexit`/`__cxa_atexit` callbacks. Function pointers in it are **mangled**:

```
mangled = rotate_left(ptr, 0x11) ^ pointer_guard      // PTR_MANGLE
```

`pointer_guard` lives in TLS at `fs:[0x30]`. Two ways through:

1. **Leak the guard** (arbitrary read of `fs:0x30`, or of a known-plaintext mangled pointer elsewhere) and mangle your own pointer to match.
2. **Overwrite the guard with 0** if your write reaches TLS, then `mangled = rotate_left(ptr, 0x11)` — no leak needed. This is usually the easier half.

The list also supports a `cxa_atexit` form that calls `func(arg)` with a controlled `arg` — so `system("/bin/sh")` directly, no ROP.

`tls_dtor_list` (walked by `__call_tls_dtors` on exit) is the same idea with the same mangling.

## Saved Return Address

If you can leak a stack address, overwriting a saved return address is the most flexible target: you are not limited to one pointer, you can lay a whole ROP chain.

```python
stack_leak = read(libc.sym['environ'])          # environ holds a stack address
ret_slot   = stack_leak - offset_to_target_frame
write(ret_slot,      pop_rdi); write(ret_slot+8,  binsh)
write(ret_slot+0x10, ret_gadget); write(ret_slot+0x18, libc.sym['system'])
```

`environ` in libc is the standard stack-leak source once you have a libc base and an arbitrary read. The offset from `environ`'s value to the frame you want is stable for a given binary and environment — derive it in GDB, and remember GDB's environment shifts the stack (`binary-protection-bypass`).

Chain construction itself is `stack-overflow-and-rop`.

## `.fini_array` and Destructors

For non-PIE, Partial RELRO binaries: `.fini_array` holds pointers called at exit. Overwrite one with `main` to loop the program (turning a one-shot bug into a repeatable one — very useful), or with a gadget/win function.

```bash
readelf -S ./binary | grep -E 'fini_array|init_array'
```

Looping back to `main` deserves its own mention: it converts "I get one write" into "I get unlimited writes", which reopens every technique above.

## Data-Only Targets

Often the correct answer, and always worth listing before you fight CFI:

- **Credentials / privilege**: a `uid` field, an `is_admin` flag, a role enum.
- **Paths and command strings**: a buffer later passed to `execve`/`system`/`popen`, a config path, a plugin directory, `LD_PRELOAD` in an environment array.
- **Size and bounds fields**: extend a length field to convert a small write into an unbounded one, then take the buffer overflow instead.
- **Allocator state**: `mp_.tcache_bins` (extends tcache indexing into arbitrary memory), top chunk size.
- **Function-pointer tables in the application**: dispatch tables, callback registries, `struct` handlers in a parser — these are not protected by RELRO and rarely by CFI.

Data-only wins survive CFI, shadow stacks, and CET, because no indirect branch target is ever forged. Where the goal is to demonstrate impact rather than to build a weapon, this is frequently the cleanest proof.

## Windows and Kernel Targets

| Platform | Targets |
|---|---|
| **Windows userland** | IAT entries, `PEB->ProcessHeap` flags, TEB exception chain, `ntdll` function pointers, `_PEB_LDR_DATA` callbacks, `KernelCallbackTable` (also a common injection route) |
| **Windows kernel** | `HalDispatchTable`, `nt!SeDebugPrivilege` token bits, EPROCESS token replacement |
| **Linux kernel** | `modprobe_path`, `core_pattern`, `poweroff_cmd`, `cred` struct uid fields, `n_tty_ops` — see `kernel-exploitation` |
| **Browser** | `ArrayBuffer` backing store pointer, JIT-compiled code region, external pointer table entries — see `browser-exploitation-v8` |

## Trigger Inventory

A write with no trigger is not a finding. Before committing, name the exact event that makes the process use your value:

| Target | Trigger |
|---|---|
| GOT | Next call to that library function |
| FILE vtable | `puts`, `printf`, `fflush`, `exit`, stream close |
| `__exit_funcs`, `tls_dtor_list`, `.fini_array` | `exit()` — **not** `_exit()` or `exit_group` |
| Saved return address | Enclosing function returns |
| App function pointer | Menu option / message type that dispatches through it |
| `modprobe_path` | Execute a file with an unknown magic |
| Data-only | Ordinary program flow |

If the program only ever `_exit()`s or crashes, exit-handler targets are unreachable no matter how correct the write is.

## Failure Triage

| Symptom | Cause | Fix |
|---|---|---|
| Write succeeds, nothing happens | Target never triggered, or hooks removed (glibc ≥ 2.34) | Check the trigger inventory; check `libc.sym` |
| SIGSEGV writing to the GOT | Full RELRO | Switch to FSOP / exit handlers / return address |
| `Fatal error: glibc detected an invalid stdio handle` | Vtable outside `__libc_IO_vtables` | Use House of Apple 2 style — a legitimate vtable + controlled `_wide_data` |
| Crash inside `__run_exit_handlers` | Pointer not mangled, or wrong `pointer_guard` | Leak `fs:[0x30]`, or zero the guard first |
| `setcontext` loads garbage | Using the `rdi` variant on glibc ≥ 2.29 | It reads from **`rdx`**; verify the offset by disassembling |
| Control-flow hijack faults immediately at the target | CET/IBT — target must start with `endbr64` | Pick an `endbr64`-prefixed entry, or go data-only (`binary-protection-bypass`) |
| Works locally, fails remotely | libc version mismatch — every offset moves | Identify the remote libc from a leak and re-derive |
| One-shot write, target needs two | Loop back to `main` via `.fini_array` first | Then take the writes you need |

## Related Skills

`heap-exploitation` · `format-string-exploitation` · `stack-overflow-and-rop` (getting the write; building the chain afterwards) · `binary-protection-bypass` (which targets the mitigations leave open) · `kernel-exploitation` · `browser-exploitation-v8` · `dynamic-verification` (proving the trigger fires).
