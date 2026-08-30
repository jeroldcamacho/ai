# Advanced ROP — BROP, Partial Overwrite, ORW, JOP/COP, Other Architectures

Companion to `SKILL.md`. Read that first for fundamentals, ret2libc, ret2csu, ret2dlresolve, SROP, and failure triage.

## Blind ROP (BROP)

Exploit a remote stack overflow **with no copy of the binary**.

**Preconditions — verify all three before spending hours:**
- The service `fork()`s per connection and does **not** `exec` (canary and ASLR layout persist across crashes).
- Crash and non-crash are distinguishable from the client (connection reset vs. hang vs. output).
- No per-connection rate limit that makes thousands of probes impractical.

| Phase | Goal | Method |
|---|---|---|
| 1 | Buffer offset + canary | Byte-by-byte: correct byte → child survives; wrong → immediate crash |
| 2 | Stop gadget | An address that doesn't crash — one that blocks or loops (the accept/read loop is ideal) |
| 3 | BROP gadget | Scan for a 6-pop-then-ret sequence (the `__libc_csu_init` tail) |
| 4 | PLT entries | PLT is a table of 16-byte stubs — probe `plt_base + N*16` with RDI set to a readable address, watch for output |
| 5 | Dump the binary | `puts(addr)` page by page to recover `.text`/`.got`/`.dynamic` |
| 6 | Normal exploitation | Run ROPgadget on the dump, then standard ret2libc |

Probing for the BROP gadget:

```
[padding][canary][saved_rbp][candidate][A][A][A][A][A][A][stop_gadget]
                                        rbx rbp r12 r13 r14 r15
```

Survival to the stop gadget means the candidate consumed six stack slots then returned — very likely the BROP gadget.

- **Stop gadget** — survives, gives an observable signal.
- **Trap gadget** — `0x0` or an unmapped page; used to terminate a probe deterministically.

Same glibc caveat as `ret2csu`: on a target built against **glibc ≥ 2.34 there is no `__libc_csu_init`**, so phase 3 must instead hunt individual `pop rdi; ret` sequences — slower, but the rest of the methodology is unchanged.

## Partial Overwrite (PIE / ASLR bypass)

ASLR randomizes at page granularity, so the **low 12 bits of every address are fixed** and known from the binary's file offsets.

| Bytes overwritten | Bits you control | Bits unknown | Attempts |
|---|---|---|---|
| 1 byte | 0–7 | none (bits 8–11 keep their original, known value) | **1 — deterministic**, but you can only reach within the same 256-byte window |
| 1.5 bytes (nibble) | 0–11 | none | 1 — reaches anywhere in the same 4 KB page |
| 2 bytes | 0–15 | 12–15 randomized | 16 (1/16 per try) |
| 3 bytes | 0–23 | 12–23 | 4096 |

The source material for this technique is commonly misquoted as "one byte = 16 attempts". It isn't: a single-byte overwrite touches only bits 0–7, all of which are already known, so it is deterministic — the limit is *reach*, not probability. The 1/16 cost appears only once you overwrite into bit 12.

Practical notes:

- A one-byte overwrite is the natural product of an off-by-one null write (`buf[len] = 0`), which sets the low byte to `\x00` and can be enough to land on a different function in the same page.
- Little-endian layout means overflow-based writes naturally clobber low bytes first — exactly what you want.
- Combine with a fork server to retry the 1/16 case until it lands.
- Prefer a real leak (format string, OOB read) when one is available; partial overwrite is the fallback.

## ORW — reading a file when execve is blocked

Seccomp commonly permits `open`/`read`/`write` while blocking `execve`/`execveat`. Dump the filter first: `seccomp-tools dump ./binary`.

| Syscall | x86-64 number | Args |
|---|---|---|
| `open` | 2 | rdi=path, rsi=flags, rdx=mode |
| `openat` | 257 | rdi=AT_FDCWD (-100), rsi=path, rdx=flags, r10=mode |
| `read` | 0 | rdi=fd, rsi=buf, rdx=count |
| `write` | 1 | rdi=fd(1), rsi=buf, rdx=count |

Some filters allow only `openat` — check before assuming `open` is reachable. The returned fd is normally `3` but confirm it rather than hardcoding.

```python
rop  = b''
# open("flag", O_RDONLY)
rop += p64(pop_rdi) + p64(flag_str_addr)
rop += p64(pop_rsi_r15) + p64(0) + p64(0)
rop += p64(pop_rax) + p64(2) + p64(syscall_ret)
# read(3, buf, 0x100)
rop += p64(pop_rdi) + p64(3)
rop += p64(pop_rsi_r15) + p64(buf_addr) + p64(0)
rop += p64(pop_rdx) + p64(0x100)
rop += p64(pop_rax) + p64(0) + p64(syscall_ret)
# write(1, buf, 0x100)
rop += p64(pop_rdi) + p64(1)
rop += p64(pop_rsi_r15) + p64(buf_addr) + p64(0)
rop += p64(pop_rdx) + p64(0x100)
rop += p64(pop_rax) + p64(1) + p64(syscall_ret)
```

The path string must exist in memory — write it into `.bss` with a staged `read` first, or find it already present with `ROPgadget --binary ./b --string flag`.

## JOP — Jump-Oriented Programming

Chains through indirect `jmp` instead of `ret`. Needs a **dispatcher** that walks a table of gadget addresses:

```nasm
; dispatcher
add rax, 8
jmp [rax]
```

Every functional gadget ends by jumping back to the dispatcher.

| Gadget role | Example |
|---|---|
| Initializer | sets RAX to the dispatch table |
| Dispatcher | `add rax, 8; jmp [rax]` |
| Functional | `pop rdi; jmp [rax]` |

Worth the complexity when Intel CET **shadow stack** is enforced (every `ret` is validated against the shadow copy, so ROP dies) or when the binary simply has few `ret` gadgets. Note that CET **IBT** independently restricts indirect jumps/calls to `endbr64` targets, which cuts most JOP gadgets too — JOP defeats shadow stack, not full CET.

## COP — Call-Oriented Programming

Chains through indirect `call`. Each gadget ends `call [reg+off]`.

| | ROP | JOP | COP |
|---|---|---|---|
| Chaining | `ret` | `jmp [reg]` | `call [reg]` |
| Stack use | RSP advances | table-based | pushes a return address each hop |
| CET shadow stack | blocked | not blocked | blocked on return paths |
| CET IBT | n/a | blocked unless `endbr64` | blocked unless `endbr64` |
| Gadget supply | most | moderate | fewest |
| Complexity | low | high | high |

## ret2vdso (legacy 32-bit)

The vDSO is a kernel-mapped page carrying syscall stubs, including a `sigreturn` sequence usable for SROP.

| Kernel (32-bit) | vDSO placement |
|---|---|
| < 2.6.18 | fixed at `0xffffe000` |
| 2.6.18 – 3.17 | ~8 bits of entropy (256 slots — brute-forceable) |
| ≥ 3.18 | full ASLR |
| any 64-bit | full ASLR |

Only relevant to legacy 32-bit targets and CTF challenges built on old kernels.

## ret2csu Extended

Leaking with the csu gadget alone (no `pop rdx` in the binary):

```python
csu_pop  = elf_base + 0x40123a   # pop rbx; pop rbp; pop r12..r15; ret
csu_call = elf_base + 0x401220   # mov rdx,r13; mov rsi,r14; mov edi,r15d; call [r12+rbx*8]

payload  = b'A' * offset
payload += p64(csu_pop)
payload += p64(0)                  # rbx = 0
payload += p64(1)                  # rbp = 1 → loop exits after one call
payload += p64(elf.got['write'])   # r12 → call *GOT[write]
payload += p64(8)                  # r13 → rdx = 8
payload += p64(elf.got['puts'])    # r14 → rsi = &GOT[puts]
payload += p64(1)                  # r15 → edi = 1 (stdout)
payload += p64(csu_call)
payload += b'A' * 56               # add rsp,8 + six pops
payload += p64(main_addr)
```

Fails when: PIE is on and unleaked; the binary is built against glibc ≥ 2.34 (gadget absent); or you need the full 64-bit RDI, since only `edi` is set. For the last case, chain a separate `pop rdi; ret` after the csu call.

## Other Architectures

### ARM32 / AArch64

| | ARM32 | AArch64 |
|---|---|---|
| Return register | LR (R14) | LR (X30) |
| Args | R0–R3, then stack | X0–X7, then stack |
| Key gadget | `pop {r0-r3, pc}` | `ldp x29, x30, [sp], #N; ret` |
| Syscall | `svc #0` (r7 = number) | `svc #0` (x8 = number) |
| Modes | ARM/Thumb — a `pc` value with bit 0 set enters Thumb | A64 only |
| Notes | Thumb gadgets double the gadget pool | PAC on ARMv8.3+ signs LR — return addresses must be signed or the sign check bypassed |

Set gadget addresses with bit 0 = 1 to land in Thumb; ROPgadget/ropper need `--thumb`/appropriate arch flags to see those gadgets.

### MIPS

- Many embedded MIPS targets ship **without NX** — plain shellcode is often the shortest path; try it before ROP.
- **Branch delay slot**: the instruction after a branch/jump always executes. Gadgets must account for it.
- Calls go through `$t9`; arguments in `$a0`–`$a3`.
- **Cache coherency**: instruction and data caches are not unified. After writing shellcode you may need to force an I-cache flush — a `sleep(1)` or a large intervening `read` is the usual pragmatic trick.
- Both endiannesses exist in the wild — confirm with `readelf -h` before packing anything.

## Toolchain

```bash
ROPgadget --binary ./pwn --only "pop|ret" | grep rdi
ROPgadget --binary ./pwn --string "/bin/sh"
ropper -f ./pwn --search "pop rdi; ret"
ropper -f ./pwn --jop                       # dispatcher candidates
one_gadget ./libc.so.6 -l 2
seccomp-tools dump ./pwn
gdb ./pwn -ex "x/3i 0x401234" -ex quit      # confirm a gadget is really there
pwn template --host remote --port 1337 ./pwn > exploit.py
```
