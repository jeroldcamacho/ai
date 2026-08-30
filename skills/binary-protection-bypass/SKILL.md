---
name: binary-protection-bypass
description: Exploit mitigation assessment and bypass. Use when deciding what an exploit needs before building it, or when a working primitive is blocked by a defence — ASLR, PIE, NX/DEP, stack canary, RELRO, FORTIFY_SOURCE, CET (IBT + shadow stack), Clang CFI, Windows CFG/ACG/CIG, ARM PAC and MTE, glibc pointer mangling and safe-linking. Covers info-leak taxonomy and how to turn each leak into a base address, partial overwrite, brute force against forking servers, GOT dereference, and reading mitigation state with checksec/readelf/dumpbin.
---

# SKILL: Binary Protection Bypass

The mitigation layer. Read this **before** choosing a technique — what is enabled decides which exploit is even possible, and every other pwn skill branches off this assessment. Chain construction is `stack-overflow-and-rop`; target selection after a write is `arbitrary-write-to-rce`.

Use only on targets you are authorized to attack.

## Discipline

**Enumerate mitigations first, from the actual binary and the actual host.** `checksec` describes the file; ASLR, `ptrace_scope`, and `mmap_min_addr` are properties of the *system* the target runs on, and remote hosts differ from your laptop.

**Nearly every modern exploit is leak-first.** With ASLR + PIE + canary + Full RELRO, the question is never "which gadget" — it is "what do I have that tells me an address". Spend your effort finding a leak; the rest usually follows.

**Do not report a mitigation as bypassed until you show it bypassed.** "PIE could be defeated with a leak" is a hypothesis. The leaked base value printed next to the true base is evidence.

## Enumerate

```bash
checksec --file=./binary                 # RELRO, canary, NX, PIE, fortify, RPATH
readelf -d ./binary | grep -E 'BIND_NOW|FLAGS'      # Full RELRO
readelf -n ./binary | grep -A2 properties           # IBT / SHSTK (.note.gnu.property)
objdump -d ./binary | grep -c endbr64               # CET-instrumented?
rabin2 -i ./binary | grep _chk                      # FORTIFY_SOURCE in use
nm -D ./binary | grep -E 'stack_chk|cfi'
seccomp-tools dump ./binary                         # syscall filter
```

System-side (check on the target host, not yours):

```bash
cat /proc/sys/kernel/randomize_va_space   # 0 off | 1 partial | 2 full
cat /proc/sys/vm/mmap_min_addr            # NULL-deref viability
cat /proc/sys/kernel/yama/ptrace_scope
sysctl kernel.randomize_va_space
```

Windows: `dumpbin /headers app.exe` → `NX compatible`, `Dynamic base`, `Guard`; or `Get-ProcessMitigation -Name app.exe`.

## Mitigation Reference

| Mitigation | Stops | Bypass |
|---|---|---|
| **NX / DEP** | Executing injected data | ROP/JOP, ret2libc, `mprotect`/`mmap` in the chain, ret2dlresolve |
| **ASLR** | Hardcoded library addresses | Any libc pointer leak → base by subtraction; partial overwrite; brute force (32-bit) |
| **PIE** | Hardcoded binary addresses | Leak a code pointer (return address, GOT, vtable); 12-bit page-offset partial overwrite |
| **Stack canary** | Naive stack smash | Leak it (format string, OOB read, uninitialised read); brute-force in a fork-no-exec server; overwrite past it without touching it; corrupt a pointer *before* the canary and write through it |
| **Partial RELRO** | Nothing much | GOT is writable — overwrite it |
| **Full RELRO** | GOT overwrite | Other write targets (`arbitrary-write-to-rce`) |
| **FORTIFY_SOURCE** | Compile-time-known overflows, `%n` in writable format strings | Only covers calls where the size is statically known; heap sizes, computed sizes, and non-fortified TUs are untouched |
| **CET / IBT** | Landing ROP/JOP on a non-`endbr64` instruction | Use `endbr64`-prefixed entry points as gadget heads; data-only attacks; call-oriented chains through legal entries |
| **CET / Shadow Stack** | Return-address overwrite | Not defeated by classic ROP — pivot to JOP/COP, data-only, or a bug that hijacks an indirect *call* |
| **Clang CFI** | Indirect calls to wrong-type functions | Same-signature targets are still legal; data-only; non-CFI modules |
| **Windows CFG / XFG** | Indirect calls to non-valid targets | Return addresses are unprotected (until CET); valid-target gadgets; data-only |
| **Windows ACG / CIG** | Making memory executable / loading unsigned code | Data-only, ROP, abuse of already-executable JIT regions |
| **ARM PAC** | Forged pointers | Signing gadgets, pointer reuse in the same context, `AUT*`-free paths |
| **ARM MTE** | Tag-mismatched OOB/UAF access | Tag leak/brute force (4 bits), tag-confusion, adjacent-same-tag allocation |
| **glibc PTR_MANGLE** | Forged `atexit`/`jmp_buf` pointers | Leak `fs:[0x30]` guard, or overwrite it with 0 |
| **glibc Safe-Linking** | Blind tcache/fastbin poisoning | Heap leak → derive the key (`heap-exploitation`) |
| **Seccomp** | `execve` | ORW chain; check the filter first, always |

## Info Leak Taxonomy

Rank your candidate leaks by cost, not by how interesting they look.

| Source | Yields | Notes |
|---|---|---|
| Format string `%p` | Stack, libc, PIE, canary — all at once | Cheapest possible leak; see `format-string-exploitation` |
| GOT read via `puts`/`write` | libc base | Entry must already be resolved; `write(1, got, 8)` is null-safe, `puts` is not |
| Unsorted-bin `fd`/`bk` | libc base | `heap-exploitation` |
| Freed tcache `next` (glibc ≥ 2.32) | Heap base | The safe-linking key *is* the leak |
| Uninitialised stack/heap read | Whatever was there — often a return address or a canary | Free of side effects; easy to miss |
| OOB read on an array | Adjacent object pointers, vtables | Classic in parsers |
| Verbose error messages / stack traces | Paths, addresses, versions | Cheap, non-crashing |
| `environ` in libc | **Stack address** | Requires libc base + arbitrary read |
| Timing / oracle differences | One bit at a time | Slow; last resort but works blind |

Once you have one leak, derive the rest:

```python
libc.address = leak_puts - libc.sym['puts']       # libc base from any libc symbol
elf.address  = leak_ret  - known_offset_in_elf    # PIE base from any code pointer
stack        = read(libc.sym['environ'])          # stack from libc
heap         = demangle(tcache_next)              # heap from safe-linking
```

Always sanity-check: a real libc base ends in `000` (page-aligned). If yours doesn't, you leaked the wrong slot or parsed the bytes wrong (`.strip()` eating `0x0a`/`0x20` is the usual culprit).

## Partial Overwrite

The lowest-entropy attack on ASLR/PIE, and it needs **no leak at all**.

Randomisation is page-granular, so the **low 12 bits of every address are fixed**. Writing only the low bytes preserves the unknown high bits:

| Bytes written | Unknown bits | Brute-force cost |
|---|---|---|
| 1 (low byte) | 0 | Deterministic — free |
| 1.5 (low byte + 1 nibble) | 4 | 1 in 16 |
| 2 | 4 | 1 in 16 |
| 3 | 12 | 1 in 4096 |

Uses:

- **PIE bypass**: overwrite the low 2 bytes of a saved return address to redirect within the same binary — reaching a `win` function or a gadget without knowing the base.
- **libc retarget**: turn a leaked/known `__libc_start_main` return into a one_gadget by editing low bytes only.
- **Heap pointer retarget**: aim a pointer at a neighbouring object.

The catch is that you must not disturb the bytes above what you write — so this pairs with off-by-one/null-byte bugs and with `%hn`/`%hhn` format writes.

## Brute Force

Viable in exactly one common situation: **a server that `fork()`s per connection without `exec()`**. The child inherits the parent's canary, ASLR layout, and PIE base, so a wrong guess kills only the child and you can try again.

| Target | Cost (x86-64) |
|---|---|
| Canary | Low byte is `\x00`; 7 unknown bytes × 256 = 1792 worst case, ~896 expected |
| PIE base (byte at a time) | Same shape as canary |
| One nibble via partial overwrite | 16 |
| Full 64-bit ASLR | Not feasible — don't try |
| 32-bit ASLR (libc) | ~2^8–2^16 depending on config; often feasible |

Byte-at-a-time is the key idea: guess byte *i*, keep the value that doesn't crash, move to *i+1*. Linear, not exponential.

`fork()` **followed by `execve`** re-randomises everything — brute force and BROP are both off the table. Confirm which one the server does before spending hours.

## Canary Specifics

- Stored at `fs:[0x28]` (x86-64) / `gs:[0x14]` (x86); the low byte is `\x00` to stop string-function leaks.
- The value is per-**thread** — a leak from one thread is valid for that thread.
- There is a master copy in TLS. If your overflow reaches TLS too, write the same value in both places and the check passes with an arbitrary value.
- Canaries protect the return address, not everything: local **pointers** and buffers below the canary can be corrupted and used before the function returns. Overwriting a local pointer and writing through it never touches the canary.
- Not every function gets one. `-fstack-protector` (as opposed to `-strong`/`-all`) only instruments functions with char arrays. Check the specific function's prologue for `mov rax, fs:0x28`.

## CET, CFI, and What Still Works

Modern hardware and toolchain mitigations change which chain shapes are legal, not whether exploitation is possible.

- **IBT** requires every indirect branch target to be an `endbr64`. Your gadget set shrinks to gadgets that *begin* at an `endbr64`. `objdump -d ./binary | grep -c endbr64` tells you if the binary is instrumented; `readelf -n` tells you if it's marked. Note enforcement needs kernel + CPU + binary all in agreement — often it is compiled in but not enforced, so test rather than assume.
- **Shadow stack** blocks return-address overwrite outright. Classic ROP dies; JOP/COP through legal `endbr64` entries, and data-only attacks, do not.
- **Clang CFI** validates the *type* of indirect call targets. A function with the same signature is still a legal target — vtable hijacking within a compatible class hierarchy survives.
- **Data-only attacks are the general answer** to all three. Overwriting a uid, a path, a size, or a function-pointer table entry that CFI does not cover forges no branch target. See the data-only section of `arbitrary-write-to-rce`.

## Environment Differences That Break Exploits

Stack addresses depend on the environment block, so an exploit tuned under a debugger frequently fails outside it:

```bash
env -i ./binary                       # minimal environment, closest to a clean run
gdb -ex 'unset env LINES' -ex 'unset env COLUMNS' ./binary
setarch $(uname -m) -R ./binary       # disable ASLR for local development only
```

Never hardcode a stack address observed only inside GDB. If your exploit needs one, leak it at runtime (`environ`) — that is the whole reason the `environ` trick exists.

## Failure Triage

| Symptom | Cause | Fix |
|---|---|---|
| `*** stack smashing detected ***` | Canary clobbered | Leak or preserve it; or corrupt a local pointer instead of the return address |
| SIGSEGV writing to a GOT entry | Full RELRO | `arbitrary-write-to-rce` |
| Chain runs then faults at the first gadget | IBT enforcing `endbr64` | Use `endbr64`-headed gadgets, or JOP/data-only |
| Return-address overwrite silently reverts | Shadow stack | Not a ROP target any more; switch to indirect-call hijack |
| Leaked "libc base" is not page-aligned | Wrong slot, or bytes eaten by `.strip()` | `recvline()[:-1]`, re-derive the offset |
| Exploit works with ASLR off, fails on | Hardcoded address | Leak it at runtime |
| Works in GDB, fails in the shell | Environment shifts the stack | `env -i`; leak instead of hardcode |
| `mmap` at NULL fails | `mmap_min_addr` | NULL-deref exploitation needs a kernel/config with it at 0 |
| Brute force never succeeds | Server `exec`s after `fork` | Re-randomised per connection — find a leak instead |
| FORTIFY aborts a `memcpy` you control | Compile-time-known destination size | Reach the same data through a non-fortified path (computed size, heap buffer) |

## Related Skills

`stack-overflow-and-rop` · `heap-exploitation` · `format-string-exploitation` (getting leaks and primitives) · `arbitrary-write-to-rce` (spending them) · `kernel-exploitation` (KASLR/SMEP/SMAP/KPTI — the kernel-side version of this table) · `dynamic-verification` (measuring mitigation state at runtime).
