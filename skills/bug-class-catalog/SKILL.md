---
name: bug-class-catalog
description: Memory corruption and vulnerability class catalog with CWE IDs, exploit primitives, per-language dangerous sink patterns (C/C++, Python, Java, PHP), and sanitizer bypass techniques. Use when auditing source code for stack/heap buffer overflow, use-after-free, double-free, OOB read/write, integer overflow, format string bugs, type confusion, doing taint analysis source-to-sink, or mapping bug classes to exploit primitives.
---

# SKILL: Bug Class Catalog

Reference for memory corruption and vulnerability classes, exploit primitives, and source code review patterns.

## Source Code Review

Manual audit targets: C/C++, Python, Java, Go, Rust, JS/TS, PHP, C#.

Tools:
- **grep/ripgrep, weggli** — fast sink sweeps before deep review.
- **Semgrep** — custom YAML rules for project-specific sinks (`semgrep` skill); per-CWE secure/vulnerable examples live in the `code-security` skill.
- **CodeQL / joern** — when the sink and the source are in different files and you need to prove the path.

Attack surface mapping: identify every entry point (network parsers, file parsers, IPC/RPC handlers, CLI args, env vars, config parsers, deserializers, protocol handlers) before reading a single function body. The full enumeration workflow — surface mapping, tool escalation, backward taint, SAST triage, coverage tracking — is the `source-audit` skill.

Differential review focus: parsing code, bounds handling, memory management, string formatting, privilege boundaries.

## Memory Corruption Classes

For each class: determine the **exploit primitive** it yields (relative/absolute write, info leak, control-flow hijack) and whether it chains to RCE. Primitive → technique selection lives in the `exploit-dev` skill; runtime verification of each class lives in the `dynamic-verification` skill.

### Class → Exploitation Skill

Once a class is confirmed and you are moving from audit to proof, go straight to the depth skill:

| Class | Depth skill |
|---|---|
| Stack overflow, saved-RIP control | `stack-overflow-and-rop` |
| Heap overflow, UAF, double free, off-by-one | `heap-exploitation` |
| Format string (CWE-134) | `format-string-exploitation` |
| Any confirmed write primitive | `arbitrary-write-to-rce` |
| Type confusion in a JS engine | `browser-exploitation-v8` |
| Anything in kernel/driver context | `kernel-exploitation` |
| Assessing what the mitigations allow | `binary-protection-bypass` |
| Command injection / shell sinks | `exploit-dev`, `injection-checking` |

### Stack Buffer Overflow (CWE-121)
- Unbounded copies into fixed buffers.
- Unsafe: `strcpy`, `sprintf`, `gets`, `scanf("%s")`.
- Off-by-one on null terminators.
- **Primitive**: overwrite saved RIP/LR → control-flow hijack.

### Heap Overflow (CWE-122)
- `malloc(n)` then copy `n+k`.
- Undersized allocation from integer overflow.
- Heap metadata corruption, overlapping chunks.
- **Primitive**: overwrite adjacent heap object (vtable, function pointer, fd) → control-flow hijack or arbitrary write.

### Use-After-Free (CWE-416)
- Dangling pointers after error paths.
- Ref-count bugs.
- Freed memory accessed in callbacks/handlers.
- `free` without NULL-ing the pointer.
- **Primitive**: type confusion or controlled write into freed chunk → RCE if vtable/function pointer is overwritten.

### Double Free (CWE-415)
- `free` called twice on the same pointer.
- Often from error-path bugs or ref-count underflow.
- **Primitive**: heap metadata corruption → arbitrary write.

### Out-of-Bounds Read/Write (CWE-125/787)
- Missing length checks on attacker-controlled indices or lengths.
- Negative index (signed/unsigned confusion).
- Endianness or length-field confusion in parsers.
- **Primitive**: OOB read → info leak (bypass ASLR/canary); OOB write → arbitrary write.

### Integer Overflow/Underflow & Signedness (CWE-190/191/195)
- Size calculations that wrap: `len+1`, `a*b`.
- Signed→unsigned comparisons (e.g. `if (len < MAX)` where `len` is signed and attacker-controlled negative).
- Truncation on cast (e.g. `uint16_t size = attacker_value`).
- **Primitive**: undersized allocation → heap overflow; bypassed length check → OOB.

### Format String (CWE-134)
- `printf(user)` and friends.
- `%n` writes to arbitrary addresses.
- `%x`/`%p` leaks stack/heap values.
- **Primitive**: arbitrary read (info leak) and arbitrary write.

### Type Confusion (CWE-843)
- Union/pun misuse, bad downcasts.
- Deserialization type mismatches.
- **Primitive**: controlled object layout → vtable/function pointer overwrite.

### Other Classes
- **Uninitialized memory** (CWE-457): stack/heap data leaked or interpreted as pointers.
- **Race condition / TOCTOU** (CWE-367): check-then-use with a window for attacker interference.
- **Use-after-return**: pointer to stack variable escapes the function frame.

## Key Sink Patterns by Language

### C/C++
```c
// Unbounded copy
strcpy(dest, src);          // no length limit
sprintf(buf, fmt, input);   // format + no length limit
gets(buf);                  // never safe

// Bounded but misused
strncpy(dst, src, sizeof(dst));  // may not null-terminate
snprintf(buf, n, user_fmt);      // user-controlled format

// Size calculation overflow
malloc(count * size);       // wraps if count*size overflows
malloc(len + 1);            // wraps if len == SIZE_MAX

// Format string
printf(user_input);         // %n, %x, info leak + write
fprintf(fp, user_input);
```

### Python
```python
os.system(f"cmd {user}")           # shell=True equivalent
subprocess.call(cmd, shell=True)   # command injection
eval(user_input)                   # arbitrary code
pickle.loads(user_data)            # arbitrary code
yaml.load(data)                    # use yaml.safe_load
exec(user_input)
```

### Java
```java
Runtime.exec(new String[]{"sh", "-c", userInput});  // command injection
new ProcessBuilder("sh", "-c", userInput).start();
new ObjectInputStream(untrusted).readObject();       // deserialization RCE
statement.execute("SELECT * FROM t WHERE id=" + id); // SQLi
```

### PHP
```php
system($input);
exec($input);
eval($input);
unserialize($input);              // deserialization RCE
include($user_path);              // LFI/RFI
```

## Sanitizer Bypass Patterns

Common insufficient checks:
- **Length checked after copy** — check comes too late.
- **`strncpy` without null termination** — subsequent operations read past the buffer.
- **Signed comparison with unsigned value** — `if (len < 1024)` where `len` can be negative.
- **TOCTOU** — file existence/permission checked, then used; attacker swaps the file between check and use.
- **Encoding bypass** — input encoded (URL, UTF-8, double-encode) to bypass string matching.
- **Integer truncation** — `uint16_t checked_len = input_len; memcpy(buf, src, input_len);` — check passes on truncated value, copy uses full value.
