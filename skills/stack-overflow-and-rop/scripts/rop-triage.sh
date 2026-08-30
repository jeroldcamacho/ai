#!/usr/bin/env bash
# rop-triage.sh — one-shot recon for a stack-overflow target.
# Answers, before you read any disassembly: what arch, what mitigations,
# which gadgets exist, what can be leaked, and whether seccomp is in the way.
#
# Usage: rop-triage.sh ./binary [./libc.so.6]
# Every tool is optional; missing ones are reported and skipped.

set -u
BIN=${1:-}
LIBC=${2:-}

[ -z "$BIN" ] && { echo "usage: $0 ./binary [./libc.so.6]" >&2; exit 2; }
[ -r "$BIN" ] || { echo "error: cannot read $BIN" >&2; exit 2; }

have() { command -v "$1" >/dev/null 2>&1; }
hdr()  { printf '\n===== %s =====\n' "$1"; }
skip() { printf '  [skipped] %s not installed\n' "$1"; }

hdr "FILE"
file "$BIN"
if have readelf; then
  readelf -h "$BIN" 2>/dev/null | grep -E 'Class|Data|Type|Machine|Entry'
fi

hdr "MITIGATIONS"
if have checksec; then
  checksec --file="$BIN" 2>/dev/null || checksec --file "$BIN" 2>/dev/null
elif have pwn; then
  pwn checksec "$BIN"
else
  skip "checksec (pip install pwntools)"
fi
echo "  NX off -> ret2shellcode | Canary -> leak or fork-brute | PIE -> leak or partial overwrite"
echo "  Full RELRO -> GOT is read-only, pick another write target"

hdr "SECCOMP"
if have seccomp-tools; then
  seccomp-tools dump "$BIN" 2>&1 | head -40
  echo "  (if execve is blocked, build an ORW chain instead)"
else
  skip "seccomp-tools"
  if have strings; then
    strings "$BIN" | grep -qiE 'seccomp|prctl' && \
      echo "  WARNING: seccomp/prctl strings present — assume a filter until proven otherwise"
  fi
fi

hdr "IMPORTS"
if have readelf; then
  # names carry @GLIBC_x.y version suffixes -- strip them before matching
  SYMS=$(readelf --dyn-syms -W "$BIN" 2>/dev/null | awk '$8 != "" {split($8,a,"@"); print a[1]}' | sort -u)
  echo "  overflow sinks:"
  printf '%s\n' "$SYMS" | grep -xE 'gets|strcpy|strcat|sprintf|vsprintf|scanf|__isoc99_scanf|read|recv|recvfrom|memcpy|fgets|fread' \
    | sed 's/^/    /' || true
  echo "  useful targets:"
  printf '%s\n' "$SYMS" | grep -xE 'system|execve|execl|popen|mprotect|syscall|puts|printf|write|open|openat|fork|setvbuf|alarm' \
    | sed 's/^/    /' || true
  echo "  -- unbounded: gets/strcpy/strcat/sprintf/scanf %s ; size-controlled: read/recv/memcpy"
  if printf '%s\n' "$SYMS" | grep -qxE 'fork|vfork'; then
    echo "  -- fork present: canary brute-force / BROP viable IF it forks without exec"
  fi
fi

hdr "GLIBC ERA / ret2csu AVAILABILITY"
if have readelf; then
  GVER=$(readelf --dyn-syms -W "$BIN" 2>/dev/null | grep -oE 'GLIBC_[0-9]+\.[0-9]+' \
         | sort -t_ -k2 -V | tail -1)
  [ -n "$GVER" ] && echo "  minimum glibc required by imports: $GVER"
fi
if { have nm && nm "$BIN" 2>/dev/null | grep -q '__libc_csu_init'; } \
   || { have readelf && readelf -sW "$BIN" 2>/dev/null | grep -q '__libc_csu_init'; }; then
  echo "  __libc_csu_init PRESENT -> ret2csu available (3-arg calls without pop rdx)"
else
  echo "  __libc_csu_init ABSENT -> glibc >= 2.34 build, or stripped"
  echo "  -> ret2csu is OUT. Leak libc and take pop rdx from there, or use SROP."
fi
echo "  (glibc >= 2.34 also removed __malloc_hook/__free_hook -- do not plan chains around them)"

hdr "ESSENTIAL GADGETS"
if have ROPgadget; then
  ALL=$(ROPgadget --binary "$BIN" 2>/dev/null)
  for g in "pop rdi ; ret" "pop rsi ; ret" "pop rsi ; pop r15 ; ret" \
           "pop rdx ; ret" "pop rax ; ret" "syscall" "leave ; ret" \
           "pop rsp ; ret" "pop ebx ; ret" "int 0x80"; do
    hit=$(printf '%s\n' "$ALL" | grep -m1 -F ": $g")
    if [ -n "$hit" ]; then printf '  FOUND  %s\n' "$hit"
    else                   printf '  ----   %s\n' "$g"; fi
  done
  # a bare ret, for x86-64 stack alignment
  bare=$(printf '%s\n' "$ALL" | grep -m1 -E ': ret$')
  [ -n "$bare" ] && printf '  FOUND  %s   <- use for movaps alignment\n' "$bare"
  printf '  (total gadgets: %s)\n' "$(printf '%s\n' "$ALL" | grep -c ' : ')"
else
  skip "ROPgadget (pip install ROPgadget)"
fi

hdr "USEFUL STRINGS"
if have ROPgadget; then
  ROPgadget --binary "$BIN" --string "/bin/sh" 2>/dev/null | tail -n +3
  ROPgadget --binary "$BIN" --string "flag"    2>/dev/null | tail -n +3
fi

hdr "WRITABLE SEGMENTS (chain staging / pivot targets)"
if have readelf; then
  readelf -SW "$BIN" 2>/dev/null | grep -E '\.(bss|data|got|got\.plt)' \
    | awk '{printf "  %-12s addr=%s size=%s\n", $2, $4, $6}'
fi

if [ -n "$LIBC" ] && [ -r "$LIBC" ]; then
  hdr "LIBC"
  if have strings; then strings "$LIBC" | grep -m1 'GNU C Library'; fi
  if have one_gadget; then
    one_gadget "$LIBC" 2>/dev/null | head -40
    echo "  constraints hold at the moment you jump — verify in GDB, not on paper"
  else
    skip "one_gadget (gem install one_gadget)"
  fi
fi

hdr "NEXT"
cat <<'TXT'
  1. Reach the overflow and confirm you control the saved return address.
  2. cyclic / pattern_offset for the exact offset.
  3. Leak whatever the mitigations require (canary, libc base, PIE base).
  4. Build the smallest chain that works, then verify by running it.
TXT
