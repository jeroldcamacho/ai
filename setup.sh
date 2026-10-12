#!/usr/bin/env bash
# Prerequisite installer and auditor for the GINGER (binary/source VR) and
# ALPHA (mobile pentest) agents.
#
# Run with no arguments for usage. The four primary modes are --install-deps,
# --verify-tools and --write; usage() below is the single source of
# truth for all of them, so this comment cannot drift out of date.
#
# Detection deliberately does NOT rely on `command -v` alone. GDB plugins are
# sourced scripts that never appear on PATH, Ruby gem binaries live outside it,
# and venv modules are invisible to the system interpreter - all three produce
# false "missing" results. Everything here is verified by executing it.

set -uo pipefail

VR="$HOME/.local/venvs/vr"          # angr/z3/lief live here; system python is PEP-668 managed
BIN="$HOME/.local/bin"
GEMBIN=$(echo "$HOME"/.local/share/gem/ruby/*/bin 2>/dev/null | awk '{print $1}')

# The script gets renamed (ginger-setup.sh -> ginger-setup2.sh -> setup.sh), and
# every hardcoded copy of the old name in the help was a lie the moment it did.
# Derive it instead; BASH_SOURCE survives `bash setup.sh` as well as `./setup.sh`.
SELF=$(basename "${BASH_SOURCE[0]:-$0}")

usage(){
  local s="./$SELF" w
  w=$(( ${#s} + 27 ))                     # flag column: name + --agent=X + longest flag
  printf '%s - prerequisite installer and auditor for the GINGER and ALPHA agents\n\n' "$SELF"
  printf '  %-*s %s\n' "$w" "$s"                'show this help and exit'
  printf '\n  %s\n' '--agent=ginger|alpha|all is REQUIRED by the three modes below.'
  printf '  %s\n\n' 'ginger = binary/source VR · alpha = mobile pentest · all = both'
  printf '  %-*s %s\n' "$w" "$s --agent=X --install-deps" 'install every missing tool (apt, pipx, gem,'
  printf '  %-*s %s\n' "$w" ''                  'cargo, go, venv) and list what still needs'
  printf '  %-*s %s\n' "$w" ''                  'a manual install from GitHub'
  printf '  %-*s %s\n' "$w" "$s --agent=X --verify-tools" 'execute every tool and report which are'
  printf '  %-*s %s\n' "$w" ''                  'installed, off-PATH, aliased or broken'
  printf '  %-*s %s\n' "$w" "$s --agent=X --write"        'regenerate the tool-inventory table inside'
  printf '  %-*s %s\n' "$w" ''                  "the agent's own file (implies --verify-tools)"
  printf '  %-*s %s\n' "$w" "$s --selftest"     "check every $SELF command quoted in the"
  printf '  %-*s %s\n' "$w" ''                  'agent and skill docs still parses' 
  cat <<'USAGE'

Additional flags
  --agent=NAME             ginger | alpha | all. Required by --install-deps,
                           --verify-tools and --write; scopes them to that
                           agent's tier. Not needed by --new-engagement
  --all                    include the optional per-workflow extras, and offer
                           the infer source build (30-60 min, asks first)
  --yes, -y                do not prompt before apt
  --new-engagement NAME    scaffold the three ledger logs
  --new-engagement=NAME    same, equals form
  --help, -h               show this help
USAGE
}

# MODE defaults to `help`, NOT `install`. A bare run used to install everything,
# which meant a stray invocation mutated the machine; the spec now reserves that
# for the explicit --install-deps.
MODE=help; WITH_OPTIONAL=0; ASSUME_YES=0; WRITE=0; ENG=""; EXPECT_ENG=0; AGENT=""
for a in "$@"; do case "$a" in
  --agent=*) AGENT="${a#*=}" ;;
  --install-deps) MODE=install ;;
  --verify-tools) MODE=verify ;;
  --selftest) MODE=selftest ;;
  --write) WRITE=1 ;;                 # mode resolved after the loop: implies verify
  --all)   WITH_OPTIONAL=1 ;;
  --yes|-y) ASSUME_YES=1 ;;
  --new-engagement=*) MODE=engagement; ENG="${a#*=}"; EXPECT_ENG=0 ;;
  --new-engagement) MODE=engagement; EXPECT_ENG=1 ;;   # name may follow as a positional
  --help|-h) usage; exit 0 ;;
  -*) echo "unknown option: $a (try --help)"; exit 2 ;;
  # bare `--new-engagement NAME`: GINGER.md documents the space-separated form, so
  # accept it as well as `=NAME`. Anything else positional is still an error.
  *) if [ "$EXPECT_ENG" = 1 ] && [ -z "$ENG" ]; then ENG="$a"; EXPECT_ENG=0
     else echo "unexpected argument: $a (try --help)"; exit 2; fi ;;
esac; done

# --write on its own means "regenerate the table", which requires the probes that
# only run in verify mode. Resolved here so flag order never matters, and so an
# an explicit --install-deps still wins over the implication.
[ "$WRITE" = 1 ] && [ "$MODE" = help ] && MODE=verify

# --agent is REQUIRED for the three modes that touch a tier. There is no sensible
# default: `all` provisions a mobile stack onto a box that may only ever do binary
# RE, and `ginger` silently skips what an alpha run came for. Make the caller say.
case "$MODE" in
  install|verify)
    if [ -z "$AGENT" ]; then
      # echo back the flag the caller typed, not the internal mode name
      if [ "$MODE" = install ]; then F=--install-deps
      elif [ "$WRITE" = 1 ];  then F=--write
      else F=--verify-tools; fi
      {
        printf '%s needs --agent\n\n' "$F"
        printf '  ./%s --agent=ginger %s\n'   "$SELF" "$F"
        printf '  ./%s --agent=alpha  %s\n'   "$SELF" "$F"
        printf '  ./%s --agent=all    %s\n\n' "$SELF" "$F"
        printf '  ginger = binary/source VR | alpha = mobile pentest | all = both\n'
      } >&2
      exit 2
    fi ;;
esac
case "${AGENT:-all}" in
  ginger|alpha|all) ;;
  *) echo "unknown agent: $AGENT (expected ginger, alpha or all)" >&2; exit 2 ;;
esac

# Tier selector: everything below is tagged with the agent that actually uses it.
want(){ [ "${AGENT:-all}" = all ] || [ "${AGENT:-all}" = "$1" ]; }

# Where the agent files and the skills live, relative to wherever this script is.
# Two layouts are supported and both must find their OWN trees:
#   repo checkout   <repo>/setup.sh   with <repo>/agents and <repo>/skills
#   installed       ~/.claude/agents/setup.sh   with ~/.claude/skills
# A clone that audited the installed tree would pass while its own copies were
# broken, so the checkout case is tested first.
SELF_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]:-$0}")")"
if   [ -d "$SELF_DIR/agents" ] && [ -d "$SELF_DIR/skills" ]; then
  AGENTS_DIR="$SELF_DIR/agents";          SKILLS_DIR="$SELF_DIR/skills"
elif [ "$SELF_DIR" = "$HOME/.claude/agents" ] && [ -d "$HOME/.claude/skills" ]; then
  AGENTS_DIR="$SELF_DIR";                 SKILLS_DIR="$HOME/.claude/skills"
elif [ -d "$SELF_DIR/../skills" ]; then
  AGENTS_DIR="$SELF_DIR";                 SKILLS_DIR="$(readlink -f "$SELF_DIR/../skills")"
else
  AGENTS_DIR="$SELF_DIR";                 SKILLS_DIR="${HOME}/.claude/skills"
fi

# --selftest re-execs this script once per documented invocation with this set,
# to ask "would these flags be accepted?" without running the mode. Everything
# above here is argument handling; everything below does work.
[ -n "${SETUP_PARSE_ONLY:-}" ] && exit 0

if [ "$MODE" = help ]; then usage; exit 0; fi

R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; B=$'\e[1m'; D=$'\e[2m'; N=$'\e[0m'
ok(){ printf "  ${G}ok${N}      %s\n" "$1"; }
add(){ printf "  ${Y}install${N} %s\n" "$1"; }
miss(){ printf "  ${R}manual${N}  %s${D} — %s${N}\n" "$1" "$2"; }
hdr(){ printf "\n${B}%s${N}\n" "$1"; }

MISSING_MANUAL=()


# ---------- --new-engagement: scaffold the ledger (Evidence Discipline rule 7) ----------
# Three append-only logs, outside the target tree by construction. Never inside the
# code under review: it pollutes a tree we don't own, and our own notes would enter
# the corpus for every later rg sweep.
if [ "$MODE" = engagement ]; then
  [ -n "${ENG:-}" ] || ENG=$(basename "$PWD")
  ENG=$(printf '%s' "$ENG" | tr -c 'A-Za-z0-9._-' '_')
  DIR="$HOME/.claude/agents/workspace/$ENG"
  hdr "New engagement: $ENG"
  if [ -d "$DIR" ]; then
    printf "  ${Y}exists${N}  %s ${D}— leaving it alone (logs are append-only)${N}\n" "$DIR"
  else
    mkdir -p "$DIR" || { echo "could not create $DIR"; exit 1; }
    ok "created $DIR"
  fi
  TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  seed(){ # file, header block
    if [ -e "$DIR/$1" ]; then printf "  ${D}kept${N}    %s\n" "$1"; return; fi
    printf '%s\n' "$2" > "$DIR/$1"; ok "$1"
  }
  seed observations.md "# $ENG — observations (append-only log)
#
# O-nn  <address or file:line>  <raw fact>  [tool that produced it]
#
# Raw facts only, never conclusions. Always record the producing tool: Pseudo C,
# MLIL SSA, Ghidra's decompiler and raw disassembly do not carry equal weight,
# and recorded later that distinction is unrecoverable.
# Opened $TS"
  seed hypotheses.md "# $ENG — hypotheses (append-only log; the single candidate ledger)
#
# H-nn  <status>  <claim / evidence>  [refs]
#   status: proposed -> testing -> confirmed | rejected
#
# Nothing is ever edited. State changes are NEW LINES, and the latest line for an
# ID wins. IDs are permanent. Findings and rejections are VIEWS over this file --
# do not split them into separate files. At write-up, fold the log (replay each ID
# to its latest line), filter by status, and record the F-nn = H-nn mapping.
#
# H-01  proposed   <claim>   [from O-nn, <tool>]
# H-01  rejected   <verdict sentence and why>
# Opened $TS"
  seed coverage.md "# $ENG — coverage (append-only log)
#
# E-nn  <status>  <entry point>  <reachability / review method>
#   status: reviewed | not reviewed | out of scope   (keep these three distinct)
#
# One appended verdict per entry point; assembles into the report's entry-point
# table at write-up. Never a bare percentage -- a coverage number needs its
# denominator. 'blocked' subagent rows land here as 'not reviewed', never silence.
# Opened $TS"
  cat <<EOF

  ${D}Ledger:${N}   $DIR
  ${D}Append at the phase boundaries your agent names — GINGER.md's Audit${N}
  ${D}Methodology, or ALPHA.md's Method.${N}
  ${D}Re-read all three before writing up; anything unbacked is a gap, not prose.${N}
EOF
  exit 0
fi

# ---------- detection ----------
# Opt trees are DISCOVERED, never assumed. Every vendor picks its own layout --
# /opt/honggfuzz/honggfuzz, /opt/honggfuzz/hfuzz_cc/, /opt/tools/ghidra_*/support/
# -- so a hardcoded /opt/*/bin guess misses whatever does not match it, which is
# the same false-"missing" failure this script exists to avoid. Walk for the
# executables and take the directories they are actually in.
OPT_DIRS_CACHE=""; OPT_DIRS_DONE=0
opt_dirs(){
  if [ "$OPT_DIRS_DONE" = 0 ]; then       # one walk per run; have() is called per tool
    OPT_DIRS_DONE=1
    local roots=() r
    for r in /opt "$HOME/.local/opt"; do [ -d "$r" ] && roots+=("$r"); done
    [ ${#roots[@]} -gt 0 ] && OPT_DIRS_CACHE=$(find -L "${roots[@]}" -maxdepth 4 \
      -type f -perm -u+x -printf '%h\n' 2>/dev/null | sort -u)
  fi
  [ -n "$OPT_DIRS_CACHE" ] && printf '%s\n' "$OPT_DIRS_CACHE"
}

# Every directory a tool can plausibly live in but that PATH may not cover.
# ONE list, used by both have() and resolve() — they disagreed before this, so
# one mode called a tool missing that the other then resolved by full path.
search_dirs(){
  # /snap/bin: a snap's entry point is a symlink here and nowhere else, and it is
  # absent from PATH for non-login shells -- msfvenom installed this way read as
  # missing even though it ran fine interactively.
  printf '%s\n' /usr/bin /usr/local/bin "$BIN" "$HOME/go/bin" "$HOME/.cargo/bin" \
    "$VR/bin" "$GEMBIN" /snap/bin
  opt_dirs
}

have(){ resolve "$1" >/dev/null 2>&1; }   # present anywhere, incl. /opt and aliases
have_py(){ "${2:-python3}" -c "import $1" >/dev/null 2>&1; }   # module, interpreter
# `dpkg -s` exits 0 for a package in `deinstall ok config-files` -- removed, but
# its conffiles kept. Three packages are in that state on this box, so the bare
# query reports removed packages as installed. Match the status line instead.
have_apt(){ dpkg -s "$1" 2>/dev/null | grep -q '^Status: install ok installed'; }
plugin_ok(){                              # gdb plugin: present AND sources without error
  [ -f "$1" ] || return 1
  ! setsid -w timeout -k 5 90 gdb -nx -batch -ex "source $1" </dev/null 2>&1 | grep -q 'ModuleNotFoundError\|Traceback'
}

confirm_run(){                            # print the command, then ask unless --yes
  printf "  ${B}%s${N}\n" "$1"
  [ "$ASSUME_YES" = 1 ] && return 0
  read -rp "  run this now? [y/N] " r; [[ "$r" =~ ^[Yy] ]]
}

# --check is gone: --install-deps is the only mutating mode, and it is explicit,
# so there is no dry-run to suppress. run() now simply runs.
run(){ "$@"; }

# ============================================================================
#  --verify-tools : regenerate the tool inventory that GINGER.md carries
#
#  Exists because the inventory was hand-maintained and wrong six times in one
#  session — infer, osv-scanner, govulncheck, honggfuzz and gosec were all
#  reported absent while installed off PATH, and psalm was reported broken for
#  the wrong reason. Detection here follows two rules the hand version broke:
#
#   1. Search where things actually install, not just $PATH.
#   2. Verify the tool RUNS. `--version` is a weak probe and for some tools it
#      lies outright: psalm prints its version happily and then dies on the
#      first real file with "undefined function mb_strcut" because php-mbstring
#      is missing. Where a cheap functional probe exists, that is what runs.
# ============================================================================

alts(){                                   # canonical name -> alternate binary names
  case "$1" in
    fd)  echo "fdfind" ;;                 # Debian fd-find (collides with fdclone)
    bat) echo "batcat" ;;                 # Debian bat (collides with bacula-console)
    nc)  echo "ncat netcat" ;;
    *)   : ;;
  esac
}

resolve(){                                # absolute path, searching off-PATH dirs, hints, aliases
  local n=$1 hint=${2:-} p d cand
  [ -n "$hint" ] && [ -x "$hint" ] && { printf '%s' "$hint"; return 0; }
  for cand in "$n" $(alts "$n"); do
    p=$(command -v "$cand" 2>/dev/null) && { printf '%s' "$p"; return 0; }
    while IFS= read -r d; do
      # -f as well as -x: `-x` alone is TRUE for a directory, and /opt/honggfuzz
      # is a directory named exactly like the tool — that matched on the folder
      # and reported a tool present that may not be installed at all.
      [ -n "$d" ] && [ -f "${d%/}/$cand" ] && [ -x "${d%/}/$cand" ] \
        && { printf '%s' "${d%/}/$cand"; return 0; }
    done <<<"$(search_dirs)"
  done
  return 1
}

runs(){                                   # executes without a load/link/import failure?
  local p=$1; shift
  local err rc
  # Run with NO controlling terminal. </dev/null alone is not enough: it covers a
  # probe that reads stdin (rizin, radare2 calling tcsetattr for their line
  # editor), but not one that opens /dev/tty directly -- the JVM behind baksmali
  # and keytool does exactly that. Either way the process takes SIGTTOU, which
  # STOPS its whole group including `timeout`, so the bound never fires and
  # --verify-tools hangs forever on an interactive terminal. setsid -w detaches
  # the session, so /dev/tty cannot be opened and the signal cannot be raised.
  err=$(setsid -w timeout -k 5 30 "$p" "$@" </dev/null 2>&1 >/dev/null); rc=$?
  case $rc in 126|127) return 1 ;; esac    # not executable / missing loader
  grep -qiE 'error while loading shared librar|cannot open shared object|ModuleNotFoundError|GLIBC_[0-9.]+ .*not found|undefined function|Uncaught Error' <<<"$err" && return 1
  return 0
}

remedy(){                                 # known root cause -> the fix
  case "$1" in
    # The old text named php8.4-mbstring and assumed mbstring was the cause. On
    # this box PHP is 8.5 and mbstring is already loaded, so that advice sent the
    # reader after a dependency they had. Check what is actually missing instead.
    psalm) if ! php -m 2>/dev/null | grep -qi mbstring; then
             echo "PHP mbstring not loaded: sudo apt install php-mbstring"
           else
             echo "PHP $(php -r 'echo PHP_VERSION;' 2>/dev/null) has mbstring — re-run composer global require vimeo/psalm"
           fi ;;
    *)     : ;;
  esac
}

# Functional probes, for tools whose --version does not exercise the failing path.
func_probe(){
  local n=$1 p=$2 d rc
  case "$n" in
    psalm)
      d=$(mktemp -d); printf '<?php\nfunction f(string $s): int { return $s; }\n' >"$d/t.php"
      printf '<?xml version="1.0"?>\n<psalm errorLevel="1"><projectFiles><directory name="."/></projectFiles></psalm>\n' >"$d/psalm.xml"
      ( cd "$d" && setsid -w timeout -k 5 120 "$p" --no-cache --no-progress </dev/null >/dev/null 2>"$d/e" ); rc=$?
      grep -qiE 'Uncaught Error|undefined function' "$d/e" && rc=1
      rm -rf "$d"; return $rc ;;
    *) return 0 ;;
  esac
}

classify(){                               # STATUS|name|path|note
  local n=$1 args=$2 hint=${3:-} p dir note=""
  if ! p=$(resolve "$n" "$hint"); then printf 'ABSENT|%s||\n' "$n"; return; fi
  # shellcheck disable=SC2086
  if ! runs "$p" $args; then printf 'BROKEN|%s|%s|fails to execute\n' "$n" "$p"; return; fi
  if ! func_probe "$n" "$p"; then
    r=$(remedy "$n")
    printf 'BROKEN|%s|%s|runs but fails on real input%s\n' "$n" "$p" "${r:+ — $r}"; return
  fi
  dir=$(dirname "$p")
  case ":$PATH:" in *":$dir:"*) ;; *) note="not on PATH" ;; esac
  # a tool found under an alias is present but will not answer to the name you typed
  [ "$(basename "$p")" != "$n" ] && note="${note:+$note; }installed as $(basename "$p")"
  printf 'OK|%s|%s|%s\n' "$n" "$p" "$note"
}

# name | probe args | hint path.  Grouped only for readability; grouping is derived.
INVENTORY=(
  # core, expected on PATH
  "rg|--version|"            "jq|--version|"           "gdb|--version|"
  "lldb|--version|"          "rizin|-v|"               "radare2|-v|"
  "objdump|--version|"       "readelf|--version|"      "nm|--version|"
  "checksec|--version|"      "clang|--version|"        "gcc|--version|"
  "llvm-cov|--version|"      "llvm-profdata|--version|" "llvm-dwarfdump|--version|"
  "cppcheck|--version|"      "clang-tidy|--version|"   "scan-build|-h|"
  "cmake|--version|"         "ninja|--version|"        "bear|--version|"
  "go|version|"              "cargo|--version|"        "rustc|--version|"
  "yara|--version|"          "uv|--version|"           "afl-fuzz|-h|"
  "afl-clang-fast|--version|" "binwalk|--help|"        "upx|--version|"
  # commonly installed off PATH
  "semgrep|--version|"       "joern|--help|"           "joern-parse|--help|"
  "weggli|--help|"           "honggfuzz|--help|"       "seccomp-tools|--version|"
  "one_gadget|--version|"    "ropper|--version|"       "pwninit|--version|"
  "tokei|--version|"         "cloc|--version|"         "bandit|--version|"
  "brakeman|--version|"      "infer|--version|"        "frida|--version|"
  "gosec|--version|"         "govulncheck|-version|"   "osv-scanner|--version|"
  "patchelf|--version|"
  # explicit-hint installs
  "codeql|--version|/opt/tools/codeql/codeql"
  "rustup|--version|$HOME/.cargo/bin/rustup"
  "psalm|--version|"
  # notable absences worth asserting rather than assuming
  "valgrind|--version|"      "cargo-fuzz|--version|"   "cargo-audit|--version|"
  "pip-audit|--version|"     "grype|version|"
  "dwarfdump|--version|"     "fd|--version|"           "trivy|--version|"
  # honggfuzz ships its instrumenting compiler wrappers separately from the fuzzer
  # binary, and they land in the source tree rather than on PATH. Without them you
  # get ptrace-only feedback, which is a much weaker campaign — so probe them.
  # No hint needed: opt_dirs() discovers whatever subdirectory they were built into.
  "hfuzz-clang|--version|"   "hfuzz-clang++|--version|"   "hfuzz-gcc|--version|"
  # Invoked by GINGER.md and the skills but previously asserted by neither mode:
  # rabin2 alone appears in 6 skills, and ROPgadget ships in APT_REQ as
  # python3-ropgadget while only `ropper` (a different tool) was ever probed.
  "rabin2|-v|"               "radiff2|-v|"             "rz-bin|-v|"
  "ROPgadget|--version|"     "strings|--version|"      "llvm-objdump|--version|"
  "strace|-V|"               "ltrace|--version|"       "socat|-V|"
  "jadx|--version|"          "apktool|--version|"
  "afl-tmin|-h|"             "afl-cmin|-h|"
  # reverse-shell-techniques and exploit-dev both reach for msfvenom, which is in
  # APT_OPT -- so it arrives only with --all. Probe it so its absence is asserted
  # here rather than discovered mid-engagement.
  "msfvenom|--help|"
  # Phase 0 steps 1 and 8 run `file` and `ldd`; reverse-shell-techniques reaches
  # for openssl/nc; kernel and firmware work uses cpio and xxd. All were invoked
  # by GINGER.md or a skill while asserted by neither mode.
  "file|--version|"          "ldd|--version|"          "openssl|version|"
  "nc|-h|"                   "cpio|--version|"         "xxd|-v|"
  "php|--version|"           "composer|--version|"
)

# The alpha agent's device tier, probed only when alpha is in scope.
INVENTORY_ALPHA=(
  "adb|version|"             "objection|version|"      "apksigner|--version|"
  "idevice_id|-h|"           "mitmproxy|--version|"    "frida|--version|"
  "frida-ps|--version|"      "jadx|--version|"         "apktool|--version|"
  "baksmali|--help|"         "keytool|-help|"          "scrcpy|--version|"
)

# Assembled per --agent. GINGER's list is the default one above; alpha narrows to
# the device tier, since a mobile assessment never asks whether angr is present.
case "$AGENT" in
  alpha) INVENTORY=( "${INVENTORY_ALPHA[@]}" ) ;;
  all)   INVENTORY+=( "${INVENTORY_ALPHA[@]}" ) ;;
esac

# ---------- --selftest: do the docs still name commands this script accepts? ----------
# Three times an interface change (a rename, dropping --check, requiring --agent)
# silently invalidated commands embedded in GINGER.md, ALPHA.md and the skills.
# Markdown cannot fail a syntax check, so nothing caught it. This does: every
# documented invocation is re-parsed by the current argument handler.
# ---------- package tiers (data only; install logic is further down) ----------
# Declared up here because --selftest reads them to answer "does anything in
# this toolchain track that tool?" -- which needs the tiers and the INVENTORY
# before either is actually used.
# CORE is what both agents need: toolchain, VCS, interpreters, archive handling.
APT_CORE=(
  file binutils xxd unzip jq git curl build-essential
  python3-pip python3-venv python3-six pipx ruby golang-go sqlite3
  # Android artefact handling: GINGER reverses the DEX, ALPHA assesses the app.
  jadx apktool libsmali-java
)
# GINGER: binary RE, source audit, fuzzing, exploit development.
APT_GINGER=(
  checksec rizin radare2 binwalk squashfs-tools upx-ucl
  gdb lldb strace ltrace cpio qemu-system-x86 qemu-user-binfmt
  clang cppcheck bear gh socat 7zip
  python3-ropgadget
  # Tier 1 -- every one of these is invoked by GINGER.md or a skill and was
  # reported absent by --verify-tools. clang-tidy and clang-tools are SEPARATE
  # packages: clang-tools ships scan-build and clang-apply-replacements but not
  # clang-tidy, so both are required. fd-find installs the binary as `fdfind`,
  # which alts() already maps back to `fd`.
  clang-tidy clang-tools yara tokei cloc valgrind dwarfdump fd-find
  # psalm's runtime: php-cli plus mbstring, which psalm dies on without. Both
  # are present here already, but a fresh machine needs them before the
  # manual composer step below can produce a working psalm.
  php-cli php-mbstring composer
)
# nmap, masscan and sqlmap were here but no skill invokes them -- they appeared
# once in a GINGER.md prose line and nowhere else. Network scanning is not what
# this agent does; metasploit stays because msfvenom has 9 real references.
APT_OPT=( wabt android-sdk-libsparse-utils ncat metasploit-framework )
# The alpha agent's tier: device-side Android/iOS tooling. Optional because a
# binary-RE engagement never needs it, and it is a large install. apktool, jadx,
# baksmali and keytool are already in APT_REQ and serve both agents.
APT_MOBILE=( adb apksigner zipalign libimobiledevice-utils ideviceinstaller
             ifuse libplist-utils mitmproxy scrcpy )

if [ "$MODE" = selftest ]; then
  hdr "Self-test — documented invocations"
  ROOT="$AGENTS_DIR"; SKILLS="$SKILLS_DIR"
  # Match on the script's OWN name, never a hardcoded one -- this file has been
  # renamed twice already, and a self-test that greps for the old name passes by
  # finding nothing. The dot needs escaping or `setup.sh` also matches `setupXsh`.
  # Done with parameter expansion: a sed bracket expression holding both / and \
  # is a quoting trap, and when it silently produced an EMPTY pattern the grep
  # matched every line of every file instead of failing.
  SELF_RE=$SELF
  SELF_RE=${SELF_RE//\\/\\\\}
  SELF_RE=${SELF_RE//./\\.}
  SELF_RE=${SELF_RE//+/\\+}
  [ -n "$SELF_RE" ] || { printf "  ${R}cannot determine this script's name${N}\n"; exit 3; }
  SEEN=0; BAD=0   # not N: that is the colour-reset escape
  while IFS= read -r f; do
    while IFS= read -r hit; do
      ln=${hit%%:*}; cmd=${hit#*:}
      # Normalise documentation placeholders so a template is judged on its flags:
      # --agent=X, <target>, NAME are stand-ins, not errors.
      args=$(printf '%s' "$cmd" \
        | sed -E "s@^.*${SELF_RE}@@" \
        | sed -E 's@;.*@@; s@-->.*@@' \
        | sed -E 's@--agent=(X|NAME|AGENT_NAME)@--agent=ginger@g' \
        | sed -E 's@<[^>]*>@selftest@g' \
        | sed -E 's@(^| )NAME( |$)@\1selftest\2@g' \
        | sed -E 's@[[:space:],.]+$@@')
      [ -z "${args// /}" ] && continue
      SEEN=$((SEEN+1))
      # shellcheck disable=SC2086
      if SETUP_PARSE_ONLY=1 bash "$0" $args >/dev/null 2>&1; then
        ok "${f#"$HOME"/}:$ln ${D}./$SELF$args${N}"
      else
        BAD=$((BAD+1))
        miss "${f#"$HOME"/}:$ln" "./$SELF$args — rejected by the current flags"
      fi
    done < <(grep -noE "(\./)?$SELF_RE"'[^`)"'"'"']*' "$f" 2>/dev/null)
  done < <(find "$ROOT" "$SKILLS" -name '*.md' 2>/dev/null | sort)
  echo
  # Zero matches is NOT a pass. It is what a rename looks like from in here: the
  # docs still name the old script, so nothing matches and the counters stay at
  # zero. Say which names the docs DO mention, since that is the fix.
  if [ "$SEEN" -eq 0 ]; then
    printf "  ${R}no %s invocations found in the docs${N}\n" "$SELF"
    OTHER=$(grep -rhoE '[A-Za-z0-9_-]*setup[A-Za-z0-9_-]*\.sh' "$ROOT" "$SKILLS" --include='*.md' 2>/dev/null \
            | sort -u | grep -vFx "$SELF" | tr '\n' ' ')
    if [ -n "$OTHER" ]; then
      printf "  ${D}the docs name: %s${N}\n" "${OTHER% }"
      printf "  ${D}this script is %s — it was renamed and the docs were not updated${N}\n" "$SELF"
    else
      printf "  ${D}and no other setup script either — the docs reference none of them${N}\n"
    fi
    exit 1
  fi
  if [ "$BAD" -eq 0 ]; then
    printf "  ${G}%d/%d documented invocations still valid${N}\n" "$SEEN" "$SEEN"
  else
    printf "  ${R}%d of %d documented invocations are broken${N} ${D}— fix the docs or the flags${N}\n" "$BAD" "$SEEN"
  fi

  # ---- phase 2: does anything in this toolchain track the tools the docs use? ----
  # Parsing only proves the commands are well-formed. It says nothing about a skill
  # that tells the agent to run a tool nobody installs and nobody probes -- which is
  # how msfvenom, rabin2, ROPgadget, strings and jadx all went unasserted until they
  # were found by hand. A tool is TRACKED if it is probed by INVENTORY or named by
  # any install tier; untracked-and-absent is the one that fails the run.
  hdr "Self-test — tool references"
  TRACKED=$(
    { printf '%s\n' "${INVENTORY[@]}" "${INVENTORY_ALPHA[@]}" | cut -d'|' -f1
      printf '%s\n' "${APT_CORE[@]}" "${APT_GINGER[@]}" "${APT_MOBILE[@]}" "${APT_OPT[@]}"
      # package name and installed binary differ often enough to list both
      # the solver venv's modules are tracked by the Python-modules section, not
      # INVENTORY, but a doc invoking them is still covered
      printf '%s\n' pwn angr z3 claripy lief unicorn capstone elftools ropper
      printf '%s\n' semgrep bandit pip-audit uv frida frida-tools objection patchelf \
                    one_gadget seccomp-tools brakeman weggli pwninit cargo-fuzz cargo-audit \
                    gosec govulncheck osv-scanner jefferson ubi_reader \
                    afl-fuzz honggfuzz codeql joern psalm infer grype trivy \
                    pwndbg gef peda binaryninja ghidra analyzeHeadless \
                    phpggc ysoserial ysoserial.exe php composer \
                    libc-identify libc-get libc-find libc-add libc-dump libc-download
    } | sed 's/-dev$//' | sort -u)

  # Shell builtins, coreutils and the common non-tools that show up at the start of
  # a documented command line. Anything here is never reported.
  COMMON=$(printf '%s\n' if then else fi for do done while case esac echo cd set export local \
    return exit read printf test true false source eval function break continue shift trap \
    exec wait sudo env time command which type ls cat grep sed awk head tail cut sort uniq \
    wc tr find xargs cp mv rm mkdir chmod chown ln tee diff dd od basename dirname seq date \
    sleep kill ps git curl wget python python3 pip pip3 bash sh make tar unzip gzip touch df \
    du mount umount nproc tmux less man timeout nohup watch yes apt apt-get dpkg mktemp uname \
    stty mkfifo perl ruby node npm go cargo rustc rustup stat sysctl nsenter chroot id whoami \
    free open size close write malloc memcpy strcpy nl rev paste join comm split truncate sync \
    java javac jar echo printf let declare unset alias pushd popd pkill pgrep setsid script \
    base64 md5sum sha1sum sha256sum xxd hexdump strings file ldd nc socat openssl ssh scp \
    docker podman kubectl systemctl journalctl service mount awk | sort -u)

  UNTRACKED_ABSENT=""; UNTRACKED_PRESENT=""; MACOS_ONLY=""; DECLINED=""; TSEEN=0
  # Extraction is deliberately conservative. A fenced block holds prose, sample
  # HTTP, pseudo-code and tool OUTPUT as well as commands, and every one of those
  # yields plausible-looking tokens ("token", "GET", "Step"). So: line-initial
  # position only, lowercase, and the rest of the line must look like an argument
  # list -- a flag or a path. Claude's own synced skills are not ours to audit.
  CANDS=$(while IFS= read -r f; do
      awk '
        /^```/ { lang=substr($0,4); gsub(/[^a-zA-Z]/,"",lang)
                 inb=!inb; ok=(lang==""||lang=="bash"||lang=="sh"||lang=="shell"||lang=="console"); next }
        inb && ok {
          line=$0; sub(/^[ \t]*\$?[ \t]*/,"",line)
          if (line ~ /^#/ || line=="") next
          if (!match(line,/^[a-z][a-z0-9_.+-]{2,}/)) next
          tool=substr(line,RSTART,RLENGTH); rest=substr(line,RLENGTH+1)
          if (rest ~ /^=/) next                                    # name=value, not a command
          if (rest !~ /(^| )-{1,2}[a-zA-Z]/ && rest !~ /\//) next   # needs a flag or a path
          print tool
        }' "$f"
    done < <(find "$ROOT" "$SKILLS" -name '*.md' -not -path '*/synced/*' 2>/dev/null) | sort | uniq -c | sort -rn)

  while read -r cnt tool; do
    [ -z "$tool" ] && continue
    [ "$cnt" -lt 2 ] && continue                       # a single mention is usually prose
    case "$tool" in http|https|data|www|ftp|file|localhost) continue ;; esac  # URL schemes, not commands
    grep -qxF "$tool" <<<"$COMMON"  && continue
    grep -qxF "$tool" <<<"$TRACKED" && continue
    TSEEN=$((TSEEN+1))
    # macOS-only tooling cannot be installed here and is not a gap on Linux --
    # pe-and-macho-analysis and the iOS skills reference it by design.
    case "$tool" in
      otool|plutil|class-dump|class-dump-dyld|codesign|lipo|xcrun|xcodebuild|dyldinfo|vtool|nm-classic)
        MACOS_ONLY="$MACOS_ONLY $tool($cnt)"; continue ;;
      # Deliberately NOT installed. Listed so the check can still reach a clean
      # exit: a gate that always fails is a gate everyone learns to ignore, and
      # then a genuinely new untracked tool goes unnoticed. Removing a name from
      # here makes it fail again, which is the point -- these are decisions, and
      # the reason is recorded next to each.
      npx|node|nodejs)   DECLINED="$DECLINED $tool($cnt: ~200MB of node for three example commands)"; continue ;;
      expect)            DECLINED="$DECLINED $tool($cnt: two references, no workflow depends on it)"; continue ;;
    esac
    if have "$tool"; then UNTRACKED_PRESENT="$UNTRACKED_PRESENT $tool($cnt)"
    else                  UNTRACKED_ABSENT="$UNTRACKED_ABSENT $tool($cnt)"; fi
  done <<<"$CANDS"

  if [ -n "$UNTRACKED_ABSENT" ]; then
    printf "  ${R}referenced, not installed, tracked by nothing${N} ${D}— the agent will hit \"command not found\"${N}\n"
    printf "    %s\n" "${UNTRACKED_ABSENT# }"
  fi
  if [ -n "$UNTRACKED_PRESENT" ]; then
    printf "  ${Y}referenced and installed, but asserted by nothing${N} ${D}— breaks silently if it goes away${N}\n"
    printf "    %s\n" "${UNTRACKED_PRESENT# }"
  fi
  if [ -n "$MACOS_ONLY" ]; then
    printf "  ${D}macOS-only, not installable here (informational):%s${N}\n" "$MACOS_ONLY"
  fi
  if [ -n "$DECLINED" ]; then
    printf "  ${D}declined on purpose:%s${N}\n" "$DECLINED"
  fi
  [ -z "$UNTRACKED_ABSENT$UNTRACKED_PRESENT" ] && ok "every tool the docs invoke is tracked"

  echo
  if [ "$BAD" -eq 0 ] && [ -z "$UNTRACKED_ABSENT" ]; then exit 0; else exit 1; fi
fi

if [ "$MODE" = verify ]; then
  hdr "Binaries"
  ROWS=()
  for spec in "${INVENTORY[@]}"; do
    IFS='|' read -r n a h <<<"$spec"
    r=$(classify "$n" "$a" "$h"); ROWS+=("$r")
    IFS='|' read -r st nm pth note <<<"$r"
    case $st in
      OK)     [ -n "$note" ] && printf "  ${Y}off-PATH${N} %-18s ${D}%s${N}\n" "$nm" "$pth" \
                             || ok "$nm ${D}$pth${N}" ;;
      BROKEN) miss "$nm" "$pth — $note" ;;
      ABSENT) printf "  ${R}absent${N}   %s\n" "$nm" ;;
    esac
  done

  PYROWS=(); RUSTROWS=(); PLUGROWS=(); TOOLCHAINS=""; MIRI=""
  if want ginger; then
  hdr "Python modules"
  for m in pwn capstone elftools angr z3 claripy lief unicorn; do
    sysok=no; vrok=no
    have_py "$m" python3 && sysok=yes
    [ -x "$VR/bin/python3" ] && have_py "$m" "$VR/bin/python3" && vrok=yes
    PYROWS+=("$m|$sysok|$vrok")
    if [ $sysok = yes ]; then ok "$m ${D}(system python3)${N}"
    elif [ $vrok = yes ]; then printf "  ${Y}venv${N}     %-18s ${D}%s${N}\n" "$m" "$VR/bin/python3"
    else printf "  ${R}absent${N}   %s\n" "$m"; fi
  done

  hdr "Rust toolchains and components"
  RUSTROWS=(); TOOLCHAINS=""
  RU=$(resolve rustup "$HOME/.cargo/bin/rustup" 2>/dev/null || true)
  if [ -n "$RU" ]; then
    for tc in stable nightly; do
      "$RU" toolchain list 2>/dev/null | grep -q "^$tc" || { printf "  ${R}absent${N}   %s toolchain\n" "$tc"; continue; }
      TOOLCHAINS="$TOOLCHAINS $tc"; ok "$tc toolchain"
      inst=$("$RU" component list --toolchain "$tc" --installed 2>/dev/null || true)
      for c in clippy miri rust-src llvm-tools; do
        if grep -q "^$c" <<<"$inst"; then
          printf "    ${G}ok${N}      %s ${D}(+$tc)${N}\n" "$c"; RUSTROWS+=("$c|$tc|yes")
        else RUSTROWS+=("$c|$tc|no"); fi
      done
    done
    # miri is the consequential one: it is the only tool that EXECUTES UB checks
    # over unsafe Rust, so its absence changes the evidence bar for every finding.
    if printf '%s\n' "${RUSTROWS[@]}" | grep -q '^miri|.*|yes$'; then
      mtc=$(printf '%s\n' "${RUSTROWS[@]}" | grep '^miri|.*|yes$' | head -1 | cut -d'|' -f2)
      if setsid -w timeout -k 5 120 "$HOME/.cargo/bin/cargo" "+$mtc" miri --version </dev/null >/dev/null 2>&1; then
        ok "\$HOME/.cargo/bin/cargo +$mtc miri ${D}(runtime UB checking available)${N}"; MIRI="~/.cargo/bin/cargo +$mtc miri"
      else miss "miri" "component present but '~/.cargo/bin/cargo +$mtc miri' fails"; MIRI=""; fi
    else printf "  ${R}absent${N}   miri ${D}(nightly-only: rustup component add miri --toolchain nightly)${N}\n"; MIRI=""; fi
  else printf "  ${R}absent${N}   rustup — cannot enumerate toolchains\n"; MIRI=""; fi

  hdr "GDB plugins"
  PLUGROWS=()
  for pair in "pwndbg:$HOME/pwndbg/gdbinit.py" "gef:$HOME/gef/gef.py" "peda:$HOME/peda/peda.py"; do
    nm=${pair%%:*}; entry=${pair#*:}
    if plugin_ok "$entry"; then ok "$nm ${D}$entry${N}"; PLUGROWS+=("$nm|ok")
    elif [ -f "$entry" ]; then miss "$nm" "$entry — present but fails to load"; PLUGROWS+=("$nm|broken")
    else printf "  ${R}absent${N}   %s\n" "$nm"; PLUGROWS+=("$nm|absent"); fi
  done
  fi   # want ginger — solver venv, Rust toolchains, GDB plugins

  # Shadowing is a property of the machine, not of one agent -- both run it.
  hdr "Shadowed names"
  SHADOWL=""
  for n in cargo rustc rustdoc rustfmt clippy-driver python3 pip3 gdb; do
    onpath=$(command -v "$n" 2>/dev/null) || continue
    for d in "$HOME/.cargo/bin" "$BIN" "$HOME/go/bin" /usr/local/bin; do
      [ -x "$d/$n" ] || continue
      [ "$d/$n" = "$onpath" ] && continue
      # same file via symlink is not a shadow
      [ "$(readlink -f "$d/$n")" = "$(readlink -f "$onpath")" ] && continue
      printf "  ${Y}shadowed${N} %-14s ${D}PATH gives %s; also %s${N}\n" "$n" "$onpath" "$d/$n"
      SHADOWL="$SHADOWL \`$n\` — \`$onpath\` shadows \`$d/$n\` ·"
    done
  done

  [ -z "$SHADOWL" ] && ok "no shadowed names among the probed set"
  SHADOWL=${SHADOWL% ·}; SHADOWL=${SHADOWL# }
  # ---------- build the markdown table ----------
  #
  #  Classified by STATUS, not by location. Location was the original mistake:
  #  a row labelled "not on PATH" that actually listed "everything in
  #  ~/.local/bin" is wrong the moment that directory is on PATH, which it is
  #  here. The only actionable fact is whether `command -v` finds the tool.
  #
  FALLBACK=""      # exists, but command -v missed it — the false-negative set
  BROKENL=""       # exists and resolves, but does not work
  ABSENTL=""       # genuinely not installed
  PATHDIRS=""      # non-standard dirs that ARE on PATH here (shell-dependent)

  for r in "${ROWS[@]}"; do
    IFS='|' read -r st nm pth note <<<"$r"
    case "$st" in
      OK)
        if [ -n "$note" ]; then FALLBACK="$FALLBACK \`$nm\` — \`${pth/#$HOME/\~}\` ·"
        else
          d=$(dirname "$pth")
          case "$d" in /usr/bin|/usr/local/bin|/bin|/usr/sbin|/sbin) ;;
            *) case " $PATHDIRS " in *" ${d/#$HOME/\~} "*) ;; *) PATHDIRS="$PATHDIRS ${d/#$HOME/\~}" ;; esac ;;
          esac
        fi ;;
      BROKEN) BROKENL="$BROKENL \`$nm\` (${note}) ·" ;;
      ABSENT) ABSENTL="$ABSENTL \`$nm\` ·" ;;
    esac
  done
  for x in "${RUSTROWS[@]:-}"; do
    IFS='|' read -r c tc st <<<"$x"
    # miri ships nightly-only; recommending it for stable is advice that cannot succeed.
    [ "$c" = miri ] && [ "$tc" = stable ] && continue
    [ "$st" = no ] && ABSENTL="$ABSENTL \`rustup component add $c --toolchain $tc\` ·"
  done
  for x in "${PLUGROWS[@]:-}"; do
    case "${x#*|}" in
      absent) ABSENTL="$ABSENTL \`${x%%|*}\` (gdb plugin) ·" ;;
      broken) BROKENL="$BROKENL \`${x%%|*}\` (gdb plugin fails to load) ·" ;;
    esac
  done
  FALLBACK=${FALLBACK% ·}; BROKENL=${BROKENL% ·}; ABSENTL=${ABSENTL% ·}
  FALLBACK=${FALLBACK# }; BROKENL=${BROKENL# }; ABSENTL=${ABSENTL# }
  PATHDIRS=${PATHDIRS# }

  VENVL=""; SYSL=""; PYABS=""
  for r in "${PYROWS[@]}"; do IFS='|' read -r m sysok vrok <<<"$r"
    if   [ "$sysok" = yes ]; then SYSL="$SYSL \`$m\`"
    elif [ "$vrok"  = yes ]; then VENVL="$VENVL \`$m\`"
    else PYABS="$PYABS \`$m\`"; fi; done
  VENVL=${VENVL# }; SYSL=${SYSL# }; PYABS=${PYABS# }
  [ -n "$PYABS" ] && ABSENTL="${ABSENTL:+$ABSENTL · }$PYABS (python)"

  if [ -n "${MIRI:-}" ]; then
    MIRI_CELL="\`$MIRI test\` — available, so an unsafe finding can be confirmed at runtime"
  else
    MIRI_CELL="unavailable — unsafe findings rest on the static-proof bar"
  fi

  # objdump architecture support: a CAPABILITY false positive, not a presence one.
  # An x86-only build emits no output AND no error on ARM/MIPS firmware, which is
  # indistinguishable from a clean result. Probe it rather than trusting the name.
  OBJD_CELL=""
  if want ginger && have objdump; then
    OA=$(objdump --help 2>&1 | sed -n 's/^.*supported architectures: *//p' | head -1)
    if [ -n "$OA" ] && ! printf '%s' "$OA" | grep -qiE 'aarch64|(^| )arm|mips|powerpc|riscv'; then
      ALT=""
      have rz-asm  && ALT="$ALT \`rz-asm -a arm -b 64 -d\`"
      have rasm2   && ALT="$ALT \`rasm2 -a arm -b 64 -d\`"
      python3 -c 'import capstone' 2>/dev/null && ALT="$ALT capstone in system python"
      OBJD_CELL="\`objdump --help\` — \`$OA\` only. On ARM/AArch64/MIPS it emits **no output and no error** — indistinguishable from a clean result. Foreign-arch disassembly here:${ALT:- none found — install one}"
    fi
  fi

  # AFL++ LD_PRELOAD libs (the no-rebuild sanitizer tier) + qemu-user for foreign arch
  AFLLIB=""
  want ginger && for d in /usr/local/lib/afl "$HOME/Desktop/AFLplusplus" /usr/lib/afl; do
    if [ -f "$d/libdislocator.so" ]; then
      L=""; for l in libdislocator libtokencap libcompcov libqasan; do
        [ -f "$d/$l.so" ] && L="$L \`$l.so\`"; done
      # The emulators are NOT named qemu-*-static any more. Ubuntu folded them
      # into qemu-user (built static-pie) and made qemu-user-static a virtual
      # package; globbing the old name reports zero on a box carrying 41 of
      # them, which is the false-"missing" failure this script exists to stop.
      # Match both layouts and strip the non-emulator helpers qemu also ships.
      QL=$(ls /usr/bin/qemu-*-static /usr/bin/qemu-* 2>/dev/null \
           | grep -vE 'qemu-(system|img|io|nbd|pr-helper|storage-daemon|edid|ga|vmsr-helper)' \
           | sed 's|.*/qemu-||;s|-static$||' | sort -u)
      QN=$(printf '%s\n' "$QL" | grep -c .)
      QE=$(printf '%s\n' "$QL" | grep -xE 'aarch64|arm|mips|mipsel|mips64|riscv64|ppc' | tr '\n' ' ')
      [ "$QN" -gt 0 ] && QE="${QE}(+$QN total)"
      AFLLIB="${L# } at \`${d/#$HOME/\~}\`${QE:+; \`qemu-user\` emulators for ${QE% }} — so the no-rebuild sanitizer tier is live (\`sanitizers-and-coverage\`)"
      break
    fi
  done
  GINGER_ROWS=""; want ginger && GINGER_ROWS=1
TABLE=$(cat <<TBL
| Fact | Detail |
|---|---|
| **\`command -v\` misses these** — resolve by full path | ${FALLBACK:-none found} |
| **installed but broken** — treat as missing | ${BROKENL:-none} |
| **absent** | ${ABSENTL:-none} |${GINGER_ROWS:+
| Python: system \`python3\` imports | ${SYSL:-?} |
| Python: only in \`${VR/#$HOME/\~}/bin/python3\` | ${VENVL:-?} |
| **runtime UB checking for \`unsafe\` Rust** | ${MIRI_CELL} |}
| **shadowed names** — \`command -v\` answers, but with the *other* implementation | ${SHADOWL:-none among the probed set} |${OBJD_CELL:+
| **capability false positive — \`objdump\` is x86-only here** | ${OBJD_CELL} |}${AFLLIB:+
| **AFL++ \`LD_PRELOAD\` libs** | ${AFLLIB} |}
| Non-standard dirs on PATH *in this shell* — may not be in others, so still check them | ${PATHDIRS:-?} |
TBL
)
  hdr "GINGER.md table"
  echo "$TABLE"

  # --write regenerates the inventory inside the selected agent's own document.
  # With --agent=all there are two candidates and no basis to choose, so it asks.
  case "$AGENT" in
    ginger) GMD="$AGENTS_DIR/GINGER.md" ;;
    alpha)  GMD="$AGENTS_DIR/ALPHA.md" ;;
    *)      GMD="$AGENTS_DIR/GINGER.md"
            [ "$WRITE" = 1 ] && printf "\n  ${Y}--agent not given; writing GINGER.md${N} ${D}— pass --agent=alpha for ALPHA.md${N}\n" ;;
  esac
  B='<!-- BEGIN:tool-inventory -->'; E='<!-- END:tool-inventory -->'
  if [ "$WRITE" = 1 ]; then
    if ! grep -qF "$B" "$GMD" 2>/dev/null; then
      printf "\n  ${R}no markers in %s${N} — add %s / %s around the table first\n" "$GMD" "$B" "$E"; exit 3
    fi
    tmp=$(mktemp)
    awk -v b="$B" -v e="$E" -v tbl="$TABLE" -v ts="$(date -u +%Y-%m-%d)" -v self="$SELF --agent=$AGENT" '
      $0 ~ b {print; print "<!-- regenerated " ts " by " self " --write; edit the script, not this table -->"; print ""; print tbl; skip=1; next}
      $0 ~ e {skip=0}
      !skip {print}
    ' "$GMD" > "$tmp" && mv "$tmp" "$GMD"
    printf "\n  ${G}wrote${N} %s\n" "$GMD"
  else
    printf "\n  ${D}re-run with --write to update %s${N}\n" "$GMD"
  fi
  exit 0
fi

# ---------- PATH sanity ----------
# Everything below installs into these directories. A tool landing in one that
# PATH does not cover is invisible to every later shell -- the per-tool
# "off-PATH" notes in --verify-tools only say so after the fact, and only for
# tools that were probed. Say it once, up front, before anything is written.
hdr "PATH"
for d in "$BIN" "$HOME/.cargo/bin" "$HOME/go/bin" "$GEMBIN" /snap/bin; do
  [ -n "$d" ] && [ -d "$d" ] || continue
  case ":$PATH:" in
    *":$d:"*) ok "${d/#$HOME/\~}" ;;
    *) miss "${d/#$HOME/\~}" "not on PATH — anything installed here stays invisible; add it in ~/.bashrc or ~/.profile" ;;
  esac
done

# ---------- apt ----------

hdr "APT packages"
APT_SEL=( "${APT_CORE[@]}" )
want ginger && APT_SEL+=( "${APT_GINGER[@]}" )
want alpha  && APT_SEL+=( "${APT_MOBILE[@]}" )   # mobile is required for alpha,
                                                 # optional-only for a ginger run
APT_TODO=()
# dpkg alone is not the question -- a tool installed by hand (~/.local/opt, /opt,
# a tarball on PATH) satisfies the requirement just as well as a .deb does, and
# have()/resolve() already walks exactly those trees. Asking dpkg only is the
# same false-"missing" failure the opt_dirs comment above exists to avoid.
# Packages whose binary name differs (upx-ucl, python3-ropgadget, golang-go...)
# just fall through to the dpkg check as before.
for p in "${APT_SEL[@]}"; do
  { have_apt "$p" || have "$p"; } && ok "$p" || { add "$p"; APT_TODO+=("$p"); }
done
if [ "$WITH_OPTIONAL" = 1 ]; then
  OPTSEL=(); want ginger && OPTSEL+=( "${APT_OPT[@]}" )
  want alpha || OPTSEL+=( "${APT_MOBILE[@]}" )   # already in APT_SEL when alpha is selected
  for p in "${OPTSEL[@]}"; do
    { have_apt "$p" || have "$p"; } && ok "$p ${D}(optional)" || { add "$p (optional)"; APT_TODO+=("$p"); }
  done
fi

# One apt-get for the whole list means one unavailable package takes every other
# package down with it ("Unable to locate package X" aborts before installing
# anything). Drop what no configured repo offers, and say so, rather than losing
# the installs that would have worked.
APT_RUN=()
for p in "${APT_TODO[@]}"; do
  # Not "does apt know the name" -- apt prints a stanza for a name it has only
  # ever seen as someone else's dependency. The installable test is a Candidate
  # that is not (none); anything else aborts apt-get before it installs a thing.
  cand=$(apt-cache policy "$p" 2>/dev/null | awk -F': ' '/Candidate:/{print $2; exit}')
  if [ -n "$cand" ] && [ "$cand" != "(none)" ]; then APT_RUN+=("$p")
  else miss "$p" "no installable candidate in the configured repos — install by hand or add the repo"; fi
done

if [ ${#APT_RUN[@]} -gt 0 ]; then
  echo
  # confirm_run rather than a second hand-rolled prompt: it prints the command
  # first and treats a closed stdin as "no", which a bare `read` does not.
  if confirm_run "sudo apt install -y ${APT_RUN[*]}"; then
    sudo apt-get install -y "${APT_RUN[@]}"
  fi
fi

if want ginger; then
# ---------- python: the vr venv ----------
hdr "Python — solver venv ($VR)"
VRPY="$VR/bin/python3"
if [ ! -x "$VRPY" ]; then
  add "create venv"
  run python3 -m venv "$VR" && run "$VR/bin/pip" install -q --upgrade pip
else ok "venv exists"; fi

VR_PKGS=(angr z3-solver claripy lief unicorn capstone pyelftools ropper pwntools)
VR_TODO=()
for m in angr z3 claripy lief unicorn capstone elftools ropper pwn; do
  if [ -x "$VRPY" ] && have_py "$m" "$VRPY"; then ok "$m"; else add "$m"; fi
done
if [ -x "$VRPY" ]; then
  have_py angr "$VRPY" || VR_TODO+=("${VR_PKGS[@]}")
  [ ${#VR_TODO[@]} -gt 0 ] && "$VR/bin/pip" install -q "${VR_TODO[@]}"
fi

hdr "Python — system interpreter"
for m in pwn capstone elftools; do
  have_py "$m" python3 && ok "$m" || miss "python3-$m" "system python is PEP-668 managed; use the venv"
done
fi   # want ginger — solver venv

# ---------- pipx / gem / cargo / go ----------
hdr "pipx"
# pkg|binary: the pipx PACKAGE and the command it installs are not always the
# same name -- frida-tools provides `frida`. Checking have "frida-tools" never
# succeeds, so every run re-ran pipx and got "already seems to be installed".
PIPX_TOOLS=( "frida-tools|frida" )          # frida serves both agents
want ginger && PIPX_TOOLS+=( "semgrep|semgrep" "bandit|bandit" "pip-audit|pip-audit" "uv|uv" )
want alpha  && PIPX_TOOLS+=( "objection|objection" )
for spec in "${PIPX_TOOLS[@]}"; do
  pkg=${spec%%|*}; bin=${spec#*|}
  have "$bin" && ok "$bin" || { add "$bin"; run pipx install "$pkg"; }
done
if [ "$WITH_OPTIONAL" = 1 ]; then
  for t in jefferson ubi_reader; do
    have "$t" && ok "$t ${D}(optional)" || { add "$t (optional, firmware extractors — re-tools)"; run pipx install "$t"; }
  done
  # objection is in PIPX_TOOLS proper when alpha is selected; offer it here for a
  # ginger run that asked for the optional extras anyway.
  want alpha || { have objection && ok "objection ${D}(optional)" || { add "objection (optional, mobile — alpha)"; run pipx install objection; }; }
fi

if want ginger; then
hdr "Ruby gems"
for t in one_gadget seccomp-tools brakeman; do
  have "$t" && ok "$t" || { add "$t"; run gem install --user-install "$t"; }
done

hdr "cargo / go"
if have cargo; then
  for t in weggli pwninit cargo-fuzz cargo-audit; do have "$t" && ok "$t" || { add "$t"; run cargo install "$t"; }; done
else
  for t in weggli pwninit cargo-fuzz cargo-audit; do have "$t" && ok "$t" || miss "$t" "needs rustup (https://rustup.rs)"; done
fi
# osv-scanner is on the /v2 module path (v2.7.0); the v1 path still resolves but
# installs a stale build, so it is pinned to v2 deliberately.
GO_TOOLS=( "gosec|github.com/securego/gosec/v2/cmd/gosec@latest"
           "govulncheck|golang.org/x/vuln/cmd/govulncheck@latest"
           "osv-scanner|github.com/google/osv-scanner/v2/cmd/osv-scanner@latest" )
for spec in "${GO_TOOLS[@]}"; do
  gt=${spec%%|*}; gm=${spec#*|}
  if have "$gt"; then ok "$gt"
  elif have go; then add "$gt"; run go install "$gm"
  else miss "$gt" "needs golang-go"; fi
done

have patchelf && ok patchelf || { add patchelf; run pipx install patchelf; }
fi   # want ginger — gems, cargo, go

if want ginger; then
# ---------- GDB plugins (sourced scripts, never on PATH) ----------
hdr "GDB plugins"
declare -A PLUGINS=(
  [pwndbg]="https://github.com/pwndbg/pwndbg $HOME/pwndbg/gdbinit.py"
  [gef]="https://github.com/hugsy/gef $HOME/gef/gef.py"
  [peda]="https://github.com/longld/peda $HOME/peda/peda.py"
)
for name in pwndbg gef peda; do
  read -r url entry <<<"${PLUGINS[$name]}"
  dir="$HOME/$name"
  if [ ! -d "$dir" ]; then
    add "$name (clone)"
    run git clone -q --depth 1 "$url" "$dir"
    [ "$name" = pwndbg ] && run bash "$dir/setup.sh"
  fi
  # peda vendors six 1.9.0, whose meta-path importer uses find_module — removed in
  # Python 3.12. That breaks `six.moves` and silently kills every peda command.
  if [ "$name" = peda ] && [ -f "$dir/lib/six.py" ]; then
    v=$(grep -m1 '__version__' "$dir/lib/six.py" | grep -oE '[0-9]+\.[0-9]+' | head -1)
    if [ -n "$v" ] && [ "${v%%.*}" -eq 1 ] && [ "${v#*.}" -lt 16 ] 2>/dev/null; then
      add "peda: replacing vendored six $v with system six"
      run cp -n "$dir/lib/six.py" "$dir/lib/six.py.orig-$v.bak"
      run cp /usr/lib/python3/dist-packages/six.py "$dir/lib/six.py"
      run rm -rf "$dir/lib/__pycache__"
    fi
  fi
  if plugin_ok "$entry"; then ok "$name ${D}(gdb -ex 'source $entry')"; else miss "$name" "present but fails to load"; fi
done

# ---------- PATH shims ----------
hdr "PATH shims"
run mkdir -p "$BIN"
for t in seccomp-tools one_gadget brakeman; do
  if [ -n "$GEMBIN" ] && [ -x "$GEMBIN/$t" ] && [ ! -e "$BIN/$t" ]; then
    add "symlink $t into ~/.local/bin"; run ln -sf "$GEMBIN/$t" "$BIN/$t"
  elif have "$t"; then ok "$t on PATH"; fi
done
fi   # want ginger — plugins and shims

# ---------- large / manual installs: detect and instruct, never auto-download ----------
hdr "Manual installs"
if want ginger; then
have afl-fuzz     && ok "AFL++"        || MISSING_MANUAL+=("AFL++|github.com/AFLplusplus/AFLplusplus — make && sudo make install")
have honggfuzz    && ok "honggfuzz"    || MISSING_MANUAL+=("honggfuzz|github.com/google/honggfuzz")
have codeql       && ok "CodeQL"       || MISSING_MANUAL+=("CodeQL|github.com/github/codeql-cli-binaries/releases")
have joern        && ok "joern"        || MISSING_MANUAL+=("joern|joern.io/installation")
have psalm        && ok "psalm"        || MISSING_MANUAL+=("psalm|github.com/vimeo/psalm/blob/master/docs/running_psalm/installation.md — composer or the .phar; needs PHP mbstring")
# libc-database is a git checkout of bash scripts, not a packaged binary, and its
# entry points are named `identify`, `find`, `get`, `add`, `dump` -- names that
# collide with coreutils and ImageMagick on PATH. exploit-dev/SKILL.md therefore
# documents the prefixed `libc-identify` / `libc-get`; those are WRAPPERS created
# here, not anything upstream ships, which is why `have libc-identify` reported
# the tool missing while a populated checkout sat in /opt/tools.
#
# Each script does `cd "$(dirname "$0")"` and then sources common/libc.sh, so a
# symlink from ~/.local/bin breaks it -- $0 would resolve to the link. The wrapper
# execs the absolute path instead, which keeps dirname correct.
#
# Presence is not the question either: an empty db/ means `identify` matches
# nothing, so the tool is installed and useless. Count the symbol sets.
LIBCDB=""
for d in /opt/tools/libc-database /opt/libc-database \
         "$HOME/.local/opt/libc-database" "$HOME/libc-database"; do
  [ -x "$d/identify" ] && { LIBCDB="$d"; break; }
done
if [ -z "$LIBCDB" ]; then
  # /opt/tools is where this box keeps hand-built tooling (honggfuzz, codeql), and
  # it is the first path the discovery loop above looks in -- so name it, or the
  # checkout lands somewhere the next run will not find.
  MISSING_MANUAL+=("libc-database|manual install — put it in /opt/tools (git clone into /opt/tools/libc-database, then ./get debian to populate db/); more info: https://github.com/niklasb/libc-database")
else
  NLIBC=$(find "$LIBCDB/db" -maxdepth 1 -name '*.symbols' 2>/dev/null | wc -l)
  if [ "$NLIBC" -eq 0 ]; then
    miss "libc-database" "$LIBCDB — db/ is EMPTY, so identify matches nothing; run '$LIBCDB/get debian'"
  else
    ok "libc-database ${D}$LIBCDB — $NLIBC libcs indexed${N}"
  fi
  for w in identify get find add dump download; do
    [ -x "$LIBCDB/$w" ] || continue
    [ -x "$BIN/libc-$w" ] && continue
    add "libc-$w wrapper"
    mkdir -p "$BIN"
    printf '#!/bin/sh\n# generated by %s — exec keeps $0 inside the checkout\nexec "%s/%s" "$@"\n' \
      "$SELF" "$LIBCDB" "$w" > "$BIN/libc-$w" && chmod +x "$BIN/libc-$w"
  done
fi
# Tier 3 -- no apt package and no language package manager. grype and trivy have
# vendor-documented install procedures, run below after an explicit confirmation;
# infer is a release download whose steps depend on the platform, so it stays a
# pointer. Both automated paths need sudo, and each is printed before it runs.
# infer has no apt package and no current Linux binary release, so source is the
# only route. Its OCaml toolchain build takes 30-60 min and several GB, which is
# far too costly to fire from a plain --install-deps --yes -- so it is gated on
# --all AS WELL AS a confirmation. Without --all it stays a manual pointer.
#
# Build deps come from docker/master-java/Dockerfile upstream, minus two: this is
# Ubuntu 26.04, where python3-distutils no longer exists (removed with Python
# 3.12) and pkg-config is already provided by pkgconf. Everything else on that
# list is present on this box; only opam is genuinely missing.
INFER_SRC="$HOME/.local/opt/infer"
INFER_DEPS=( opam autoconf automake cmake g++ libgmp-dev libmpfr-dev
             libsqlite3-dev sqlite3 zlib1g-dev patch xz-utils bzip2 )

if have infer; then ok "infer"
elif [ "$WITH_OPTIONAL" != 1 ]; then
  MISSING_MANUAL+=("infer|github.com/facebook/infer/blob/main/INSTALL.md — source build; re-run with --all to build it here (30-60 min)")
else
  add "infer"
  if confirm_run "build infer from source into ${INFER_SRC/#$HOME/~} (30-60 min, several GB, needs opam)"; then
    (
      set -e
      # only the deps that are actually missing, and only ones apt can resolve
      ID=()
      for d in "${INFER_DEPS[@]}"; do
        have_apt "$d" && continue
        c=$(apt-cache policy "$d" 2>/dev/null | awk -F': ' '/Candidate:/{print $2; exit}')
        [ -n "$c" ] && [ "$c" != "(none)" ] && ID+=("$d")
      done
      [ ${#ID[@]} -gt 0 ] && sudo apt-get install -y "${ID[@]}"
      # a JDK is required for the `java` target; default-jdk-headless satisfies it
      have javac || sudo apt-get install -y default-jdk-headless

      if [ -d "$INFER_SRC/.git" ]; then git -C "$INFER_SRC" pull --ff-only
      else mkdir -p "$(dirname "$INFER_SRC")"; git clone --depth 1 https://github.com/facebook/infer.git "$INFER_SRC"; fi

      # OPAMYES keeps opam from prompting part-way through a long unattended build
      ( cd "$INFER_SRC" && OPAMYES=1 ./build-infer.sh java )

      # Match this machine's existing convention for hand-built tools (jadx,
      # rizin): leave the tree in ~/.local/opt and symlink the entry point, so
      # no sudo make install is needed and opt_dirs() can discover it either way.
      mkdir -p "$BIN" && ln -sf "$INFER_SRC/infer/bin/infer" "$BIN/infer"
    ) && ok "infer ${D}$BIN/infer${N}" \
      || miss "infer" "source build failed — see $INFER_SRC and github.com/facebook/infer/blob/main/INSTALL.md"
  else
    MISSING_MANUAL+=("infer|github.com/facebook/infer/blob/main/INSTALL.md — git clone, ./build-infer.sh java, sudo make install")
  fi
fi

hdr "Third-party installers"
if have grype; then ok "grype"
else
  add "grype"
  # Upstream's documented one-liner. It pipes a remote script into `sudo sh`, so
  # it is shown in full and gated on a yes rather than run silently.
  if confirm_run 'curl -sSfL https://get.anchore.io/grype | sudo sh -s -- -b /usr/local/bin'; then
    curl -sSfL https://get.anchore.io/grype | sudo sh -s -- -b /usr/local/bin \
      || miss "grype" "installer failed — see github.com/anchore/grype"
  else
    MISSING_MANUAL+=("grype|curl -sSfL https://get.anchore.io/grype | sudo sh -s -- -b /usr/local/bin")
  fi
fi

if have trivy; then ok "trivy"
else
  add "trivy"
  # Aqua's apt repository. NOTE: this adds a third-party repo and its signing key
  # to the system, which then participates in every later `apt update`.
  if confirm_run 'add the Aqua apt repo (/etc/apt/sources.list.d/trivy.list) and install trivy'; then
    (
      set -e
      sudo apt-get install -y wget gnupg
      wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key \
        | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg >/dev/null
      echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" \
        | sudo tee /etc/apt/sources.list.d/trivy.list >/dev/null
      sudo apt-get update
      sudo apt-get install -y trivy
    ) || miss "trivy" "repo setup failed — see github.com/aquasecurity/trivy"
  else
    MISSING_MANUAL+=("trivy|aquasecurity.github.io/trivy-repo — add the deb repo, then apt install trivy")
  fi
fi
BN=$(resolve binaryninja) \
  && ok "Binary Ninja $("$BN" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+[.0-9]*( [A-Za-z]+)?' | head -1) ${D}(default RE tool — $BN)${N}" \
  || MISSING_MANUAL+=("Binary Ninja|binary.ninja — default RE tool; enable the built-in UI MCP server for mcp__binaryninja__bn_* tools")
# Ghidra: located by finding analyzeHeadless under the discovered opt dirs, at
# whatever depth it sits, and reporting the NEWEST — two versions side by side
# (a system one and a vendor bundle) is the normal case, and the old glob picked
# whichever sorted first rather than the one you would actually want to run.
GHIDRA_DIR=$(opt_dirs | while IFS= read -r d; do
    [ -f "$d/analyzeHeadless" ] && [ -x "$d/analyzeHeadless" ] && dirname "$d"
  done | sort -V | tail -1)
if [ -n "$GHIDRA_DIR" ]; then
  ok "Ghidra $(basename "$GHIDRA_DIR" | grep -oE '[0-9]+\.[0-9.]+' | head -1) ${D}(secondary — $GHIDRA_DIR)${N}"
else
  MISSING_MANUAL+=("Ghidra|ghidra-sre.org — secondary RE tool; plus the GhidraMCP plugin for mcp__ghidra__* tools")
fi
if [ "$WITH_OPTIONAL" = 1 ]; then
  have pycdc          && ok "pycdc"          || MISSING_MANUAL+=("pycdc (optional)|github.com/zrax/pycdc — .pyc decompiler; python -m dis is the fallback")
  have sasquatch      && ok "sasquatch"      || MISSING_MANUAL+=("sasquatch (optional)|github.com/devttys0/sasquatch — vendor-modified SquashFS")
  have payload_dumper && ok "payload_dumper" || MISSING_MANUAL+=("payload_dumper (optional)|github.com/vm03/payload_dumper — Android OTA payload.bin extraction")
  have gn             && ok "depot_tools"    || MISSING_MANUAL+=("depot_tools (optional)|chromium.googlesource.com/chromium/tools/depot_tools — to build d8")
fi
fi   # want ginger — manual + third-party installers

if want alpha; then
  # Gadget-chain generators: neither is packaged anywhere, and both are a download
  # rather than a build. deserialization-insecure invokes them by name.
  have phpggc     && ok "phpggc"     || MISSING_MANUAL+=("phpggc|github.com/ambionics/phpggc — PHP gadget chains (deserialization-insecure)")
  have ysoserial  && ok "ysoserial"  || MISSING_MANUAL+=("ysoserial|github.com/frohoff/ysoserial/releases — Java gadget chains; the docs write it ysoserial.exe, on Linux it is 'java -jar ysoserial.jar' (deserialization-insecure)")
  # The device tier is apt/pipx only; what cannot be packaged is the device.
  have adb || MISSING_MANUAL+=("android platform-tools|sudo apt install adb — or Android Studio's SDK Platform-Tools")
  have frida && ok "frida ${D}(host side; frida-server must be pushed to the device)${N}" \
             || MISSING_MANUAL+=("frida-server|github.com/frida/frida/releases — matching the host frida version, pushed to the device")
fi

for e in "${MISSING_MANUAL[@]}"; do miss "${e%%|*}" "${e#*|}"; done

# ---------- report ----------
hdr "Summary"
if want ginger; then
printf "  Binary Ninja MCP ${D}(default)${N}: "
if curl -s -m 3 -o /dev/null -X POST http://127.0.0.1:24642/mcp \
     -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
     -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"ginger-setup","version":"1"}}}' 2>/dev/null
then printf "${G}listening on :24642${N}\n"
else printf "${Y}not running${N} ${D}— start the Binary Ninja GUI with the built-in MCP server enabled${N}\n"; fi

printf "  GhidraMCP bridge ${D}(secondary)${N}: "
# /check_connection, not / -- the plugin answers 404 on /, and curl exits 0 on a
# 404, so the old probe also passed for any unrelated service holding the port.
# The status field proves it is actually GhidraMCP and reports its version.
if GC=$(curl -s -m 3 http://127.0.0.1:8089/check_connection 2>/dev/null) \
   && printf '%s' "$GC" | grep -q '"status":"ok"'; then
  printf "${G}listening on :8089${N} ${D}(%s)${N}\n" "$(printf '%s' "$GC" | grep -oE '"version":"[^"]+"' | cut -d'"' -f4)"
else printf "${Y}not running${N} ${D}— start Ghidra with the GhidraMCP plugin${N}\n"; fi
fi   # want ginger — RE backends

if want ginger; then cat <<EOF

  ${D}Solver scripts:${N}  $VRPY script.py   ${D}(angr/z3 are not on system python3)${N}
  ${D}Debugger:${N}        gdb -ex 'source ~/pwndbg/gdbinit.py' ./target
EOF
fi
if want alpha; then cat <<EOF

  ${D}Device:${N}          adb devices   ${D}|${N}   frida-ps -U
  ${D}Instrument:${N}      objection -g <package> explore
EOF
fi
cat <<EOF

  ${D}Re-audit:${N}        ./$SELF --agent=$AGENT --verify-tools
EOF
[ ${#MISSING_MANUAL[@]} -gt 0 ] && printf "\n  ${Y}%d item(s) need a manual install — see above.${N}\n" "${#MISSING_MANUAL[@]}"
exit 0

