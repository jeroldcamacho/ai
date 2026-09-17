#!/usr/bin/env bash
# ginger-setup.sh — prerequisite installer and auditor for the GINGER agent
#
#   ./ginger-setup.sh                    install everything required, skip what works
#   ./ginger-setup.sh --check            audit only, change nothing
#   ./ginger-setup.sh --all              also install the optional per-workflow extras
#   ./ginger-setup.sh --yes              don't prompt before apt
#   ./ginger-setup.sh --verify-tools     print the GINGER.md tool-inventory table
#   ./ginger-setup.sh --verify-tools --write   regenerate that table in GINGER.md
#
# Detection deliberately does NOT rely on `command -v` alone. GDB plugins are
# sourced scripts that never appear on PATH, Ruby gem binaries live outside it,
# and venv modules are invisible to the system interpreter — all three produce
# false "missing" results. Everything here is verified by executing it.

set -uo pipefail

VR="$HOME/.local/venvs/vr"          # angr/z3/lief live here; system python is PEP-668 managed
BIN="$HOME/.local/bin"
GEMBIN=$(echo "$HOME"/.local/share/gem/ruby/*/bin 2>/dev/null | awk '{print $1}')

MODE=install; WITH_OPTIONAL=0; ASSUME_YES=0; WRITE=0
for a in "$@"; do case "$a" in
  --check) MODE=check ;;
  --all)   WITH_OPTIONAL=1 ;;
  --yes|-y) ASSUME_YES=1 ;;
  --verify-tools) MODE=verify ;;
  --write) WRITE=1 ;;
  --help|-h) sed -n '2,18p' "$0"; exit 0 ;;
  *) echo "unknown option: $a (try --help)"; exit 2 ;;
esac; done

R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; B=$'\e[1m'; D=$'\e[2m'; N=$'\e[0m'
ok(){ printf "  ${G}ok${N}      %s\n" "$1"; }
add(){ printf "  ${Y}install${N} %s\n" "$1"; }
miss(){ printf "  ${R}manual${N}  %s${D} — %s${N}\n" "$1" "$2"; }
hdr(){ printf "\n${B}%s${N}\n" "$1"; }

MISSING_MANUAL=()

# ---------- detection ----------
have(){                                   # binary, anywhere it could plausibly live
  command -v "$1" >/dev/null 2>&1 && return 0
  local d; for d in /usr/bin /usr/local/bin "$BIN" "$HOME/go/bin" "$HOME/.cargo/bin" "$VR/bin" "$GEMBIN"; do
    [ -n "$d" ] && [ -x "$d/$1" ] && return 0
  done
  return 1
}
have_py(){ "${2:-python3}" -c "import $1" >/dev/null 2>&1; }   # module, interpreter
have_apt(){ dpkg -s "$1" >/dev/null 2>&1; }
plugin_ok(){                              # gdb plugin: present AND sources without error
  [ -f "$1" ] || return 1
  ! timeout 90 gdb -nx -batch -ex "source $1" 2>&1 | grep -q 'ModuleNotFoundError\|Traceback'
}

run(){ [ "$MODE" = check ] && return 0; "$@"; }

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
    for d in "$BIN" "$HOME/go/bin" "$HOME/.cargo/bin" "$VR/bin" "$GEMBIN" /usr/local/bin \
             /opt /opt/*/ /opt/*/bin "$HOME/.local/opt" "$HOME/.local/opt"/*/ ; do
      [ -n "$d" ] && [ -x "${d%/}/$cand" ] && { printf '%s' "${d%/}/$cand"; return 0; }
    done
  done
  return 1
}

runs(){                                   # executes without a load/link/import failure?
  local p=$1; shift
  local err rc
  err=$(timeout 30 "$p" "$@" 2>&1 >/dev/null); rc=$?
  case $rc in 126|127) return 1 ;; esac    # not executable / missing loader
  grep -qiE 'error while loading shared librar|cannot open shared object|ModuleNotFoundError|GLIBC_[0-9.]+ .*not found|undefined function|Uncaught Error' <<<"$err" && return 1
  return 0
}

remedy(){                                 # known root cause -> the fix
  case "$1" in
    psalm) echo "needs PHP mbstring: sudo apt install php8.4-mbstring" ;;
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
      ( cd "$d" && timeout 120 "$p" --no-cache --no-progress >/dev/null 2>"$d/e" ); rc=$?
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
  "codeql|--version|$HOME/codeql/codeql/codeql"
  "rustup|--version|$HOME/.cargo/bin/rustup"
  "psalm|--version|$HOME/.local/opt/psalm/psalm.phar"
  # notable absences worth asserting rather than assuming
  "valgrind|--version|"      "cargo-fuzz|--version|"   "cargo-audit|--version|"
  "pip-audit|--version|"     "grype|version|"
  "dwarfdump|--version|"     "fd|--version|"           "trivy|--version|"
  # honggfuzz ships its instrumenting compiler wrappers separately from the fuzzer
  # binary, and they land in the source tree rather than on PATH. Without them you
  # get ptrace-only feedback, which is a much weaker campaign — so probe them.
  "hfuzz-clang|--version|/opt/honggfuzz/hfuzz_cc/hfuzz-clang"
  "hfuzz-clang++|--version|/opt/honggfuzz/hfuzz_cc/hfuzz-clang++"
  "hfuzz-gcc|--version|/opt/honggfuzz/hfuzz_cc/hfuzz-gcc"
)

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

  hdr "Python modules"
  PYROWS=()
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
      if timeout 120 "$HOME/.cargo/bin/cargo" "+$mtc" miri --version >/dev/null 2>&1; then
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
      SHADOWL="$SHADOWL \`$n\` → \`$onpath\` shadows \`$d/$n\` ·"
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
        if [ -n "$note" ]; then FALLBACK="$FALLBACK \`$nm\` → \`${pth/#$HOME/~}\` ·"
        else
          d=$(dirname "$pth")
          case "$d" in /usr/bin|/usr/local/bin|/bin|/usr/sbin|/sbin) ;;
            *) case " $PATHDIRS " in *" ${d/#$HOME/~} "*) ;; *) PATHDIRS="$PATHDIRS ${d/#$HOME/~}" ;; esac ;;
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
  TABLE=$(cat <<TBL
| Fact | Detail |
|---|---|
| **\`command -v\` misses these** — resolve by full path | ${FALLBACK:-none found} |
| **installed but broken** — treat as missing | ${BROKENL:-none} |
| **absent** | ${ABSENTL:-none} |
| Python: system \`python3\` imports | ${SYSL:-—} |
| Python: only in \`${VR/#$HOME/~}/bin/python3\` | ${VENVL:-—} |
| **runtime UB checking for \`unsafe\` Rust** | ${MIRI_CELL} |
| **shadowed names** — \`command -v\` answers, but with the *other* implementation | ${SHADOWL:-none among the probed set} |
| Non-standard dirs on PATH *in this shell* — may not be in others, so still check them | ${PATHDIRS:-—} |
TBL
)
  hdr "GINGER.md table"
  echo "$TABLE"

  GMD="$(dirname "$(readlink -f "$0")")/GINGER.md"
  B='<!-- BEGIN:tool-inventory -->'; E='<!-- END:tool-inventory -->'
  if [ "$WRITE" = 1 ]; then
    if ! grep -qF "$B" "$GMD" 2>/dev/null; then
      printf "\n  ${R}no markers in %s${N} — add %s / %s around the table first\n" "$GMD" "$B" "$E"; exit 3
    fi
    tmp=$(mktemp)
    awk -v b="$B" -v e="$E" -v tbl="$TABLE" -v ts="$(date -u +%Y-%m-%d)" '
      $0 ~ b {print; print "<!-- regenerated " ts " by ginger-setup.sh --verify-tools; edit the script, not this table -->"; print ""; print tbl; skip=1; next}
      $0 ~ e {skip=0}
      !skip {print}
    ' "$GMD" > "$tmp" && mv "$tmp" "$GMD"
    printf "\n  ${G}wrote${N} %s\n" "$GMD"
  else
    printf "\n  ${D}re-run with --write to update %s${N}\n" "$GMD"
  fi
  exit 0
fi

# ---------- apt ----------
APT_REQ=(
  file checksec rizin radare2 binutils xxd binwalk squashfs-tools upx-ucl
  gdb lldb strace ltrace cpio qemu-system-x86 qemu-user-static
  clang cppcheck bear gh jq socat nmap 7zip unzip sqlite3
  python3-ropgadget python3-six jadx apktool libsmali-java
  build-essential git curl python3-pip python3-venv pipx ruby golang-go
)
APT_OPT=( wabt android-sdk-libsparse-utils ncat metasploit-framework sqlmap masscan )

hdr "APT packages"
APT_TODO=()
for p in "${APT_REQ[@]}"; do have_apt "$p" && ok "$p" || { add "$p"; APT_TODO+=("$p"); }; done
if [ "$WITH_OPTIONAL" = 1 ]; then
  for p in "${APT_OPT[@]}"; do have_apt "$p" && ok "$p ${D}(optional)" || { add "$p (optional)"; APT_TODO+=("$p"); }; done
fi

if [ ${#APT_TODO[@]} -gt 0 ] && [ "$MODE" != check ]; then
  echo
  echo "  ${B}sudo apt install -y ${APT_TODO[*]}${N}"
  if [ "$ASSUME_YES" = 1 ]; then
    sudo apt-get install -y "${APT_TODO[@]}"
  else
    read -rp "  run this now? [y/N] " r; [[ "$r" =~ ^[Yy] ]] && sudo apt-get install -y "${APT_TODO[@]}"
  fi
fi

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
if [ "$MODE" != check ] && [ -x "$VRPY" ]; then
  have_py angr "$VRPY" || VR_TODO+=("${VR_PKGS[@]}")
  [ ${#VR_TODO[@]} -gt 0 ] && "$VR/bin/pip" install -q "${VR_TODO[@]}"
fi

hdr "Python — system interpreter"
for m in pwn capstone elftools; do
  have_py "$m" python3 && ok "$m" || miss "python3-$m" "system python is PEP-668 managed; use the venv"
done

# ---------- pipx / gem / cargo / go ----------
hdr "pipx"
for t in semgrep bandit; do
  have "$t" && ok "$t" || { add "$t"; run pipx install "$t"; }
done
if [ "$WITH_OPTIONAL" = 1 ]; then
  for t in jefferson ubi_reader; do
    have "$t" && ok "$t ${D}(optional)" || { add "$t (optional, firmware extractors — re-tools)"; run pipx install "$t"; }
  done
fi

hdr "Ruby gems"
for t in one_gadget seccomp-tools brakeman; do
  have "$t" && ok "$t" || { add "$t"; run gem install --user-install "$t"; }
done

hdr "cargo / go"
if have cargo; then
  for t in weggli pwninit; do have "$t" && ok "$t" || { add "$t"; run cargo install "$t"; }; done
else
  for t in weggli pwninit; do have "$t" && ok "$t" || miss "$t" "needs rustup (https://rustup.rs)"; done
fi
if have go; then
  have gosec && ok gosec || { add gosec; run go install github.com/securego/gosec/v2/cmd/gosec@latest; }
else have gosec && ok gosec || miss gosec "needs golang-go"; fi

have patchelf && ok patchelf || { add patchelf; run pipx install patchelf; }

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
    [ "$name" = pwndbg ] && [ "$MODE" != check ] && run bash "$dir/setup.sh"
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

# ---------- large / manual installs: detect and instruct, never auto-download ----------
hdr "Manual installs"
have afl-fuzz     && ok "AFL++"        || MISSING_MANUAL+=("AFL++|github.com/AFLplusplus/AFLplusplus — make && sudo make install")
have honggfuzz    && ok "honggfuzz"    || MISSING_MANUAL+=("honggfuzz|github.com/google/honggfuzz")
have codeql       && ok "CodeQL"       || MISSING_MANUAL+=("CodeQL|github.com/github/codeql-cli-binaries/releases")
have joern        && ok "joern"        || MISSING_MANUAL+=("joern|joern.io/installation")
have psalm        && ok "psalm"        || MISSING_MANUAL+=("psalm|composer global require vimeo/psalm")
have libc-identify && ok "libc-database" || MISSING_MANUAL+=("libc-database|github.com/niklasb/libc-database")
ls -d /opt/ghidra*/support/analyzeHeadless >/dev/null 2>&1 \
  && ok "Ghidra $(ls -d /opt/ghidra_* 2>/dev/null | head -1 | grep -oE '[0-9.]+' | head -1)" \
  || MISSING_MANUAL+=("Ghidra|ghidra-sre.org — plus the GhidraMCP plugin for mcp__ghidra__* tools")
if [ "$WITH_OPTIONAL" = 1 ]; then
  have pycdc          && ok "pycdc"          || MISSING_MANUAL+=("pycdc (optional)|github.com/zrax/pycdc — .pyc decompiler; python -m dis is the fallback")
  have sasquatch      && ok "sasquatch"      || MISSING_MANUAL+=("sasquatch (optional)|github.com/devttys0/sasquatch — vendor-modified SquashFS")
  have payload_dumper && ok "payload_dumper" || MISSING_MANUAL+=("payload_dumper (optional)|github.com/vm03/payload_dumper — Android OTA payload.bin extraction")
  have gn             && ok "depot_tools"    || MISSING_MANUAL+=("depot_tools (optional)|chromium.googlesource.com/chromium/tools/depot_tools — to build d8")
fi
for e in "${MISSING_MANUAL[@]}"; do miss "${e%%|*}" "${e#*|}"; done

# ---------- report ----------
hdr "Summary"
printf "  GhidraMCP bridge: "
if curl -s -m 3 -o /dev/null http://127.0.0.1:8089/ 2>/dev/null; then printf "${G}listening on :8089${N}\n"
else printf "${Y}not running${N} ${D}— start Ghidra with the GhidraMCP plugin${N}\n"; fi

cat <<EOF

  ${D}Solver scripts:${N}  $VRPY script.py   ${D}(angr/z3 are not on system python3)${N}
  ${D}Debugger:${N}        gdb -ex 'source ~/pwndbg/gdbinit.py' ./target
  ${D}Re-audit:${N}        $0 --check
EOF
[ ${#MISSING_MANUAL[@]} -gt 0 ] && printf "\n  ${Y}%d item(s) need a manual install — see above.${N}\n" "${#MISSING_MANUAL[@]}"
exit 0
