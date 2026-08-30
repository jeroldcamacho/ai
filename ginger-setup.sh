#!/usr/bin/env bash
# ginger-setup.sh — prerequisite installer and auditor for the GINGER agent
#
#   ./ginger-setup.sh            install everything required, skip what works
#   ./ginger-setup.sh --check    audit only, change nothing
#   ./ginger-setup.sh --all      also install the optional per-workflow extras
#   ./ginger-setup.sh --yes      don't prompt before apt
#
# Detection deliberately does NOT rely on `command -v` alone. GDB plugins are
# sourced scripts that never appear on PATH, Ruby gem binaries live outside it,
# and venv modules are invisible to the system interpreter — all three produce
# false "missing" results. Everything here is verified by executing it.

set -uo pipefail

VR="$HOME/.local/venvs/vr"          # angr/z3/lief live here; system python is PEP-668 managed
BIN="$HOME/.local/bin"
GEMBIN=$(echo "$HOME"/.local/share/gem/ruby/*/bin 2>/dev/null | awk '{print $1}')

MODE=install; WITH_OPTIONAL=0; ASSUME_YES=0
for a in "$@"; do case "$a" in
  --check) MODE=check ;;
  --all)   WITH_OPTIONAL=1 ;;
  --yes|-y) ASSUME_YES=1 ;;
  --help|-h) sed -n '2,14p' "$0"; exit 0 ;;
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
