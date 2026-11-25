#!/usr/bin/env bash
# Single source of truth for starting a clone in an ad-hoc test.
#
# Written because the same three harness mistakes kept producing FALSE failures that looked
# like tool bugs:
#   1. `pkill -f <pattern>` also matches the script doing the killing, so it killed its own
#      shell (exit 143/144). Here: kill by PID, never by pattern.
#   2. Most clones read stdin/stdout and need server.py in front; canaryfork32 binds and
#      forks ITSELF and must be given the port directly. Wrapping it made it print
#      "bind: Address already in use", which reads exactly like a broken exploit.
#      Here: decided from the binary's own imports (bind/listen in the PLT).
#   3. Reusing a port number while an old server lingered. Here: the OS picks the port.
#
# selftest.sh keeps its own launcher on purpose - it is green and encodes per-row details,
# so this helper deliberately does not touch it.
#
# And test through solve.py, which DERIVES offset/addresses/send-mode/timing from the
# binary and the service. Calling auto_pwn.py with hand-typed flags means inventing the
# parameters, and inventing them wrongly produces another failure that looks like a tool
# bug: canaryfork32 needs offset 80 with raw mode and a 0.05s idle, and guessing 76 with
# defaults makes the canary brute "find" 0x00000000. If a clone already has a selftest.sh
# row, that row is the authority - do not re-derive its flags here.
#
# RUN TIMING-SENSITIVE CLONES ALONE. canaryfork32 recovers the canary byte-by-byte by
# inferring whether the child survived, which is a timing judgement. In a 6-way parallel
# batch it failed at 192s; run on its own it passes in 22s at the SAME budget. A parallel
# batch is fine for ordinary clones and wrong for brute-force oracles.
#
# Usage:  source launch.sh
#         read -r PID PORT <<< "$(tb_launch combo64)"
#         ...                      # test against 127.0.0.1:$PORT
#         tb_stop "$PID"

tb_here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

tb_freeport() {
    python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'
}

tb_selfserving() {   # does this binary run its own listener?
    python3 - "$1" <<'PY'
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(sys.argv[1])) + "/..")
try:
    from elftool import ELF
    plt = ELF(sys.argv[1]).report().get("plt") or {}
    sys.exit(0 if ("bind" in plt or "listen" in plt) else 1)
except Exception:
    sys.exit(1)
PY
}

tb_waitport() {      # wait until something accepts, or fail
    local port=$1
    for _ in $(seq 1 80); do
        python3 -c "import socket,sys
s=socket.socket(); s.settimeout(0.2)
sys.exit(0 if s.connect_ex(('127.0.0.1',$port))==0 else 1)" 2>/dev/null && return 0
        sleep 0.1
    done
    return 1
}

tb_launch() {        # echoes "<pid> <port>"; empty on failure
    local name=$1 port pid
    local bin="$tb_here/$name"
    [ -x "$bin" ] || { echo "" ; return 1; }
    port=$(tb_freeport)
    # `exec` makes the subshell BECOME the server, so $! is the server's own pid. The
    # earlier version wrote the pid to /tmp/tb_pid.$$ - but $$ is the calling shell, which
    # is identical for every parallel tb_launch, so concurrent launches clobbered each
    # other's file and two tests failed at 0s with "No such file or directory".
    if tb_selfserving "$bin"; then
        ( cd "$tb_here" && exec "./$name" "$port" >/dev/null 2>&1 ) &
    else
        ( cd "$tb_here" && exec python3 server.py "$bin" --port "$port" --cwd "$tb_here" >/dev/null 2>&1 ) &
    fi
    pid=$!
    if tb_waitport "$port"; then echo "$pid $port"; else kill "$pid" 2>/dev/null; echo ""; return 1; fi
}

tb_stop() {          # by PID only
    [ -n "$1" ] || return 0
    kill "$1" 2>/dev/null
    wait "$1" 2>/dev/null
    return 0
}
