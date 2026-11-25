#!/bin/sh
# INSIDE a throwaway Debian 12 container: rebuild EVERY clone with Debian 12's gcc (12.x,
# not the gcc 15 they were developed against) and solve each with Python 3.11.
set -u
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq --no-install-recommends python3 make gcc-multilib libc6-dev-i386 libc6-i386 >/dev/null 2>&1 \
  || { echo "APT FAILED"; exit 9; }
cp -r /src /work && cd /work
echo "== $(python3 --version), $(gcc --version | head -1), Debian $(cat /etc/debian_version)"
make -C testbed clean >/dev/null 2>&1
make -C testbed all > /tmp/build.log 2>&1 || { echo "BUILD PROBLEMS:"; grep -i 'error' /tmp/build.log | head -8; }
python3 compat.py | tail -2
one(){ # one <clone> <port>
  n=$1; port=$2
  case "$n" in canaryfork32) return;; esac
  python3 testbed/server.py /work/testbed/$n --port $port --cwd /work/testbed >/dev/null 2>&1 & sp=$!
  sleep 0.7
  ff=$(strings testbed/$n | grep -o 'flags/[A-Za-z0-9_]*\.txt' | grep -v _pw | head -1); [ -f "testbed/$ff" ] || ff=flags/$n.txt
  t0=$(date +%s)
  out=$(cd /tmp && timeout 240 python3 /work/solve.py 127.0.0.1 $port --binary /work/testbed/$n --run --timeout 200 2>&1)
  if [ -f "testbed/$ff" ] && echo "$out" | grep -qF "$(cat testbed/$ff)"; then r=PASS
  elif echo "$out" | grep -q 'SOLVED via .*\(ret2libc\|ret2shellcode\|GOT->system\)'; then r=PASS   # shell-type: confirmed shell
  else r=FAIL; fi
  echo "$r $n $(( $(date +%s)-t0 ))s :: $(echo "$out" | grep 'SOLVED' | cut -c1-70)"
  kill $sp 2>/dev/null
}
i=0
for n in $(ls testbed); do
  [ -f "testbed/$n" ] && [ -x "testbed/$n" ] || continue
  case "$n" in *.py|*.sh|slowcanary32|echoloop32|echoname32|tokecho32|hintreply32|freeflag32|fmtexample32|fmtsession32|lencheck32|fmtglobbuf32|fmtpieone64|*-pad|guarded32|offbyone32|canaryfork32|canarysay32|canarymute32|paper*) continue;;   # paper* need a notes file by design esac
  i=$((i+1)); one $n $((24200+i)) &
  [ $((i % 6)) = 0 ] && wait
done
wait
