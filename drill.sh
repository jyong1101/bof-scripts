#!/usr/bin/env bash
# drill.sh - practise on a clone WITHOUT being told which one it is.
#
# The toolkit is verified; what is not verified is you driving it under time pressure.
# This picks a random clone, serves it on a random port, and tells you nothing else -
# exactly the position you are in when the professor hands you a host and a port.
#
#   bash drill.sh            one random challenge
#   bash drill.sh 3          three in a row
#   bash drill.sh 1 hard     only the awkward ones (gates, menus, logins, rate limits)
#
# It prints the port, waits for you, and reveals the answer when you press Enter.
set -u
cd "$(dirname "$0")"
source testbed/launch.sh

ROUNDS=${1:-1}
MODE=${2:-any}

EASY=(winarg64 twoarg64 strarg64 var64 varsrc fnptr32 strncpy32 blind32 cyclic32
      pie32 pie64 canary32 align64 twoarg32 strcpy32 fixedread32 decoywin32 randbanner32
      fmtwrite32 relro32 got32 scanf32 scanfshell32 tworead32 alarm32
      fmtsecret32 fmtsecret64 fmtglobal32 fmtglobal64 fmtsmall32 fmttarget64 fmtnonzero32
      fmtnonzero64 fmtgotwin32 fmtgotwin64 adjchar32 adjbool32 adjbool64 adjone32
      varpair32 adjmem32 adjcmd32 shellwin32 shellwin64 bufleak32 bufleak64)
HARD=(gated32 gatedcanary32 gatedpie32 gatedshell32 gatedecho32 menu32 menucanary32
      menufmt32 menulibc32 login32 loginread32 logincanary32 slowcanary32 combo64
      filtered32 toupper32 pieblind32 ret2libc32 libc64 chatty_echo
      fmtcanary32 fmtcanary64 fmtpie32 fmtpie64 fmtboth64 fmtprefix32 fmtshort32 bufsmall32
      fmtguess32 fmtguess64 fmtpass32 fmtgotshell32 varscanf32 varstrcpy32)
# locone64 / locstr32 are easy once seen; they live in EASY via the line below.
EASY+=(locone64 locstr32 decoyfmt32 decoytaunt32)
HARD+=(randguard32 randguard64 randarg32 gatedfmt32 hexwin32 revwin32 fmtloop32 tight64 smalldec32 loginfmt32 randarg2_32 randarg64 fmtrandlocal32)

case "$MODE" in
  hard) POOL=("${HARD[@]}") ;;
  easy) POOL=("${EASY[@]}") ;;
  *)    POOL=("${EASY[@]}" "${HARD[@]}") ;;
esac

for r in $(seq 1 "$ROUNDS"); do
    pick=${POOL[$((RANDOM % ${#POOL[@]}))]}
    [ -x "testbed/$pick" ] || { echo "[!] $pick is not built; run: make -C testbed"; continue; }
    # Serve it from a directory that holds ONLY this target's own flag. The testbed's
    # flags/ is shared by a hundred clones, so any exploit that ends in a shell and runs
    # `cat flag* flags/*` printed all of them - nothing like the exam, where there is one.
    ddir=$(mktemp -d /tmp/drill_dir_XXXXXX); mkdir -p "$ddir/flags"
    needs=$(strings "testbed/$pick" | grep -o 'flags/[A-Za-z0-9_]*\.txt' | sort -u)
    [ -n "$needs" ] || needs="flags/$pick.txt"
    for f in $needs; do cp "testbed/$f" "$ddir/$f" 2>/dev/null; done
    # A clone that ends in a shell names no flag file in its binary, and the older ones
    # are not named after their clone (ret2libc32 -> flags/libc.txt). Without a file
    # there would be nothing to find at all, so those keep the shared directory.
    if [ -z "$(ls "$ddir/flags" 2>/dev/null)" ]; then cp testbed/flags/*.txt "$ddir/flags/" 2>/dev/null; shared=1; else shared=0; fi
    own=$(for f in $needs; do case $f in *_pw.txt) ;; *) cat "testbed/$f" 2>/dev/null;; esac; done | head -1)
    port=$(tb_freeport)
    ( exec python3 testbed/server.py "$PWD/testbed/$pick" --port "$port" --cwd "$ddir" >/dev/null 2>&1 ) &
    pid=$!
    if ! tb_waitport "$port"; then echo "[!] could not start $pick"; kill "$pid" 2>/dev/null; rm -rf "$ddir"; continue; fi

    echo
    echo "=============================================================="
    echo " DRILL $r of $ROUNDS"
    echo " target : 127.0.0.1 $port"
    echo " binary : testbed/UNKNOWN  (copied below so you cannot peek at the name)"
    cp "testbed/$pick" "/tmp/drill_target_$port" 2>/dev/null
    echo "          /tmp/drill_target_$port"
    echo
    echo " You get what the exam gives you: a host, a port, and a binary."
    echo " Start with:  bash smoke.sh        (are my tools alive?)"
    echo " Then     :  python3 solve.py 127.0.0.1 $port --binary /tmp/drill_target_$port"
    echo " If that refuses, read WHY and pick the matching RUNBOOK.md row."
    echo "=============================================================="
    start=$(date +%s)
    printf "\n[press Enter when you have the flag, or to give up] "
    read -r _ || true
    took=$(( $(date +%s) - start ))

    echo
    echo "  it was: $pick        (your time: ${took}s)"
    if [ "$shared" = 1 ]; then echo "  its flag: one of flags/*.txt (this clone ends in a shell; see its source header)"
    else echo "  its flag: ${own:-?}"; fi
    head -12 "testbed/src/$pick.c" 2>/dev/null | sed -n '2,12p' | sed 's|^ \*||' | sed 's/^/    /'
    echo "  reference solve:"
    echo "    python3 solve.py 127.0.0.1 PORT --binary testbed/$pick --run"
    tb_stop "$pid"
    rm -f "/tmp/drill_target_$port"; rm -rf "$ddir"
done
echo
echo "Done. Anything that took over ~5 minutes is worth a second look in RUNBOOK.md."
