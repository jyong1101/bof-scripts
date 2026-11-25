"""Can junk pass as a flag? Realistic junk: what a format-string leak or a crashed service prints."""
import os, random, sys, time
sys.path.insert(0, ".")
import flags
random.seed(20261123)
def addr(bits):
    k = random.random()
    if bits == 64:
        return (random.choice((0x7ffc, 0x7ffd, 0x7ffe, 0x7fff)) << 32 | random.getrandbits(32)) if k < .4 else \
               (random.choice((0x55, 0x56)) << 40 | random.getrandbits(40)) if k < .7 else \
               (0x7f << 40 | random.getrandbits(40)) if k < .85 else random.getrandbits(random.choice((8, 16, 32)))
    return (0xff << 24 | random.getrandbits(24)) if k < .4 else (0xf7 << 24 | random.getrandbits(24)) if k < .6 else \
           (0x0804 << 16 | random.getrandbits(16)) if k < .8 else random.getrandbits(random.choice((8, 16, 32)))
def dump(bits, n, sep, pfx):
    return sep.join((pfx + "%x" % addr(bits)) for _ in range(n))
def gen():
    k = random.random() * 0.85          # realistic junk only: dumps and raw bytes
    if k < .45:
        return dump(random.choice((32, 64)), random.randint(4, 40), random.choice((".", " ", "", "-", "|")), random.choice(("", "", "0x")))
    if k < .65:
        return "Name: " + dump(64, random.randint(3, 12), " ", "") + "\nbye\n"
    if k < .85:
        return os.urandom(random.randint(8, 200)).decode("latin-1")
    return "".join(random.choice("abcdefghijklmnopqrstuvwxyzABCDEF0123456789{}_ \n=+/") for _ in range(random.randint(10, 160)))
bycat = {}
N = int(sys.argv[1]); hits = {True: [], False: []}; t0 = time.time()
for i in range(N):
    s = gen()
    for strong in (True, False):
        try:
            r = flags.decode_and_find(s, None, strong_only=strong)
        except Exception as exc:
            print("EXCEPTION", type(exc).__name__, exc, repr(s[:80])); raise
        f = r[0] if isinstance(r, tuple) else r
        if f:
            hits[strong].append((f, flags.LAST_HOW, s[:70]))
            cat = "hexdump" if s[:1] in "0123456789abcdefN" and all(c in "0123456789abcdefx .-|\nName:by" for c in s) else "binary"
            bycat[(strong, cat, flags.LAST_HOW)] = bycat.get((strong, cat, flags.LAST_HOW), 0) + 1
print(f"{N} junk inputs in {time.time()-t0:.0f}s")
for strong in (True, False):
    h = hits[strong]
    print(f"strong_only={strong}: {len(h)} accepted as a flag ({100*len(h)/N:.3f}%)")
    seen = {}
    for f, how, s in h:
        seen.setdefault(how, []).append((f, s))
    for how, lst in seen.items():
        print(f"   via {how}: {len(lst)}   e.g. {lst[0][0][:50]!r}   from {lst[0][1][:50]!r}")

print("by junk type:", {f"{'strict' if k[0] else 'loose'}/{k[1]}/{k[2]}": v for k, v in sorted(bycat.items(), key=str)})
for strong in (True, False):
    for f, how, src in hits[strong][:6]:
        print("  ", "strict" if strong else "loose ", how, repr(f[:44]), "<-", repr(src[:44]))
