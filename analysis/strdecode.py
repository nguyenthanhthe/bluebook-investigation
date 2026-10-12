"""Decode Bluebook's obfuscated string table.

The obfuscator stores literals as percent-encoded byte strings, e.g.
    B3'$Kk_8%209%5B#T1%25%25U#%5E*h%20J#C;...
Decoding each %XX yields raw bytes that still contain control characters
(0x12, 0x13, 0x1A, ...), i.e. the payload is also obfuscated. This script
percent-decodes, then tries single-byte XOR and additive keys to find a
transform that produces readable ASCII, and reports the best candidates.

Usage: python analysis/strdecode.py <file-with-strings> [--dump]
"""
import re
import sys
from collections import Counter

PRINTABLE = set(range(0x20, 0x7F)) | {9, 10, 13}


def pct_decode(s: str) -> bytes:
    out = bytearray()
    i = 0
    while i < len(s):
        if s[i] == "%" and i + 2 < len(s) + 1:
            try:
                out.append(int(s[i + 1:i + 3], 16))
                i += 3
                continue
            except ValueError:
                pass
        out.append(ord(s[i]) & 0xFF)
        i += 1
    return bytes(out)


def score(b: bytes) -> float:
    if not b:
        return 0.0
    return sum(1 for c in b if c in PRINTABLE) / len(b)


def best_single_xor(b: bytes):
    best = None
    for k in range(256):
        x = bytes(c ^ k for c in b)
        sc = score(x)
        if best is None or sc > best[0]:
            best = (sc, k, x)
    return best


def best_add(b: bytes):
    best = None
    for k in range(256):
        x = bytes((c - k) & 0xFF for c in b)
        sc = score(x)
        if best is None or sc > best[0]:
            best = (sc, k, x)
    return best


def main():
    path = sys.argv[1]
    dump = "--dump" in sys.argv
    data = open(path, "r", encoding="utf-8", errors="surrogatepass").read()

    # Candidates: quoted literals that look percent-encoded (many %XX).
    lits = re.findall(r"""(['"])((?:\\.|(?!\1).){40,}?)\1""", data)
    cands = []
    for _, s in lits:
        if s.count("%") >= 8 and s.isascii():
            cands.append(s)
    print(f"percent-encoded candidates: {len(cands)}")

    shown = 0
    for s in cands[:400]:
        raw = pct_decode(s)
        sc_x, kx, x = best_single_xor(raw)
        sc_a, ka, a = best_add(raw)
        if sc_x < 0.9 and sc_a < 0.9:
            continue
        if sc_x >= sc_a:
            print(f"\n[ctor={len(s)}] XOR key={kx:#04x} printable={sc_x:.2f}")
            print("   ", x[:160])
        else:
            print(f"\n[ctor={len(s)}] ADD key={ka:#04x} printable={sc_a:.2f}")
            print("   ", a[:160])
        shown += 1
        if shown >= 25:
            break

    if not shown:
        print("\nNo simple transform found; showing byte histogram of first candidate:")
        if cands:
            raw = pct_decode(cands[0])
            c = Counter(raw)
            print("  top bytes:", c.most_common(20))
            if dump:
                print("  raw:", raw[:200])


if __name__ == "__main__":
    main()
