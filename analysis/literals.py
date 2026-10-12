"""Extract readable ASCII string literals from a (partially) obfuscated JS bundle.

Bluebook's main bundle keeps string literals but hides many behind a runtime
string-array/decoder, so plain grep finds little. This script pulls out every
run of printable ASCII that looks like a real string (>= minlen) and prints the
ones matching interest keywords, with surrounding context.
"""
import re
import sys

KEYWORDS = sys.argv[2].split(",") if len(sys.argv) > 2 else []
MINLEN = 6

data = open(sys.argv[1], "r", encoding="utf-8", errors="surrogatepass").read()

# Find quoted runs that are now readable after de-escaping.
literal = re.compile(r"""(['"])((?:\\.|(?!\1).){%d,}?)\1""" % MINLEN)

seen = {}
for m in literal.finditer(data):
    s = m.group(2)
    if not s.isascii():
        continue
    if not any(31 < ord(c) < 127 or c in "\t\n\r" for c in s):
        continue
    printable = sum(1 for c in s if 31 < ord(c) < 127)
    if printable / max(len(s), 1) < 0.9:
        continue
    if KEYWORDS and not any(k.lower() in s.lower() for k in KEYWORDS):
        continue
    seen.setdefault(s, m.start())

print(f"# {len(seen)} matching literals")
for s, pos in sorted(seen.items(), key=lambda kv: kv[1]):
    print(f"@{pos:>9}  {s[:200]!r}")
