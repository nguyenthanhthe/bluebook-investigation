"""Collapse Bluebook's char-by-char string concatenation in the obfuscated bundles.

The obfuscator builds identifiers and literals one character at a time:

    l3t += "C";
    l3t += "h";
    l3t += "a";
    ...

This pass folds each run of single-character `NAME += "c";` statements into a
single `NAME += "CharCode";` statement so the bundle becomes greppable. It is a
pure text transform; nothing is executed.

Usage:
    python analysis/collapse.py <input.js> <output.js>
"""
import re
import sys

ASSIGN = re.compile(r'([A-Za-z_$\u00a0-\uffff][\w$\u00a0-\uffff]*)\s*\+=\s*"((?:[^"\\]|\\.)")\s*;\s*')


def unescape_char(s: str) -> str:
    if s.startswith("\\"):
        return {"n": "\n", "r": "\r", "t": "\t"}.get(s[1], s[1])
    return s


def collapse(text: str) -> str:
    out = []
    pos = 0
    while True:
        m = ASSIGN.search(text, pos)
        if not m:
            out.append(text[pos:])
            break
        out.append(text[pos:m.start()])
        name = m.group(1)
        chars = [unescape_char(m.group(2))]
        end = m.end()
        # Greedily absorb following single-char appends to the same variable.
        while True:
            nxt = ASSIGN.match(text, end)
            if not nxt or nxt.group(1) != name:
                break
            chars.append(unescape_char(nxt.group(2)))
            end = nxt.end()
        joined = "".join(chars)
        # Only fold runs; a single append is left untouched.
        if len(chars) > 1:
            safe = joined.replace("\\", "\\\\").replace('"', '\\"')
            out.append(f'{name} += "{safe}";')
        else:
            out.append(m.group(0))
        pos = end
    return "".join(out)


def main():
    src, dst = sys.argv[1], sys.argv[2]
    data = open(src, "r", encoding="utf-8", errors="surrogatepass").read()
    out = collapse(data)
    with open(dst, "w", encoding="utf-8", errors="surrogatepass") as fh:
        fh.write(out)
    print(f"{src} -> {dst}  ({len(data):,} -> {len(out):,} chars)")


if __name__ == "__main__":
    main()
