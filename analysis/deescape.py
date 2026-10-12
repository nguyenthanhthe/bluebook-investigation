"""Static de-escaper for Bluebook's obfuscated JavaScript bundles.

The obfuscator used by Bluebook (0.9.725) applies control-flow flattening
(`var X=4; for(;X!==3;){switch(X){...}}`) and replaces identifiers with
Cyrillic/Greek homoglyphs, but it leaves string *literals* in place as
backslash escapes (`'\x64\u0065\x66...'`). That makes the strings recoverable
without executing any code: decode the escape sequences and the literal
contents become plain ASCII.

This script performs only that decode. It never evaluates the JavaScript.

Usage:
    python analysis/deescape.py <input.js> <output.js>
"""
import re
import sys

# \xNN  |  \uNNNN  |  \u{N..}  |  \0  |  \n \r \t \b \f \v  |  \' \" \\ \/
ESCAPE = re.compile(
    r"""\\(?:x([0-9A-Fa-f]{2})
        |u\{([0-9A-Fa-f]{1,6})\}
        |u([0-9A-Fa-f]{4})
        |([0-7]{1,3})
        |(.) )""",
    re.VERBOSE | re.DOTALL,
)

SIMPLE = {
    "n": "\n", "r": "\r", "t": "\t", "b": "\b",
    "f": "\f", "v": "\v", "0": "\0",
    "'": "'", '"': '"', "\\": "\\", "/": "/", "`": "`",
}


def decode(text: str) -> str:
    def repl(m):
        hex2, ubrace, u4, octal, simple = m.groups()
        if hex2 is not None:
            return chr(int(hex2, 16))
        if ubrace is not None:
            return chr(int(ubrace, 16))
        if u4 is not None:
            return chr(int(u4, 16))
        if octal is not None:
            return chr(int(octal, 8))
        return SIMPLE.get(simple, "\\" + (simple or ""))

    return ESCAPE.sub(repl, text)


def main():
    src, dst = sys.argv[1], sys.argv[2]
    data = open(src, "r", encoding="utf-8", errors="surrogateescape").read()
    out = decode(data)
    # Lone surrogates appear in the bundle (the obfuscator emits \uD800-style
    # escapes); surrogatepass lets them round-trip instead of raising.
    with open(dst, "w", encoding="utf-8", errors="surrogatepass") as fh:
        fh.write(out)
    print(f"{src} -> {dst}")
    print(f"  input  {len(data):,} chars")
    print(f"  output {len(out):,} chars")


if __name__ == "__main__":
    main()
