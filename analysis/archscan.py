"""Scan executables under a directory tree and report PE machine type + whether
the app looks like Electron (has resources/app.asar or a large exe).

Used to test: are there any other 32-bit apps installed in the user profile,
and do they work?

Usage: python analysis/archscan.py <root-dir> [maxdepth]
"""
import os
import struct
import sys


def machine(path):
    try:
        with open(path, "rb") as fh:
            d = fh.read(0x400)
        if d[:2] != b"MZ":
            return None
        pe = struct.unpack_from("<I", d, 0x3C)[0]
        if d[pe:pe + 4] != b"PE\0\0":
            return None
        return struct.unpack_from("<H", d, pe + 4)[0]
    except Exception:
        return None


NAMES = {0x014C: "i386/32-bit", 0x8664: "x64/64-bit", 0xAA64: "ARM64", 0x01C4: "ARM"}


def main():
    root = sys.argv[1]
    maxdepth = int(sys.argv[2]) if len(sys.argv) > 2 else 3
    rows = []
    root_depth = root.rstrip("\\/").count(os.sep)
    for dirpath, dirnames, filenames in os.walk(root):
        if dirpath.count(os.sep) - root_depth >= maxdepth:
            dirnames[:] = []
        for fn in filenames:
            if not fn.lower().endswith(".exe"):
                continue
            p = os.path.join(dirpath, fn)
            try:
                size = os.path.getsize(p)
            except OSError:
                continue
            if size < 20 * 1024 * 1024:
                continue
            m = machine(p)
            if m is None:
                continue
            # Electron detection: sibling resources/app.asar
            asar = os.path.join(dirpath, "resources", "app.asar")
            is_electron = os.path.exists(asar)
            rows.append((m, size, is_electron, p))

    rows.sort()
    for m, size, el, p in rows:
        tag = "ELECTRON" if el else "        "
        print(f"{NAMES.get(m, hex(m)):<12} {size/1e6:8.1f}MB {tag}  {p}")


if __name__ == "__main__":
    main()
