"""Anchor the ICU globals in a Bluebook child dump by locating the icudtl.dat
path string in dump memory, then reading each global.

Ghidra labels like _DAT_0b5a1004 are ABSOLUTE addresses assuming the preferred
image base 0x400000, so the file RVA is (label - 0x400000).

Usage: python analysis/icuanchor.py <dump.dmp>
"""
import struct
import sys

IB_PREF = 0x400000
PATH = "C:\\Users\\Admin\\AppData\\Local\\Programs\\bluebook\\icudtl.dat"

# Ghidra absolute labels from FUN_19E0680 (base/i18n/icu_util.cc).
LABELS = [
    ("icu_data_ptr", 0x0B416014),
    ("g_last_error", 0x0B5A1004),
    ("g_err2", 0x0B5A1008),
    ("g_path_buf", 0x0B5A100C),
    ("g_icu_16", 0x0B5A0FE8),
    ("g_ff8", 0x0B5A0FF8),
    ("g_ffc", 0x0B5A0FFC),
    ("g_1000", 0x0B5A1000),
    ("g_sec_cookie", 0x0B3C4040),
    ("g_1214", 0x0B5A1214),
    ("g_121c", 0x0B5A121C),
    ("g_1218", 0x0B5A1218),
    ("g_1220", 0x0B5A1220),
]

WINERR = {
    2: "ERROR_FILE_NOT_FOUND", 3: "ERROR_PATH_NOT_FOUND",
    5: "ERROR_ACCESS_DENIED", 32: "ERROR_SHARING_VIOLATION",
    87: "ERROR_INVALID_PARAMETER", 998: "ERROR_NOACCESS",
    1008: "ERROR_NO_TOKEN", 1920: "ERROR_CANT_ACCESS_FILE",
    1237: "ERROR_NO_SUCH_PACKAGE", 1812: "ERROR_BAD_IMAGE_FORMAT",
}


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0] if o + 4 <= len(b) else 0


def u64(b, o):
    return struct.unpack_from("<Q", b, o)[0] if o + 8 <= len(b) else 0


def main():
    path = sys.argv[1]
    b = open(path, "rb").read()
    ndir = u32(b, 8)
    dr = u32(b, 12)
    S = {}
    for i in range(ndir):
        o = dr + i * 12
        S[u32(b, o)] = (u32(b, o + 4), u32(b, o + 8))

    ranges = []
    if 9 in S:
        _, rva = S[9]
        n = u64(b, rva)
        cur = u64(b, rva + 8)
        for i in range(n):
            o = rva + 16 + i * 16
            st, sz = u64(b, o), u64(b, o + 8)
            ranges.append((st, sz, cur))
            cur += sz

    # image base from the module list
    ib = None
    if 4 in S:
        _, rva = S[4]
        n = u32(b, rva)
        for i in range(n):
            o = rva + 4 + i * 108
            nmr = u32(b, o + 20)
            nr = u32(b, nmr)
            nm = b[nmr + 4 : nmr + 4 + nr].decode("utf-16-le", "replace")
            if nm.lower().endswith("bluebook.exe"):
                ib = u64(b, o)
                break
    print(f"dump: {path}")
    print(f"image base: {ib:#x}" if ib else "image base: unknown")

    def read(va, n):
        for st, sz, off in ranges:
            if st <= va and va + n <= st + sz:
                return b[off + (va - st) : off + (va - st) + n]
        return None

    print("\n--- where does the icudtl.dat path live in the process? ---")
    needle = PATH.encode("utf-16-le")
    hits = []
    for st, sz, off in ranges:
        chunk = b[off : off + sz]
        i = chunk.find(needle)
        while i >= 0:
            va = st + i
            hits.append((va, va - (ib or 0)))
            i = chunk.find(needle, i + 1)
    for va, rva in hits:
        print(f"   VA {va:#010x}   RVA {rva:#010x}")

    print("\n--- ICU globals (label -> RVA = label-0x400000) ---")
    for name, lab in LABELS:
        rva = lab - IB_PREF
        va = (ib or IB_PREF) + rva
        raw = read(va, 0x110)
        if raw is None:
            print(f"  {name:<14} label {lab:#010x} RVA {rva:#09x} VA {va:#010x}  <not in dump>")
            continue
        if name in ("g_path_buf", "g_icu_16"):
            s = raw.split(b"\x00\x00")[0]
            try:
                t = s.decode("utf-16-le")
            except Exception:
                t = raw[:32].hex(" ")
            print(f"  {name:<14} VA {va:#010x} = {t!r}")
        else:
            v = struct.unpack_from("<I", raw, 0)[0]
            note = ""
            if "last_error" in name:
                note = "  -> " + WINERR.get(v, "?")
            print(f"  {name:<14} VA {va:#010x} = {v:#x} ({v}){note}")


if __name__ == "__main__":
    main()
