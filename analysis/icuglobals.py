"""Read the ICU-init globals and search memory in a Bluebook GPU/renderer
child minidump, without needing a thread context.

The crashing function (RVA 0x19E0680, base/i18n/icu_util.cc) records:
  _DAT_0b5a1004 = GetLastError()
  _DAT_0b5a1008 = second value
  _DAT_0b5a100c = path buffer (UTF-16, up to 0x104 bytes)
It also caches the resolved icudtl path and a status. Reading these from the
dump gives the exact failure without a live debugger.

Usage: python analysis/icuglobals.py <dump.dmp> [more.dmp ...]
"""
import struct
import sys

GLOBALS = [
    ("icu_data_ptr", 0x0B416014, "u32"),
    ("GetLastError", 0x0B5A1004, "u32"),
    ("err_secondary", 0x0B5A1008, "u32"),
    ("path_buf_utf16", 0x0B5A100C, "wstr"),
    ("icu_data_16", 0x0B5A0FE8, "hex16"),
    ("state_ff8", 0x0B5A0FF8, "u32"),
    ("state_ffc", 0x0B5A0FFC, "u32"),
    ("state_1000", 0x0B5A1000, "u32"),
    ("security_cookie", 0x0B3C4040, "u32"),
]

WINERR = {
    0: "ERROR_SUCCESS",
    2: "ERROR_FILE_NOT_FOUND",
    3: "ERROR_PATH_NOT_FOUND",
    5: "ERROR_ACCESS_DENIED",
    32: "ERROR_SHARING_VIOLATION",
    87: "ERROR_INVALID_PARAMETER",
    126: "ERROR_MOD_NOT_FOUND",
    998: "ERROR_NOACCESS (invalid memory access)",
    1008: "ERROR_NO_TOKEN",
    1920: "ERROR_CANT_ACCESS_FILE",
    1812: "ERROR_BAD_IMAGE_FORMAT",
    1237: "ERROR_NO_SUCH_PACKAGE",
    0x2: "ERROR_FILE_NOT_FOUND",
}


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0] if o + 4 <= len(b) else 0


def u64(b, o):
    return struct.unpack_from("<Q", b, o)[0] if o + 8 <= len(b) else 0


class Dump:
    def __init__(self, path):
        self.b = open(path, "rb").read()
        b = self.b
        self.streams = {}
        ndir = u32(b, 8)
        dir_rva = u32(b, 12)
        for i in range(ndir):
            o = dir_rva + i * 12
            st, sz, rva = u32(b, o), u32(b, o + 4), u32(b, o + 8)
            self.streams[st] = (sz, rva)
        self.ranges = []
        if 9 in self.streams:
            _, rva = self.streams[9]
            n = u64(b, rva)
            cur = u64(b, rva + 8)
            for i in range(n):
                o = rva + 16 + i * 16
                start = u64(b, o)
                size = u64(b, o + 8)
                self.ranges.append((start, size, cur))
                cur += size
        self.exes = []
        if 4 in self.streams:
            _, rva = self.streams[4]
            n = u32(b, rva)
            for i in range(n):
                o = rva + 4 + i * 108
                base = u64(b, o)
                size = u32(b, o + 8)
                nr = u32(b, u32(b, o + 20))
                nm = b[u32(b, o + 20) + 4 : u32(b, o + 20) + 4 + nr].decode("utf-16-le", "replace")
                if nm.lower().endswith("bluebook.exe"):
                    self.exes.append((base, size, nm))

    def read(self, va, n):
        for start, size, off in self.ranges:
            if start <= va and va + n <= start + size:
                return self.b[off + (va - start) : off + (va - start) + n]
        return None


def main():
    for path in sys.argv[1:]:
        d = Dump(path)
        print("=" * 78)
        print(path)
        if not d.exes:
            print("  no Bluebook.exe module")
            continue
        base = d.exes[0][0]
        print(f"  image base {base:#x}   memory ranges: {len(d.ranges)}")
        print("  --- ICU globals ---")
        for name, rva, kind in GLOBALS:
            va = base + rva
            raw = d.read(va, 0x110 if kind == "wstr" else 32)
            if raw is None:
                print(f"  {name:<18} @{va:#010x}  <not in dump>")
                continue
            if kind == "u32":
                v = struct.unpack_from("<I", raw, 0)[0]
                note = ""
                if name == "GetLastError":
                    note = f"  -> {WINERR.get(v, '?')}"
                print(f"  {name:<18} @{va:#010x} = {v:#x} ({v}){note}")
            elif kind == "wstr":
                s = raw.split(b"\x00\x00")[0]
                try:
                    t = s.decode("utf-16-le")
                except Exception:
                    t = repr(s)
                print(f"  {name:<18} @{va:#010x} = {t!r}")
            else:
                print(f"  {name:<18} @{va:#010x} = {raw[:16].hex(' ')}")

        print("  --- UTF-16 strings mentioning icu / path in dump memory ---")
        seen = set()
        needles = ("icudtl", "Can't find", "icu-open-file", "icu_util")
        for start, size, off in d.ranges:
            chunk = d.b[off : off + size]
            for nd in needles:
                nw = nd.encode("utf-16-le")
                i = chunk.find(nw)
                if i >= 0:
                    lo = max(0, i - 160)
                    hi = min(len(chunk), i + 200)
                    # trim to a UTF-16 aligned printable run
                    s = chunk[lo:hi]
                    try:
                        t = s.decode("utf-16-le", "replace")
                    except Exception:
                        continue
                    key = (nd, i)
                    if key in seen:
                        continue
                    seen.add(key)
                    clean = "".join(c if 32 <= ord(c) < 127 or c in "\\/:._-" else "."
                                    for c in t)
                    print(f"    [{nd}] @~{start + i:#x}: ...{clean}...")
                    if len(seen) > 14:
                        break
            if len(seen) > 14:
                break


if __name__ == "__main__":
    main()
