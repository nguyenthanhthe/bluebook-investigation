"""Raw stack + string dump for a Bluebook minidump (settles which crash path fired).

Prints every stack word from ESP with module resolution, and searches dump
memory for candidate log strings.

Usage: python analysis/mdstack.py <dump.dmp>
"""
import struct
import sys

ARCH = {0: "x86", 9: "x64"}


def u16(b, o): return struct.unpack_from("<H", b, o)[0]
def u32(b, o): return struct.unpack_from("<I", b, o)[0]
def u64(b, o): return struct.unpack_from("<Q", b, o)[0]


def md_string(b, rva):
    if not rva or rva + 4 > len(b):
        return ""
    n = u32(b, rva)
    return b[rva + 4: rva + 4 + n].decode("utf-16-le", "replace")


def main():
    path = sys.argv[1]
    b = open(path, "rb").read()
    ndir, dir_rva = u32(b, 8), u32(b, 12)
    streams = {}
    for i in range(ndir):
        o = dir_rva + i * 12
        streams.setdefault(u32(b, o), (u32(b, o + 4), u32(b, o + 8)))

    mods = []
    _, mrva = streams[4]
    for i in range(u32(b, mrva)):
        o = mrva + 4 + i * 108
        mods.append((u64(b, o), u32(b, o + 8), md_string(b, u32(b, o + 20))))

    def resolve(a):
        for base, size, name in mods:
            if base <= a < base + size:
                return name.split("\\")[-1], a - base
        return None, None

    ranges = []
    for st in (5, 9):
        if st in streams:
            _, r = streams[st]
            for i in range(u32(b, r)):
                o = r + 4 + i * 16
                ranges.append((u64(b, o), u32(b, o + 8), u32(b, o + 12)))

    def read_va(va, n):
        for start, dsize, drva in ranges:
            if start <= va < start + dsize:
                off = drva + (va - start)
                return b[off: off + n]
        return None

    _, er = streams[6]
    code = u32(b, er + 8)
    addr = u64(b, er + 24)
    tc_rva = u32(b, er + 164)
    eip = u32(b, tc_rva + 0xB8)
    esp = u32(b, tc_rva + 0xC4)
    ebp = u32(b, tc_rva + 0xB4)
    n, o = resolve(eip)
    print(f"exception code={code:#010x} EIP={eip:#x} ({n}+{o:#x})  ESP={esp:#x} EBP={ebp:#x}")

    print("\n--- raw stack from ESP (module-resolved words marked *) ---")
    for i in range(0, 0x180, 4):
        va = esp + i
        raw = read_va(va, 4)
        if not raw or len(raw) < 4:
            print(f"  [esp+{i:#05x}] <unreadable>")
            continue
        w = struct.unpack("<I", raw)[0]
        nm, off = resolve(w)
        mark = f"  * {nm}+{off:#x}" if nm else ""
        print(f"  [esp+{i:#05x}] {w:#010x}{mark}")

    print("\n--- interesting strings present in dump memory ---")
    for needle in [
        b"GPU process isn't usable", b"Goodbye", b"gpu_data_manager",
        b"string_view::substr", b"out_of_range was thrown",
        b"Check failed", b"CHECK failed", b"FATAL",
        b"fallback", b"FallBackToNextGpuMode", b"IntentionallyCrash",
        b"FatalGpuProcessLaunchFailure", b"GPU process crashed too many",
        b"gpu_process_host", b"Fatal error", b"Failed to",
    ]:
        c = b.count(needle)
        if c:
            i = b.find(needle)
            print(f"  {needle.decode():<38} x{c}")
            print(f"      @{i:#x}: {b[max(0,i-60):i+160].replace(bytes([0]), b'.')[:220]!r}")


if __name__ == "__main__":
    main()
