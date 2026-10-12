"""Minidump parser for Bluebook crash analysis.

Extracts the exception record, faulting module + RVA, full module list,
system info, and scans dump memory for interesting strings (command line,
process type, log lines). Pure stdlib; no WinDbg required.

Usage:
    python analysis/mdparse2.py <dump.dmp> [--strings]
"""
import struct
import sys

STREAM_NAMES = {
    3: "ThreadList", 4: "ModuleList", 5: "MemoryList", 6: "Exception",
    7: "SystemInfo", 8: "ThreadExList", 9: "MemoryList64",
    10: "CommentA", 11: "CommentW", 12: "HandleData", 13: "FunctionTable",
    14: "UnloadedModuleList", 15: "MiscInfo", 16: "MemoryInfoList",
    17: "ThreadInfoList", 18: "HandleOperationList", 19: "TokenList",
}

ARCH = {0: "x86", 9: "x64", 5: "ARM", 12: "ARM64"}


def u16(b, o): return struct.unpack_from("<H", b, o)[0]
def u32(b, o):
    if o + 4 > len(b):
        return 0
    return struct.unpack_from("<I", b, o)[0]
def u64(b, o):
    if o + 8 > len(b):
        return 0
    return struct.unpack_from("<Q", b, o)[0]


def read_md_string(b, rva):
    if rva == 0 or rva + 4 > len(b):
        return ""
    n = u32(b, rva)
    raw = b[rva + 4: rva + 4 + n]
    try:
        return raw.decode("utf-16-le", "replace")
    except Exception:
        return ""


def main():
    path = sys.argv[1]
    want_strings = "--strings" in sys.argv
    b = open(path, "rb").read()
    print(f"file      : {path}")
    print(f"size      : {len(b):,} bytes")
    sig = b[:4]
    print(f"signature : {sig!r}  version={u32(b,4):#x}  streams={u32(b,8)}")
    ndir = u32(b, 8)
    dir_rva = u32(b, 12)

    streams = {}
    for i in range(ndir):
        o = dir_rva + i * 12
        stype, size, rva = u32(b, o), u32(b, o + 4), u32(b, o + 8)
        streams.setdefault(stype, (size, rva))
    print("\nstreams:")
    for t, (size, rva) in sorted(streams.items()):
        print(f"  {t:>3} {STREAM_NAMES.get(t,'?'):<20} size={size:<10} rva={rva:#x}")

    # SystemInfo
    if 7 in streams:
        _, rva = streams[7]
        arch = u16(b, rva)
        print(f"\nsystem    : arch={ARCH.get(arch,arch)} ({arch})")

    # Modules
    mods = []
    if 4 in streams:
        _, rva = streams[4]
        n = u32(b, rva)
        print(f"\nmodules   : {n}")
        for i in range(n):
            o = rva + 4 + i * 108
            base = u64(b, o)
            size = u32(b, o + 8)
            ts = u32(b, o + 12)
            name_rva = u32(b, o + 20)
            name = read_md_string(b, name_rva)
            mods.append((base, size, name, ts))
        # Show non-system modules prominently.
        sysdir = ("\\windows\\", "\\winsxs\\")
        print("  --- non-Windows modules ---")
        for base, size, name, ts in mods:
            low = name.lower()
            if not any(s in low for s in sysdir):
                print(f"    {base:#010x} {size:>9} {name}")

    def resolve(addr):
        for base, size, name, ts in mods:
            if base <= addr < base + size:
                return name, addr - base
        return None, None

    # Exception
    if 6 in streams:
        _, rva = streams[6]
        tid = u32(b, rva)
        code = u32(b, rva + 8)
        flags = u32(b, rva + 12)
        addr = u64(b, rva + 24)
        nparam = u32(b, rva + 32)
        params = [u64(b, rva + 40 + j * 8) for j in range(min(nparam, 15))]
        name, off = resolve(addr)
        print(f"\nexception : tid={tid} code={code:#010x} flags={flags:#x}")
        print(f"  address : {addr:#x}  -> {name}+{off:#x}" if name else f"  address : {addr:#x} (unmapped)")
        print(f"  params  : {[hex(p) for p in params]}")
        # MINIDUMP_EXCEPTION_STREAM = ThreadId(4) + align(4) + MINIDUMP_EXCEPTION(152)
        # + ThreadContext descriptor(8) => descriptor DataSize at +160, Rva at +164.
        tc_size = u32(b, rva + 160)
        tc_rva = u32(b, rva + 164)
        esp = None
        if tc_rva and tc_rva + 0xCC <= len(b):
            base_ctx = tc_rva          # raw CONTEXT struct, no size prefix
            eip = u32(b, base_ctx + 0xB8)
            esp = u32(b, base_ctx + 0xC4)
            ebp = u32(b, base_ctx + 0xB4)
            n_eip, o_eip = resolve(eip)
            print(f"  context : size={tc_size} EIP={eip:#x} ESP={esp:#x} EBP={ebp:#x}")
            if n_eip:
                print(f"            EIP -> {n_eip}+{o_eip:#x}")

        # Walk the crashing thread's stack, resolving each word to module+RVA.
        if 5 in streams or 9 in streams:
            ranges = []
            for st in (5, 9):
                if st not in streams:
                    continue
                _, mrva = streams[st]
                cnt = u32(b, mrva)
                for i in range(cnt):
                    o = mrva + 4 + i * 16
                    start = u64(b, o)
                    dsize = u32(b, o + 8)
                    drva = u32(b, o + 12)
                    ranges.append((start, dsize, drva))

            def read_va(va, n):
                for start, dsize, drva in ranges:
                    if start <= va < start + dsize:
                        off = drva + (va - start)
                        return b[off: off + n]
                return None

            print("\n  --- stack walk (words resolving into a module) ---")
            shown = 0
            for sp in range(esp, esp + 0x800, 4):
                raw = read_va(sp, 4)
                if not raw or len(raw) < 4:
                    continue
                w = struct.unpack("<I", raw)[0]
                n2, o2 = resolve(w)
                if n2 and o2 is not None and o2 < 0x2000000:
                    short = n2.split("\\")[-1]
                    print(f"    [esp+{sp-esp:#05x}] {w:#010x}  {short}+{o2:#x}")
                    shown += 1
                    if shown > 40:
                        break

    if want_strings:
        print("\n--- selected strings found in dump ---")
        needles = [
            b"--type=", b"gpu-process", b"renderer", b"utility", b"crashpad",
            b"Goodbye", b"gpu_data_manager", b"FATAL", b"CHECK failed",
            b"Bluebook.exe", b"app.asar", b"bluebook", b"Programs",
            b"swiftshader", b"ANGLE", b"disable-gpu", b"gl_", b"d3d",
        ]
        for n in needles:
            cnt = b.count(n)
            if cnt:
                i = b.find(n)
                ctx = b[max(0, i - 40): i + 120]
                ctx = ctx.replace(b"\x00", b".")
                print(f"  {n!r:<20} x{cnt}  @{i:#x}: {ctx[:150]!r}")
        # UTF-16 too
        for n in [b"--type=", b"gpu-process", b"Bluebook"]:
            w = n.decode().encode("utf-16-le")
            cnt = b.count(w)
            if cnt:
                i = b.find(w)
                print(f"  UTF16 {n!r:<16} x{cnt} @{i:#x}")


if __name__ == "__main__":
    main()
