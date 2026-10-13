"""Resolve the string/constant operands and helper calls referenced by the
Bluebook child-process crash function (RVA 0x19E0680), and find its callers.

Absolute-vs-RVA note: Ghidra symbol names embed the ABSOLUTE address
(imagebase 0x400000 + RVA), so UNK_0aaf96b1 is RVA 0x6AF96B1.
"""
import struct
import sys

from capstone import CS_ARCH_X86, CS_MODE_32, Cs

EXE = "D:/Temp/bluebook-investigation/exe/original/Bluebook.exe"
IB = 0x400000


class PE:
    def __init__(self, path):
        self.data = open(path, "rb").read()
        d = self.data
        pe = struct.unpack_from("<I", d, 0x3C)[0]
        nsec = struct.unpack_from("<H", d, pe + 6)[0]
        opt = pe + 24
        self.image_base = struct.unpack_from("<I", d, opt + 28)[0]
        sh = opt + struct.unpack_from("<H", d, pe + 20)[0]
        self.sections = []
        for i in range(nsec):
            o = sh + i * 40
            nm = d[o : o + 8].rstrip(b"\x00").decode("latin1")
            vs, va, rs, rp = struct.unpack_from("<IIII", d, o + 8)
            self.sections.append({"name": nm, "va": va, "vsize": vs, "raw": rp, "rawsize": rs})

    def rva_to_off(self, rva):
        for s in self.sections:
            if s["va"] <= rva < s["va"] + max(s["vsize"], s["rawsize"]):
                return s["raw"] + (rva - s["va"])
        return None

    def section_of(self, rva):
        for s in self.sections:
            if s["va"] <= rva < s["va"] + max(s["vsize"], s["rawsize"]):
                return s["name"]
        return None

    def read(self, rva, n):
        o = self.rva_to_off(rva)
        return None if o is None else self.data[o : o + n]

    def printable(self, rva, maxlen=512):
        b = self.read(rva, maxlen)
        if not b:
            return None
        e = b.find(b"\x00")
        if e >= 0:
            b = b[:e]
        if len(b) < 2:
            return None
        try:
            s = b.decode("utf-8")
        except UnicodeDecodeError:
            return None
        if all(32 <= ord(c) < 127 or c in "\r\n\t" for c in s):
            return s
        return None


md = Cs(CS_ARCH_X86, CS_MODE_32)


def disasm_range(pe, rva, nbytes, label=""):
    print(f"\n===== {label}  RVA {rva:#x} ({pe.section_of(rva)}) =====")
    off = pe.rva_to_off(rva)
    code = pe.data[off : off + nbytes]
    for ins in md.disasm(code, pe.image_base + rva):
        r = ins.address - pe.image_base
        note = ""
        if ins.mnemonic in ("call", "jmp") and not ins.op_str.startswith("dword"):
            try:
                t = int(ins.op_str, 16)
                note = f"   ; -> RVA {t - pe.image_base:#x}"
            except ValueError:
                pass
        if ins.mnemonic == "push":
            try:
                v = int(ins.op_str, 16)
            except ValueError:
                v = None
            if v is not None:
                if IB <= v < IB + 0x2000000:
                    vr = v - IB
                    s = pe.printable(vr)
                    note = f"   ; abs->RVA {vr:#x} ({pe.section_of(vr)})" + (
                        f" str={s[:110]!r}" if s else " (non-string)"
                    )
        print(f"{r:08x}  {ins.mnemonic:<7} {ins.op_str}{note}")


def find_callers(pe, target_rva):
    """All E8 rel32 call sites whose target is target_rva."""
    out = []
    tstart, tsize = 0x1000, 0x93C2418
    base = pe.rva_to_off(tstart)
    blob = pe.data[base : base + tsize]
    for i in range(len(blob) - 5):
        if blob[i] == 0xE8:
            rel = struct.unpack_from("<i", blob, i + 1)[0]
            if (tstart + i + 5 + rel) == target_rva:
                out.append(tstart + i)
    return out


def main():
    pe = PE(EXE)
    print(f"image base {pe.image_base:#x}; sections: "
          + ", ".join(f"{s['name']}@{s['va']:#x}" for s in pe.sections))

    print("\n########## strings / data referenced by the crash function ##########")
    for absaddr in (0x0AAF9615, 0x0AAF96A5, 0x0AAF96B1, 0x0AAF96BC, 0x0AAF96CF,
                    0x0AAC5488):
        rva = absaddr - IB
        s = pe.printable(rva)
        b = pe.read(rva, 32)
        print(f"abs {absaddr:#010x} -> RVA {rva:#09x} [{pe.section_of(rva)}]")
        print(f"    raw : {b.hex(' ')}")
        print(f"    str : {s!r}")

    print("\n########## the noreturn call: func_0x01e231d0 (called with 9) ##########")
    disasm_range(pe, 0x1A231D0, 0x60, "sub_1A231D0")

    print("\n########## func_0x03c625f0 (called with 2) ##########")
    disasm_range(pe, 0x38625F0, 0x60, "sub_38625F0")

    print("\n########## __security_check_cookie candidate: func_0x0432b454 ##########")
    disasm_range(pe, 0x3F2B454, 0x50, "sub_3F2B454")

    print("\n########## callers of the crash function FUN_01de0680 ##########")
    for c in find_callers(pe, 0x19E0680):
        print(f"   called from RVA {c:#x} ({pe.section_of(c)})")


if __name__ == "__main__":
    main()
