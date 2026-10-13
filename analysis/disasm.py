"""Targeted 32-bit disassembly for Bluebook.exe.

Resolves the import table (IAT slot -> DLL!function), maps RVAs to file
offsets, finds the function containing a given RVA by scanning back for a
prologue, disassembles it with Capstone, and resolves call/jmp targets and
pointer-sized immediate operands that land in .rdata/.data (candidate strings).

Usage:
  python analysis/disasm.py <rva-hex> [--back N] [--count N]
"""
import struct
import sys

from capstone import CS_ARCH_X86, CS_MODE_32, Cs

EXE = "D:/Temp/bluebook-investigation/exe/original/Bluebook.exe"

# ---------------------------------------------------------------- PE parsing


class PE:
    def __init__(self, path):
        self.data = open(path, "rb").read()
        d = self.data
        pe = struct.unpack_from("<I", d, 0x3C)[0]
        self.pe_off = pe
        machine, nsec = struct.unpack_from("<HH", d, pe + 4)
        self.machine = machine
        opt = pe + 24
        self.magic = struct.unpack_from("<H", d, opt)[0]
        self.image_base = struct.unpack_from("<I", d, opt + 28)[0]
        self.nsec = nsec
        self.sections = []
        sh = opt + struct.unpack_from("<H", d, pe + 20)[0]
        for i in range(nsec):
            o = sh + i * 40
            nm = d[o : o + 8].rstrip(b"\x00").decode("latin1")
            vs, va, rs, rp = struct.unpack_from("<IIII", d, o + 8)
            fl = struct.unpack_from("<I", d, o + 36)[0]
            self.sections.append(
                {"name": nm, "va": va, "vsize": vs, "raw": rp, "rawsize": rs, "flags": fl}
            )
        self._parse_imports()

    # -- RVA <-> file offset -------------------------------------------------
    def rva_to_off(self, rva):
        for s in self.sections:
            if s["va"] <= rva < s["va"] + max(s["vsize"], s["rawsize"]):
                return s["raw"] + (rva - s["va"])
        return None

    def off_to_rva(self, off):
        for s in self.sections:
            if s["raw"] <= off < s["raw"] + s["rawsize"]:
                return s["va"] + (off - s["raw"])
        return None

    def read(self, rva, n):
        o = self.rva_to_off(rva)
        if o is None:
            return None
        return self.data[o : o + n]

    def section_of(self, rva):
        for s in self.sections:
            if s["va"] <= rva < s["va"] + max(s["vsize"], s["rawsize"]):
                return s["name"]
        return None

    # -- imports -------------------------------------------------------------
    def _parse_imports(self):
        self.iat = {}  # absolute address of IAT slot -> "DLL!func"
        d = self.data
        opt = self.pe_off + 24
        # PE32 data directories start at opt+96
        dd = opt + 96
        imp_rva, imp_size = struct.unpack_from("<II", d, dd + 8)
        if not imp_rva:
            return
        off = self.rva_to_off(imp_rva)
        idx = 0
        while True:
            base = off + idx * 20
            oft, tstamp, fchain, name_rva, first_thunk = struct.unpack_from("<IIIII", d, base)
            if name_rva == 0 and first_thunk == 0:
                break
            dll_off = self.rva_to_off(name_rva)
            dll = d[dll_off : d.index(b"\x00", dll_off)].decode("latin1") if dll_off else "?"
            thunk_rva = oft if oft else first_thunk
            toff = self.rva_to_off(thunk_rva)
            k = 0
            while True:
                ent = struct.unpack_from("<I", d, toff + k * 4)[0]
                if ent == 0:
                    break
                if not (ent & 0x80000000):
                    noff = self.rva_to_off(ent)
                    if noff:
                        hint = struct.unpack_from("<H", d, noff)[0]
                        end = d.index(b"\x00", noff + 2)
                        fn = d[noff + 2 : end].decode("latin1")
                    else:
                        fn = f"ord_{ent}"
                else:
                    fn = f"ord_{ent & 0xFFFF}"
                slot = self.image_base + first_thunk + k * 4
                self.iat[slot] = f"{dll}!{fn}"
                k += 1
            idx += 1


# ---------------------------------------------------------------- disassembly

md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True


def find_function_start(pe, rva, max_back=0x2000):
    """Scan back for a prologue: 55 8b ec (push ebp;mov ebp,esp) or 55 89 e5."""
    start = max(pe.sections[0]["va"], rva - max_back)
    for a in range(rva, start, -1):
        b = pe.read(a, 4)
        if not b:
            continue
        if b[0] == 0x55 and b[1] in (0x8B, 0x89) and b[2] in (0xEC, 0xE5):
            return a
        if b[:3] == b"\x81\xec" and struct.unpack_from("<I", b, 1)[0] if len(b) >= 5 else False:
            pass
    return None


def cstr(pe, rva, maxlen=200):
    b = pe.read(rva, maxlen)
    if not b:
        return None
    e = b.find(b"\x00")
    if e >= 0:
        b = b[:e]
    if len(b) < 3:
        return None
    try:
        s = b.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if all(32 <= ord(c) < 127 or c in "\r\n\t" for c in s):
        return s
    return None


def main():
    pe = PE(EXE)
    print(f"machine={pe.machine:#x} magic={pe.magic:#x} imagebase={pe.image_base:#x}")
    print(f"imports resolved: {len(pe.iat)} IAT slots")
    print(f"sections: " + ", ".join(s["name"] for s in pe.sections))
    print()

    rva = int(sys.argv[1], 16)
    back = int(sys.argv[2], 0) if len(sys.argv) > 2 else 0x600
    count = int(sys.argv[3], 0) if len(sys.argv) > 3 else 400

    start = find_function_start(pe, rva, back)
    print(f"target RVA {rva:#x} in section {pe.section_of(rva)}")
    print(f"nearest prologue at RVA {start:#x}" if start else "no prologue found in window")
    lo = start if start else rva - 0x40
    print(f"disassembling from RVA {lo:#x}\n")

    off = pe.rva_to_off(lo)
    code = pe.data[off : off + count * 8]
    base = pe.image_base + lo
    for ins in md.disasm(code, base):
        r = ins.address - pe.image_base
        mark = "  <== TARGET" if ins.address == pe.image_base + rva else ""
        note = ""
        ops = ins.op_str
        # resolve call/jmp to IAT or absolute
        if ins.mnemonic in ("call", "jmp"):
            if ops.startswith("dword ptr [") and ops.endswith("]"):
                try:
                    addr = int(ops[len("dword ptr [") : -1], 16)
                except ValueError:
                    addr = None
                if addr in pe.iat:
                    note = f"   ; {pe.iat[addr]}"
            else:
                try:
                    tgt = int(ops, 16)
                    trva = tgt - pe.image_base
                    sec = pe.section_of(trva)
                    if sec:
                        note = f"   ; -> RVA {trva:#x} ({sec})"
                except ValueError:
                    pass
        # pointer immediate into data sections
        if "0x" in ops and ins.mnemonic in ("push", "mov"):
            for tok in ops.replace(",", " ").split():
                if tok.startswith("0x") and len(tok) >= 8:
                    try:
                        v = int(tok, 16)
                    except ValueError:
                        continue
                    if pe.image_base <= v < pe.image_base + 0x2000000:
                        vr = v - pe.image_base
                        sec = pe.section_of(vr)
                        if sec in (".rdata", ".data", ".rodata"):
                            s = cstr(pe, vr)
                            if s:
                                note += f"   ; @{vr:#x} str={s[:90]!r}"
                            else:
                                note += f"   ; @{vr:#x} ({sec}, non-string)"
        print(f"{r:08x}  {ins.mnemonic:<7} {ins.op_str}{note}{mark}")
        if ins.mnemonic == "ret":
            break


if __name__ == "__main__":
    main()
