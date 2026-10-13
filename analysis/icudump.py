"""Analyze a Bluebook GPU/renderer child minidump for the ICU-init failure.

Resolves the crashing thread's x86 context, then reads the specific globals the
crashing function touches (image base is ASLR-relocated, so addresses are
computed as child_image_base + RVA) and walks the stack for return addresses.

Usage: python analysis/icudump.py <dump.dmp>
"""
import struct
import sys

# RVAs from the disassembly of FUN_19E0680 (base/i18n/icu_util.cc).
G = {
    "icu_data_ptr(_DAT_0b416014)": 0x0B416014,
    "g_last_error(_DAT_0b5a1004)": 0x0B5A1004,
    "g_err2(_DAT_0b5a1008)": 0x0B5A1008,
    "g_path_buf(_DAT_0b5a100c)": 0x0B5A100C,
    "g_data16(_DAT_0b5a0fe8)": 0x0B5A0FE8,
    "g_state_ff8": 0x0B5A0FF8,
    "g_state_ffc": 0x0B5A0FFC,
    "g_state_1000": 0x0B5A1000,
    "g_trace_1214": 0x0B5A1214,
    "g_trace_121c": 0x0B5A121C,
    "security_cookie": 0x0B3C4040,
    "g_level_1c60": 0x0B5A1C60,
}


def u16(b, o):
    return struct.unpack_from("<H", b, o)[0] if o + 2 <= len(b) else 0


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
        self._ranges = []
        self._load_memory()

    def _load_memory(self):
        if 9 not in self.streams:  # Memory64List
            return
        _, rva = self.streams[9]
        n = u64(self.b, rva)
        base_rva = u64(self.b, rva + 8)
        cur = base_rva
        for i in range(n):
            o = rva + 16 + i * 16
            start = u64(self.b, o)
            size = u64(self.b, o + 8)
            self._ranges.append((start, size, cur))
            cur += size

    def read(self, va, n):
        for start, size, off in self._ranges:
            if start <= va and va + n <= start + size:
                return self.b[off + (va - start) : off + (va - start) + n]
        return None

    def u32at(self, va):
        d = self.read(va, 4)
        return struct.unpack("<I", d)[0] if d else None

    def modules(self):
        out = []
        if 4 not in self.streams:
            return out
        _, rva = self.streams[4]
        n = u32(self.b, rva)
        for i in range(n):
            o = rva + 4 + i * 108
            base = u64(self.b, o)
            size = u32(self.b, o + 8)
            name_rva = u32(self.b, o + 20)
            nr = u32(self.b, name_rva)
            nm = self.b[name_rva + 4 : name_rva + 4 + nr].decode("utf-16-le", "replace")
            out.append((base, size, nm))
        return out

    def threads(self):
        """MINIDUMP_THREAD_LIST (3): tid -> (context_rva, stack_start, stack_size)."""
        out = []
        if 3 not in self.streams:
            return out
        _, rva = self.streams[3]
        n = u32(self.b, rva)
        for i in range(n):
            o = rva + 4 + i * 48
            tid = u32(self.b, o)
            stack_start = u64(self.b, o + 24)
            stack_size = u32(self.b, o + 32)
            tc_size = u32(self.b, o + 40)
            tc_rva = u32(self.b, o + 44)
            out.append({"tid": tid, "stack_start": stack_start,
                        "stack_size": stack_size, "tc_size": tc_size,
                        "tc_rva": tc_rva})
        return out

    def find_fault_thread(self, exe_base, target_rva):
        want = exe_base + target_rva
        for t in self.threads():
            ctx = self.x86_context(t["tc_rva"])
            if ctx["Eip"] == want:
                t["ctx"] = ctx
                return t
        return None

    def x86_context(self, tc_rva):
        b = self.b
        return {
            "Eip": u32(b, tc_rva + 0xB8),
            "Esp": u32(b, tc_rva + 0xC4),
            "Ebp": u32(b, tc_rva + 0xB4),
            "Eax": u32(b, tc_rva + 0xB0),
            "Ebx": u32(b, tc_rva + 0xA4),
            "Ecx": u32(b, tc_rva + 0xAC),
            "Edx": u32(b, tc_rva + 0xA8),
            "Esi": u32(b, tc_rva + 0xA0),
            "Edi": u32(b, tc_rva + 0x9C),
        }


def main():
    path = sys.argv[1]
    d = Dump(path)
    print(f"=== {path} ===")
    mods = d.modules()
    exe_base = None
    for base, size, nm in mods:
        if nm.lower().endswith("bluebook.exe"):
            exe_base = base
            print(f"IMAGE       : {nm}")
            print(f"  base      : {base:#x}  size {size:#x}")
    if exe_base is None:
        print("!! Bluebook.exe not in module list")
        return
    print(f"  ASLR delta: imagebase {exe_base:#x} (preferred 0x400000)")

    exc_t = d.find_fault_thread(exe_base, 0x19E0914)
    if exc_t is None:
        print("\n!! no thread with EIP at RVA 0x19E0914; listing all threads:")
        for t in d.threads():
            c = d.x86_context(t["tc_rva"])
            print(f"   tid={t['tid']:<7} EIP={c['Eip']:#010x} "
                  f"(RVA {c['Eip'] - exe_base:#x}) ESP={c['Esp']:#x}")
        return
    ctx = exc_t["ctx"]
    print(f"\nFAULTING THREAD tid={exc_t['tid']} EIP={ctx['Eip']:#010x} "
          f"(RVA {ctx['Eip'] - exe_base:#x})")
    print(f"  ESP={ctx['Esp']:#x} EBP={ctx['Ebp']:#x}")
    for k in ("Eax", "Ebx", "Ecx", "Edx", "Esi", "Edi"):
        print(f"  {k}={ctx[k]:#x}")

    print("\n=== globals (child VA = image_base + RVA) ===")
    for name, rva in G.items():
        va = exe_base + rva
        v = d.u32at(va)
        extra = ""
        if "path_buf" in name or name.startswith("g_data"):
            raw = d.read(va, 0x110)
            if raw:
                s = raw.split(b"\x00\x00")[0]
                try:
                    extra = f"  str={s.decode('utf-16-le', 'ignore')!r}"
                except Exception:
                    extra = ""
        print(f"  {name:<30} @{va:#010x} = {v if v is None else hex(v)}{extra}")

    print("\n=== stack walk from ESP ===")
    esp = ctx["Esp"]
    raw = d.read(esp, 0x400)
    if raw:
        for i in range(0, min(len(raw), 0x200), 4):
            v = struct.unpack_from("<I", raw, i)[0]
            tag = ""
            if exe_base <= v < exe_base + 0x2000000:
                tag = f"  <== code RVA {v - exe_base:#x}"
            elif 0x70000000 <= v:
                for base, size, nm in mods:
                    if base <= v < base + size:
                        tag = f"  <== {nm.rsplit(chr(92), 1)[-1]}+{v - base:#x}"
                        break
            if tag:
                print(f"  [esp+{i:#04x}] {v:#010x}{tag}")

    print("\n=== strings on the stack ===")
    if raw:
        cur = bytearray()
        start = 0
        for i, ch in enumerate(raw):
            if 32 <= ch < 127:
                if not cur:
                    start = i
                cur.append(ch)
            else:
                if len(cur) >= 5:
                    print(f"  [esp+{start:#04x}] {cur.decode('latin1')!r}")
                cur = bytearray()
    # UTF-16 strings (paths)
    print("\n=== UTF-16 strings on the stack (paths) ===")
    if raw:
        for i in range(0, len(raw) - 16, 2):
            try:
                s = raw[i : i + 200].decode("utf-16-le", "strict")
            except UnicodeDecodeError:
                s = raw[i : i + 200].decode("utf-16-le", "ignore")
            m = s.split("\x00")[0]
            if len(m) >= 12 and ("\\" in m or ":" in m) and all(32 <= ord(c) < 127 for c in m):
                print(f"  [esp+{i:#04x}] {m!r}")


if __name__ == "__main__":
    main()
