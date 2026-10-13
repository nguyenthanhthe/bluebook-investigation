"""Launch Bluebook with DEBUG_PROCESS, identify each descendant's real command
line (via NtQueryInformationProcess -> WOW64 PEB), and write a FULL minidump of
any process that hits the in-image int3 (RVA 0x19E0914) so the crash can be
analysed offline.

Requires elevation (SeDebugPrivilege) to read/dump sandboxed children.

Usage: python analysis/dumpchild.py <exe-path> [seconds] [outdir]
"""
import ctypes
import os
import struct
import sys
import time
from ctypes import wintypes

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll")
dbghelp = ctypes.WinDLL("dbghelp")

k32.ReadProcessMemory.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
    ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
]
k32.ReadProcessMemory.restype = wintypes.BOOL
k32.WaitForDebugEvent.argtypes = [ctypes.c_void_p, wintypes.DWORD]
k32.WaitForDebugEvent.restype = wintypes.BOOL
k32.ContinueDebugEvent.argtypes = [wintypes.DWORD, wintypes.DWORD, wintypes.DWORD]
k32.ContinueDebugEvent.restype = wintypes.BOOL
k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
k32.OpenProcess.restype = wintypes.HANDLE
ntdll.NtQueryInformationProcess.argtypes = [
    wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.ULONG,
    ctypes.POINTER(wintypes.ULONG),
]

DEBUG_PROCESS = 0x00000001
CREATE_NEW_CONSOLE = 0x00000010
DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001

EXCEPTION_DEBUG_EVENT = 1
CREATE_PROCESS_DEBUG_EVENT = 3
EXIT_PROCESS_DEBUG_EVENT = 5
OUTPUT_DEBUG_STRING_EVENT = 8

ProcessWow64Information = 26
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

# MiniDumpWriteDump
MiniDumpWithFullMemory = 0x00000002
MiniDumpWithHandleData = 0x00000004
MiniDumpWithThreadInfo = 0x00001000
MiniDumpWithFullMemoryInfo = 0x00000800
MiniDumpWithUnloadedModules = 0x00000020
MINIDUMP_TYPE = MiniDumpWithFullMemory | MiniDumpWithHandleData | \
    MiniDumpWithThreadInfo | MiniDumpWithFullMemoryInfo | MiniDumpWithUnloadedModules

dbghelp.MiniDumpWriteDump.argtypes = [
    wintypes.HANDLE, wintypes.DWORD, wintypes.HANDLE, ctypes.c_int,
    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
]
dbghelp.MiniDumpWriteDump.restype = wintypes.BOOL

# The child-process crash site: file image base 0xC50000 + RVA 0x19E0914.
CRASH_IMAGE_RVA = 0x19E0914

EXC = {
    0x80000003: "STATUS_BREAKPOINT",
    0xC0000005: "ACCESS_VIOLATION",
    0x4000001F: "STATUS_WX86_BREAKPOINT",
    0x406D1388: "MS_VC_EXCEPTION(threadname)",
    0xC0000409: "STACK_BUFFER_OVERRUN",
    0xE06D7363: "C++ exception",
}


class STARTUPINFO(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR), ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD), ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.c_void_p),
        ("hStdInput", wintypes.HANDLE), ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD),
    ]


def read_mem(h, addr, n):
    buf = ctypes.create_string_buffer(n)
    got = ctypes.c_size_t(0)
    if not k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, n, ctypes.byref(got)):
        return None
    return buf.raw[: got.value]


def ru32(h, a):
    b = read_mem(h, a, 4)
    return struct.unpack("<I", b)[0] if b and len(b) == 4 else None


def ru16(h, a):
    b = read_mem(h, a, 2)
    return struct.unpack("<H", b)[0] if b and len(b) == 2 else None


def cmdline_wow64(h, pid):
    """Command line of a 32-bit process, read from its WOW64 PEB."""
    peb32 = ctypes.c_void_p(0)
    ret = wintypes.ULONG(0)
    st = ntdll.NtQueryInformationProcess(
        h, ProcessWow64Information, ctypes.byref(peb32), ctypes.sizeof(peb32),
        ctypes.byref(ret))
    if st != 0 or not peb32.value:
        return None, None
    p = peb32.value
    params = ru32(h, p + 0x10)
    if not params:
        return None, p
    length = ru16(h, params + 0x40)
    bufptr = ru32(h, params + 0x44)
    if not length or not bufptr:
        return None, p
    raw = read_mem(h, bufptr, min(length, 4096))
    if not raw:
        return None, p
    return raw.decode("utf-16-le", "replace"), p


def write_dump(h, pid, path):
    f = k32.CreateFileW(path, 0x40000000, 0, None, 2, 0x80, None)
    if f == -1 or f == 0xFFFFFFFF:
        return False, ctypes.get_last_error()
    try:
        ok = dbghelp.MiniDumpWriteDump(h, pid, f, MINIDUMP_TYPE, None, None, None)
        return bool(ok), ctypes.get_last_error()
    finally:
        k32.CloseHandle(f)


def scan_ascii(h, addr, n, minlen=6):
    raw = read_mem(h, addr, n)
    if not raw:
        return []
    out, cur = [], bytearray()
    for ch in raw:
        if 32 <= ch < 127:
            cur.append(ch)
        else:
            if len(cur) >= minlen:
                out.append(cur.decode("latin1"))
            cur = bytearray()
    if len(cur) >= minlen:
        out.append(cur.decode("latin1"))
    return out


def main():
    exe = sys.argv[1]
    budget = float(sys.argv[2]) if len(sys.argv) > 2 else 40.0
    outdir = sys.argv[3] if len(sys.argv) > 3 else "D:/rea-tools/dumps/child"
    os.makedirs(outdir, exist_ok=True)

    si = STARTUPINFO()
    si.cb = ctypes.sizeof(si)
    pi = PROCESS_INFORMATION()
    cmd = ctypes.create_unicode_buffer(f'"{exe}"')
    cwd = exe.rsplit("\\", 1)[0]

    if not k32.CreateProcessW(exe, cmd, None, None, False,
                              DEBUG_PROCESS | CREATE_NEW_CONSOLE, None, cwd,
                              ctypes.byref(si), ctypes.byref(pi)):
        print(f"CreateProcess failed err={ctypes.get_last_error()}")
        return
    print(f"debugging tree of pid={pi.dwProcessId}\nbudget={budget}s outdir={outdir}\n")

    procs, names, bases, dumped = {}, {}, {}, set()
    ev = ctypes.create_string_buffer(512)
    t0 = time.time()

    while time.time() - t0 < budget:
        if not k32.WaitForDebugEvent(ctypes.byref(ev), 400):
            continue
        buf = ev.raw
        code, pid, tid = struct.unpack_from("<III", buf, 0)

        if code == CREATE_PROCESS_DEBUG_EVENT:
            hprocess = struct.unpack_from("<Q", buf, 24)[0]
            base = struct.unpack_from("<Q", buf, 40)[0]
            procs[pid] = hprocess
            bases[pid] = base
            # Ensure our own access even if the debug handle is limited.
            h2 = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
            cl, peb = cmdline_wow64(hprocess, pid)
            if cl is None and h2:
                cl, peb = cmdline_wow64(h2, pid)
            if h2:
                k32.CloseHandle(h2)
            names[pid] = cl
            tag = "browser"
            if cl and "--type=" in cl:
                tag = cl.split("--type=")[1].split()[0]
            print(f"[+] CREATE pid={pid} base={base:#x} tag={tag}")
            print(f"    peb32={peb if peb is None else hex(peb)}")
            print(f"    cmd: {cl}")

        elif code == EXCEPTION_DEBUG_EVENT:
            exc = struct.unpack_from("<I", buf, 16)[0]
            addr = struct.unpack_from("<Q", buf, 32)[0]
            npar = struct.unpack_from("<I", buf, 40)[0]
            first = struct.unpack_from("<I", buf, 168)[0]
            cl = names.get(pid)
            tag = cl.split("--type=")[1].split()[0] if cl and "--type=" in cl else "browser"
            rva = (addr - bases.get(pid, 0)) if bases.get(pid) else None
            inimage = rva == CRASH_IMAGE_RVA
            print(f"\n[!] EXC pid={pid} ({tag}) tid={tid} code={exc:#010x} "
                  f"{EXC.get(exc, '?')} first={first}")
            print(f"    address={addr:#x} imageRVA={rva if rva is None else hex(rva)}"
                  f"{'  <== ICU int3 site' if inimage else ''} nparams={npar}")
            h = procs.get(pid)
            if h and inimage and not first and pid not in dumped:
                # Second chance at the ICU abort: capture the stack and a dump.
                ss = scan_ascii(h, addr - 0x4000, 0x8000, 6)
                keep = [s for s in ss if any(k in s for k in (
                    "icu", "ICU", "Can't find", "icudtl", "path", "Path",
                    "CHECK", "FATAL", "GPU", "gpu", "sandbox", "Sandbox",
                    "AppContainer", "icudtl.dat"))]
                print(f"    nearby strings: {keep[:14]}")
                p = os.path.join(outdir, f"child_{pid}_t{int(time.time())}.dmp")
                ok, err = write_dump(h, pid, p)
                if ok:
                    size = os.path.getsize(p)
                    print(f"    DUMP WRITTEN {p} ({size/1048576:.1f} MB)")
                    dumped.add(pid)
                else:
                    print(f"    dump failed err={err}")
            k32.ContinueDebugEvent(pid, tid, DBG_EXCEPTION_NOT_HANDLED)
            continue

        elif code == OUTPUT_DEBUG_STRING_EVENT:
            ptr = struct.unpack_from("<Q", buf, 24)[0]
            ln = struct.unpack_from("<H", buf, 32)[0]
            uni = struct.unpack_from("<H", buf, 34)[0]
            h = procs.get(pid)
            cl = names.get(pid)
            tag = cl.split("--type=")[1].split()[0] if cl and "--type=" in cl else "browser"
            txt = ""
            if h and ptr and ln:
                raw = read_mem(h, ptr, ln * (2 if uni else 1))
                if raw:
                    txt = raw.decode("utf-16-le" if uni else "latin1", "replace")
            if txt.strip():
                print(f"[D] pid={pid} ({tag}): {txt.strip()[:300]}")

        elif code == EXIT_PROCESS_DEBUG_EVENT:
            ec = struct.unpack_from("<I", buf, 16)[0]
            cl = names.get(pid)
            tag = cl.split("--type=")[1].split()[0] if cl and "--type=" in cl else "browser"
            print(f"[-] EXIT pid={pid} ({tag}) exitCode={ec:#010x}")
            h = procs.pop(pid, None)
            if h:
                k32.CloseHandle(h)

        k32.ContinueDebugEvent(pid, tid, DBG_CONTINUE)

    try:
        k32.TerminateProcess(pi.hProcess, 0)
    except Exception:
        pass
    print("\n=== dumps written ===")
    for f in os.listdir(outdir):
        print("  ", f, os.path.getsize(os.path.join(outdir, f)) // 1024, "KB")


if __name__ == "__main__":
    main()
