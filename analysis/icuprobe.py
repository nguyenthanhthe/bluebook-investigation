"""Catch the GPU child at its ICU abort and read the failure it recorded.

The child crash function (RVA 0x19E0680, base/i18n/icu_util.cc) records why ICU
data could not be loaded into globals before it aborts:

  _DAT_0b416014  icu_data_ptr    -1 == ICU data was never loaded
  _DAT_0b5a1004  GetLastError()  the Win32 error of the failed load (0 == ok)
  _DAT_0b5a1008  secondary error
  _DAT_0b5a100c  path buffer     the path it tried to open

This launches the exe under DEBUG_PROCESS, waits for any process to hit the
in-image int3 (RVA 0x19E0914), and prints those globals read live from the
suspended child. Run it against an install inside the user profile (dies) and
one outside it (works) to see the difference.

Usage: python analysis/icuprobe.py <exe-path> [seconds]
"""
import ctypes
import os
import struct
import sys
import time
from ctypes import wintypes

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll")

DEBUG_PROCESS = 0x00000001
CREATE_NEW_CONSOLE = 0x00000010
DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001

CREATE_PROCESS_DEBUG_EVENT = 3
EXCEPTION_DEBUG_EVENT = 1
EXIT_PROCESS_DEBUG_EVENT = 5

ProcessWow64Information = 26
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

CRASH_IMAGE_RVA = 0x19E0914

# Globals written by the ICU init path. Ghidra emits these as ABSOLUTE addresses
# assuming the preferred image base 0x400000, so the file RVA is label-0x400000.
IMAGE_BASE_PREF = 0x400000
GLOBALS = [
    ("icu_data_ptr", 0x0B416014, "u32"),
    ("GetLastError", 0x0B5A1004, "u32"),
    ("err_secondary", 0x0B5A1008, "u32"),
    ("path_buf", 0x0B5A100C, "str"),
    ("state_ff8", 0x0B5A0FF8, "u32"),
    ("state_ffc", 0x0B5A0FFC, "u32"),
    ("state_1000", 0x0B5A1000, "u32"),
]

WINERR = {
    0: "ERROR_SUCCESS", 2: "ERROR_FILE_NOT_FOUND", 3: "ERROR_PATH_NOT_FOUND",
    5: "ERROR_ACCESS_DENIED", 32: "ERROR_SHARING_VIOLATION",
    87: "ERROR_INVALID_PARAMETER", 126: "ERROR_MOD_NOT_FOUND",
    998: "ERROR_NOACCESS (invalid memory access)", 1008: "ERROR_NO_TOKEN",
    1920: "ERROR_CANT_ACCESS_FILE", 1812: "ERROR_BAD_IMAGE_FORMAT",
}

k32.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p,
                                  ctypes.c_void_p, ctypes.c_size_t,
                                  ctypes.POINTER(ctypes.c_size_t)]
k32.ReadProcessMemory.restype = wintypes.BOOL
k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
k32.OpenProcess.restype = wintypes.HANDLE
ntdll.NtQueryInformationProcess.argtypes = [
    wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.ULONG,
    ctypes.POINTER(wintypes.ULONG)]


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
    _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
                ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD)]


def read_mem(h, addr, n):
    buf = ctypes.create_string_buffer(n)
    got = ctypes.c_size_t(0)
    if not k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, n,
                                 ctypes.byref(got)):
        return None
    return buf.raw[: got.value]


def cmdline(h):
    """Command line of a 32-bit process, read from its WOW64 PEB."""
    peb32 = ctypes.c_void_p(0)
    ret = wintypes.ULONG(0)
    if ntdll.NtQueryInformationProcess(h, ProcessWow64Information,
                                       ctypes.byref(peb32),
                                       ctypes.sizeof(peb32),
                                       ctypes.byref(ret)) != 0 or not peb32.value:
        return None
    b = read_mem(h, peb32.value + 0x10, 4)
    if not b:
        return None
    params = struct.unpack("<I", b)[0]
    ln = read_mem(h, params + 0x40, 2)
    bp = read_mem(h, params + 0x44, 4)
    if not ln or not bp:
        return None
    length = struct.unpack("<H", ln)[0]
    ptr = struct.unpack("<I", bp)[0]
    raw = read_mem(h, ptr, min(length, 8192))
    return raw.decode("utf-16-le", "replace") if raw else None


def tag_of(cl):
    if cl and "--type=" in cl:
        return cl.split("--type=")[1].split()[0].split("=")[0].strip('"')
    return "browser"


def show_globals(h, base, label):
    print(f"  --- ICU globals in {label} (image base {base:#x}) ---")
    for name, abs_label, kind in GLOBALS:
        rva = abs_label - IMAGE_BASE_PREF
        va = base + rva
        raw = read_mem(h, va, 0x208)
        if raw is None:
            print(f"    {name:<16} @{va:#010x}  <unreadable>")
            continue
        if kind == "u32":
            v = struct.unpack_from("<I", raw, 0)[0]
            note = ""
            if name == "GetLastError":
                note = f"  -> {WINERR.get(v, 'Win32 error %d' % v)}"
            if name == "icu_data_ptr" and v == 0xFFFFFFFF:
                note = "  -> -1 = ICU data NOT loaded"
            print(f"    {name:<16} @{va:#010x} = {v:#010x} ({v}){note}")
        else:
            # The buffer is a narrow (ANSI/UTF-8) path; show both readings.
            narrow = raw.split(b"\x00")[0]
            print(f"    {name:<16} @{va:#010x} (latin1) = {narrow[:200].decode('latin1', 'replace')!r}")
            wide = raw.split(b"\x00\x00")[0]
            if len(wide) >= 4:
                print(f"    {name:<16} @{va:#010x} (utf16)  = {wide.decode('utf-16-le', 'replace')[:200]!r}")


def main():
    exe = sys.argv[1]
    budget = float(sys.argv[2]) if len(sys.argv) > 2 else 40.0

    si = STARTUPINFO()
    si.cb = ctypes.sizeof(si)
    pi = PROCESS_INFORMATION()
    cmd = ctypes.create_unicode_buffer(f'"{exe}"')
    if not k32.CreateProcessW(exe, cmd, None, None, False,
                              DEBUG_PROCESS | CREATE_NEW_CONSOLE, None,
                              exe.rsplit("\\", 1)[0], ctypes.byref(si),
                              ctypes.byref(pi)):
        print(f"CreateProcess failed err={ctypes.get_last_error()}")
        return

    print("=" * 78)
    print(f"ICU PROBE  exe={exe}")
    print("=" * 78)
    print(f"debugging tree of pid={pi.dwProcessId}, budget={budget}s\n")

    procs, bases, names, hit = {}, {}, {}, set()
    ev = ctypes.create_string_buffer(512)
    t0 = time.time()

    while time.time() - t0 < budget:
        if not k32.WaitForDebugEvent(ctypes.byref(ev), 400):
            continue
        buf = ev.raw
        code, pid, tid = struct.unpack_from("<III", buf, 0)

        if code == CREATE_PROCESS_DEBUG_EVENT:
            h = struct.unpack_from("<Q", buf, 24)[0]
            base = struct.unpack_from("<Q", buf, 40)[0]
            procs[pid], bases[pid] = h, base
            cl = cmdline(h)
            if cl is None:
                h2 = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                                     False, pid)
                if h2:
                    cl = cmdline(h2)
                    k32.CloseHandle(h2)
            names[pid] = cl
            if cl and "--type=gpu-process" in cl:
                print(f"[+] CREATE pid={pid} tag=gpu-process base={base:#x}")
                print(f"    {cl[:400]}")

        elif code == EXCEPTION_DEBUG_EVENT:
            exc = struct.unpack_from("<I", buf, 16)[0]
            addr = struct.unpack_from("<Q", buf, 32)[0]
            first = struct.unpack_from("<I", buf, 168)[0]
            base = bases.get(pid, 0)
            rva = addr - base if base else None
            if rva == CRASH_IMAGE_RVA and pid not in hit:
                hit.add(pid)
                label = f"pid={pid} ({tag_of(names.get(pid))})"
                print(f"\n[!!] {label} hit the ICU int3 at RVA {rva:#x} "
                      f"(code={exc:#x} firstChance={first})")
                show_globals(procs[pid], base, label)
                print("    (reading while the child is suspended)")
                # Let the abort propagate, as it does without a debugger.
                k32.ContinueDebugEvent(pid, tid, DBG_EXCEPTION_NOT_HANDLED)
                continue

        k32.ContinueDebugEvent(pid, tid, DBG_CONTINUE)

    if not hit:
        print("\n[ok] no process hit the ICU int3 within the budget")
    try:
        k32.TerminateProcess(pi.hProcess, 0)
    except Exception:
        pass


if __name__ == "__main__":
    main()
