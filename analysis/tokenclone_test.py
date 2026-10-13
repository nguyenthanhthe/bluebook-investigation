"""Clone the GPU child's REAL token and use it to open icudtl.dat.

analysis/childtoken.py shows the child's token is restricted with the SID list
{Users, Everyone, RESTRICTED, ...}. Synthetic reconstructions of that shape do
NOT reproduce the ACCESS_DENIED, so something about the real token is missed.

This script removes the guesswork: it launches the app under DEBUG_PROCESS,
duplicates the *actual* token of the GPU child, impersonates it in this process,
and tries to open icudtl.dat at each candidate location. The result is produced
by the child's own credentials, not a reconstruction.

Usage: python analysis/tokenclone_test.py <exe-path> [seconds]
"""
import ctypes
import struct
import sys
import time
from ctypes import wintypes

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
adv = ctypes.WinDLL("advapi32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll")

DEBUG_PROCESS = 0x00000001
CREATE_NEW_CONSOLE = 0x00000010
DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001
CREATE_PROCESS_DEBUG_EVENT = 3

ProcessWow64Information = 26
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

TOKEN_DUPLICATE = 0x0002
TOKEN_QUERY = 0x0008
TOKEN_IMPERSONATE = 0x0004
TOKEN_ALL_ACCESS = 0x000F01FF
SecurityImpersonation = 2
TokenImpersonation = 2
GENERIC_READ = 0x80000000
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x80
INVALID = 0xFFFFFFFFFFFFFFFF

LOCATIONS = [
    ("PROFILE  (broken)", r"C:\Users\Admin\AppData\Local\Programs\bluebook\icudtl.dat"),
    ("Public\\bbt2 (works)", r"C:\Users\Public\bbt2\icudtl.dat"),
    ("D:\\bluebook_test (works)", r"D:\bluebook_test\icudtl.dat"),
    ("D:\\Temp\\bbcopy (works)", r"D:\Temp\bbcopy\icudtl.dat"),
    ("C:\\TempBB (works)", r"C:\TempBB\icudtl.dat"),
    ("Public loose (mine)", r"C:\Users\Public\icudtl.dat"),
]

# Directories along the profile path, to find which component refuses traverse.
PATH_COMPONENTS = [
    "C:\\",
    "C:\\Users",
    "C:\\Users\\Admin",
    "C:\\Users\\Admin\\AppData",
    "C:\\Users\\Admin\\AppData\\Local",
    "C:\\Users\\Admin\\AppData\\Local\\Programs",
    "C:\\Users\\Admin\\AppData\\Local\\Programs\\bluebook",
]

FILE_TRAVERSE = 0x00000020
FILE_LIST_DIRECTORY = 0x00000001

WINERR = {0: "OK", 2: "FILE_NOT_FOUND", 3: "PATH_NOT_FOUND",
          5: "ACCESS_DENIED", 32: "SHARING_VIOLATION", 87: "INVALID_PARAMETER"}

adv.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                                 ctypes.POINTER(wintypes.HANDLE)]
adv.DuplicateTokenEx.argtypes = [
    wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, ctypes.c_int,
    ctypes.c_int, ctypes.POINTER(wintypes.HANDLE)]
adv.ImpersonateLoggedOnUser.argtypes = [wintypes.HANDLE]
adv.RevertToSelf.restype = wintypes.BOOL
k32.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p,
                                  ctypes.c_void_p, ctypes.c_size_t,
                                  ctypes.POINTER(ctypes.c_size_t)]
k32.ReadProcessMemory.restype = wintypes.BOOL
k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
k32.OpenProcess.restype = wintypes.HANDLE
k32.CreateFileW.restype = wintypes.HANDLE
k32.CreateFileW.argtypes = [
    wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
    wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
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
    raw = read_mem(h, struct.unpack("<I", bp)[0], min(struct.unpack("<H", ln)[0], 8192))
    return raw.decode("utf-16-le", "replace") if raw else None


def open_as(path, access, flags=FILE_ATTRIBUTE_NORMAL):
    h = k32.CreateFileW(path, access, 7, None, OPEN_EXISTING, flags, None)
    if h == INVALID or h == -1:
        return ctypes.get_last_error()
    k32.CloseHandle(h)
    return 0


def try_open(path):
    return open_as(path, GENERIC_READ)


def probe(label, htok):
    print(f"\n[{label}]")
    if not adv.ImpersonateLoggedOnUser(htok):
        print(f"  impersonate failed err={ctypes.get_last_error()}")
        return
    try:
        print("  -- files --")
        for name, path in LOCATIONS:
            e = try_open(path)
            print(f"    {name:<26} err={e:<4} {WINERR.get(e, '')}")
        print("  -- directory traverse (FILE_TRAVERSE) --")
        for d in PATH_COMPONENTS:
            et = open_as(d, FILE_TRAVERSE, 0x02000000)  # BACKUP_SEMANTICS
            el = open_as(d, FILE_LIST_DIRECTORY, 0x02000000)
            print(f"    {d:<52} traverse={et}  list={el}")
    finally:
        adv.RevertToSelf()


def main():
    exe = sys.argv[1]
    budget = float(sys.argv[2]) if len(sys.argv) > 2 else 30.0
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
    print(f"REAL-CHILD-TOKEN ACCESS TEST  exe={exe}")
    print("=" * 78)

    procs = {}
    done = False
    ev = ctypes.create_string_buffer(512)
    t0 = time.time()
    while time.time() - t0 < budget and not done:
        if not k32.WaitForDebugEvent(ctypes.byref(ev), 400):
            continue
        buf = ev.raw
        code, pid, tid = struct.unpack_from("<III", buf, 0)
        if code == CREATE_PROCESS_DEBUG_EVENT:
            h = struct.unpack_from("<Q", buf, 24)[0]
            procs[pid] = h
            cl = cmdline(h)
            if cl is None:
                h2 = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                                     False, pid)
                if h2:
                    cl = cmdline(h2)
                    k32.CloseHandle(h2)
            if cl and "--type=gpu-process" in cl:
                time.sleep(0.4)  # let the token settle into its sandboxed form
                htok = wintypes.HANDLE()
                if not adv.OpenProcessToken(h, TOKEN_DUPLICATE | TOKEN_QUERY |
                                            TOKEN_IMPERSONATE,
                                            ctypes.byref(htok)):
                    print(f"OpenProcessToken failed err={ctypes.get_last_error()}")
                    done = True
                else:
                    dup = wintypes.HANDLE()
                    if not adv.DuplicateTokenEx(htok, TOKEN_ALL_ACCESS, None,
                                                SecurityImpersonation,
                                                TokenImpersonation,
                                                ctypes.byref(dup)):
                        print(f"DuplicateTokenEx failed err={ctypes.get_last_error()}")
                    else:
                        print(f"\ngpu-process pid={pid}; using its duplicated token")
                        probe("cloned GPU-child token", dup)
                        done = True
        k32.ContinueDebugEvent(pid, tid, DBG_CONTINUE)

    if not done:
        print("\nno gpu-process seen within the budget")
    try:
        k32.TerminateProcess(pi.hProcess, 0)
    except Exception:
        pass


if __name__ == "__main__":
    main()
