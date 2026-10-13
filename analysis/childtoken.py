"""Read the real security token of Bluebook's GPU child, live.

Launches the exe under DEBUG_PROCESS (so every descendant is suspended at
creation and we hold a full-access handle), waits for the process whose command
line says --type=gpu-process, and dumps its token:

  - user SID and whether it is deny-only
  - TokenIsRestricted and the restricting SID list
  - every group SID in the token, with attributes
  - integrity level and whether the token is an AppContainer

That token is what performs the access check on <install>\\icudtl.dat, so it is
the direct evidence for which SID can and cannot open the file.

Usage: python analysis/childtoken.py <exe-path> [seconds]
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

TOKEN_QUERY = 0x0008
TokenUser = 1
TokenGroups = 2
TokenPrivileges = 3
TokenRestrictedSids = 11
TokenIntegrityLevel = 25
TokenIsAppContainer = 29
TokenAppContainerSid = 31
TokenIsRestricted = 40

SE_GROUP_MANDATORY = 0x1
SE_GROUP_ENABLED_BY_DEFAULT = 0x2
SE_GROUP_ENABLED = 0x4
SE_GROUP_OWNER = 0x8
SE_GROUP_USE_FOR_DENY_ONLY = 0x10
SE_GROUP_LOGON_ID = 0xC0000000
SE_GROUP_RESOURCE = 0x20000000

WELL_KNOWN = {
    "S-1-0-0": "Nobody", "S-1-1-0": "Everyone", "S-1-2-0": "Local",
    "S-1-3-0": "Creator Owner", "S-1-5-7": "Anonymous",
    "S-1-5-11": "Authenticated Users", "S-1-5-12": "RESTRICTED",
    "S-1-5-18": "SYSTEM", "S-1-5-19": "LocalService",
    "S-1-5-20": "NetworkService", "S-1-5-32-544": "Administrators",
    "S-1-5-32-545": "Users", "S-1-5-32-546": "Guests",
    "S-1-5-32-559": "Perf Log Users", "S-1-5-32-580": "Remote Mgmt",
    "S-1-16-0": "Untrusted IL", "S-1-16-4096": "Low IL",
    "S-1-16-8192": "Medium IL", "S-1-16-12288": "High IL",
    "S-1-16-16384": "System IL",
}

adv.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                                 ctypes.POINTER(wintypes.HANDLE)]
adv.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int,
                                    ctypes.c_void_p, wintypes.DWORD,
                                    ctypes.POINTER(wintypes.DWORD)]
adv.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p,
                                       ctypes.POINTER(wintypes.LPWSTR)]
adv.LookupPrivilegeNameW.argtypes = [wintypes.LPCWSTR, ctypes.c_void_p,
                                     wintypes.LPWSTR,
                                     ctypes.POINTER(wintypes.DWORD)]
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


class LUID(ctypes.Structure):
    _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]


def sid_to_str(p):
    out = wintypes.LPWSTR()
    if adv.ConvertSidToStringSidW(ctypes.c_void_p(p), ctypes.byref(out)):
        s = out.value
        k32.LocalFree(out)
        return s
    return "?"


_priv_names = {}


def priv_name(low, high):
    """Resolve a LUID to its privilege name via LookupPrivilegeNameW."""
    key = (low, high)
    if key in _priv_names:
        return _priv_names[key]
    luid = LUID()
    luid.LowPart, luid.HighPart = low, high
    size = wintypes.DWORD(0)
    adv.LookupPrivilegeNameW(None, ctypes.byref(luid), None, ctypes.byref(size))
    buf = ctypes.create_unicode_buffer(size.value + 1)
    if not adv.LookupPrivilegeNameW(None, ctypes.byref(luid), buf,
                                    ctypes.byref(size)):
        return f"LUID {high:#x}:{low:#x}"
    _priv_names[key] = buf.value
    return buf.value


def name_of(sid):
    return WELL_KNOWN.get(sid, "")


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
    length = struct.unpack("<H", ln)[0]
    ptr = struct.unpack("<I", bp)[0]
    raw = read_mem(h, ptr, min(length, 8192))
    return raw.decode("utf-16-le", "replace") if raw else None


def get_tok_info(htok, cls):
    size = wintypes.DWORD(0)
    adv.GetTokenInformation(htok, cls, None, 0, ctypes.byref(size))
    buf = ctypes.create_string_buffer(size.value)
    if not adv.GetTokenInformation(htok, cls, buf, size.value,
                                   ctypes.byref(size)):
        return None
    return buf.raw


# GetTokenInformation returns structures laid out for THIS (64-bit) process, so
# a PSID is 8 bytes. SID_AND_ATTRIBUTES is { PSID; DWORD Attributes; padding }.
PTR = ctypes.sizeof(ctypes.c_void_p)
SAA = PTR + 4
SAA_STRIDE = (SAA + 7) & ~7


def tok_user(t):
    sidptr = struct.unpack_from("<Q" if PTR == 8 else "<I", t, 0)[0]
    attr = struct.unpack_from("<I", t, PTR)[0]
    return sidptr, attr


def tok_label(t):
    sidptr = struct.unpack_from("<Q" if PTR == 8 else "<I", t, 0)[0]
    return sidptr


def tok_groups(t):
    cnt = struct.unpack_from("<I", t, 0)[0]
    # TOKEN_GROUPS is { DWORD GroupCount; SID_AND_ATTRIBUTES Groups[]; } and the
    # array is naturally aligned to the pointer size.
    base = 4 if PTR == 4 else 8
    out = []
    for i in range(cnt):
        o = base + i * SAA_STRIDE
        sidptr = struct.unpack_from("<Q" if PTR == 8 else "<I", t, o)[0]
        attr = struct.unpack_from("<I", t, o + PTR)[0]
        out.append((sidptr, attr))
    return out


def dump_token(pid, h):
    htok = wintypes.HANDLE()
    if not adv.OpenProcessToken(h, TOKEN_QUERY, ctypes.byref(htok)):
        # Fall back to a fresh handle.
        h2 = k32.OpenProcess(PROCESS_QUERY_INFORMATION, False, pid)
        if not h2 or not adv.OpenProcessToken(h2, TOKEN_QUERY,
                                              ctypes.byref(htok)):
            print(f"    OpenProcessToken failed err={ctypes.get_last_error()}")
            return
    print(f"  --- token of pid={pid} ---")

    t = get_tok_info(htok, TokenUser)
    if t:
        sidptr, attr = tok_user(t)
        s = sid_to_str(sidptr)
        deny = " (DENY-ONLY)" if attr & SE_GROUP_USE_FOR_DENY_ONLY else ""
        print(f"    TokenUser: {s}  {name_of(s)}{deny}")

    t = get_tok_info(htok, TokenIsRestricted)
    if t:
        print(f"    TokenIsRestricted: {struct.unpack_from('<I', t, 0)[0]}")

    t = get_tok_info(htok, TokenIsAppContainer)
    if t:
        print(f"    TokenIsAppContainer: {struct.unpack_from('<I', t, 0)[0]}")

    t = get_tok_info(htok, TokenIntegrityLevel)
    if t:
        sidptr = tok_label(t)
        print(f"    IntegrityLevel SID: {sid_to_str(sidptr)}")

    t = get_tok_info(htok, TokenGroups)
    if t:
        groups = tok_groups(t)
        print(f"    TokenGroups ({len(groups)}):")
        for sidptr, attr in groups:
            s = sid_to_str(sidptr)
            flags = []
            if attr & SE_GROUP_MANDATORY:
                flags.append("MANDATORY")
            if attr & SE_GROUP_ENABLED:
                flags.append("ENABLED")
            if attr & SE_GROUP_ENABLED_BY_DEFAULT:
                flags.append("DEFAULT")
            if attr & SE_GROUP_USE_FOR_DENY_ONLY:
                flags.append("DENY-ONLY")
            if attr & SE_GROUP_LOGON_ID == SE_GROUP_LOGON_ID:
                flags.append("LOGON")
            if attr & SE_GROUP_RESOURCE:
                flags.append("RESOURCE")
            print(f"      {s:<46} {name_of(s):<18} {'|'.join(flags)}")

    # A restricted token carries a second SID list. An access check must pass
    # BOTH the normal groups check and the restricting list check.
    t = get_tok_info(htok, TokenRestrictedSids)
    if t:
        groups = tok_groups(t)
        print(f"    TokenRestrictedSids ({len(groups)})  <-- the restricting list:")
        for sidptr, attr in groups:
            s = sid_to_str(sidptr)
            print(f"      {s:<46} {name_of(s)}")
    else:
        print("    TokenRestrictedSids: <unavailable>")

    # Privileges matter: SeChangeNotifyPrivilege is what normally lets a user
    # traverse directories it has no traverse ACE on. Chromium's sandbox
    # removes it from children.
    t = get_tok_info(htok, TokenPrivileges)
    if t:
        cnt = struct.unpack_from("<I", t, 0)[0]
        # TOKEN_PRIVILEGES = { DWORD Count; LUID_AND_ATTRIBUTES[] } with no
        # pointer member, so the array is 4-byte aligned (LUID 8 + attrs 4).
        base = 4
        stride = 12
        print(f"    TokenPrivileges ({cnt}):")
        for i in range(cnt):
            o = base + i * stride
            low, high = struct.unpack_from("<II", t, o)
            attr = struct.unpack_from("<I", t, o + 8)[0]
            nm = priv_name(low, high)
            state = "ENABLED" if attr & 0x2 else "disabled"
            print(f"      {nm:<34} {state}  (attrs={attr:#x})")
    else:
        print("    TokenPrivileges: <unavailable>")


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
    print(f"CHILD TOKEN PROBE  exe={exe}")
    print("=" * 78)

    procs = {}
    seen = set()
    ev = ctypes.create_string_buffer(512)
    t0 = time.time()
    while time.time() - t0 < budget:
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
            if cl and "--type=gpu-process" in cl and pid not in seen:
                seen.add(pid)
                print(f"\n[+] gpu-process pid={pid}")
                print(f"    {cl[:300]}")
                # Re-read a few times: Chromium lowers the token shortly after
                # CreateProcess, so the first read may be the pre-sandbox token.
                for attempt in range(6):
                    print(f"    (read #{attempt + 1})")
                    dump_token(pid, procs[pid])
                    time.sleep(0.15)
                break
        k32.ContinueDebugEvent(pid, tid, DBG_CONTINUE)

    try:
        k32.TerminateProcess(pi.hProcess, 0)
    except Exception:
        pass


if __name__ == "__main__":
    main()
