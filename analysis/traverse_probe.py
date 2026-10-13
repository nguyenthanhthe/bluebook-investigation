"""Pin the exact reason the sandboxed GPU child is denied inside the profile.

The child's token (analysis/childtoken.py) is restricted with these enabled
SIDs: Everyone, Users, INTERACTIVE, logon session. Reproducing that set alone
does NOT deny <install>\\icudtl.dat, because a token built with
DISABLE_MAX_PRIVILEGE still holds SeChangeNotifyPrivilege ("Bypass traverse
checking"), which lets it walk directories it has no traverse ACE on.

This script therefore also removes SeChangeNotifyPrivilege, and prints the
mandatory-integrity label of each directory along both paths.

Usage: python analysis/traverse_probe.py
"""
import ctypes
import os
import struct
import subprocess
from ctypes import wintypes

adv = ctypes.WinDLL("advapi32", use_last_error=True)
k32 = ctypes.WinDLL("kernel32", use_last_error=True)

TOKEN_DUPLICATE = 0x0002
TOKEN_QUERY = 0x0008
TOKEN_ASSIGN_PRIMARY = 0x0001
TOKEN_ADJUST_DEFAULT = 0x0080
TOKEN_ADJUST_SESSIONID = 0x0100
DISABLE_MAX_PRIVILEGE = 0x1
GENERIC_READ = 0x80000000
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x80
INVALID = 0xFFFFFFFFFFFFFFFF

USER_SID = "S-1-5-21-1177312959-3883492366-3801192801-1001"
ENABLED_SIDS = ["S-1-1-0", "S-1-5-32-545", "S-1-5-4"]

class LUID(ctypes.Structure):
    _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]


# SE_CHANGE_NOTIFY_NAME / SeChangeNotifyPrivilege
adv.LookupPrivilegeValueW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR,
                                      ctypes.POINTER(LUID)]
adv.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                                 ctypes.POINTER(wintypes.HANDLE)]
adv.CreateRestrictedToken.argtypes = [
    wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
    wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p,
    ctypes.POINTER(wintypes.HANDLE)]
adv.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR,
                                       ctypes.POINTER(ctypes.c_void_p)]
adv.ImpersonateLoggedOnUser.argtypes = [wintypes.HANDLE]
adv.RevertToSelf.restype = wintypes.BOOL
adv.GetNamedSecurityInfoW.argtypes = [
    wintypes.LPCWSTR, ctypes.c_int, wintypes.DWORD, ctypes.c_void_p,
    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
adv.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p,
                                       ctypes.POINTER(wintypes.LPWSTR)]
k32.GetCurrentProcess.restype = wintypes.HANDLE
k32.CreateFileW.restype = wintypes.HANDLE
k32.CreateFileW.argtypes = [
    wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
    wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
k32.LocalFree.argtypes = [ctypes.c_void_p]

SE_FILE_OBJECT = 1
LABEL_SECURITY_INFORMATION = 0x00000010


class SAA(ctypes.Structure):
    _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]


def sid(s):
    p = ctypes.c_void_p()
    adv.ConvertStringSidToSidW(s, ctypes.byref(p))
    return p


def try_open(path):
    h = k32.CreateFileW(path, GENERIC_READ, 7, None, OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL, None)
    if h == INVALID or h == -1:
        return ctypes.get_last_error()
    k32.CloseHandle(h)
    return 0


def label_of(path):
    """Mandatory integrity label (SACL) of a filesystem object."""
    psd = ctypes.c_void_p()
    r = adv.GetNamedSecurityInfoW(path, SE_FILE_OBJECT,
                                  LABEL_SECURITY_INFORMATION, None, None,
                                  None, None, ctypes.byref(psd))
    if r != 0 or not psd.value:
        return f"<none/err {r}>"
    # SD structure: Revision(1) Sbz1(1) Control(2) Owner(4) Group(4) Sacl(4) Dacl(4)
    ctrl = struct.unpack_from("<H", ctypes.string_at(psd.value + 2, 2))[0]
    sacl = struct.unpack_from("<I", ctypes.string_at(psd.value + 16, 4))[0]
    k32.LocalFree(psd)
    if not (ctrl & 0x0010) or not sacl:  # SE_SACL_PRESENT
        return "(no SACL)"
    # ACL: Revision(1) Sbz1(1) AclSize(2) AceCount(2) Sbz2(2)
    n = struct.unpack_from("<H", ctypes.string_at(sacl + 4, 2))[0]
    out = []
    off = sacl + 8
    for _ in range(n):
        ace_type = ctypes.string_at(off, 1)[0]
        ace_size = struct.unpack_from("<H", ctypes.string_at(off + 2, 2))[0]
        if ace_type in (0x11, 0x12, 0x13):  # SYSTEM_MANDATORY_LABEL_*
            # ACE: Type(1) Flags(1) Size(2) Mask(4) Sid(...)
            mask = struct.unpack_from("<I", ctypes.string_at(off + 4, 4))[0]
            sp = off + 8
            o = wintypes.LPWSTR()
            adv.ConvertSidToStringSidW(ctypes.c_void_p(sp), ctypes.byref(o))
            out.append(f"{o.value} mask={mask:#x}")
            k32.LocalFree(o)
        off += ace_size
    return " ; ".join(out) if out else "(no label ACE)"


def main():
    print("=" * 96)
    print("TRAVERSE / INTEGRITY PROBE")
    print("=" * 96)

    print("\nIntegrity labels along both paths:")
    for d in [r"C:\\", r"C:\Users", r"C:\Users\Admin",
              r"C:\Users\Admin\AppData", r"C:\Users\Admin\AppData\Local",
              r"C:\Users\Admin\AppData\Local\Programs",
              r"C:\Users\Admin\AppData\Local\Programs\bluebook",
              r"C:\TempBB", r"D:\\", r"C:\Users\Public"]:
        print(f"  {d:<52} {label_of(d)}")

    loc = [
        ("PROFILE", r"C:\Users\Admin\AppData\Local\Programs\bluebook\icudtl.dat"),
        ("TempBB", r"C:\TempBB\icudtl.dat"),
        ("rea-tools", r"D:\rea-tools\icudtl.dat"),
        ("Public", r"C:\Users\Public\icudtl.dat"),
    ]

    htok = wintypes.HANDLE()
    adv.OpenProcessToken(k32.GetCurrentProcess(),
                         TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY |
                         TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID,
                         ctypes.byref(htok))

    luid = LUID()
    have_luid = adv.LookupPrivilegeValueW(None, "SeChangeNotifyPrivilege",
                                          ctypes.byref(luid))

    header = f"\n{'case':<58}" + "".join(f"{l[:14]:>16}" for l, _ in loc)
    print(header)
    print("-" * len(header))

    for keep_traverse in (True, False):
        dis = [sid(USER_SID)]
        disarr = (ctypes.c_void_p * len(dis))(*dis)
        arr = (SAA * len(ENABLED_SIDS))()
        for i, s in enumerate(ENABLED_SIDS):
            arr[i].Sid = sid(s)
            arr[i].Attributes = 0
        delpriv = (LUID * 1)(luid) if (have_luid and not keep_traverse) else None
        hres = wintypes.HANDLE()
        ok = adv.CreateRestrictedToken(
            htok, DISABLE_MAX_PRIVILEGE, len(dis), disarr,
            1 if delpriv else 0, ctypes.cast(delpriv, ctypes.c_void_p) if delpriv else None,
            len(ENABLED_SIDS), ctypes.byref(arr), ctypes.byref(hres))
        name = ("Everyone+Users+INTERACTIVE, traverse KEPT"
                if keep_traverse else
                "Everyone+Users+INTERACTIVE, SeChangeNotify REMOVED")
        if not ok:
            print(f"  {name:<58} create failed err={ctypes.get_last_error()}")
            continue
        if not adv.ImpersonateLoggedOnUser(hres):
            print(f"  {name:<58} impersonate failed err={ctypes.get_last_error()}")
            k32.CloseHandle(hres)
            continue
        try:
            row = "".join(f"{try_open(p):>16}" for _, p in loc)
        finally:
            adv.RevertToSelf()
            k32.CloseHandle(hres)
        print(f"  {name:<58}{row}")

    print("\nObserved real GPU child: PROFILE -> 5 ACCESS_DENIED ; outside -> opens.")


if __name__ == "__main__":
    main()
