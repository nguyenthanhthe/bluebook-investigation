"""Reproduce the GPU child's exact file-access result using its real token.

analysis/childtoken.py reads the live token of Bluebook's GPU child. On the
broken (in-profile) install that token is a RESTRICTED, LOW-integrity token
whose *enabled* SIDs are only:

    S-1-1-0        Everyone       (MANDATORY|ENABLED|DEFAULT)
    S-1-5-32-545   Users          (MANDATORY|ENABLED|DEFAULT)
    S-1-5-4        INTERACTIVE    (MANDATORY|ENABLED|DEFAULT)
    S-1-5-5-0-...  logon session  (MANDATORY|ENABLED|DEFAULT|LOGON)
    S-1-16-4096    Low IL

while the user's own SID, Administrators, Authenticated Users, Local, etc. are
all DENY-ONLY (they no longer grant access).

This script builds restricted tokens matching that shape and reports the Win32
error for opening icudtl.dat in each install location, so the discriminator
becomes an observation rather than a guess.

Usage: python analysis/restricted_token_childset.py
"""
import ctypes
import os
import subprocess
import sys
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

LOCATIONS = [
    ("PROFILE", r"C:\Users\Admin\AppData\Local\Programs\bluebook\icudtl.dat"),
    ("TempBB", r"C:\TempBB\icudtl.dat"),
    ("D:\rea-tools", r"D:\rea-tools\icudtl.dat"),
    ("Public", r"C:\Users\Public\icudtl.dat"),
]

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
k32.GetCurrentProcess.restype = wintypes.HANDLE
k32.CreateFileW.restype = wintypes.HANDLE
k32.CreateFileW.argtypes = [
    wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
    wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]


class SAA(ctypes.Structure):
    _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]


def try_open(path):
    h = k32.CreateFileW(path, GENERIC_READ, 7, None, OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL, None)
    if h == INVALID or h == -1:
        return ctypes.get_last_error()
    k32.CloseHandle(h)
    return 0


def acl(path):
    if not os.path.exists(path):
        return "(absent)"
    out = subprocess.run(["icacls", path], capture_output=True, text=True,
                         timeout=30).stdout
    lines = [l.strip() for l in out.splitlines() if l.strip()
             and "Successfully" not in l]
    return " | ".join(l.split(":")[0].strip() for l in lines)


def sid(s):
    p = ctypes.c_void_p()
    adv.ConvertStringSidToSidW(s, ctypes.byref(p))
    return p


# The first case is the observed GPU-child token; the rest isolate one SID each.
CASES = [
    ("Everyone+Users+INTERACTIVE (child)", ["S-1-1-0", "S-1-5-32-545", "S-1-5-4"], True),
    ("Everyone only", ["S-1-1-0"], True),
    ("Users only", ["S-1-5-32-545"], True),
    ("INTERACTIVE only", ["S-1-5-4"], True),
    ("Authenticated Users only", ["S-1-5-11"], True),
    ("Everyone+Users+INTERACTIVE (user ENABLED)", ["S-1-1-0", "S-1-5-32-545", "S-1-5-4"], False),
]


def main():
    print("=" * 100)
    print("RESTRICTED-TOKEN REPRODUCTION OF THE GPU CHILD  (0 = opened, 5 = ACCESS_DENIED)")
    print("=" * 100)

    print("\nDACL principals per location:")
    for label, path in LOCATIONS:
        print(f"  {label:<14} {acl(path)}")

    htok = wintypes.HANDLE()
    if not adv.OpenProcessToken(k32.GetCurrentProcess(),
                                TOKEN_DUPLICATE | TOKEN_QUERY |
                                TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT |
                                TOKEN_ADJUST_SESSIONID, ctypes.byref(htok)):
        print(f"OpenProcessToken failed err={ctypes.get_last_error()}")
        return

    print("\nnormal token (this process):")
    for label, path in LOCATIONS:
        print(f"  {label:<14} err={try_open(path)}")

    header = f"\n{'restricted token':<44}" + "".join(
        f"{lbl[:16]:>18}" for lbl, _ in LOCATIONS)
    print(header)
    print("-" * len(header))

    for name, sids, deny_user in CASES:
        dis = [sid(USER_SID)] if deny_user else []
        arr = (SAA * len(sids))()
        for i, s in enumerate(sids):
            arr[i].Sid = sid(s)
            arr[i].Attributes = 0
        hres = wintypes.HANDLE()
        if not adv.CreateRestrictedToken(
                htok, DISABLE_MAX_PRIVILEGE, len(dis),
                (ctypes.c_void_p * len(dis))(*dis) if dis else None,
                0, None, len(sids), ctypes.byref(arr), ctypes.byref(hres)):
            print(f"  {name:<44} create failed err={ctypes.get_last_error()}")
            continue
        if not adv.ImpersonateLoggedOnUser(hres):
            print(f"  {name:<44} impersonate failed err={ctypes.get_last_error()}")
            k32.CloseHandle(hres)
            continue
        try:
            row = "".join(f"{try_open(p):>18}" for _, p in LOCATIONS)
        finally:
            adv.RevertToSelf()
            k32.CloseHandle(hres)
        print(f"  {name:<44}{row}")

    print("\nObserved GPU child (read live from its own memory):")
    print("  PROFILE  -> 5 ACCESS_DENIED   (GetLastError recorded in the child)")
    print("  outside  -> opens fine        (no crash outside the profile)")
    print("\n=> The row matching 5/0/0/? identifies the discriminating SID.")


if __name__ == "__main__":
    main()
