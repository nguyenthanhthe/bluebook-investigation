"""Find which restricted-SID set reproduces the observed split:
the GPU child can open icudtl.dat OUTSIDE the profile but gets
ACCESS_DENIED INSIDE it.

Chromium's Windows sandbox gives sandboxed children a restricted token. An
access check against a restricted token must pass BOTH the normal check and the
restricted check, so only ACEs matching the restricted SID list grant access.

This enumerates candidate restricted SID sets and reports the access result for
each location, so the discriminating SID becomes an observation rather than a
guess.

Usage: python analysis/restricted_token_matrix.py
"""
import ctypes
import os
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
k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                            ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                            wintypes.HANDLE]
k32.CloseHandle.argtypes = [wintypes.HANDLE]

INVALID = 0xFFFFFFFFFFFFFFFF

LOCATIONS = [
    ("PROFILE", r"C:\Users\Admin\AppData\Local\Programs\bluebook\icudtl.dat"),
    ("C:\\TempBB", r"C:\TempBB\icudtl.dat"),
    ("D:\\rea-tools", r"D:\rea-tools\icudtl.dat"),
    ("C:\\Users\\Public", r"C:\Users\Public\icudtl.dat"),
]

# Candidate restricted SID sets, mirroring plausible sandbox token shapes.
CANDIDATES = [
    ("RESTRICTED only", ["S-1-5-12"]),
    ("RESTRICTED+Users", ["S-1-5-12", "S-1-5-32-545"]),
    ("RESTRICTED+AuthUsers", ["S-1-5-12", "S-1-5-11"]),
    ("RESTRICTED+Everyone", ["S-1-5-12", "S-1-5-0"]),
    ("Users only", ["S-1-5-32-545"]),
    ("Everyone only", ["S-1-5-0"]),
    ("RESTRICTED+Users+Everyone", ["S-1-5-12", "S-1-5-32-545", "S-1-5-0"]),
]


class SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]


def try_open(path):
    h = k32.CreateFileW(path, GENERIC_READ, 0x1 | 0x2 | 0x4, None,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None)
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
    # keep only the principal names
    return " | ".join(l.split(":")[0].strip() for l in lines)


def main():
    print("=" * 100)
    print("RESTRICTED-TOKEN MATRIX  (0 = opened, 5 = ACCESS_DENIED)")
    print("=" * 100)

    print("\nDACL principals per location:")
    for label, path in LOCATIONS:
        print(f"  {label:<16} {acl(path)}")

    htok = wintypes.HANDLE()
    adv.OpenProcessToken(k32.GetCurrentProcess(),
                         TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY |
                         TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID,
                         ctypes.byref(htok))

    print("\nnormal token:")
    for label, path in LOCATIONS:
        e = try_open(path)
        print(f"  {label:<16} err={e}")

    header = f"\n{'restricted SID set':<28}" + "".join(
        f"{lbl[:15]:>17}" for lbl, _ in LOCATIONS)
    print(header)
    print("-" * len(header))

    for name, sids in CANDIDATES:
        n = len(sids)
        arr = (SID_AND_ATTRIBUTES * n)()
        ok = True
        for i, s in enumerate(sids):
            p = ctypes.c_void_p()
            if not adv.ConvertStringSidToSidW(s, ctypes.byref(p)):
                ok = False
                break
            arr[i].Sid = p
            arr[i].Attributes = 0
        if not ok:
            continue
        hres = wintypes.HANDLE()
        if not adv.CreateRestrictedToken(htok, DISABLE_MAX_PRIVILEGE,
                                        0, None, 0, None, n,
                                        ctypes.byref(arr),
                                        ctypes.byref(hres)):
            print(f"  {name:<28} CreateRestrictedToken failed "
                  f"err={ctypes.get_last_error()}")
            continue
        if not adv.ImpersonateLoggedOnUser(hres):
            print(f"  {name:<28} impersonate failed "
                  f"err={ctypes.get_last_error()}")
            continue
        try:
            row = "".join(f"{try_open(p):>17}" for _, p in LOCATIONS)
        finally:
            adv.RevertToSelf()
            k32.CloseHandle(hres)
        print(f"  {name:<28}{row}")

    print("\nObserved real behaviour of the GPU child:")
    print("  PROFILE -> ACCESS_DENIED (5)   [read from its own dump]")
    print("  C:\\TempBB / D: / Public -> works [path matrix, prior session]")
    print("  => the row matching that pattern identifies the discriminating SID.")


if __name__ == "__main__":
    main()
