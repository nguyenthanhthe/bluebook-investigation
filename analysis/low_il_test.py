"""Is the LOW integrity level the discriminator, rather than the SID set?

analysis/restricted_token_childset.py shows that a restricted token with
Everyone/Users/INTERACTIVE enabled still OPENS icudtl.dat inside the profile.
The real GPU child is denied. The remaining difference is that the child also
runs at LOW mandatory integrity (S-1-16-4096).

This script builds a restricted token matching the child's enabled SID set and
then sets its integrity level, so the effect of integrity can be separated from
the effect of the SID list.

Usage: python analysis/low_il_test.py
"""
import ctypes
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

TokenIntegrityLevel = 25
SE_GROUP_INTEGRITY = 0x00000020

USER_SID = "S-1-5-21-1177312959-3883492366-3801192801-1001"
ENABLED = ["S-1-1-0", "S-1-5-32-545", "S-1-5-4"]

LOCATIONS = [
    ("PROFILE", r"C:\Users\Admin\AppData\Local\Programs\bluebook\icudtl.dat"),
    ("TempBB", r"C:\TempBB\icudtl.dat"),
    ("rea-tools", r"D:\rea-tools\icudtl.dat"),
    ("Public-bbt2", r"C:\Users\Public\bbt2\icudtl.dat"),
]

# Files created at each level of the profile path (see --walk). Their inherited
# integrity label shows where Low IL stops being able to read.
WALK = [
    ("C:\\Users", r"C:\Users\zz_il_probe.txt"),
    ("C:\\Users\\Admin", r"C:\Users\Admin\zz_il_probe.txt"),
    ("...\\Admin\\AppData", r"C:\Users\Admin\AppData\zz_il_probe.txt"),
    ("...\\AppData\\Local", r"C:\Users\Admin\AppData\Local\zz_il_probe.txt"),
    ("...\\Local\\Programs", r"C:\Users\Admin\AppData\Local\Programs\zz_il_probe.txt"),
    ("...\\Programs\\bluebook", r"C:\Users\Admin\AppData\Local\Programs\bluebook\zz_il_probe.txt"),
]


class LUID(ctypes.Structure):
    _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]


class SAA(ctypes.Structure):
    _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]


class TOKEN_MANDATORY_LABEL(ctypes.Structure):
    _fields_ = [("Label", SAA)]


adv.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                                 ctypes.POINTER(wintypes.HANDLE)]
adv.CreateRestrictedToken.argtypes = [
    wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
    wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p,
    ctypes.POINTER(wintypes.HANDLE)]
adv.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR,
                                       ctypes.POINTER(ctypes.c_void_p)]
adv.SetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int,
                                    ctypes.c_void_p, wintypes.DWORD]
adv.ImpersonateLoggedOnUser.argtypes = [wintypes.HANDLE]
adv.RevertToSelf.restype = wintypes.BOOL
k32.GetCurrentProcess.restype = wintypes.HANDLE
k32.CreateFileW.restype = wintypes.HANDLE
k32.CreateFileW.argtypes = [
    wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
    wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]


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


def make_token(htok, low):
    dis = [sid(USER_SID)]
    arr = (SAA * len(ENABLED))()
    for i, s in enumerate(ENABLED):
        arr[i].Sid = sid(s)
        arr[i].Attributes = 0
    hres = wintypes.HANDLE()
    if not adv.CreateRestrictedToken(
            htok, DISABLE_MAX_PRIVILEGE, len(dis),
            (ctypes.c_void_p * len(dis))(*dis), 0, None, len(ENABLED),
            ctypes.byref(arr), ctypes.byref(hres)):
        return None, ctypes.get_last_error()
    if low:
        label = TOKEN_MANDATORY_LABEL()
        label.Label.Sid = sid("S-1-16-4096")  # Low mandatory level
        label.Label.Attributes = SE_GROUP_INTEGRITY
        if not adv.SetTokenInformation(hres, TokenIntegrityLevel,
                                       ctypes.byref(label),
                                       ctypes.sizeof(label)):
            err = ctypes.get_last_error()
            k32.CloseHandle(hres)
            return None, err
    return hres, 0


def main():
    print("=" * 92)
    print("INTEGRITY-LEVEL TEST  (0 = opened, 5 = ACCESS_DENIED)")
    print("=" * 92)

    htok = wintypes.HANDLE()
    adv.OpenProcessToken(k32.GetCurrentProcess(),
                         TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY |
                         TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID,
                         ctypes.byref(htok))

    header = f"\n{'token':<52}" + "".join(f"{l[:12]:>15}" for l, _ in LOCATIONS)
    print(header)
    print("-" * len(header))

    for low in (False, True):
        hres, err = make_token(htok, low)
        name = ("Everyone+Users+INTERACTIVE, Medium IL"
                if not low else
                "Everyone+Users+INTERACTIVE, LOW IL  <-- child")
        if not hres:
            print(f"  {name:<52} build failed err={err}")
            continue
        if not adv.ImpersonateLoggedOnUser(hres):
            print(f"  {name:<52} impersonate failed err={ctypes.get_last_error()}")
            k32.CloseHandle(hres)
            continue
        try:
            row = "".join(f"{try_open(p):>15}" for _, p in LOCATIONS)
        finally:
            adv.RevertToSelf()
            k32.CloseHandle(hres)
        print(f"  {name:<52}{row}")

    print("\nReal GPU child (its own recorded GetLastError): PROFILE -> 5.")

    # Walk the profile path: a file created at each level inherits that level's
    # integrity label, so the first denial marks where Low IL is cut off.
    print("\n--- path walk: Low IL reading a file created at each level ---")
    hres, err = make_token(htok, True)
    if hres and adv.ImpersonateLoggedOnUser(hres):
        try:
            for label, path in WALK:
                e = try_open(path)
                mark = "" if e == 0 else "   <-- denied from here down"
                print(f"    {label:<26} err={e}{mark}")
        finally:
            adv.RevertToSelf()
            k32.CloseHandle(hres)


if __name__ == "__main__":
    main()
