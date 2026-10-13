"""Prove the mechanism: a Chromium-style RESTRICTED token cannot open
icudtl.dat inside the user profile, but can outside it.

Chromium's Windows sandbox gives sandboxed children (gpu-process, renderer) a
restricted token: the user SID is set to DENY-ONLY and only the RESTRICTED SID
(S-1-5-12) plus the logon SID remain enabled. So an ACE granting the *user*
full control no longer applies, and only ACEs for Everyone/Users/RESTRICTED do.

This script:
  1. prints the DACL of icudtl.dat in the profile install and in a relocated copy
  2. builds a restricted token (S-1-5-12) from the current token
  3. impersonates it and tries to open both files, reporting the Win32 error

Usage: python analysis/restricted_token_test.py
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
TOKEN_IMPERSONATE = 0x0004
TOKEN_ASSIGN_PRIMARY = 0x0001
TOKEN_ADJUST_DEFAULT = 0x0080
TOKEN_ADJUST_SESSIONID = 0x0100
DISABLE_MAX_PRIVILEGE = 0x1
MAXIMUM_ALLOWED = 0x02000000
GENERIC_READ = 0x80000000
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x80
SECURITY_IMPERSONATION = 2

adv.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
adv.CreateRestrictedToken.argtypes = [
    wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
    wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p,
    ctypes.POINTER(wintypes.HANDLE),
]
adv.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
adv.ImpersonateLoggedOnUser.argtypes = [wintypes.HANDLE]
adv.RevertToSelf.restype = wintypes.BOOL
k32.GetCurrentProcess.restype = wintypes.HANDLE
k32.CreateFileW.restype = wintypes.HANDLE
k32.CreateFileW.argtypes = [
    wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
    wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
]
k32.CloseHandle.argtypes = [wintypes.HANDLE]

INVALID_HANDLE = ctypes.c_void_p(-1).value

PROFILE_FILE = r"C:\Users\Admin\AppData\Local\Programs\bluebook\icudtl.dat"
OUTSIDE_FILE = r"C:\TempBB\icudtl.dat"
ALT_OUTSIDE = r"D:\rea-tools\icudtl.dat"
PUBLIC_FILE = r"C:\Users\Public\icudtl.dat"


def try_open(path, label):
    h = k32.CreateFileW(path, GENERIC_READ, 0x1 | 0x2 | 0x4, None,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None)
    if h == INVALID_HANDLE or h == -1 or h == 0xFFFFFFFFFFFFFFFF:
        err = ctypes.get_last_error()
        print(f"    OPEN {label:<10} FAILED  err={err} ({os.strerror(err) if err < 200 else 'Win32 ' + str(err)})")
        return False
    k32.CloseHandle(h)
    print(f"    OPEN {label:<10} OK")
    return True


def acl(path):
    print(f"  --- DACL: {path} ---")
    if not os.path.exists(path):
        print("    (file not present)")
        return
    try:
        out = subprocess.run(["icacls", path], capture_output=True, text=True,
                             timeout=30).stdout
        for line in out.splitlines():
            print("    " + line.rstrip())
    except Exception as e:
        print(f"    icacls failed: {e}")


def main():
    print("=" * 78)
    print("RESTRICTED-TOKEN FILE ACCESS TEST")
    print("=" * 78)

    for p in (PROFILE_FILE, OUTSIDE_FILE, ALT_OUTSIDE):
        acl(p)

    print("\n  --- normal token (current process) ---")
    try_open(PROFILE_FILE, "profile")
    try_open(OUTSIDE_FILE, "outside")

    # Build a restricted token with S-1-5-12 (RESTRICTED), like Chromium's sandbox.
    htok = wintypes.HANDLE()
    if not adv.OpenProcessToken(k32.GetCurrentProcess(),
                               TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY |
                               TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID,
                               ctypes.byref(htok)):
        print(f"  OpenProcessToken failed err={ctypes.get_last_error()}")
        return

    sid = ctypes.c_void_p()
    if not adv.ConvertStringSidToSidW("S-1-5-12", ctypes.byref(sid)):
        print(f"  ConvertStringSidToSid failed err={ctypes.get_last_error()}")
        return

    class SID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]

    sids = (SID_AND_ATTRIBUTES * 1)()
    sids[0].Sid = sid
    sids[0].Attributes = 0

    hrestricted = wintypes.HANDLE()
    ok = adv.CreateRestrictedToken(
        htok, DISABLE_MAX_PRIVILEGE,
        0, None,                 # no SIDs to disable
        0, None,                 # no privileges to delete
        1, ctypes.byref(sids),   # restrict to S-1-5-12
        ctypes.byref(hrestricted),
    )
    if not ok:
        print(f"  CreateRestrictedToken failed err={ctypes.get_last_error()}")
        return
    print("\n  restricted token created (RESTRICTED SID S-1-5-12, max privilege disabled)")

    print("  --- impersonating restricted token ---")
    if not adv.ImpersonateLoggedOnUser(hrestricted):
        print(f"  ImpersonateLoggedOnUser failed err={ctypes.get_last_error()}")
        return
    try:
        try_open(PROFILE_FILE, "profile")
        try_open(OUTSIDE_FILE, "outside")
        try_open(ALT_OUTSIDE, "D:\\Temp")
    finally:
        adv.RevertToSelf()

    print("\n  interpretation:")
    print("    - OK under the normal token but FAILED (5/ACCESS_DENIED) under the")
    print("      restricted token reproduces the GPU child's exact failure.")
    print("    - That is why relocating the install outside the profile fixes it:")
    print("      C:\\ and D:\\ grant Everyone/Users read, the profile does not.")


if __name__ == "__main__":
    main()
