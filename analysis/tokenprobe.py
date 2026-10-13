"""Query the real security token of Bluebook's sandboxed children.

Launches Bluebook under DEBUG_PROCESS (so every descendant is suspended at
creation and we hold a handle), then for each child reports:
  - token user SID
  - whether the token is restricted (TokenIsRestricted)
  - the full enabled SID list (TokenGroups)
  - integrity level (TokenIntegrityLevel)
  - whether it is an AppContainer and its AppContainer SID

Because Chromium lowers the token shortly after CreateProcess, the token is
re-read on every debug event until it stabilises, which catches the final
sandboxed token before the child dies.

Requires elevation.

Usage: python analysis/tokenprobe.py <exe-path> [seconds]
"""
import ctypes
import struct
import sys
import time
from ctypes import wintypes

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
adv = ctypes.WinDLL("advapi32", use_last_error=True)

DEBUG_PROCESS = 0x00000001
CREATE_NEW_CONSOLE = 0x00000010
DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001
CREATE_PROCESS_DEBUG_EVENT = 3
EXIT_PROCESS_DEBUG_EVENT = 5

TOKEN_QUERY = 0x0008
TokenUser = 1
TokenGroups = 2
TokenIntegrityLevel = 25
TokenIsAppContainer = 29
TokenAppContainerSid = 31
TokenIsRestricted = 40

SE_GROUP_ENABLED = 0x00000004
SE_GROUP_INTEGRITY = 0x00000020

k32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                                 ctypes.POINTER(wintypes.HANDLE)]
adv.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int,
                                    ctypes.c_void_p, wintypes.DWORD,
                                    ctypes.POINTER(wintypes.DWORD)]
adv.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p,
                                       ctypes.POINTER(wintypes.LPWSTR)]

WELL_KNOWN = {
    "S-1-0-0": "Nobody", "S-1-1-0": "Everyone", "S-1-2-0": "Local",
    "S-1-2-1": "ConsoleLogon", "S-1-3-0": "CreatorOwner",
    "S-1-5-7": "Anonymous", "S-1-5-11": "AuthenticatedUsers",
    "S-1-5-12": "RESTRICTED", "S-1-5-18": "SYSTEM",
    "S-1-5-19": "LOCAL SERVICE", "S-1-5-20": "NETWORK SERVICE",
    "S-1-5-32-544": "Administrators", "S-1-5-32-545": "Users",
    "S-1-5-32-546": "Guests", "S-1-5-32-547": "PowerUsers",
    "S-1-5-32-555": "RemoteDesktopUsers",
    "S-1-5-32-559": "PerformanceLogUsers",
    "S-1-16-0": "UNTRUSTED", "S-1-16-4096": "LOW",
    "S-1-16-8192": "MEDIUM", "S-1-16-12288": "HIGH",
    "S-1-16-16384": "SYSTEM", "S-1-16-20480": "PROTECTED",
}

INTEGRITY = {0: "Untrusted", 0x1000: "Low", 0x2000: "Medium",
             0x2100: "MediumPlus", 0x3000: "High", 0x4000: "System"}


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


class SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]


def sid_str(p):
    out = wintypes.LPWSTR()
    if adv.ConvertSidToStringSidW(p, ctypes.byref(out)):
        s = out.value
        k32.LocalFree(out)
        return s
    return "?"


def tok_info(h, cls, size_hint=0x400):
    need = wintypes.DWORD(0)
    adv.GetTokenInformation(h, cls, None, 0, ctypes.byref(need))
    if need.value == 0:
        return None
    buf = ctypes.create_string_buffer(need.value)
    if not adv.GetTokenInformation(h, cls, buf, need.value, ctypes.byref(need)):
        return None
    return buf.raw


def describe(h):
    """Return a dict describing the token, or None."""
    htok = wintypes.HANDLE()
    if not k32.OpenProcessToken(h, TOKEN_QUERY, ctypes.byref(htok)):
        return None
    try:
        d = {}
        raw = tok_info(htok, TokenUser)
        if raw:
            d["user"] = sid_str(ctypes.c_void_p(struct.unpack_from("<Q", raw, 0)[0]))

        raw = tok_info(htok, TokenGroups)
        groups = []
        if raw:
            n = struct.unpack_from("<I", raw, 0)[0]
            for i in range(n):
                o = 8 + i * (8 + 4)
                sidp = struct.unpack_from("<Q", raw, o)[0]
                attr = struct.unpack_from("<I", raw, o + 8)[0]
                s = sid_str(ctypes.c_void_p(sidp))
                if attr & SE_GROUP_ENABLED and not (attr & SE_GROUP_INTEGRITY):
                    groups.append(s)
            d["groups"] = groups

        raw = tok_info(htok, TokenIntegrityLevel)
        if raw:
            n = struct.unpack_from("<I", raw, 0)[0]
            o = 8
            sidp = struct.unpack_from("<Q", raw, o)[0]
            s = sid_str(ctypes.c_void_p(sidp))
            lvl = int(s.rsplit("-", 1)[-1]) if "-" in s else -1
            d["integrity"] = INTEGRITY.get(lvl, f"{s}")

        raw = tok_info(htok, TokenIsAppContainer, 4)
        if raw:
            d["appcontainer"] = bool(struct.unpack_from("<I", raw, 0)[0])
        raw = tok_info(htok, TokenAppContainerSid)
        if raw:
            n = struct.unpack_from("<I", raw, 0)[0]
            if n:
                d["ac_sid"] = sid_str(ctypes.c_void_p(struct.unpack_from("<Q", raw, 8)[0]))
        raw = tok_info(htok, TokenIsRestricted, 4)
        if raw:
            d["restricted"] = bool(struct.unpack_from("<I", raw, 0)[0])
        return d
    finally:
        k32.CloseHandle(htok)


def fmt(d):
    if not d:
        return "  <token unavailable>"
    lines = []
    lines.append(f"    user        : {d.get('user')} "
                 f"[{WELL_KNOWN.get(d.get('user'), '')}]")
    lines.append(f"    restricted  : {d.get('restricted')}")
    lines.append(f"    appcontainer: {d.get('appcontainer')} {d.get('ac_sid', '')}")
    lines.append(f"    integrity   : {d.get('integrity')}")
    gs = d.get("groups", [])
    lines.append(f"    enabled SIDs ({len(gs)}):")
    for g in gs:
        lines.append(f"      {g:<60} {WELL_KNOWN.get(g, '')}")
    return "\n".join(lines)


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
        print("CreateProcess failed", ctypes.get_last_error())
        return

    procs, names, seen = {}, {}, {}
    ev = ctypes.create_string_buffer(512)
    t0 = time.time()
    while time.time() - t0 < budget:
        if not k32.WaitForDebugEvent(ctypes.byref(ev), 300):
            continue
        buf = ev.raw
        code, pid, tid = struct.unpack_from("<III", buf, 0)
        if code == CREATE_PROCESS_DEBUG_EVENT:
            h = struct.unpack_from("<Q", buf, 24)[0]
            procs[pid] = h
            names[pid] = f"pid{pid}"
        if pid in procs and code != EXIT_PROCESS_DEBUG_EVENT:
            d = describe(procs[pid])
            if d:
                sig = (d.get("user"), tuple(d.get("groups", [])),
                       d.get("integrity"), d.get("restricted"),
                       d.get("appcontainer"), d.get("ac_sid"))
                if seen.get(pid) != sig:
                    seen[pid] = sig
                    print(f"\n=== pid={pid} token change (event code={code}) ===")
                    print(fmt(d))
        if code == EXIT_PROCESS_DEBUG_EVENT:
            ec = struct.unpack_from("<I", buf, 16)[0]
            print(f"\n--- pid={pid} EXIT {ec:#010x} ---")
            h = procs.pop(pid, None)
            if h:
                k32.CloseHandle(h)
        k32.ContinueDebugEvent(pid, tid,
                               DBG_EXCEPTION_NOT_HANDLED
                               if code == 1 else DBG_CONTINUE)
    try:
        k32.TerminateProcess(pi.hProcess, 0)
    except Exception:
        pass


if __name__ == "__main__":
    main()
