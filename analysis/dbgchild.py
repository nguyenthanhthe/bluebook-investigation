"""Launch Bluebook with DEBUG_PROCESS so every descendant (browser, GPU,
renderer, utility) is debugged automatically, and log each child's command
line plus any first-chance exception (address, module, faulting bytes) and
nearby ASCII strings from the child's memory.

This is how the GPU process's own crash reason becomes visible: the browser's
Crashpad only keeps the browser dump.

Usage: python analysis/dbgchild.py <exe-path> [seconds]
"""
import ctypes
import struct
import sys
import time
from ctypes import wintypes

k32 = ctypes.WinDLL("kernel32", use_last_error=True)

# Explicit prototypes: without them ctypes truncates 64-bit pointers/handles.
k32.ReadProcessMemory.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
    ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
]
k32.ReadProcessMemory.restype = wintypes.BOOL
k32.WaitForDebugEvent.argtypes = [ctypes.c_void_p, wintypes.DWORD]
k32.WaitForDebugEvent.restype = wintypes.BOOL
k32.ContinueDebugEvent.argtypes = [wintypes.DWORD, wintypes.DWORD, wintypes.DWORD]
k32.ContinueDebugEvent.restype = wintypes.BOOL
k32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
k32.CloseHandle.argtypes = [wintypes.HANDLE]
k32.CreateProcessW.restype = wintypes.BOOL

DEBUG_PROCESS = 0x00000001
CREATE_NEW_CONSOLE = 0x00000010
CREATE_NO_WINDOW = 0x08000000
INFINITE = 0xFFFFFFFF
DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001

EXCEPTION_DEBUG_EVENT = 1
CREATE_THREAD_DEBUG_EVENT = 2
CREATE_PROCESS_DEBUG_EVENT = 3
EXIT_THREAD_DEBUG_EVENT = 4
EXIT_PROCESS_DEBUG_EVENT = 5
LOAD_DLL_DEBUG_EVENT = 6
UNLOAD_DLL_DEBUG_EVENT = 7
OUTPUT_DEBUG_STRING_EVENT = 8
RIP_EVENT = 9

EXCEPTION_CODES = {
    0x80000003: "STATUS_BREAKPOINT (IMMEDIATE_CRASH / int3)",
    0xC0000005: "STATUS_ACCESS_VIOLATION",
    0x80000004: "STATUS_SINGLE_STEP",
    0xC000001D: "STATUS_ILLEGAL_INSTRUCTION",
    0xC0000094: "STATUS_INTEGER_DIVIDE_BY_ZERO",
    0xC0000374: "STATUS_HEAP_CORRUPTION",
    0xC0000409: "STATUS_STACK_BUFFER_OVERRUN (/GS)",
    0xC0000602: "STATUS_FAIL_FAST_EXCEPTION",
    0x4000001F: "WinRT originate (WER 0x4000001f)",
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
    ok = k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, n, ctypes.byref(got))
    if not ok:
        return None
    return buf.raw[: got.value]


def read_u32(h, addr):
    b = read_mem(h, addr, 4)
    return struct.unpack("<I", b)[0] if b and len(b) == 4 else None


def read_u16(h, addr):
    b = read_mem(h, addr, 2)
    return struct.unpack("<H", b)[0] if b and len(b) == 2 else None


def cmdline_of(h, teb_base):
    """Read the 32-bit child's command line via TEB->PEB->ProcessParameters."""
    try:
        peb = read_u32(h, teb_base + 0x30)
        if not peb:
            return None
        params = read_u32(h, peb + 0x10)
        if not params:
            return None
        # RTL_USER_PROCESS_PARAMETERS.CommandLine (UNICODE_STRING) @ +0x40
        length = read_u16(h, params + 0x40)
        bufptr = read_u32(h, params + 0x44)
        if not length or not bufptr:
            return None
        raw = read_mem(h, bufptr, min(length, 2048))
        return raw.decode("utf-16-le", "replace") if raw else None
    except Exception:
        return None


def scan_ascii(h, addr, n, minlen=8):
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
    budget = float(sys.argv[2]) if len(sys.argv) > 2 else 30.0

    si = STARTUPINFO()
    si.cb = ctypes.sizeof(si)
    pi = PROCESS_INFORMATION()
    cmd = ctypes.create_unicode_buffer(f'"{exe}"')
    cwd = exe.rsplit("\\", 1)[0]

    ok = k32.CreateProcessW(
        exe, cmd, None, None, False,
        DEBUG_PROCESS | CREATE_NEW_CONSOLE, None, cwd,
        ctypes.byref(si), ctypes.byref(pi),
    )
    if not ok:
        print(f"CreateProcess failed err={ctypes.get_last_error()}")
        return
    print(f"debugging tree of pid={pi.dwProcessId} (exe={exe})")
    print(f"budget={budget}s\n")

    procs = {}          # pid -> handle
    tebs = {}           # pid -> thread local base (first thread)
    names = {}          # pid -> exe name
    ev = ctypes.create_string_buffer(512)
    t0 = time.time()
    crashes = {}

    while time.time() - t0 < budget:
        if not k32.WaitForDebugEvent(ctypes.byref(ev), 400):
            continue
        buf = ev.raw
        code, pid, tid = struct.unpack_from("<III", buf, 0)

        if code == CREATE_PROCESS_DEBUG_EVENT:
            hprocess = struct.unpack_from("<Q", buf, 24)[0]
            base = struct.unpack_from("<Q", buf, 40)[0]
            teb = struct.unpack_from("<Q", buf, 56)[0]
            procs[pid] = hprocess
            tebs[pid] = teb
            cl = cmdline_of(hprocess, teb) if teb else None
            names[pid] = cl or f"<pid {pid}>"
            tag = "browser"
            if cl and "--type=" in cl:
                tag = cl.split("--type=")[1].split()[0]
            print(f"[+] CREATE pid={pid} type={tag} base={base:#x}")
            print(f"    cmd: {cl}")

        elif code == EXCEPTION_DEBUG_EVENT:
            exc_code = struct.unpack_from("<I", buf, 16)[0]
            exc_addr = struct.unpack_from("<Q", buf, 32)[0]
            nparam = struct.unpack_from("<I", buf, 40)[0]
            params = [struct.unpack_from("<Q", buf, 48 + i * 8)[0] for i in range(min(nparam, 4))]
            first = struct.unpack_from("<I", buf, 168)[0]
            desc = EXCEPTION_CODES.get(exc_code, "?")
            who = names.get(pid, str(pid))
            tag = "browser"
            if "--type=" in who:
                tag = who.split("--type=")[1].split()[0]
            print(f"\n[!] EXCEPTION pid={pid} ({tag}) tid={tid} code={exc_code:#010x} {desc}")
            print(f"    address={exc_addr:#x} firstChance={first} params={[hex(p) for p in params]}")
            h = procs.get(pid)
            if h:
                # Faulting bytes.
                fb = read_mem(h, exc_addr - 16, 48)
                if fb:
                    print(f"    bytes@{exc_addr-16:#x}: {fb.hex(' ')}")
                # Strings near the exception address and on the stack region.
                for label, addr in (("code-strings", exc_addr & ~0xFFF),):
                    ss = scan_ascii(h, addr, 0x1000)
                    if ss:
                        print(f"    {label}: {ss[:6]}")
                # Stack: EBP/ESP from the x86 context are not in the debug event,
                # so scan a window around the exception for a CHECK message.
                ss2 = scan_ascii(h, exc_addr, 0x2000)
                hits = [s for s in ss2 if any(k in s for k in (
                    "Check", "CHECK", "DCHECK", "FATAL", "gpu", "GPU", "sandbox",
                    "sandboxed", "failed", "Failed", "invalid", "Invalid",
                    "not found", "denied", "Access", "path", "Path", "angle",
                    "ANGLE", "d3d", "D3D", "vulkan", "Vulkan", "shader", "GL",
                ))]
                if hits:
                    print(f"    message candidates: {hits[:10]}")
            crashes.setdefault(pid, []).append((exc_code, exc_addr, first))
            k32.ContinueDebugEvent(pid, tid, DBG_EXCEPTION_NOT_HANDLED)
            continue

        elif code == OUTPUT_DEBUG_STRING_EVENT:
            # DEBUG_EVENT.OutputDebugString: lpDebugStringData@24, nDebugStringLength@32, fUnicode@34
            ptr = struct.unpack_from("<Q", buf, 24)[0]
            length = struct.unpack_from("<H", buf, 32)[0]
            unicode_flag = struct.unpack_from("<H", buf, 34)[0]
            who = names.get(pid, str(pid))
            tag = who.split("--type=")[1].split()[0] if "--type=" in who else "browser"
            h = procs.get(pid)
            txt = ""
            if h and ptr and length:
                raw = read_mem(h, ptr, length * (2 if unicode_flag else 1))
                if raw:
                    txt = raw.decode("utf-16-le" if unicode_flag else "latin1", "replace")
            if txt.strip():
                print(f"[D] OUTPUT_DEBUG pid={pid} ({tag}): {txt.strip()[:400]}")

        elif code == EXIT_PROCESS_DEBUG_EVENT:
            ec = struct.unpack_from("<I", buf, 16)[0]
            who = names.get(pid, str(pid))
            tag = "browser"
            if "--type=" in who:
                tag = who.split("--type=")[1].split()[0]
            print(f"[-] EXIT   pid={pid} type={tag} exitCode={ec} ({ec & 0xFFFFFFFF:#010x})")
            h = procs.pop(pid, None)
            if h:
                k32.CloseHandle(h)

        k32.ContinueDebugEvent(pid, tid, DBG_CONTINUE)

    print("\n=== crash summary ===")
    for pid, lst in crashes.items():
        who = names.get(pid, str(pid))
        tag = who.split("--type=")[1].split()[0] if "--type=" in who else "browser"
        print(f"  pid={pid} ({tag}) events={len(lst)}")
        for c, a, f in lst[:8]:
            print(f"     code={c:#010x} addr={a:#x} first={f}")
    try:
        k32.TerminateProcess(pi.hProcess, 0)
    except Exception:
        pass


if __name__ == "__main__":
    main()
