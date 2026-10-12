"""Capture OutputDebugString output system-wide via the DBWIN_BUFFER shared
memory (no admin required). Chromium's CHECK/DLOG failures in the GPU process
are emitted through OutputDebugString, so this can reveal the GPU process's
actual crash reason.

Usage: python analysis/dbwin.py [seconds]
Run it, then launch Bluebook from the crashing path.
"""
import ctypes
import sys
import threading
import time
from ctypes import wintypes

k32 = ctypes.WinDLL("kernel32", use_last_error=True)

DBWIN_BUFFER_READY = "DBWIN_BUFFER_READY"
DBWIN_DATA_READY = "DBWIN_DATA_READY"
DBWIN_BUFFER = "DBWIN_BUFFER"
EVENT_MODIFY_STATE = 0x0002
SYNCHRONIZE = 0x00100000

k32.CreateFileMappingW.restype = wintypes.HANDLE
k32.CreateFileMappingW.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                                   wintypes.DWORD, wintypes.DWORD, wintypes.LPCWSTR]
k32.CreateEventW.restype = wintypes.HANDLE
k32.CreateEventW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR]
k32.MapViewOfFile.restype = ctypes.c_void_p
k32.MapViewOfFile.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD,
                              wintypes.DWORD, ctypes.c_size_t]
k32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
k32.SetEvent.argtypes = [wintypes.HANDLE]
k32.OpenEventW.restype = wintypes.HANDLE

PAGE_READWRITE = 0x04
FILE_MAP_READ = 0x0004
BUFFER_SIZE = 4096


def main():
    seconds = float(sys.argv[1]) if len(sys.argv) > 1 else 60.0

    # INVALID_HANDLE_VALUE must be a full-width -1, not 0xFFFFFFFF.
    hmap = k32.CreateFileMappingW(ctypes.c_void_p(-1), None, PAGE_READWRITE, 0,
                                  BUFFER_SIZE, DBWIN_BUFFER)
    if not hmap:
        print(f"CreateFileMapping failed: {ctypes.get_last_error()}")
        return
    buf = k32.MapViewOfFile(hmap, FILE_MAP_READ, 0, 0, BUFFER_SIZE)
    if not buf:
        print(f"MapViewOfFile failed: {ctypes.get_last_error()}")
        return

    ack = k32.CreateEventW(None, False, False, DBWIN_BUFFER_READY)
    ready = k32.CreateEventW(None, False, False, DBWIN_DATA_READY)
    print(f"DBWIN listener active for {seconds}s  (buffer@{buf:#x})", flush=True)
    k32.SetEvent(ack)

    t0 = time.time()
    seen = set()
    while time.time() - t0 < seconds:
        rc = k32.WaitForSingleObject(ready, 500)
        if rc != 0:
            continue
        pid = ctypes.c_uint32.from_address(buf).value
        text = ctypes.string_at(buf + 4, 4000).split(b"\0", 1)[0]
        try:
            line = text.decode("latin1", "replace").strip()
        except Exception:
            line = repr(text)
        if line and line not in seen:
            seen.add(line)
            el = time.time() - t0
            print(f"[{el:7.3f}] pid={pid:<7} {line[:600]}", flush=True)
        k32.SetEvent(ack)


if __name__ == "__main__":
    main()
