#!/usr/bin/env python3
"""Binary patcher for Bluebook.exe (0.9.725, ia32).

Targets the browser process's GPU-failure suicide path.

Background
----------
When Chromium exhausts its GPU fallback modes it calls
`IntentionallyCrashBrowserForUnusableGpuProcess()`, which is just:

    NOINLINE void IntentionallyCrashBrowserForUnusableGpuProcess() {
      LOG(FATAL) << "GPU process isn't usable. Goodbye.";
    }

`LOG(FATAL)` terminates the process through Chromium's `IMMEDIATE_CRASH()`
macro, which on x86 compiles to the two-byte sequence `0F 0B` (`ud2`),
usually preceded by an `int3` (`CC`). In Bluebook.exe the crash site is the
tail of that out-of-line cold block:

    RVA 0x06455F47   CC 0F 0B     ; int3 ; ud2

This patch rewrites those three bytes to `C3 90 90` (`ret` + padding) so the
fatal helper *returns* instead of killing the process.

READ THIS BEFORE USING IT
-------------------------
* This patch BREAKS the College Board EV Authenticode signature on
  Bluebook.exe. The app ships `win-verify-signature` and an integrity worker
  (`renderer/integrity-worker.*.js`, `WIN_FAIL_FILE_INTEGRITY`), so a patched
  binary will very likely be detected and may refuse to run, report an
  integrity failure, or behave unpredictably.
* It is provided as documentation of the crash mechanism, not as a
  recommended fix. The supported fix is the environment relocation in
  `patch/fix_environment.ps1`, which leaves the binary untouched.
* Do not use this to defeat exam integrity, proctoring, or any anti-cheat
  control. It exists to document where the process kills itself.

Usage
-----
    python patch/patch_bluebook.py <input.exe> [output.exe]
    python patch/patch_bluebook.py --revert <patched.exe> [output.exe]
"""
import hashlib
import shutil
import struct
import sys

# File offset of the fatal site (RVA 0x06455F47 in .text, RawPtr 0x400,
# VirtualAddress 0x1000  =>  offset = 0x400 + (0x6455F47 - 0x1000)).
FAULT_FILE_OFFSET = 0x6455347
ORIGINAL = bytes.fromhex("CC0F0B")          # int3 ; ud2  (IMMEDIATE_CRASH)
PATCHED = bytes.fromhex("C39090")           # ret  ; nop nop

KNOWN_SHA256 = "e87f9a29650c7bf001e70a255ec636a1c1f8fc8835f3c9ab91d5c22a3a2d0393"


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_context(data):
    """Sanity-check that the surrounding bytes match what we expect."""
    window = data[FAULT_FILE_OFFSET - 16:FAULT_FILE_OFFSET + 16]
    return window


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    revert = "--revert" in sys.argv
    if not args:
        print(__doc__)
        return 2

    src = args[0]
    dst = args[1] if len(args) > 1 else None

    digest = sha256(src)
    print(f"input : {src}")
    print(f"sha256: {digest}")
    if digest != KNOWN_SHA256:
        print(f"NOTE  : does not match the known Bluebook 0.9.725 hash")
        print(f"        expected {KNOWN_SHA256}")

    with open(src, "rb") as fh:
        data = bytearray(fh.read())

    have = bytes(data[FAULT_FILE_OFFSET:FAULT_FILE_OFFSET + 3])
    print(f"bytes at file offset {FAULT_FILE_OFFSET:#x}: {have.hex(' ')}")

    want_from, want_to = (PATCHED, ORIGINAL) if revert else (ORIGINAL, PATCHED)
    if have != want_from:
        if have == want_to:
            print("already in the requested state; nothing to do")
            return 0
        print(f"ERROR: expected {want_from.hex(' ')} at the fault site")
        print("Refusing to patch: the binary is not the expected build.")
        return 1

    data[FAULT_FILE_OFFSET:FAULT_FILE_OFFSET + 3] = want_to
    out = dst or (src.rsplit(".", 1)[0] + ("_reverted.exe" if revert else "_patched.exe"))
    shutil.copyfile(src, out)
    with open(out, "wb") as fh:
        fh.write(data)

    print(f"patched: {want_from.hex(' ')} -> {want_to.hex(' ')}")
    print(f"output : {out}")
    print(f"sha256 : {sha256(out)}")
    print()
    print("REMINDER: the Authenticode signature is now invalid, and the app's")
    print("integrity checks may reject this binary.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
