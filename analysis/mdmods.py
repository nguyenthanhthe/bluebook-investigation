"""List modules loaded in a minidump, flagging graphics-related ones.

Usage: python analysis/mdmods.py <dump.dmp>
"""
import struct
import sys

b = open(sys.argv[1], "rb").read()


def u32(o):
    return struct.unpack_from("<I", b, o)[0]


def u64(o):
    return struct.unpack_from("<Q", b, o)[0]


def s(rva):
    n = u32(rva)
    return b[rva + 4:rva + 4 + n].decode("utf-16-le", "replace")


nd, dr = u32(8), u32(12)
st = {}
for i in range(nd):
    o = dr + i * 12
    st.setdefault(u32(o), (u32(o + 4), u32(o + 8)))

_, mr = st[4]
n = u32(mr)
names = []
for i in range(n):
    o = mr + 4 + i * 108
    names.append((u32(o + 8), s(u32(o + 20))))

GRAPHICS = ["egl", "gles", "d3d", "dxgi", "swift", "vulkan", "angle", "opengl",
            "nvwgf", "igd", "libgl", "osmesa", "dcomp", "dwmapi", "d2d1", "dwrite"]

print(f"total modules: {n}")
print("\n--- graphics-related modules present ---")
found = False
for size, nm in names:
    short = nm.replace("\\\\?\\", "").split("\\")[-1]
    if any(g in short.lower() for g in GRAPHICS):
        print(f"  {size:>10}  {short}")
        found = True
if not found:
    print("  (none)")

print("\n--- all module short names ---")
shorts = sorted({nm.replace("\\\\?\\", "").split("\\")[-1] for _, nm in names})
for i in range(0, len(shorts), 4):
    print("  " + ", ".join(shorts[i:i + 4]))
