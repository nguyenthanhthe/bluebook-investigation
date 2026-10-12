"""Identify the two native N-API addons inside Bluebook's app.asar.

Run:  python analysis/addon_strings.py <extracted-asar-root>
"""
import re
import sys

TARGETS = [
    ("0168fb5f428ae50416523bf915b82f49.node", "addon-A"),
    ("f44e2a3d05186f76337879f7e48d7fdb.node", "addon-B"),
]

KEYWORDS = [
    "verify", "sign", "trust", "registr", "keytar", "credential", "secret",
    "hklm", "hkcu", "currentversion", "uninstall", "machine", "guid", "adapter",
    "wlan", "crypt", "cert", "token", "http", "fingerprint", "bios", "disk",
    "serial", "product", "wow64", "sysnative", "napi", "node_api", "getvalue",
    "setvalue", "enum", "displayname", "publisher",
]


def ascii_strings(data, minlen=6):
    return {m.decode("latin1") for m in re.findall(rb"[ -~]{%d,}" % minlen, data)}


def main():
    root = sys.argv[1].replace("\\", "/")
    for name, label in TARGETS:
        path = f"{root}/main/{name}"
        data = open(path, "rb").read()
        print(f"=== {label}  {name}  ({len(data)} bytes) ===")
        strings = ascii_strings(data)
        hits = sorted(
            s for s in strings if any(k in s.lower() for k in KEYWORDS)
        )
        for s in hits:
            print("   ", s)
        print()


if __name__ == "__main__":
    main()
