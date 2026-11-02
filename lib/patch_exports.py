#!/usr/bin/env python3
"""Hide Wine's query exports in a built runner by renaming the export-name strings
(last char), so GetProcAddress() can't resolve them. Binary-safe: same length, which
preserves the sorted export table used by GetProcAddress's binary search. Internal
callers resolve these by implementation, not by the exported name, so nothing breaks.

Usage: patch_exports.py <runner-dir>   (scans every PE ntdll.dll / kernel32.dll)
"""
import sys, pathlib

# null-terminated export names -> same-length replacement (final byte changed)
PAIRS = [
    (b"wine_get_version\x00",          b"wine_get_versiox\x00"),
    (b"wine_get_build_id\x00",         b"wine_get_build_ix\x00"),
    (b"wine_get_host_version\x00",     b"wine_get_host_versiox\x00"),
    (b"wine_get_unix_file_name\x00",   b"wine_get_unix_file_namx\x00"),
    (b"wine_get_dos_file_name\x00",    b"wine_get_dos_file_namx\x00"),
]

def patch_file(p: pathlib.Path) -> int:
    try:
        d = p.read_bytes()
    except Exception:
        return 0
    orig = d
    changed = 0
    for old, new in PAIRS:
        assert len(old) == len(new)
        n = d.count(old)
        if n:
            d = d.replace(old, new)
            changed += n
    if d != orig:
        try:
            p.chmod(0o755)
        except Exception:
            pass
        p.write_bytes(d)
    return changed

def main():
    if len(sys.argv) != 2:
        print(__doc__); sys.exit(2)
    root = pathlib.Path(sys.argv[1])
    total = 0
    for name in ("ntdll.dll", "kernel32.dll"):
        for f in root.rglob(name):
            if "-windows" in str(f.parent):  # PE builtins only
                c = patch_file(f)
                if c:
                    print(f"  {f.relative_to(root)}: {c} export(s) hidden")
                    total += c
    print(f"[exports] {total} export name(s) renamed")

if __name__ == "__main__":
    main()
