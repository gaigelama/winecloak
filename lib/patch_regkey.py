#!/usr/bin/env python3
r"""Rename Wine's config registry key  Software\Wine -> Software\<KEY>  in built
binaries, in BOTH encodings (ASCII and UTF-16LE). <KEY> is a 4-char name (same
length as "Wine", so offsets/relocations are unaffected). Pass the SAME --key to
every binary and to wine.inf in one patch run so the key stays coherent; use a
fresh random key per install so a detector can't hardcode the name.

Usage: patch_regkey.py --key <4chars> <file> [<file> ...]
"""
import sys, pathlib, argparse, secrets, string

def gen_key() -> str:
    alpha = string.ascii_letters
    alnum = string.ascii_letters + string.digits
    return secrets.choice(alpha) + "".join(secrets.choice(alnum) for _ in range(3))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--key", default=None, help="4-char replacement for 'Wine' (random if omitted)")
    ap.add_argument("files", nargs="+")
    a = ap.parse_args()
    key = a.key or gen_key()
    if len(key) != 4 or "\\" in key or not key.isalnum():
        sys.exit("--key must be 4 alphanumeric chars")

    A_OLD = b"Software\\Wine";            A_NEW = ("Software\\" + key).encode()
    U_OLD = "Software\\Wine".encode("utf-16-le"); U_NEW = ("Software\\" + key).encode("utf-16-le")

    patched = 0
    for f in a.files:
        p = pathlib.Path(f)
        try:
            d = p.read_bytes()
        except Exception:
            continue
        if A_OLD not in d and U_OLD not in d:
            continue
        na, nu = d.count(A_OLD), d.count(U_OLD)
        d = d.replace(A_OLD, A_NEW).replace(U_OLD, U_NEW)
        try:
            p.chmod(0o644 if p.suffix not in (".so", ".dll", ".exe") else 0o755)
            p.write_bytes(d); patched += 1
            print(f"  {p.name}: ascii={na} utf16={nu}")
        except PermissionError:
            print(f"  SKIP (read-only) {p}")
    print(f"[regkey] Software\\Wine -> Software\\{key} in {patched} file(s)")
    # emit the chosen key so the caller can reuse it for wine.inf
    print(f"KEY={key}")

if __name__ == "__main__":
    main()
