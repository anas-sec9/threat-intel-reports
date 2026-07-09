#!/usr/bin/env python3
"""
BugSleep (MuddyWater) config / payload extractor.

BugSleep is NOT packed with a third-party packer. It protects its code and config
with a trivial byte cipher: every byte is stored as (plaintext + N) & 0xFF, and it
is LAYERED - the code section is shifted once, and config strings inside it are
shifted again, so some strings need a single subtract and others a double subtract.
Different samples use different N (public reporting notes keys like 5, 6, 8).

    Decryption:  plaintext[i] = (ciphertext[i] - N) & 0xFF

This tool brute-forces the shift (0..MAX) over both ASCII and UTF-16 strings, so it
peels every layer, and reports which shift revealed each indicator. It never runs
the sample - pure static byte math - so it is safe against a live binary.

Recovered by reversing
73c677dd3b264e7eb80e26e78ac9df1dba30915b5ce3b1bc1c83db52b9c6b30e in Ghidra:
decrypt loop at RVA 0x24af0 (PSUBB XMM0, XMM6, XMM6 = 0x06 x16) and the bulk code
self-decrypt at RVA ~0x24e3f (VirtualProtect + byte -6 over 0x23940 bytes).

Usage:
    python3 bugsleep_config_extractor.py <sample.exe> [--max 16] [--min 5] [--all]
    python3 bugsleep_config_extractor.py <sample.exe> --key 6      # force one shift

Author: Anas  |  TLP:CLEAR
"""
import argparse
import re
import sys


def shift(data: bytes, k: int) -> bytes:
    if k == 0:
        return data
    return bytes((b - k) & 0xFF for b in data)


def ascii_strings(data: bytes, minlen: int):
    return [m.group() for m in re.finditer(rb"[\x20-\x7e]{%d,}" % minlen, data)]


def wide_strings(data: bytes, minlen: int):
    # runs of (printable, 0x00) pairs = UTF-16LE ASCII text
    out = []
    for m in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % minlen, data):
        out.append(bytes(m.group()[::2]))
    return out


IOC_PATTERNS = {
    "ipv4": re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "exe":  re.compile(rb"[A-Za-z0-9_\-\\:.]+\.exe", re.I),
    "path": re.compile(rb"[A-Za-z]:\\[^\x00-\x1f\"<>|]{3,}", re.I),
    "url":  re.compile(rb"https?://[^\s\"\x00]+", re.I),
}


def is_sane_ip(b: bytes) -> bool:
    try:
        return all(0 <= int(x) <= 255 for x in b.split(b"."))
    except ValueError:
        return False


def main() -> int:
    ap = argparse.ArgumentParser(description="BugSleep layered subtract-N config extractor.")
    ap.add_argument("sample")
    ap.add_argument("--max", type=int, default=16, help="max shift to brute-force (default 16)")
    ap.add_argument("--key", type=int, default=None, help="force a single shift instead of brute-force")
    ap.add_argument("--min", type=int, default=5, help="minimum string length (default 5)")
    ap.add_argument("--all", action="store_true", help="also dump every string newly revealed by decryption")
    args = ap.parse_args()

    try:
        raw = open(args.sample, "rb").read()
    except OSError as e:
        print(f"[!] cannot read {args.sample}: {e}", file=sys.stderr)
        return 1

    shifts = [args.key] if args.key is not None else range(0, args.max + 1)
    print(f"[*] {args.sample}: {len(raw)} bytes | shifts {list(shifts)}\n")

    plaintext_strings = set(ascii_strings(raw, args.min) + wide_strings(raw, args.min))

    iocs = {}       # (type, value) -> set(shift)
    revealed = {}   # value -> set(shift)   (strings hidden until decrypted)

    for k in shifts:
        data = shift(raw, k)
        strings = ascii_strings(data, args.min) + wide_strings(data, args.min)
        for s in strings:
            if k > 0 and s not in plaintext_strings:
                revealed.setdefault(s, set()).add(k)
            for name, rx in IOC_PATTERNS.items():
                for m in rx.findall(s):
                    if name == "ipv4" and not is_sane_ip(m):
                        continue
                    iocs.setdefault((name, m), set()).add(k)

    print("=== IOCs ===")
    if iocs:
        for (name, val), ks in sorted(iocs.items(), key=lambda x: (x[0][0], sorted(x[1]))):
            tag = "plain" if 0 in ks else "shift " + ",".join(map(str, sorted(ks)))
            print(f"  [{tag:>8}] {name:5} {val.decode(errors='replace')}")
    else:
        print("  (none)")

    if args.all:
        print("\n=== strings revealed only after decryption ===")
        for s, ks in sorted(revealed.items(), key=lambda x: sorted(x[1])):
            if len(s) >= args.min:
                print(f"  [shift {','.join(map(str, sorted(ks)))}] {s.decode(errors='replace')}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
