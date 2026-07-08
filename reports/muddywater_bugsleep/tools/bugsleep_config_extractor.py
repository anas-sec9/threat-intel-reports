#!/usr/bin/env python3
"""
BugSleep (MuddyWater) config / payload extractor.

BugSleep is NOT packed with a third-party packer. It protects its real code and
config strings with a trivial byte cipher: every byte is stored as
(plaintext + 6) & 0xFF. At runtime a stub calls VirtualProtect(PAGE_EXECUTE_READWRITE)
over the code region and subtracts 6 from every byte (SSE `PSUBB` against a key
vector of sixteen 0x06 bytes), then decrypts individual config strings the same
way in 0x30-byte PSUBB chunks.

    Decryption:  plaintext[i] = (ciphertext[i] - 6) & 0xFF
    Key:         0x06   (encrypt = +6, decrypt = -6)

Recovered by reversing the analyzed sample
(73c677dd3b264e7eb80e26e78ac9df1dba30915b5ce3b1bc1c83db52b9c6b30e) in Ghidra:
the decrypt loop lives at RVA 0x24af0 (PSUBB XMM0, XMM6) and the bulk code
self-decrypt at RVA ~0x24e3f (VirtualProtect + byte -6 over 0x23940 bytes).

This script subtracts 6 across the whole sample and pulls out readable strings +
likely IOCs (IPv4, executables, Windows paths, URLs). It works on the BugSleep
family as long as they keep the -6 scheme; if a variant changes the constant,
pass it with --key.

Usage:
    python3 bugsleep_config_extractor.py <sample.exe> [--key 6] [--min 5]

Author: Anas  |  TLP:CLEAR
"""
import argparse
import re
import sys


def decrypt(data: bytes, key: int) -> bytes:
    return bytes((b - key) & 0xFF for b in data)


def ascii_strings(data: bytes, minlen: int):
    return re.findall(rb"[\x20-\x7e]{%d,}" % minlen, data)


IOC_PATTERNS = {
    "ipv4": re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "exe":  re.compile(rb"[A-Za-z0-9_\-\\:.]+\.exe", re.I),
    "path": re.compile(rb"[A-Za-z]:\\[^\x00-\x1f\"<>|]{3,}", re.I),
    "url":  re.compile(rb"https?://[^\s\"\x00]+", re.I),
    "mutex_hint": re.compile(rb"\b(?:PackageManager|Global\\[A-Za-z0-9_]+)\b"),
}


def main() -> int:
    ap = argparse.ArgumentParser(description="BugSleep config/payload extractor (subtract-6 cipher).")
    ap.add_argument("sample", help="path to the BugSleep PE sample")
    ap.add_argument("--key", type=int, default=6, help="byte subtraction key (default 6)")
    ap.add_argument("--min", type=int, default=5, help="minimum string length (default 5)")
    args = ap.parse_args()

    try:
        raw = open(args.sample, "rb").read()
    except OSError as e:
        print(f"[!] cannot read {args.sample}: {e}", file=sys.stderr)
        return 1

    dec = decrypt(raw, args.key)
    print(f"[*] {args.sample}: {len(raw)} bytes, decrypted with -{args.key}\n")

    seen = set()
    for s in ascii_strings(dec, args.min):
        for name, rx in IOC_PATTERNS.items():
            for m in rx.findall(s):
                k = (name, m)
                if k not in seen:
                    seen.add(k)
                    print(f"  {name:10} {m.decode(errors='replace')}")

    if not seen:
        print("  (no IOCs surfaced - try a different --key or --min)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
