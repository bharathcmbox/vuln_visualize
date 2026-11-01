#!/usr/bin/env python3
"""Native virtual patch for the libpng iCCP over-read (Lab 2).

You cannot put a WAF in front of a PNG decoder, so the interim mitigation is an
INPUT FILTER at the boundary: a tiny, positive-model parser that validates the
PNG chunk structure and refuses malformed input BEFORE libpng ever sees it.
It contains the bug until the real code fix ships — a bandage with an expiry.

The planted PoC declares an iCCP chunk of ~837 MB inside a ~420-byte file; the
structural rule ("a chunk cannot be larger than the bytes that remain") rejects
it outright. A targeted iCCP keyword rule adds defence in depth.

Policy modes:
  strict   (default) allow well-formed PNGs; reject structurally-impossible
           chunks and malformed iCCP keywords.
  no-iccp  also reject ANY iCCP chunk (feature-disable: refuse ICC profiles
           entirely until the code fix lands — the most conservative patch).

Usage:
  python3 vpatch_filter.py [--mode strict|no-iccp] <file.png>   # exit 0 allow, 1 deny
Importable: decision(data, mode) -> (allowed: bool, reason: str)
"""
import struct
import sys

PNG_SIG = b"\x89PNG\r\n\x1a\n"
MAX_ICCP_KEYWORD = 79  # PNG spec: keyword is 1-79 bytes, then a NUL separator


def decision(data, mode="strict"):
    if data[:8] != PNG_SIG:
        return False, "not a PNG (bad signature)"
    i, n = 8, len(data)
    saw_iccp = False
    while i < n:
        if i + 8 > n:
            return False, f"truncated chunk header at offset {i}"
        (ln,) = struct.unpack(">I", data[i:i + 4])
        ctype = data[i + 4:i + 8]
        # STRUCTURAL positive model: declared length + 12 (len+type+crc) must fit.
        if i + 12 + ln > n:
            return (False, f"chunk {ctype.decode('latin1','replace')} declares "
                           f"{ln} bytes but only {n - i - 12} remain "
                           f"(structurally impossible)")
        if ctype == b"iCCP":
            saw_iccp = True
            if mode == "no-iccp":
                return False, "iCCP chunk present and policy is no-iccp"
            # TARGETED positive model: a valid iCCP starts with a NUL-terminated
            # keyword of 1..79 bytes. Reject if no terminator in that window.
            body = data[i + 8:i + 8 + ln]
            nul = body.find(b"\x00", 0, MAX_ICCP_KEYWORD + 1)
            if nul < 1:
                return (False, "iCCP keyword is missing its NUL terminator "
                               f"within {MAX_ICCP_KEYWORD} bytes (malformed)")
        i += 12 + ln
    return True, "well-formed" + (" (iCCP present, accepted)" if saw_iccp else "")


def main():
    mode = "strict"
    args = sys.argv[1:]
    if args and args[0] == "--mode":
        mode = args[1]; args = args[2:]
    if not args:
        sys.exit("usage: vpatch_filter.py [--mode strict|no-iccp] <file.png>")
    data = open(args[0], "rb").read()
    ok, why = decision(data, mode)
    print(("ALLOW" if ok else "DENY") + ": " + why)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
