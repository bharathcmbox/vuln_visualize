#!/usr/bin/env python3
"""Validation gate for the native virtual patch (Lab 2).

Same two-sided gate as Lab 1, for a file-format filter instead of a WAF:
  1. the malicious PoC must be DENIED (the over-read input never reaches libpng)
  2. every benign PNG must be ALLOWED (no false positives that break decoding)

Benign corpus is libpng's own test images (contrib/pngsuite/*.png). Run after
./setup.sh has fetched target/. Stdlib only.
"""
import glob
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from vpatch_filter import decision  # noqa: E402

POC = os.path.join(HERE, "target/.aixcc/vulns/vuln_0/blobs/sample_data.bin")
BENIGN = sorted(glob.glob(os.path.join(HERE, "target/contrib/pngsuite/*.png")))


def main():
    if not os.path.exists(POC) or not BENIGN:
        sys.exit("target/ not found — run ./setup.sh first.")
    print(f"{'mode':9} | {'malicious PoC':16} | {'benign PNGs':18} | verdict")
    print("-" * 64)
    for mode in ("strict", "no-iccp"):
        poc_denied = not decision(open(POC, "rb").read(), mode)[0]
        allowed = sum(decision(open(f, "rb").read(), mode)[0] for f in BENIGN)
        # under no-iccp, benign files that legitimately carry iCCP are expected
        # to be denied; strict must pass them all.
        ok = poc_denied and (allowed == len(BENIGN) if mode == "strict" else True)
        print(f"{mode:9} | {'DENIED' if poc_denied else 'ALLOWED(!)':16} | "
              f"{allowed:3}/{len(BENIGN):<3} allowed      | "
              f"{'PASS' if ok else 'FAIL'}")
    print("\nstrict must block the PoC and pass every benign image. no-iccp is the"
          "\nfeature-disable fallback: it also blocks any image carrying an ICC"
          "\nprofile, which is a heavier (but simpler) containment choice.")
    # show WHY the PoC is blocked
    print("\nPoC rejection reason:", decision(open(POC, "rb").read(), "strict")[1])


if __name__ == "__main__":
    main()
