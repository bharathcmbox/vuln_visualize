#!/usr/bin/env bash
# PROVE gate: build the (unpatched) target and replay the PoV blob. Expect a
# sanitizer abort -- that is the proof the vulnerability is live.
set -euo pipefail
cd "$(dirname "$0")"
rm -f target/Makefile
docker run --rm -v "$PWD/target:/work/target" \
  -v "$PWD/oneshot_driver.c:/work/oneshot_driver.c:ro" lab2-libpng prove
