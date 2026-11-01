#!/usr/bin/env bash
# Fetch the deliberately-vulnerable challenge target (not vendored into this
# repo). Safe to re-run. The repo is a known-vulnerable AIxCC sample; it is only
# ever built and run inside the lab container, never executed on the host.
set -euo pipefail
cd "$(dirname "$0")"
if [ -d target/.git ]; then
  echo "target/ already present."
else
  git clone --depth 1 --branch challenges/full-scan \
    https://github.com/tob-challenges/example-libpng target
fi
echo "Building the lab container image..."
docker build -t lab2-libpng .
echo "Done. Next: ./prove.sh   (reproduce the bug under ASan/UBSan)"
