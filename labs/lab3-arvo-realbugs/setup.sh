#!/usr/bin/env bash
# Lab 3 needs only Docker — ARVO ships prebuilt images per case, and run.py
# pulls them on demand. This optional helper pre-pulls the curated cases.
# WARNING: each ARVO image is ~4–6 GB.
set -euo pipefail
cd "$(dirname "$0")"
command -v docker >/dev/null || { echo "Docker is required."; exit 1; }
ids=$(python3 -c "import json;print(' '.join(str(c['id']) for c in json.load(open('cases.json'))['cases']))")
echo "Cases: $ids"
for id in $ids; do
  echo "== pulling n132/arvo:$id-vul (~4-6 GB) =="
  docker pull "n132/arvo:$id-vul"
done
echo "Done. Run: . ~/.openrouter_env && python3 -u -I run.py --case <id>"
