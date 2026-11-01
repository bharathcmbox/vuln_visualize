# Lab 3 — Real bugs at scale (ARVO)

**Lab 2, deepened.** Instead of one planted bug, this runs the
find → patch → verify loop against *real, historical* OSS-Fuzz vulnerabilities
from the [ARVO dataset](https://github.com/n132/arvo) — each one a real crash in
a real project, with a known maintainer fix to score against.

> **Scope & ethics.** ARVO cases are already-public, already-patched bugs
> distributed as Docker images for research. Everything runs locally in a
> container. This is reproduction and patching of fixed bugs, not live
> vulnerability research against anyone's systems.

## Why this is the strongest evidence in the series

Lab 2 proved the pipeline on a planted bug. Lab 3 asks the real question: **how
often does the loop actually produce a correct fix for a real bug?** CyberGym
(ICLR 2026) found that even strong agent setups solve only ~20% of real-world
cases, so this is where claims meet reality.

## How a case works

Each ARVO case is two prebuilt images: `n132/arvo:<id>-vul` and `<id>-fix`. The
`-vul` image contains the vulnerable source (a git checkout under `/src`), the
crashing PoC at `/tmp/poc`, and an `arvo` command that replays it.

```
PROVE    docker run <id>-vul arvo        -> sanitizer abort (bug is live)
CONTEXT  pull the implicated source from the ASan trace out of the container
DRAFT    open-weight model proposes a unified-diff patch
REVIEW   frontier model hardens it
VERIFY   in a fresh <id>-vul container: git apply --recount -> compile -> arvo
         PASS = applies AND recompiles AND the PoC no longer crashes
SCORE    compare the file(s) touched against the vendored maintainer fix
```

Ground truth is the **sanitizer plus the recompile**, never a model. The gate is
calibrated: running the real `-fix` image's build exits cleanly, exactly what the
gate requires of a good patch.

## Run it

```bash
./setup.sh                              # optional: pre-pull curated cases (~4-6 GB each)
. ~/.openrouter_env && python3 -u -I run.py --case 8007
. ~/.openrouter_env && python3 -u -I run.py --all          # whole curated set
#   --no-review   open-weight drafter only (no frontier review)
#   --drafter / --reviewer <openrouter-slug>
```

Cases are listed in `cases.json`; each has a vendored `cases/<id>.meta.json`
(project, sanitizer, crash type) and `cases/<id>.good.diff` (the maintainer fix,
for scoring) so the lab is self-contained without cloning all of ARVO-Meta.

## What we observed on a real bug (curl, case 8007)

Case 8007 is a real curl heap-buffer-overflow: `strcpy_url()` %-encoded more
bytes than `strlen_url()` had counted when sizing the buffer, so the write ran
past the allocation (the crash surfaces deep in `mprintf.c`, but the root cause
is in `lib/transfer.c`). A genuinely multi-function bug.

| Setup | Result | Cost |
|---|---|---|
| Open-weight **draft + frontier review** | **PASS** — produced the *exact* maintainer fix (`!ISPRINT` → `>= 0x80`), gate-verified | ~$0.034 |
| Open-weight **draft only** (attempt 1) | FAIL — patch did not even apply | ~$0.001 |
| Open-weight **draft only** (attempt 2) | FAIL — patched the crash *symptom* site (`mprintf.c`), not the root cause | ~$0.001 |

Two lessons for the series, now on a real bug rather than a planted one:

1. **The frontier review is what crosses the line from "plausible" to "correct."**
   Open-weight alone either misfired or fixed the wrong location; with a frontier
   reviewer the same cheap draft became the maintainer's actual fix.
2. **You cannot trust any single draft.** Across runs the open-weight model
   proposed different patches — one wrong-but-applying, one that failed to apply,
   one (post-review) correct. The gate, not the model, decides which run shipped.

(Single local runs; results vary run to run — that variance is the point.)

## Notes & limits

- ARVO's "verify" is *PoC no longer crashes + recompiles*. It is not a full
  project test suite (ARVO does not ship one per case), so a patch that silences
  the crash while subtly changing behaviour could still pass. For high-stakes
  use, add project tests and a fuzz-regression pass on top — the same hard-gate
  principle, more gates.
- ARVO's own patch identification is ~80% accurate, so an occasional
  `good.diff` may be imperfect. Scoring here is "same file as maintainer," a
  weak signal; the **gate** is the real verdict.
- Images are large (~4–6 GB each) and pulled on demand.
