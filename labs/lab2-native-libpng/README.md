# Lab 2 — Native code: the sanitizer-as-judge pipeline

The other half of the find → patch → verify loop, for **native C code** where a
WAF cannot help. Target: `example-libpng`, Trail of Bits' AIxCC sample with a
planted CWE-121 out-of-bounds read/write in libpng's `png_handle_iCCP`.

> **Scope & ethics.** The target is a *known-vulnerable* sample repo. It is
> fetched by `setup.sh`, never committed here, and only ever built/run inside
> the lab container — never on the host. Everything is local.

## The bug (teaching note)

In `pngrutil.c`, `keyword` is `wpng_byte keyword[41]` and `wpng_byte` is a
2-byte `png_uint_16`, so the array is 82 bytes. The code does
`read_length = sizeof(keyword)` — that is **82 (bytes)**, but `read_length` is
then used as a **count of wide characters**, so the keyword loop indexes
`keyword[41]` and beyond — past the 41-element array. Classic `sizeof` misuse.

## Run it

```bash
./setup.sh      # clone the target + build the container image (needs network)
./prove.sh      # PROVE: reproduce the crash under ASan/UBSan

# the model loop (needs OPENROUTER_API_KEY):
. ~/.openrouter_env && python3 -u -I model_patch.py
```

## The two gates (`build_and_check.sh`, inside the container)

Ground truth here is **tools, not models**:

- **PROVE** — build the unpatched target with ASan+UBSan, replay the blob, and
  require a sanitizer abort. If the sanitizer stays quiet, the bug is not
  reproducing and nothing downstream is trustworthy.
- **VERIFY** — build the *patched* target, replay the blob (must **not** crash),
  then run libpng's own `make test`. A patch passes only if it both stops the
  crash **and** keeps every test green. This is what stops a patch that "fixes"
  the bug by breaking the decoder — the native-code equivalent of the 1Password
  26%/54% patch-quality problem.

The one-shot driver (`oneshot_driver.c`) feeds a single input to the fuzz
target's entrypoint, so we reproduce the PoV without a full libFuzzer build.

## The model loop (`model_patch.py`)

Same shape as Lab 1: open-weight model drafts, frontier model reviews, the gate
judges — but it also **scores against the reference fix** shipped with the
challenge (`.aixcc/vulns/vuln_0/patches/good_patch.diff`). `target/` is reverted
to the vulnerable state after every run, so runs are repeatable.

### What one real run showed (illustrative)

Drafter `deepseek/deepseek-v4-flash`, reviewer `anthropic/claude-sonnet-5.5`,
**total ~$0.011**. The gate **PASSed** (crash gone, full test suite green).

The interesting part: the model did **not** reproduce the reference patch. The
reference changes `sizeof(keyword)` to a precomputed `max_keyword_wbytes`; the
model instead wrote `sizeof(keyword) / sizeof(keyword[0])` — the idiomatic
"element count" fix, which is arguably cleaner. See
`generated/generated-patch.diff.example`.

Two lessons for enterprise teams:
1. A correct fix need not match the maintainer's fix. **The gate, not a diff
   comparison, is what certifies correctness** — judging patches by similarity
   to a "golden" patch would have wrongly rejected a good one.
2. The model reasoned about the defect rather than memorizing the known patch —
   evidence the capability is real, not recall.

## Native-code "virtual patching"

You cannot put a WAF in front of a PNG decoder, so the interim-mitigation
options differ from Lab 1 and are worth discussing with teams:

- **Input filtering at the boundary**: reject or size-cap `iCCP` chunks before
  the decoder runs (a positive model on the file format).
- **Sandboxing / seccomp**: contain the process so an over-read cannot escalate
  (this is exactly the microVM/containment theme from the main visualizer).
- **Feature disable**: refuse ICC profiles until the real fix ships.

These contain the blast radius; only the code patch removes the bug.
