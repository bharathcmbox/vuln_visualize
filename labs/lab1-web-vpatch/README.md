# Lab 1 — Web vuln: code patch vs. virtual patch

An educational lab for **enterprise security teams** on where virtual patching
fits in the find → fix pipeline, and why a generic WAF is not the same as a
targeted virtual patch. Everything runs locally in Docker, bound to `127.0.0.1`.

> **Scope & ethics.** The target is OWASP Juice Shop, a *deliberately
> vulnerable* training app. Run this only on your own machine. Do not expose the
> ports. Nothing here is a real disclosure.

## What it shows

The same deliberately-vulnerable app is reached three ways, so teams can compare
protection side by side:

| Path | Port | What it is |
|------|------|------------|
| `direct-no-waf` | 3000 | the raw app, no protection (the baseline) |
| `generic-waf`   | 8080 | OWASP Core Rule Set defaults (signature WAF) |
| `waf-vpatch`    | 8081 | CRS **plus** a targeted positive-model virtual patch |

## Run it

```bash
docker compose up -d          # start all three paths
python3 -I validate.py        # run the validation gate (stdlib only)
docker compose down           # stop everything
```

## The validation gate

`validate.py` is the core idea. Every virtual patch — and every AI-generated
code patch — must pass the same two-sided gate before anyone trusts it:

1. **The malicious corpus is blocked** (all of `test-corpus.jsonl`, including
   shape-variants, not just the one canonical attack).
2. **Legitimate traffic still passes** (no false positives that break real
   users).

This is the defensive mirror of the 1Password finding that 54% of LLM-written
patches either fail to fix the bug or break behaviour: the gate is what keeps a
patch out of that 54%.

The corpus is labelled by **evasion category**, deliberately not written as a
copy-paste payload cookbook.

## What we actually observed (illustrative)

```
direct-no-waf  : 3/4 blocked, 3/3 benign pass   -> one live bypass on the raw app
generic-waf    : 4/4 blocked, 3/3 benign pass   -> caught every tested category
waf-vpatch     : 4/4 blocked, 3/3 benign pass   -> also clean
```

**The honest lesson.** In this lab the stock CRS already blocked the categories
tested. That is the trap: a signature WAF blocks what it *recognizes*. The
targeted virtual patch (`vpatches/010-vpatch-login.conf`) enforces a **positive
model** — on the login route the email field must be email-shaped — so it holds
against a novel variant the signatures have never seen. "The generic WAF looked
fine" is exactly when teams over-trust it.

## The virtual patch itself

See `vpatches/010-vpatch-login.conf`. Three properties to teach:

- **Targeted**: scoped to one route + one field, so it survives CRS tuning and
  false-positive exclusions elsewhere.
- **Positive model**: defines what is *allowed*, not an endless list of what is
  bad — robust to evasion.
- **Expiry-required**: tagged `expiry-required`. A virtual patch is a bandage.
  It must be removed when the upstream code fix (a parameterized query) ships,
  or it becomes invisible permanent tech debt.

## The model loop (`model_loop.py`)

This turns the fixed demo into the real find -> patch -> verify loop, driven by
models through OpenRouter. Needs `OPENROUTER_API_KEY` in the environment:

```bash
. ~/.openrouter_env && python3 -u -I model_loop.py
# options: --drafter <slug> --reviewer <slug> --no-review --dry-run
```

Pipeline:

1. **Draft** — an open-weight model (default `deepseek/deepseek-v4-flash`) reads
   `vuln-brief.md` and drafts a positive-model ModSecurity rule.
2. **Review** — a frontier model (default `anthropic/claude-sonnet-5.5`) hardens
   it against bypasses.
3. **Apply** — the final rule is written to
   `vpatches-generated/020-generated-login.conf` and loaded on an **isolated**
   path (port 8082), so it never mixes with the hand-written rule on 8081.
4. **Judge** — `validate.py` runs. A tool, not a model, decides if it is real.
   If the rule is malformed the WAF container fails to start, and that counts as
   a failing gate result (the script reports it with the container logs).

The script prints the **exact OpenRouter cost** of each run.

### What one real run showed (illustrative)

A representative run cost **~$0.045 total**: ~$0.0001 for the open-weight draft,
~$0.045 for the frontier review. The gate PASSed (4/4 malicious blocked, 3/3
benign passed). The committed example of that run's output is
`vpatches-generated/020-generated-login.conf.example`.

The teaching point: the cheap draft was plausible but shallow. The frontier
review (≈400× the cost, still under 5 cents) is where robustness came from — it
caught object/array injection (`json.email` sent as an object), the
missing-field rule-skip, a Content-Type bypass of JSON parsing, and a
trailing-newline anchor bug. **Open models draft; a frontier model reviews; a
tool certifies.** That division is the whole argument.

## Where the AI models plug in (for the diagram)

- The model that writes the proof-of-concept also **drafts** the virtual-patch
  rule and the code patch from it.
- `validate.py` is the **ground-truth gate** — a tool, not a model, decides
  whether the patch is real. Open-weight models draft; the gate judges.
- The draft/review/gate split maps directly onto the diagram's Patch and Verify
  stages, and the per-run cost numbers can feed the model-picker.
