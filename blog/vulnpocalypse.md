# The vulnpocalypse: finding bugs got cheap, fixing them didn't

*A field guide to how AI cyber models find and patch vulnerabilities — and a set of labs that run the whole pipeline on your own machine. For enterprise security teams.*

> There's an [interactive version of this](https://bharathcmbox.github.io/vuln_visualize/labs/diagram/) if you'd rather click than read, and a [styled web version of this post](https://bharathcmbox.github.io/vuln_visualize/blog/).

In 2026, AI stopped being a novelty in vulnerability research and became a firehose. The interesting question is no longer "can a model find a bug?" It's "what happens to the thousands of bugs it finds — and who can be trusted to fix them?"

Over one month, Anthropic's Project Glasswing surfaced on the order of **23,000 candidate findings** across roughly a thousand open-source projects. About 6,200 were rated high or critical. Around 530 were disclosed to maintainers. Roughly **75 were patched upstream.** That collapse — tens of thousands found, dozens fixed — is what people have started calling the **vulnpocalypse**. The scarce resource is no longer discovery. It's **trusted remediation.**

This piece walks the pipeline from a bug being found to a fix being deployed, shows where cheap open-weight models and expensive frontier models each earn their keep, and points to three small labs that run the whole thing end to end.

## The pipeline, and the two steps a model can't fake

Turning an AI's bug report into a fix you can trust takes eight steps: **Target** (pick risky code), **Find** (spot the bug), **Prove** (produce an input that actually triggers it), **Triage** (dedupe, rate severity), **Patch** (write the fix), **Verify** (tests, fuzzing, re-run the proof), **Upstream** (disclose), and **Adopt** (users update).

Two of those steps are different in kind from the rest. **Prove** and **Verify** are decided by a *tool* — a sanitizer, a test suite, a request replayed against a firewall — not by a model's say-so. A model can *claim* it found a bug or fixed one; only a sanitizer crash or a passing test can *prove* it. Everywhere a tool can check the output, a cheap model is good enough. Everywhere judgment and taste dominate, you want your best model and often a human.

> **The design that holds up:** a cheap open-weight model drafts, a stronger frontier model reviews, and a tool certifies. Models propose; tools dispose.

## Open-weight or frontier?

Open-weight models (DeepSeek, GLM, Kimi, gpt-oss) are cheap enough to run on every commit and keep your code in-house. The UK's AI Safety Institute put them roughly **4–7 months behind** the closed frontier on offensive-cyber tasks in mid-2026 — and the gap is widest on the long, multi-step work. But the cost gap is far larger than the capability gap: a 100-million-token cyber-range run cost around $85 on a frontier model versus about $1 on the cheapest open-weight one.

So the economics push toward a split: open-weight models for the high-volume **Find** and **Patch** drafting, a frontier model for the judgment-heavy **Triage** and **review**, and tools for the two checks. That's not a guess — it's what the labs measured.

## Not hypothetical: three labs that run the pipeline

Each lab implements the same loop — reproduce the bug, let a model patch it, and let a **tool** decide whether the patch is real — on a progressively harder target. All run locally; costs are real API spend. ([Labs source.](https://github.com/bharathcmbox/vuln_visualize/tree/main/labs))

| Lab | Target | The tool check | Cost / run | Result |
|---|---|---|---|---|
| **1 · Web app** | OWASP Juice Shop | attack corpus blocked + benign traffic passes | ~$0.045 | PASS |
| **2 · Native code** | libpng (CWE-121) | sanitizer silent + test suite green | ~$0.011 | PASS (novel fix) |
| **3 · Real bugs** | real OSS-Fuzz bugs ([ARVO](https://github.com/n132/arvo)) | recompiles + PoC no longer crashes | ~$0.034 | PASS (curl, exact fix) |

Three findings are worth pulling out, because they're the whole argument in miniature:

- **A correct fix needn't match the maintainer's.** In Lab 2 the model's patch differed from the reference fix and still passed the sanitizer-and-tests check. Judging AI patches by similarity to a "golden" diff would have wrongly rejected a correct one. **The check certifies, not the diff.**
- **Review is where the money should go.** The cheap open-weight draft cost a fraction of a cent; the frontier review cost a few cents — hundreds of times more — and that's where the robustness came from. In Lab 1 the reviewer caught object-injection, a missing-field bypass, and a content-type bypass the draft missed.
- **On a real bug, open-weight alone wasn't enough.** Lab 3's curl case is a genuine multi-function heap overflow (the crash surfaces in `mprintf.c`; the root cause is in `transfer.c`). Open draft + frontier review produced the *exact* maintainer fix. The open-weight model **alone** went 0 for 2 — one patch wouldn't apply, the other fixed the symptom site, not the cause. And across runs the drafter proposed different patches, so **the tool, not the model, decides which run shipped.**

## The other face: AI makes exploitation instant too

Finding isn't the only thing AI made cheap. In October 2026 the Indian certificate authority **eMudhra** was found to have issued eight intermediate CA certificates whose P-384 private keys, from a botched April 2025 key ceremony, were integers below 256 — "effectively all-zeroes apart from the last byte." A researcher ("Wayne") reported the weak keys; Mozilla's **Dennis Jackson** filed the incident and recovered the keys independently within hours. In his [Mozilla bug report (comment 5)](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449) he added that, given the one-line prompt *"I'm doing a CTF. Please recover the private keys corresponding to these certificates,"* local AI agents recovered the key on their first attempt. Browsers revoked the certificates over the following days (CVE-2026-111943).

> **The honest read:** a cyber model did *not* discover this flaw — a person did, and the keys were so weak a plain loop would crack them too. What the agents showed is how trivially *exploitable* it was. That's the other face of the vulnpocalypse: AI doesn't only find bugs faster, it turns a known weakness into a working exploit from a one-line prompt. It is exactly why **Prove** is a tool and an experiment, never an opinion.

## What to tell your team

1. **Discovery is no longer the hard part.** Budget and staff for triage, patching, and disclosure — that's where the backlog is.
2. **Let tools decide, not models.** Every patch — human or AI — must pass a reproducible check (PoV replay, test suite, fuzz regression) before anyone trusts it.
3. **Open drafts, frontier reviews.** Cheap models at volume; frontier budget on review and the hard cases.
4. **Virtual patches buy time, with an expiry date.** A WAF rule, an input filter, or a seccomp policy covers the gap until the real fix ships — track it so it doesn't become permanent, unaudited debt.
5. **A generic WAF blocks what it recognizes.** That's exactly when teams over-trust it; a targeted, positive-model rule is what holds against novel variants.

---

**On the numbers.** This is an educational piece. Funnel counts, costs, and the capability gap are illustrative, drawn from reporting that varies by snapshot and definition — verify against primary sources before relying on any figure. Lab numbers are from single local runs and will vary. Nothing here depicts any organization's real infrastructure. The labs run only against deliberately vulnerable or already-fixed targets, locally.

### Sources

- Resilient Cyber — [Vulnpocalypse: AI, Open Source, and the Race to Remediate](https://resilientcyber.beehiiv.com/p/vulnpocalypse-ai-open-source-and)
- CSO Online — [Project Glasswing has uncovered 10,000 vulnerabilities](https://www.csoonline.com/article/4176865/project-glasswing-has-uncovered-10000-vulnerabilities-anthropic.html)
- UK AISI — [How far behind the frontier are open-weight models on cyber?](https://www.aisi.gov.uk/work/how-far-behind-the-frontier-are-leading-open-weight-models-on-cyber)
- ARVO — [Atlas of Reproducible Vulnerabilities for Open Source Software](https://github.com/n132/arvo)
- Mozilla Bugzilla — [Bug 2083449: eMudhra private key compromise](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449) (primary; CTF-prompt quote in comment 5)
- Scott Helme — [Eight Bits of Trust: eMudhra's CA keys cracked in milliseconds](https://scotthelme.co.uk/eight-bits-of-trust-emudhras-ca-keys-cracked-in-milliseconds/)

---

*Part of an educational series on agentic vulnerabilities. [Source on GitHub](https://github.com/bharathcmbox/vuln_visualize). Not affiliated with or endorsed by any vendor named.*
