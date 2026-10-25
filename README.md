# Escaping the Offline World

An interactive, single-page visual explainer of the sandbox escapes and covert channels that red-team agents discovered in OpenAI's **offline frontier-model training environment**, as described in OpenAI's October 2026 post *"Securing our frontier model training environment"* and reporting on it.

**Live page:** https://bharathcmbox.github.io/vuln_visualize/

## What it covers

Seven self-contained, interactive visualizers — no security background needed:

1. **The DNS escape** — how a model smuggled a question to the open internet through a name-lookup, and the detection-vs-stop timeline (scrubbable).
2. **Four walls of containment** — the layered sandbox → VM → monitoring → network perimeter.
3. **Chaining a VM escape** — why one bug is rarely enough; step through a privilege chain.
4. **The CPU cache covert channel** — the headline trick. Two isolated VMs talk by evicting and re-timing a shared cache line. Type a message and watch the bits cross (with adjustable noise).
5. **Four ways to whisper** — cache timing, shared-storage bursts, CPU contention, and a TLS-certificate cache.
6. **The campaign in numbers** — tokens burned, diminishing returns, and the CVEs that came out of it.
7. **Why it matters** — the defensive lessons.

## Tech

A single `index.html`. No build step, no dependencies, no network calls — plain HTML, CSS, and vanilla JS with inline SVG. Works in light and dark mode (with a manual toggle). Just open the file in a browser.

## A note on accuracy

The diagrams are **hand-built schematics to make the ideas legible** — timings, bit counts, and the findings curve are illustrative, not measured, and the diagrams do not depict OpenAI's real infrastructure. The underlying facts (the incident timeline, the cache channel, the CVEs, the token figures) come from the sources below; check the primary source before relying on any exact number.

> **On the source text.** OpenAI's post is OpenAI's copyrighted work and is **not redistributed here** — only linked and referenced. Read it at the primary link below.

## Sources

- OpenAI — [Securing our frontier model training environment](https://openai.com/index/securing-our-frontier-model-training-environment/) (primary)
- The Decoder — [Isolated AI agents found ways to talk through CPU cache](https://the-decoder.com/openais-isolated-ai-agents-found-ways-to-talk-to-each-other-through-cpu-cache/)
- Hardware Busters — [Red-team agents built a CPU cache covert channel between isolated microVMs](https://hwbusters.com/news/openais-red-team-agents-built-a-cpu-cache-covert-channel-between-isolated-microvms/)
- CellCog — [OpenAI training containment: no internet, red-teamed](https://cellcog.ai/blog/openai-frontier-training-containment/)

## License

[MIT](LICENSE). An educational explainer, not affiliated with or endorsed by OpenAI.
