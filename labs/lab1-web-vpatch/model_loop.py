#!/usr/bin/env python3
"""Lab 1 find->patch->verify loop, driven by models via OpenRouter.

Pipeline (this is the thing the diagram illustrates):

    vuln-brief.md ---> [DRAFTER: open-weight] ---> candidate rule
                              |
                              v
                       [REVIEWER: frontier]  ---> final rule
                              |
                              v
             write vpatches-generated/020-generated-login.conf
                              |
                              v
        restart waf-vpatch-gen (port 8082), then validate.py  <-- GROUND TRUTH

The models only *draft*. validate.py (sanitiser of the web world: real requests
against a real WAF) decides whether the patch is real. That division -- models
propose, tools dispose -- is the whole argument.

Requires OPENROUTER_API_KEY in the environment. Run it as:
    . ~/.openrouter_env && python3 -I model_loop.py

Stdlib only. Output tokens are capped so a run stays ~1-2 cents.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import urllib.request
import urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
API = "https://openrouter.ai/api/v1/chat/completions"

# USD per million tokens (prompt, completion). Used only to report run cost.
PRICING = {
    "deepseek/deepseek-v4-flash": (0.091, 0.182),
    "z-ai/glm-5.3": (0.070, 1.400),
    "anthropic/claude-sonnet-5.5": (2.0, 10.0),
    "anthropic/claude-haiku-5.5": (0.10, 0.50),
}

DRAFT_SYSTEM = (
    "You are a defensive application-security engineer. You write ModSecurity v3 "
    "rules for the OWASP CRS nginx image. You produce virtual patches that use a "
    "POSITIVE security model (allow only well-formed input; deny the rest). You "
    "never write or include attack payloads. Output ONLY the rule file contents "
    "inside a single ```conf fenced block, nothing else."
)
REVIEW_SYSTEM = (
    "You are a senior security reviewer. You are given a vulnerability brief and a "
    "candidate ModSecurity virtual-patch rule drafted by another model. Check: (a) "
    "it is scoped strictly to the named route, (b) it enforces a positive model on "
    "the right field, (c) it will NOT block legitimate email logins, (d) the rule "
    "id and syntax are valid. Fix any problem yourself. Output ONLY the final, "
    "corrected rule file contents inside a single ```conf fenced block."
)


def call(model, system, user, max_tokens):
    key = os.environ.get("OPENROUTER_API_KEY")
    if not key:
        sys.exit("OPENROUTER_API_KEY not in environment. Run:\n"
                 "  . ~/.openrouter_env && python3 -I model_loop.py")
    body = json.dumps({
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "max_tokens": max_tokens,
        "temperature": 0.1,
    }).encode()
    req = urllib.request.Request(API, data=body, headers={
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/local/vuln_visualize",
        "X-Title": "vuln_visualize lab1",
    })
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            data = json.load(r)
    except urllib.error.HTTPError as e:
        sys.exit(f"OpenRouter error {e.code}: {e.read().decode(errors='replace')[:400]}")
    choice = data["choices"][0]
    msg = choice["message"]
    content = msg.get("content") or msg.get("reasoning") or ""
    finish = choice.get("finish_reason")
    usage = data.get("usage", {})
    if not content.strip():
        sys.exit(f"{model} returned empty content (finish_reason={finish}). "
                 "Try a higher --max-tokens or a different model.")
    if finish == "length":
        print(f"      WARNING: {model} output was truncated (hit token cap).")
    return content, usage


def extract_conf(text):
    m = re.search(r"```(?:conf|apache|nginx|modsec)?\s*\n(.*?)```", text, re.S)
    return (m.group(1) if m else text).strip() + "\n"


def cost(model, usage):
    # OpenRouter returns the exact charged cost; prefer it over the estimate.
    if usage.get("cost") is not None:
        return float(usage["cost"])
    pin, pout = PRICING.get(model, (0, 0))
    return (usage.get("prompt_tokens", 0) * pin
            + usage.get("completion_tokens", 0) * pout) / 1e6


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--drafter", default="deepseek/deepseek-v4-flash")
    ap.add_argument("--reviewer", default="anthropic/claude-sonnet-5.5")
    ap.add_argument("--no-review", action="store_true",
                    help="skip the frontier review step (draft only)")
    ap.add_argument("--dry-run", action="store_true",
                    help="generate the rule but do not apply/restart/validate")
    args = ap.parse_args()

    brief = open(os.path.join(HERE, "vuln-brief.md")).read()
    total = 0.0

    print(f"[1/4] drafting with open-weight model: {args.drafter}")
    draft, u = call(args.drafter, DRAFT_SYSTEM,
                    f"Here is the vulnerability brief:\n\n{brief}\n\n"
                    "Write the virtual-patch rule now.", max_tokens=2000)
    c = cost(args.drafter, u); total += c
    rule = extract_conf(draft)
    print(f"      drafted {len(rule.splitlines())} lines, "
          f"{u.get('completion_tokens','?')} out tokens, ${c:.4f}")

    if not args.no_review:
        print(f"[2/4] reviewing with frontier model: {args.reviewer}")
        rev, u = call(args.reviewer, REVIEW_SYSTEM,
                      f"Vulnerability brief:\n\n{brief}\n\n"
                      f"Candidate rule to review:\n\n```conf\n{rule}\n```",
                      max_tokens=8000)
        c = cost(args.reviewer, u); total += c
        rule = extract_conf(rev)
        print(f"      reviewed, {u.get('completion_tokens','?')} out tokens, ${c:.4f}")
    else:
        print("[2/4] review skipped (--no-review)")

    out = os.path.join(HERE, "vpatches-generated", "020-generated-login.conf")
    header = ("# AUTO-GENERATED virtual patch (lab). Drafter: %s  Reviewer: %s\n"
              "# Judged by validate.py, not trusted on sight.\n" %
              (args.drafter, "none" if args.no_review else args.reviewer))
    print(f"[3/4] writing {os.path.relpath(out, HERE)}")
    with open(out, "w") as f:
        f.write(header + rule)

    print(f"\n--- generated rule ---\n{rule}\n----------------------")
    print(f"total model cost this run: ${total:.4f}")

    if args.dry_run:
        print("[4/4] dry-run: not applying or validating.")
        return
    print("[4/4] restarting waf-vpatch-gen and running the gate...")
    subprocess.run(["docker", "compose", "restart", "waf-vpatch-gen"],
                   cwd=HERE, check=False)
    # Wait for the container to actually serve. If the generated rule is
    # malformed, ModSecurity/nginx fails to start and the port never opens --
    # that is itself a (failing) gate result, so report it with the logs.
    import time
    up = False
    for _ in range(20):
        try:
            urllib.request.urlopen("http://127.0.0.1:8082/", timeout=3)
            up = True
            break
        except urllib.error.HTTPError:
            up = True
            break
        except Exception:
            time.sleep(1)
    if not up:
        print("\nFAIL: waf-vpatch-gen did not come up -- the generated rule is "
              "likely invalid and nginx/ModSecurity refused to load it.")
        print("--- last container logs ---")
        subprocess.run(["docker", "compose", "logs", "--tail", "25",
                        "waf-vpatch-gen"], cwd=HERE, check=False)
        return
    subprocess.run([sys.executable, "-I", os.path.join(HERE, "validate.py")],
                   cwd=HERE, check=False)


if __name__ == "__main__":
    main()
