#!/usr/bin/env python3
"""Lab 2 find->patch->verify loop for native code (libpng), via OpenRouter.

    vuln context (function source + sanitizer trace)
        -> [DRAFTER: open-weight]  unified-diff patch to pngrutil.c
        -> [REVIEWER: frontier]    corrected minimal patch
        -> git apply to target/
        -> docker run ... verify   (sanitizer + libpng test suite = GROUND TRUTH)
        -> score vs the reference good_patch.diff

The sanitizer and the test suite decide whether the patch is real. The models
only draft and review. target/ is always reverted to the vulnerable state
afterwards, so runs are repeatable.

Requires OPENROUTER_API_KEY. Run:
    . ~/.openrouter_env && python3 -u -I model_patch.py
Stdlib only.
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
TARGET = os.path.join(HERE, "target")
SRCFILE = "pngrutil.c"
FUNC_LINES = (1419, 1460)  # the png_handle_iCCP region to show the model
GOOD_PATCH = os.path.join(TARGET, ".aixcc/vulns/vuln_0/patches/good_patch.diff")
GEN_DIR = os.path.join(HERE, "generated")
API = "https://openrouter.ai/api/v1/chat/completions"

DRAFT_SYSTEM = (
    "You are a C security engineer fixing a memory-safety bug in libpng. You "
    "produce the MINIMAL correct fix and change nothing unrelated. You must "
    "preserve normal decoding behaviour for valid PNGs. Output ONLY a unified "
    "diff that `git apply` accepts, with `a/pngrutil.c` and `b/pngrutil.c` "
    "headers, inside a single ```diff fenced block. No prose."
)
REVIEW_SYSTEM = (
    "You are a senior C reviewer. Given a vulnerability, a candidate unified-diff "
    "patch, and the source, verify the patch is minimal, actually removes the "
    "out-of-bounds access, keeps valid-PNG behaviour, and applies cleanly against "
    "the shown source (correct line context). Fix any problem yourself. Output "
    "ONLY the final unified diff in a single ```diff fenced block."
)


def call(model, system, user, max_tokens):
    key = os.environ.get("OPENROUTER_API_KEY")
    if not key:
        sys.exit("OPENROUTER_API_KEY not set. Run: . ~/.openrouter_env && python3 -u -I model_patch.py")
    body = json.dumps({
        "model": model,
        "messages": [{"role": "system", "content": system},
                     {"role": "user", "content": user}],
        "max_tokens": max_tokens, "temperature": 0.1,
    }).encode()
    req = urllib.request.Request(API, data=body, headers={
        "Authorization": f"Bearer {key}", "Content-Type": "application/json",
        "X-Title": "vuln_visualize lab2"})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            data = json.load(r)
    except urllib.error.HTTPError as e:
        sys.exit(f"OpenRouter error {e.code}: {e.read().decode(errors='replace')[:400]}")
    ch = data["choices"][0]
    content = ch["message"].get("content") or ch["message"].get("reasoning") or ""
    if not content.strip():
        sys.exit(f"{model} returned empty (finish={ch.get('finish_reason')}).")
    if ch.get("finish_reason") == "length":
        print(f"      WARNING: {model} truncated (token cap).")
    return content, data.get("usage", {})


def extract_diff(text):
    m = re.search(r"```(?:diff|patch)?\s*\n(.*?)```", text, re.S)
    return (m.group(1) if m else text).strip() + "\n"


def cost(usage):
    return float(usage["cost"]) if usage.get("cost") is not None else 0.0


def git(*args):
    return subprocess.run(["git", "-C", TARGET, *args],
                          capture_output=True, text=True)


def revert_target():
    git("checkout", "--", SRCFILE)
    try:
        os.remove(os.path.join(TARGET, "Makefile"))
    except FileNotFoundError:
        pass


def try_apply(diff_path):
    for extra in ([], ["--recount"], ["--ignore-whitespace"]):
        r = git("apply", *extra, diff_path)
        if r.returncode == 0:
            return True, "git apply " + " ".join(extra) if extra else "git apply"
    # last resort: patch(1) with fuzz
    r = subprocess.run(["patch", "-p1", "--fuzz=3", "-i", diff_path],
                       cwd=TARGET, capture_output=True, text=True)
    return (r.returncode == 0), ("patch --fuzz=3" if r.returncode == 0
                                 else "APPLY FAILED:\n" + r.stderr[-400:])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--drafter", default="deepseek/deepseek-v4-flash")
    ap.add_argument("--reviewer", default="anthropic/claude-sonnet-5.5")
    ap.add_argument("--no-review", action="store_true")
    ap.add_argument("--dry-run", action="store_true", help="draft only; do not apply/verify")
    args = ap.parse_args()

    os.makedirs(GEN_DIR, exist_ok=True)
    revert_target()  # start from a known vulnerable state
    src = open(os.path.join(TARGET, SRCFILE)).read().splitlines()
    func = "\n".join(f"{i}: {src[i-1]}" for i in range(*FUNC_LINES))
    pov = open(os.path.join(HERE, "pov-report.txt")).read()
    desc = ("libpng png_handle_iCCP has a CWE-121 out-of-bounds read/write: the "
            "read length is computed with sizeof() of a wide-char array (bytes), "
            "then used as a wide-character element count, so the keyword loop "
            "indexes past the array. Fix it minimally.")

    user_draft = (f"{desc}\n\nSanitizer proof:\n{pov}\n\n"
                  f"Source of pngrutil.c around the bug (line: text):\n{func}\n\n"
                  "Produce the minimal unified diff now.")
    total = 0.0
    print(f"[1/4] drafting patch with open-weight model: {args.drafter}")
    draft, u = call(args.drafter, DRAFT_SYSTEM, user_draft, 1500)
    total += cost(u); diff = extract_diff(draft)
    print(f"      drafted {len(diff.splitlines())} diff lines, ${cost(u):.4f}")

    if not args.no_review:
        print(f"[2/4] reviewing patch with frontier model: {args.reviewer}")
        rev, u = call(args.reviewer, REVIEW_SYSTEM,
                      f"{desc}\n\nSource (line: text):\n{func}\n\n"
                      f"Candidate patch:\n```diff\n{diff}\n```", 4000)
        total += cost(u); diff = extract_diff(rev)
        print(f"      reviewed, ${cost(u):.4f}")
    else:
        print("[2/4] review skipped")

    diff_path = os.path.join(GEN_DIR, "generated-patch.diff")
    open(diff_path, "w").write(diff)
    print(f"\n--- generated patch ---\n{diff}\n-----------------------")
    print(f"total model cost this run: ${total:.4f}")
    if args.dry_run:
        print("[4/4] dry-run: not applying.")
        return

    print("[3/4] applying patch to target/ ...")
    ok, how = try_apply(diff_path)
    if not ok:
        print(f"[GATE] FAIL at apply -- {how}")
        revert_target()
        return
    print(f"      applied via: {how}")

    print("[4/4] running the verify gate in Docker (sanitizer + test suite)...")
    r = subprocess.run(["docker", "run", "--rm",
                        "-v", f"{TARGET}:/work/target",
                        "-v", f"{os.path.join(HERE,'oneshot_driver.c')}:/work/oneshot_driver.c:ro",
                        "lab2-libpng", "verify"], cwd=HERE)
    gate_pass = (r.returncode == 0)

    # score against the reference fix
    good = open(GOOD_PATCH).read()
    good_hit = "max_keyword_wbytes" in diff and "sizeof(keyword)" not in \
        "".join(l for l in diff.splitlines() if l.startswith("+"))
    print("\n=== result ===")
    print(f"verify gate : {'PASS' if gate_pass else 'FAIL'}")
    print(f"matches reference approach (uses max_keyword_wbytes, drops the "
          f"bad sizeof): {'yes' if good_hit else 'no / different approach'}")
    print("(a different approach that still passes the gate is a valid fix.)")

    revert_target()
    print("target/ reverted to vulnerable state.")


if __name__ == "__main__":
    main()
