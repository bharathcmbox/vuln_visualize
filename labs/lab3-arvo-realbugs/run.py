#!/usr/bin/env python3
"""Lab 3 — find->patch->verify on REAL reproduced OSS-Fuzz bugs (ARVO).

This is Lab 2, deepened: instead of one planted bug, it runs the loop against
real historical vulnerabilities from the ARVO dataset (n132/arvo Docker images),
each of which ships a vulnerable build, the crashing PoC, and a known-good fix.

Per case:
  PROVE   docker run <id>-vul arvo        -> expect a sanitizer abort (nonzero)
  CONTEXT pull the implicated source out of the container (from the ASan trace)
  DRAFT   open-weight model proposes a unified-diff patch
  REVIEW  frontier model hardens it
  VERIFY  in a fresh <id>-vul container: git apply -> compile -> arvo
          pass = applies AND recompiles AND the PoC no longer crashes
  SCORE   compare against the vendored ground-truth patch (cases/<id>.good.diff)

Ground truth is the sanitizer + the recompile, never a model. target images are
large (~5 GB each) and pulled on demand.

Requires OPENROUTER_API_KEY. Run:
    . ~/.openrouter_env && python3 -u -I run.py --case 8007
    . ~/.openrouter_env && python3 -u -I run.py --all
Stdlib only.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.request
import urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
CASES = os.path.join(HERE, "cases")
API = "https://openrouter.ai/api/v1/chat/completions"

DRAFT_SYSTEM = (
    "You are a C/C++ security engineer fixing a memory-safety bug found by a "
    "fuzzer. Produce the MINIMAL correct fix; change nothing unrelated; preserve "
    "behaviour for valid inputs. Output ONLY a unified diff that `git apply -p1` "
    "accepts from the repository root, with a/<path> and b/<path> headers, inside "
    "a single ```diff fenced block. No prose.")
REVIEW_SYSTEM = (
    "You are a senior C/C++ reviewer. Given the crash, the candidate unified-diff "
    "patch and the source, confirm it removes the out-of-bounds/UAF access, is "
    "minimal, keeps valid-input behaviour, and applies cleanly with correct path "
    "context. Fix any issue. Output ONLY the final unified diff in one ```diff "
    "block.")


def call(model, system, user, max_tokens):
    key = os.environ.get("OPENROUTER_API_KEY")
    if not key:
        sys.exit("OPENROUTER_API_KEY not set. Run: . ~/.openrouter_env && python3 -u -I run.py ...")
    body = json.dumps({"model": model, "max_tokens": max_tokens, "temperature": 0.1,
                       "messages": [{"role": "system", "content": system},
                                    {"role": "user", "content": user}]}).encode()
    req = urllib.request.Request(API, data=body, headers={
        "Authorization": f"Bearer {key}", "Content-Type": "application/json",
        "X-Title": "vuln_visualize lab3"})
    try:
        with urllib.request.urlopen(req, timeout=180) as r:
            data = json.load(r)
    except urllib.error.HTTPError as e:
        sys.exit(f"OpenRouter error {e.code}: {e.read().decode(errors='replace')[:300]}")
    ch = data["choices"][0]
    content = ch["message"].get("content") or ch["message"].get("reasoning") or ""
    if not content.strip():
        sys.exit(f"{model} returned empty (finish={ch.get('finish_reason')}).")
    if ch.get("finish_reason") == "length":
        print(f"      WARNING: {model} truncated.")
    return content, data.get("usage", {})


def extract_diff(text):
    m = re.search(r"```(?:diff|patch)?\s*\n(.*?)```", text, re.S)
    return (m.group(1) if m else text).strip() + "\n"


def ucost(u):
    return float(u["cost"]) if u.get("cost") is not None else 0.0


def drun(image, cmd, mounts=None, capture=True):
    args = ["docker", "run", "--rm"]
    for h, c in (mounts or []):
        args += ["-v", f"{h}:{c}:ro"]
    args += ["--entrypoint", "bash", image, "-lc", cmd]
    return subprocess.run(args, capture_output=capture, text=True)


def image_present(tag):
    r = subprocess.run(["docker", "images", "-q", f"n132/arvo:{tag}"],
                       capture_output=True, text=True)
    return bool(r.stdout.strip())


def ensure_image(tag):
    if image_present(tag):
        return True
    print(f"      pulling n132/arvo:{tag} (~5 GB, one-time)...")
    return subprocess.run(["docker", "pull", f"n132/arvo:{tag}"]).returncode == 0


def srcdir(image):
    """Find the project's git worktree under /src (for context display)."""
    r = drun(image, "ls -d /src/*/.git 2>/dev/null | head -1")
    p = r.stdout.strip()
    return os.path.dirname(p) if p else "/src"


def patch_dir_for(image, relpath):
    """The /src subdir that actually contains the file the patch targets."""
    r = drun(image, f"find /src -maxdepth 5 -path '*/{relpath}' 2>/dev/null | head -1")
    hit = r.stdout.strip()
    if hit and hit.endswith(relpath):
        return hit[:-len(relpath)].rstrip("/")
    return "/src"


def build_dir_for(image):
    """Where `compile` must run. /src/build.sh often calls a relative script
    (e.g. ./ossfuzz.sh) that lives in a sibling dir, so find that script."""
    r = drun(image, "cat /src/build.sh 2>/dev/null")
    for tok in re.findall(r'(\S+\.sh)', r.stdout):
        name = os.path.basename(tok)
        if name == "build.sh":
            continue
        loc = drun(image, f"find /src -maxdepth 5 -name '{name}' 2>/dev/null | head -1")
        if loc.stdout.strip():
            return os.path.dirname(loc.stdout.strip())
    return "/src"


def trace_sites(report):
    """Return [(abs_path, line)] for frames pointing into /src, de-duped, in order."""
    sites, seen = [], set()
    for m in re.finditer(r'(/src/[^\s:]+):(\d+)', report):
        key = (m.group(1), m.group(2))
        if key not in seen:
            seen.add(key); sites.append((m.group(1), int(m.group(2))))
    return sites


def fetch_context(image, sites, proj):
    """Pull ±40 lines around each implicated site out of the container."""
    blocks = []
    for path, line in sites[:4]:
        lo, hi = max(1, line - 40), line + 40
        r = drun(image, f"sed -n '{lo},{hi}p' '{path}' 2>/dev/null | cat -n | "
                         f"sed 's/^/    /'")
        rel = path.replace(proj + "/", "")
        if r.stdout.strip():
            blocks.append(f"// {rel}  (lines {lo}-{hi}; crash near {line}; "
                          f"line numbers are relative offsets)\n{r.stdout}")
    return "\n\n".join(blocks)


def run_case(cid, drafter, reviewer, no_review):
    meta = json.load(open(os.path.join(CASES, f"{cid}.meta.json")))
    proj_name = meta["project"]; crash = meta["crash_type"]
    good = open(os.path.join(CASES, f"{cid}.good.diff")).read()
    vul = f"{cid}-vul"
    print(f"\n==== case {cid}  project={proj_name}  crash={crash} ====")
    if not ensure_image(vul):
        print("  FAIL: could not obtain image"); return None

    proj = srcdir(f"n132/arvo:{vul}")
    print(f"[1/5] PROVE: reproducing under sanitizer...")
    r = subprocess.run(["docker", "run", "--rm", f"n132/arvo:{vul}", "arvo"],
                       capture_output=True, text=True)
    report = r.stdout + r.stderr
    if r.returncode == 0:
        print("  FAIL: PoC did not crash the vulnerable build (unexpected)."); return None
    print(f"      sanitizer aborted (exit {r.returncode}) — bug confirmed live.")

    sites = trace_sites(report)
    ctx = fetch_context(f"n132/arvo:{vul}", sites, proj)
    short_report = "\n".join(l for l in report.splitlines()
                             if "ERROR" in l or "#" in l or "SUMMARY" in l)[:1500]
    print(f"[2/5] CONTEXT: {len(sites)} source site(s) from the trace.")

    desc = (f"Project {proj_name}. Fuzzer found: {crash}.\n"
            f"Sanitizer summary:\n{short_report}\n\n"
            f"Relevant source (repo-relative paths; patch against these):\n{ctx}\n\n"
            "Write the minimal unified diff to fix the memory-safety bug.")
    total = 0.0
    print(f"[3/5] DRAFT with {drafter}...")
    d, u = call(drafter, DRAFT_SYSTEM, desc, 2400); total += ucost(u)
    diff = extract_diff(d)
    print(f"      {len(diff.splitlines())} diff lines, ${ucost(u):.4f}")
    if not no_review:
        print(f"[4/5] REVIEW with {reviewer}...")
        rv, u = call(reviewer, REVIEW_SYSTEM,
                     f"{desc}\n\nCandidate patch:\n```diff\n{diff}\n```", 4000)
        total += ucost(u); diff = extract_diff(rv)
        print(f"      ${ucost(u):.4f}")

    gdir = os.path.join(HERE, "generated"); os.makedirs(gdir, exist_ok=True)
    dpath = os.path.join(gdir, f"{cid}.generated.diff")
    open(dpath, "w").write(diff)

    gen_files = list(re.findall(r'^\+\+\+ b/(.+)$', diff, re.M))
    pdir = patch_dir_for(f"n132/arvo:{vul}", gen_files[0]) if gen_files else proj
    bdir = build_dir_for(f"n132/arvo:{vul}")
    print(f"[5/5] VERIFY: apply in {pdir}, compile in {bdir}, rerun PoC ...")
    # Stage sentinels so we can tell apply / compile / crash apart.
    vcmd = (f"cd {pdir} && git apply -p1 --recount /patch.diff 2>/tmp/ap.log "
            f"&& echo __APPLIED__; "
            f"cd {bdir} && compile >/tmp/co.log 2>&1 && echo __COMPILED__; "
            f"arvo >/tmp/ru.log 2>&1; echo __ARVO__:$?")
    vr = drun(f"n132/arvo:{vul}", vcmd, mounts=[(dpath, "/patch.diff")], capture=True)
    out = vr.stdout + vr.stderr
    applied = "__APPLIED__" in out
    compiled = "__COMPILED__" in out
    m = re.search(r"__ARVO__:(\d+)", out)
    exitc = int(m.group(1)) if m else None
    gate = applied and compiled and exitc == 0

    # score vs ground truth: same file(s) touched?
    good_files = set(re.findall(r'^\+\+\+ b/(.+)$', good, re.M))
    same_file = bool(good_files & set(gen_files))
    if not applied:   reason = "patch did not apply"
    elif not compiled:reason = "did not recompile"
    elif exitc != 0:  reason = "PoC still crashes"
    else:             reason = "PoC no longer crashes"

    print(f"\n  --- case {cid} result ---")
    print(f"  applied / compiled : {applied} / {compiled}")
    print(f"  verify gate   : {'PASS' if gate else 'FAIL'}  ({reason})")
    print(f"  touches same file as maintainer fix: "
          f"{'yes' if same_file else 'no'} ({', '.join(gen_files) or 'none'})")
    print(f"  model cost    : ${total:.4f}")
    return dict(case=cid, project=proj_name, applied=applied, gate=gate,
                same_file=same_file, cost=total)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--case", type=int, help="single ARVO case id")
    ap.add_argument("--all", action="store_true", help="run every case in cases.json")
    ap.add_argument("--drafter", default="deepseek/deepseek-v4-flash")
    ap.add_argument("--reviewer", default="anthropic/claude-sonnet-5.5")
    ap.add_argument("--no-review", action="store_true")
    args = ap.parse_args()

    if args.all:
        cfg = json.load(open(os.path.join(HERE, "cases.json")))
        ids = [c["id"] for c in cfg["cases"]]
    elif args.case:
        ids = [args.case]
    else:
        ap.error("pass --case <id> or --all")

    results = []
    for cid in ids:
        res = run_case(cid, args.drafter, args.reviewer, args.no_review)
        if res:
            results.append(res)

    if len(results) > 1:
        npass = sum(r["gate"] for r in results)
        print(f"\n===== SUMMARY: {npass}/{len(results)} cases passed the verify gate "
              f"(${sum(r['cost'] for r in results):.3f} total) =====")
        for r in results:
            print(f"  {r['case']:>7} {r['project'][:16]:16} "
                  f"{'PASS' if r['gate'] else 'FAIL':4}  "
                  f"{'same-file' if r['same_file'] else 'diff-file'}  ${r['cost']:.4f}")


if __name__ == "__main__":
    main()
