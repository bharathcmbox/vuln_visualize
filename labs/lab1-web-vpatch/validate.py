#!/usr/bin/env python3
"""Virtual-patch validation gate for Lab 1.

The gate every virtual patch (and code patch) must pass before anyone trusts it.
For each protection path it asks:
  1. Is the malicious-input CORPUS blocked? (including shape variants, not just
     the one canonical string)
  2. Does LEGITIMATE traffic still pass? (no false positives that break users)

Reports PASS/FAIL per category only; it does not print the request bodies it
sends. The labelled inputs live in test-corpus.jsonl.

Usage: python3 validate.py
Stdlib only -- no jq, no requests.
"""
import json
import os
import urllib.request
import urllib.error

PATHS = [
    ("direct-no-waf", 3000),
    ("generic-waf", 8080),
    ("waf-vpatch", 8081),
    ("model-vpatch", 8082),  # isolated path for the model-generated rule
]
LOGIN = "/rest/user/login"
CORPUS = os.path.join(os.path.dirname(__file__), "test-corpus.jsonl")


def send(port, body):
    """POST a login body. Return (status_code, response_text)."""
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{LOGIN}",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")
    except Exception as e:  # noqa: BLE001
        return 0, f"<error: {e}>"


def is_blocked(code, body):
    """Blocked = app never authenticated it (4xx/5xx, or no token in body)."""
    if 400 <= code < 600:
        return True
    return '"token"' not in body


def load_corpus():
    rows = []
    with open(CORPUS) as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            rows.append(json.loads(line))
    return rows


def reachable(port):
    """True if something answers on the port (container is up)."""
    try:
        urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5)
        return True
    except urllib.error.HTTPError:
        return True  # answered, just not 2xx
    except Exception:
        return False


def main():
    rows = load_corpus()
    print(f"\n{'PATH':16} | {'malicious corpus':22} | {'benign logins':18} | verdict")
    print("-" * 78)
    for name, port in PATHS:
        if not reachable(port):
            print(f"{name:16} | {'(container not running)':22} | {'':18} | skipped")
            continue
        mal = [r for r in rows if r["kind"] == "malicious"]
        ben = [r for r in rows if r["kind"] == "benign"]
        mal_blocked = sum(is_blocked(*send(port, r["body"])) for r in mal)
        # benign "passes" unless the WAF itself returned 403 (app 401 on a wrong
        # password is correct behaviour, not a false positive)
        ben_passed = sum(send(port, r["body"])[0] != 403 for r in ben)

        if mal_blocked == len(mal) and ben_passed == len(ben):
            verdict = "PASS"
        elif mal_blocked == 0:
            verdict = "UNPROTECTED"
        else:
            verdict = "PARTIAL / review"
        print(
            f"{name:16} | {mal_blocked:5}/{len(mal):<3} blocked      | "
            f"{ben_passed:5}/{len(ben):<3} passed    | {verdict}"
        )
    print(
        "\nLegend: a good virtual patch blocks the WHOLE malicious corpus AND lets\n"
        "all benign logins through. 'PARTIAL' means variants slipped past -- the\n"
        "rule is too narrow. 'UNPROTECTED' is the no-WAF baseline."
    )


if __name__ == "__main__":
    main()
