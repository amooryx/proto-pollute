#!/usr/bin/env python3
"""
Proto Pollute — JavaScript Prototype Pollution Detection Tool
Tests REST APIs and web pages for prototype pollution via __proto__ / constructor injection.
Author: Omar Khalid (amooryx) | github.com/amooryx/proto-pollute
AUTHORIZED USE ONLY.
"""

import argparse
import json
import math
import random
import string
import sys
import urllib.error
import urllib.parse
import urllib.request



MAX_URL_LENGTH = 2048
MAX_TIMEOUT_SECONDS = 60.0
MIN_TIMEOUT_SECONDS = 0.1
MAX_RESPONSE_BYTES = 8192

def rand_marker() -> str:
    return ''.join(random.choices(string.ascii_lowercase, k=8))

def validate_url(url: str) -> str:
    if len(url) > MAX_URL_LENGTH:
        raise ValueError(f"URL exceeds the {MAX_URL_LENGTH}-character limit")
    if any(ord(char) < 32 or ord(char) == 127 for char in url):
        raise ValueError("URL must not contain control characters")
    if any(char.isspace() for char in url):
        raise ValueError("URL must not contain whitespace")

    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError as ex:
        raise ValueError(f"URL is malformed: {ex}") from ex
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("URL must be an absolute HTTP or HTTPS URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URL must not include credentials")
    try:
        parsed.port
    except ValueError as ex:
        raise ValueError(f"URL has an invalid port: {ex}") from ex
    return url

def validate_timeout(timeout: float) -> float:
    if (
        not math.isfinite(timeout)
        or not MIN_TIMEOUT_SECONDS <= timeout <= MAX_TIMEOUT_SECONDS
    ):
        raise ValueError(
            f"timeout must be between {MIN_TIMEOUT_SECONDS} and "
            f"{MAX_TIMEOUT_SECONDS} seconds"
        )
    return timeout

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
    validate_url(url)
    validate_timeout(timeout)
    data = json.dumps(payload).encode()
    req  = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent",   "ProtoPollute/1.0")
    for k, v in headers.items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(MAX_RESPONSE_BYTES).decode(errors="ignore")
            return {"status": resp.status, "body": body}
    except urllib.error.HTTPError as e:
        body = e.read(MAX_RESPONSE_BYTES).decode(errors="ignore")
        return {"status": e.code, "body": body}

def test_json_pollution(url: str, headers: dict, timeout: float) -> list[dict]:
    validate_url(url)
    validate_timeout(timeout)
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
                "classification": "heuristic_candidate",
                "note": "Injected marker reflected; reflection alone does not establish prototype pollution",
            })
            print(f"  [?] JSON marker reflected (heuristic): {json.dumps(payload)[:60]}")
    return findings

def test_qs_pollution(url: str, headers: dict, timeout: float) -> list[dict]:
    validate_url(url)
    validate_timeout(timeout)
    findings = []
    for fn in QUERY_PAYLOADS:
        marker  = rand_marker()
        key     = f"test_{rand_marker()}"
        extra_qs = fn(marker, key)
        parsed = urllib.parse.urlsplit(url)
        query = f"{parsed.query}&{extra_qs}" if parsed.query else extra_qs
        test_url = urllib.parse.urlunsplit(parsed._replace(query=query))
        if len(test_url) > MAX_URL_LENGTH:
            raise ValueError(
                f"query probe URL exceeds the {MAX_URL_LENGTH}-character limit"
            )
        req = urllib.request.Request(test_url)
        for k, v in headers.items():
            req.add_header(k, v)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(MAX_RESPONSE_BYTES).decode(errors="ignore")
            if marker in body:
                findings.append({
                    "type": "qs_proto_pollution",
                    "payload": extra_qs[:80],
                    "marker": marker,
                    "status": resp.status,
                    "classification": "heuristic_candidate",
                    "note": "Query marker reflected; reflection alone does not establish prototype pollution",
                })
                print(f"  [?] Query marker reflected (heuristic): {extra_qs[:60]}")
    return findings

def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Proto Pollute - heuristic prototype-pollution assessment (authorized use only)",
    )
    parser.add_argument("url",        help="HTTP(S) URL (JSON API endpoint)")
    parser.add_argument("--qs",       action="store_true", help="Also test query-string pollution")
    parser.add_argument("--timeout",  type=validate_timeout, default=10)
    parser.add_argument("--header",   nargs="*", help="Extra headers: 'Key: Value'")
    parser.add_argument("--out",      help="Output JSON file")
    args = parser.parse_args(argv)

    headers = {}
    if args.header:
        for h in args.header:
            if ":" not in h:
                parser.error(f"invalid header {h!r}; expected 'Key: Value'")
            k, v = h.split(":", 1)
            if not k.strip() or any(ord(char) < 32 for char in k + v):
                parser.error(f"invalid header {h!r}")
            headers[k.strip()] = v.strip()

    try:
        validate_url(args.url)
        print(f"[*] Prototype pollution assessment: {args.url}")
        findings = test_json_pollution(args.url, headers, args.timeout)
        if args.qs:
            findings += test_qs_pollution(args.url, headers, args.timeout)
    except (ValueError, urllib.error.URLError, OSError) as ex:
        print(f"[!] Assessment failed: {ex}", file=sys.stderr)
        return 2

    print(f"\n[*] {len(findings)} heuristic candidate(s); reflection is not proof")
    if args.out:
        try:
            with open(args.out, "w", encoding="utf-8") as f:
                json.dump(findings, f, indent=2)
                f.write("\n")
        except OSError as ex:
            print(f"[!] Could not write results to {args.out}: {ex}", file=sys.stderr)
            return 2
        print(f"[*] Results → {args.out}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
