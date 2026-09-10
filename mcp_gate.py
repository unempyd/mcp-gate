#!/usr/bin/env python3
"""mcp-gate: does this MCP endpoint enforce authentication?

One question, measured one way: send `initialize`, then replay `tools/list`
with no token, and record what came back. If the server hands over its tool
list to an unauthenticated caller, that is the finding. If it refuses, check
that the refusal carries an RFC 9728 challenge a client can actually follow.

Fault classes (only what has been observed in a real population):
  F1 auth-absence        endpoint answers tool calls with no token
  F2 incomplete-oauth-rs 401 without RFC 9728 resource_metadata, or PRM broken

Scope is deliberate. This probes endpoints; it does not read source. A server
distributed for stdio can still ship an HTTP mode — run it and probe that URL
like any other. See README for the measurement behind this scope.

Methodology honesty: single-shot unauthenticated probes establish posture, not
full OAuth conformance. Anything unclear is reported inconclusive, never as a
fault.
"""
import argparse, hashlib, hmac, json, os, re, sys
import urllib.error, urllib.parse, urllib.request
from datetime import datetime, timezone

VERSION = "0.3.0"
CLASSES = {
    "F1": "auth-absence (endpoint answers tool calls with no token)",
    "F2": "incomplete-oauth-rs (RFC 9728 protected-resource metadata missing/broken)",
}
PRM_MAX_BYTES = 256 * 1024
BODY_SNIPPET = 4096

def hget(headers, name):
    """Case-insensitive header lookup (HTTP/2 lowercases everything)."""
    for k, v in headers.items():
        if k.lower() == name.lower():
            return v
    return None

# ---------------- runtime probe (single-shot, unauthenticated) ----------------
def probe_http(url, timeout=10):
    """One initialize, one tokenless tools/list replay, then the PRM checks."""
    findings, evidence = [], []

    def post(body, extra=None):
        req = urllib.request.Request(url, data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json",
                     "Accept": "application/json, text/event-stream",
                     "User-Agent": f"mcp-gate/{VERSION} (correctness probe)", **(extra or {})})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, dict(r.headers), r.read(BODY_SNIPPET).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), (e.read(BODY_SNIPPET) or b"").decode("utf-8", "replace")
        except Exception as e:
            return None, {}, str(e)

    init = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2026-07-28", "capabilities": {},
                       "clientInfo": {"name": "mcp-gate", "version": VERSION}}}
    s1, h1, b1 = post(init)
    evidence.append(f"POST initialize -> {s1}")
    if s1 is None:
        return [{"id": "NET", "class": "F1", "status": "inconclusive",
                 "evidence": f"unreachable: {b1} — no posture observable, no fault claimed"}], evidence

    low = b1.lower()
    if s1 in (403, 429, 503) and ("cloudflare" in low or "error 1010" in low or "access denied" in low
                                  or "captcha" in low or "rate limit" in low) and "jsonrpc" not in low:
        # WAF / bot wall, not an MCP auth response — never claim a fault we did not observe.
        return [{"id": "PROBE-BLOCKED", "class": "F1", "status": "inconclusive",
                 "evidence": f"endpoint returned {s1} from bot protection; auth posture untestable from here"}], evidence

    sess = hget(h1, "Mcp-Session-Id")
    if sess:
        evidence.append("session header issued (Mcp-Session-Id present)")
    s2, h2, _ = post({"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                     {"Mcp-Session-Id": sess} if sess else None)
    evidence.append(f"tokenless tools/list -> {s2}")

    if s2 == 200:
        advertised = s1 in (401, 403) and (hget(h1, "WWW-Authenticate") or hget(h2, "WWW-Authenticate"))
        findings.append({"id": "AUTH-OPEN", "class": "F1", "status": "fail",
                         "evidence": f"tools/list answered 200 with no token (chained replay; initialize -> {s1})"
                                     + (" — OAuth advertised but not enforced" if advertised else "")})
    elif s2 in (401, 403):
        # Keyed on s2: the tools/list response is the authoritative challenge;
        # initialize may 401 generically without resource_metadata.
        wa = hget(h2, "WWW-Authenticate") or hget(h1, "WWW-Authenticate") or ""
        m = re.search(r'resource_metadata="?([^",]+)"?', wa)
        if not m:
            findings.append({"id": "AUTH-NO-PRM-CHALLENGE", "class": "F2", "status": "fail",
                             "evidence": f"401 without RFC 9728 resource_metadata (got: {wa[:120] or 'no WWW-Authenticate'})"})
        else:
            prm_url = m.group(1)
            # The scanned server chooses this URL. urllib speaks file:// and ftp://,
            # so an allowlist is the difference between fetching metadata and being
            # made to read our own disk.
            if urllib.parse.urlsplit(prm_url).scheme.lower() not in ("http", "https"):
                findings.append({"id": "PRM-BAD-SCHEME", "class": "F2", "status": "fail",
                                 "evidence": f"resource_metadata is not an http(s) URL, refused unfetched: {prm_url[:120]!r}"})
            else:
                try:
                    req = urllib.request.Request(prm_url, headers={"User-Agent": f"mcp-gate/{VERSION}"})
                    with urllib.request.urlopen(req, timeout=timeout) as r:
                        prm = json.loads(r.read(PRM_MAX_BYTES).decode("utf-8", "replace"))
                    if not isinstance(prm, dict):
                        raise ValueError("PRM document is not a JSON object")
                    ok = "authorization_servers" in prm or "resource" in prm
                    findings.append({"id": "OAUTH-POSTURE", "class": "F2",
                                     "status": "pass" if ok else "fail",
                                     "evidence": f"PRM fetched: {prm_url} -> keys={sorted(prm)[:6]}"})
                except Exception:
                    findings.append({"id": "PRM-UNREACHABLE", "class": "F2", "status": "fail",
                                     "evidence": f"resource_metadata advertised but unfetchable: {prm_url}"})

    if s2 not in (200, 401, 403) and not any(f["id"] == "AUTH-OPEN" for f in findings):
        findings.append({"id": "POSTURE-UNDETERMINED", "class": "F1", "status": "inconclusive",
                         "evidence": f"initialize -> {s1}, tools/list -> {s2}: no interpretable auth posture"})
    return findings, evidence

# ---------------- receipt ----------------
def _signing_key():
    """$MCP_GATE_KEY, else a per-machine key. The scheme is symmetric: a receipt
    verifies only where its key is present, which is why CI must set it explicitly."""
    key = os.environ.get("MCP_GATE_KEY")
    if key:
        return key.strip()
    kf = os.path.expanduser("~/.mcp-gate-key")
    if not os.path.exists(kf):
        # 0600 at creation: no window in which the secret is world-readable.
        fd = os.open(kf, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(os.urandom(32).hex())
    with open(kf, encoding="utf-8") as fh:
        return fh.read().strip()

def _canon(body):
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()

def receipt(target, checks, evidence):
    body = {"schema": "mcp-gate/receipt@3", "tool_version": VERSION,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target": target, "mode": "runtime",
            "checks": checks, "probe_evidence": evidence}
    body["receipt_sha256"] = hashlib.sha256(_canon(body)).hexdigest()
    body["hmac_sha256"] = hmac.new(_signing_key().encode(), _canon(body), hashlib.sha256).hexdigest()
    return body

def verify_receipt(path):
    with open(path, encoding="utf-8") as fh:
        r = json.load(fh)
    sig = r.pop("hmac_sha256", "")
    ok = hmac.compare_digest(hmac.new(_signing_key().encode(), _canon(r), hashlib.sha256).hexdigest(), sig)
    return ok, r

# ---------------- CLI ----------------
def main():
    p = argparse.ArgumentParser(
        prog="mcp-gate", description="Does this MCP endpoint enforce authentication?")
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check", help="probe an MCP endpoint URL")
    c.add_argument("target", help="http(s) URL of the MCP endpoint")
    c.add_argument("--receipt-out", default=None)
    c.add_argument("--timeout", type=float, default=10)
    v = sub.add_parser("verify-receipt", help="check a receipt's signature")
    v.add_argument("receipt")
    a = p.parse_args()

    if a.cmd == "verify-receipt":
        ok, r = verify_receipt(a.receipt)
        print(json.dumps({"signature_valid": ok, "receipt_sha256": r.get("receipt_sha256"),
                          "target": r.get("target")}, indent=1))
        return 0 if ok else 1

    if urllib.parse.urlsplit(a.target).scheme.lower() not in ("http", "https"):
        print(f"target must be an http(s) MCP endpoint URL, got: {a.target}\n"
              f"mcp-gate probes running endpoints. If a server is distributed for stdio,\n"
              f"start its HTTP mode and probe that URL.", file=sys.stderr)
        return 2

    checks, ev = probe_http(a.target, timeout=a.timeout)
    rc = receipt(a.target, checks, ev)
    if a.receipt_out:
        out = a.receipt_out
    else:
        rdir = os.path.abspath("mcp-gate-receipts")
        os.makedirs(rdir, exist_ok=True)
        out = os.path.join(rdir, re.sub(r"[^A-Za-z0-9._-]+", "_", a.target) + ".receipt.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(rc, fh, indent=1)

    fails = [x for x in checks if x["status"] == "fail"]
    print(json.dumps({"target": a.target, "failures": len(fails), "checks": checks,
                      "receipt": out, "fault_classes": sorted({x["class"] for x in fails})}, indent=1))
    return 1 if fails else 0

if __name__ == "__main__":
    sys.exit(main())
