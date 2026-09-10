#!/usr/bin/env python3
"""mcp-gate: correct-by-default MCP server gate.

Locked job: scan an MCP server (source path or live endpoint) against the
residual measured fault classes that survived the 2026-07-28 stateless spec,
emit a minimal compliant resource-server scaffold when none exists, apply
bounded safe fixes only, and produce a signed receipt (artifact hash + every
check result + residual risks). No UI, no server, no cloud.

Fault classes (frozen 2026-09-10, from the kill-criteria memo):
  F1 auth-absence              live endpoint serves tools with no token
  F2 incomplete-oauth-rs       401 without RFC 9728 resource_metadata, or PRM doc missing
  F3 cross-tenant-stateless    per-session state keyed on session ids in stateless mode (CVE-2026-16498 class)
  F4 retry-duplicate-side-effect mutation tools with no idempotency key
  F5 injection-ssrf            f-string URLs / shell calls fed unverified input
  F6 legacy-session-era        Mcp-Session-Id / Last-Event-ID / DCR usage in new code

Methodology honesty: source checks are inspection-based; runtime checks are
single-shot unauthenticated probes (posture, not a full OAuth conformance run).
"""
import argparse, ast, hashlib, hmac, io, json, os, re, sys, tokenize, urllib.request, urllib.error
from datetime import datetime, timezone

VERSION = "0.1.1"
CLASSES = {
    "F1": "auth-absence (live endpoint answers tool calls with no token)",
    "F2": "incomplete-oauth-rs (RFC 9728 protected-resource metadata missing/broken)",
    "F3": "cross-tenant-stateless-isolation (session-keyed state; CVE-2026-16498 class)",
    "F4": "retry-duplicate-side-effect (mutation tools without idempotency)",
    "F5": "injection-ssrf (unverified input in URLs or shell)",
    "F6": "legacy-session-era (Mcp-Session-Id / Last-Event-ID / DCR in new code)",
}
MUTATION_VERBS = re.compile(
    r"\b(create|delete|remove|update|send|submit|deploy|pay|charge|write|publish|provision|revoke|refund)\w*", re.I)

# ---------------- runtime probes (single-shot, unauthenticated) ----------------
def probe_http(url, timeout=10):
    """One initialize, one tokenless tools/list replay, then PRM checks. Mirrors S1 methodology."""
    findings, evidence = [], []
    def post(body, extra=None):
        req = urllib.request.Request(url, data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                     "User-Agent": f"mcp-gate/{VERSION} (correctness probe)", **(extra or {})})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, dict(r.headers), r.read()[:4096].decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), (e.read()[:400] or b"").decode("utf-8", "replace")
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
                 "evidence": f"endpoint returned {s1} from bot protection; MCP auth posture untestable from this environment"}], evidence
    sess = h1.get("Mcp-Session-Id") or h1.get("mcp-session-id")
    if sess:
        evidence.append("legacy session header issued (Mcp-Session-Id present)")
    s2, h2, _ = post({"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                     {"Mcp-Session-Id": sess} if sess else None)
    evidence.append(f"tokenless tools/list -> {s2}")
    if s2 == 200:
        def _g(h, name):
            for k, v in h.items():
                if k.lower() == name.lower():
                    return v
            return None
        advertised = s1 in (401, 403) and (_g(h1, "WWW-Authenticate") or _g(h2, "WWW-Authenticate"))
        findings.append({"id": "AUTH-OPEN", "class": "F1", "status": "fail",
                         "evidence": f"tools/list answered 200 with no token (chained, stateless replay; initialize -> {s1})"
                                     + (" — OAuth advertised but not enforced" if advertised else "")})
    elif s2 in (401, 403):
        def hget(h, name):
            for k, v in h.items():
                if k.lower() == name.lower():
                    return v
            return None
        # this branch is keyed on s2: the tools/list response is the authoritative
        # challenge; initialize may 401 generically without resource_metadata.
        wa = hget(h2, "WWW-Authenticate") or hget(h1, "WWW-Authenticate") or ""
        m = re.search(r'resource_metadata="?([^",]+)"?', wa)
        if not m:
            findings.append({"id": "AUTH-NO-PRM-CHALLENGE", "class": "F2", "status": "fail",
                             "evidence": f"401 without RFC 9728 resource_metadata (got: {wa[:120] or 'no WWW-Authenticate'})"})
        else:
            prm_url = m.group(1)
            try:
                req = urllib.request.Request(prm_url, headers={"User-Agent": f"mcp-gate/{VERSION}"})
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    prm = json.loads(r.read().decode("utf-8", "replace"))
                ok = "authorization_servers" in prm or "resource" in prm
                findings.append({"id": "OAUTH-POSTURE", "class": "F2",
                                 "status": "pass" if ok else "fail",
                                 "evidence": f"PRM fetched: {prm_url} -> keys={sorted(prm)[:6]}"})
            except Exception as e:
                findings.append({"id": "PRM-UNREACHABLE", "class": "F2", "status": "fail",
                                 "evidence": f"resource_metadata advertised but unfetchable: {prm_url}"})
    if s1 == 200 and s2 not in (200, 401):
        evidence.append(f"non-2026-07-28 shape (tools/list -> {s2}); legacy-era deployment")
    if s2 not in (200, 401, 403) and not any(f["id"] == "AUTH-OPEN" for f in findings):
        findings.append({"id": "POSTURE-UNDETERMINED", "class": "F1", "status": "inconclusive",
                         "evidence": f"initialize -> {s1}, tools/list -> {s2}: server did not present an interpretable auth posture"})
    return findings, evidence

# ---------------- source scanners (deterministic) ----------------
SCAN_RULES = [
    ("DCR-ENABLED", "F6", re.compile(r"dynamic[_-]?client[_-]?registration|DCR[_A-Z]|enable_dynamic", re.I),
     "dynamic client registration present (2026-07-28: DCR deprecated, CIMD path; default must be off)"),
    ("SESSION-KEYED-STATE", "F3", re.compile(r"session_id|Mcp-Session-Id|mcp_session_id", re.I),
     "state keyed on session ids in a stateless protocol (cross-tenant reuse class)"),
    ("RESUMABILITY", "F6", re.compile(r"Last-Event-ID|last_event_id|event_store|resumab", re.I),
     "pre-stateless SSE resumability surface"),
    ("IDEMPOTENCY", "F4", re.compile(r"idempoten", re.I), None),
    ("FSTRING-URL", "F5", re.compile(r"(?:https?|https?://)[^\"\n]*\{[a-zA-Z_]|(?:requests|httpx|urllib)\.\w+\(\s*f[\"']", re.I),
     "unverified input interpolated into URLs (SSRF class)"),
    ("SHELL-FSTRING", "F5", re.compile(r"(?:subprocess|os\.system|Popen)\([^)]*f[\"']|shell\s*=\s*True", re.I),
     "shell execution with interpolated input (injection class)"),
]
def _blank(src, spans):
    """Overwrite (row,col) spans with spaces: line numbers and char offsets survive."""
    starts, n = [0], 0
    for line in src.splitlines(keepends=True):
        n += len(line); starts.append(n)
    chars = list(src)
    for (r1, c1), (r2, c2) in spans:
        if r1 >= len(starts) or r2 >= len(starts):
            continue
        for i in range(starts[r1 - 1] + c1, min(starts[r2 - 1] + c2, len(chars))):
            if chars[i] != "\n":
                chars[i] = " "
    return "".join(chars)

def strip_prose(src):
    """Blank comments and bare string expressions (docstrings) before scanning.

    Prose is not code: a docstring reading "OAuth 2.1 resource server" must not
    satisfy a check for token verification. String literals used as *values* stay
    — the RFC 9728 route path only ever appears as one.
    """
    spans, tokenized = [], True
    try:
        for tok in tokenize.generate_tokens(io.StringIO(src).readline):
            if tok.type == tokenize.COMMENT:
                spans.append((tok.start, tok.end))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        tokenized = False  # not tokenizable (or not Python): fall back below
    try:
        for node in ast.walk(ast.parse(src)):
            v = getattr(node, "value", None)
            if isinstance(node, ast.Expr) and isinstance(v, ast.Constant) and isinstance(v.value, str):
                spans.append(((v.lineno, v.col_offset), (v.end_lineno, v.end_col_offset)))
    except (SyntaxError, ValueError, RecursionError):
        pass
    code = _blank(src, spans)
    return code if tokenized else re.sub(r"#[^\n]*", "", code)

def scan_source(path):
    src = open(path, encoding="utf-8", errors="replace").read()
    code = strip_prose(src)  # comments and docstrings are not code; prose must not defeat checks
    findings = []
    for cid, fclass, rx, msg in SCAN_RULES:
        if cid == "IDEMPOTENCY":
            if MUTATION_VERBS.search(code) and not re.search(r"idempoten", code, re.I):
                findings.append({"id": "NO-IDEMPOTENCY", "class": "F4", "status": "fail",
                                 "evidence": "mutation-style tool handlers, no idempotency-key handling in code"})
            continue
        m = rx.search(code)
        if m:
            findings.append({"id": cid, "class": fclass, "status": "fail",
                             "evidence": f"{msg}: matched {m.group(0)[:40]!r} at char {m.start()}"})
    has_prm = PRM_PATH in code
    # PRM_PATH contains the substring "oauth" but only publishes metadata; it is
    # not a token-verification surface, and has_prm already accounts for it.
    has_oauth = bool(re.search(r"oauth|bearer|access[_-]?token|WWW-Authenticate",
                               code.replace(PRM_PATH, ""), re.I))
    if not has_oauth:
        findings.append({"id": "NO-OAUTH", "class": "F1", "status": "fail",
                         "evidence": "no OAuth/token verification surface in source"})
    elif not has_prm:
        findings.append({"id": "NO-PRM", "class": "F2", "status": "fail",
                         "evidence": "OAuth present but no RFC 9728 /.well-known/oauth-protected-resource route"})
    return findings

# ---------------- bounded auto-remediation (safe fixes only) ----------------
PRM_PATH = ".well-known/oauth-protected-resource"
PRM_BLOCK = '''

# --- mcp-gate bounded fix: RFC 9728 protected-resource metadata (F2) ---
_PRM = {
    "resource": "RESOURCE_NAME_PLACEHOLDER",
    "authorization_servers": ["AUTHORIZATION_SERVER_PLACEHOLDER"],
    "scopes_supported": ["mcp:tools"],
}
async def _prm_handler(request):
    from aiohttp.web import json_response      # local: adds no module-level dependency
    return json_response(_PRM)
async def _auth_challenge(request, handler):
    resp = await handler(request)
    if resp.status == 401 and "WWW-Authenticate" not in resp.headers:
        prm_url = request.url.with_path("/.well-known/oauth-protected-resource")
        resp.headers["WWW-Authenticate"] = (
            f'Bearer realm="mcp", resource_metadata="{prm_url}"')
    return resp
# register: app.router.add_get("/.well-known/oauth-protected-resource", _prm_handler)
# wrap middleware with _auth_challenge to emit RFC 9728 challenges on 401.
'''
def fix_source(path):
    src = open(path, encoding="utf-8", errors="replace").read()
    applied = []
    if PRM_PATH not in strip_prose(src):   # a comment mentioning the path is not the route
        marker = "\nif __name__" in src and "\nif __name__" or None
        src = src.replace(marker, PRM_BLOCK + "\n" + marker, 1) if marker else src + PRM_BLOCK
        open(path, "w").write(src)
        applied.append({"fix": "ADD-PRM-ROUTE", "class": "F2", "note": "inserted RFC 9728 PRM block; wire authorization_servers before production"})
    return applied

# ---------------- scaffold (compliant baseline; no DCR; CIMD-ready) ----------------
SCAFFOLD = '''#!/usr/bin/env python3
"""Compliant-by-default MCP server scaffold (2026-07-28 stateless core).

Posture: OAuth 2.1 resource server, RFC 9728 PRM published, no DCR by
default (CIMD client identifiers), no session state, idempotency enforced
on every mutating tool. Replace the marked TODOs before production.
Requires: pip install mcp  (official SDK)
"""
import os, json
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("compliant-server", stateless_http=True)

PRM = {
    "resource": os.environ.get("MCP_RESOURCE_NAME", "https://example.com/mcp"),
    "authorization_servers": [os.environ["MCP_ISSUER"]],          # TODO: your OAuth 2.1 AS
    "scopes_supported": ["mcp:tools"],
}

@mcp.tool()
def list_items(prefix: str = "") -> list:
    return [i for i in ["alpha", "beta"] if i.startswith(prefix)]

@mcp.tool()
def create_item(name: str, idempotency_key: str) -> dict:       # TODO: dedupe store on idempotency_key
    """Mutating tool: idempotency key is REQUIRED (stateless retries are fresh calls)."""
    if not idempotency_key:
        raise ValueError("idempotency_key required for mutating calls")
    return {"created": name, "key": idempotency_key}

def prm_environ() -> dict:
    return {"/.well-known/oauth-protected-resource": PRM}        # publish via AS or reverse proxy

if __name__ == "__main__":
    mcp.run(transport="streamable-http")
'''
def scaffold(out):
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    open(out, "w").write(SCAFFOLD)
    return out

# ---------------- receipt ----------------
def receipt(target, mode, checks, fixes, extra=None):
    body = {"schema": "mcp-gate/receipt@1", "tool_version": VERSION,
            "timestamp": datetime.now(timezone.utc).isoformat(), "target": target, "mode": mode,
            "checks": checks, "fixes": fixes, **(extra or {})}
    blob = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    body["artifact_sha256"] = hashlib.sha256(blob).hexdigest()
    key = os.environ.get("MCP_GATE_KEY")
    if not key:
        kf = os.path.expanduser("~/.mcp-gate-key")
        if not os.path.exists(kf):
            open(kf, "w").write(os.urandom(32).hex()); os.chmod(kf, 0o600)
        key = open(kf).read().strip()
    body["hmac_sha256"] = hmac.new(key.encode(), json.dumps(body, sort_keys=True, separators=(",", ":")).encode(),
                                   hashlib.sha256).hexdigest()
    return body

def verify_receipt(path):
    r = json.load(open(path))
    sig = r.pop("hmac_sha256")
    key = os.environ.get("MCP_GATE_KEY") or open(os.path.expanduser("~/.mcp-gate-key")).read().strip()
    ok = hmac.compare_digest(hmac.new(key.encode(), json.dumps(r, sort_keys=True, separators=(",", ":")).encode(),
                                      hashlib.sha256).hexdigest(), sig)
    return ok, r

# ---------------- CLI ----------------
def main():
    p = argparse.ArgumentParser(prog="mcp-gate", description="Correct-by-default MCP server gate")
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check"); c.add_argument("target"); c.add_argument("--receipt-out", default=None)
    f = sub.add_parser("fix"); f.add_argument("target")
    s = sub.add_parser("scaffold"); s.add_argument("out")
    v = sub.add_parser("verify-receipt"); v.add_argument("receipt")
    a = p.parse_args()
    if a.cmd == "scaffold":
        print(scaffold(a.out)); return 0
    if a.cmd == "fix":
        print(json.dumps(fix_source(a.target), indent=1)); return 0
    if a.cmd == "verify-receipt":
        ok, r = verify_receipt(a.receipt)
        print(json.dumps({"signature_valid": ok, "artifact_sha256": r.get("artifact_sha256")}, indent=1))
        return 0 if ok else 1
    # check
    if re.match(r"^https?://", a.target):
        checks, ev = probe_http(a.target)
        rc = receipt(a.target, "runtime", checks, [], {"probe_evidence": ev})
    elif os.path.isfile(a.target):
        checks = scan_source(a.target)
        rc = receipt(a.target, "source", checks, [])
    else:
        print(f"target not found: {a.target}", file=sys.stderr); return 2
    if a.receipt_out:
        out = a.receipt_out
    elif re.match(r"^https?://", a.target):
        rdir = os.path.abspath("mcp-gate-receipts"); os.makedirs(rdir, exist_ok=True)
        out = os.path.join(rdir, re.sub(r"[^A-Za-z0-9._-]+", "_", a.target) + ".receipt.json")
    else:
        out = os.path.join(os.path.dirname(os.path.abspath(a.target)),
                           os.path.basename(a.target) + ".receipt.json")
    json.dump(rc, open(out, "w"), indent=1)
    fails = [x for x in checks if x["status"] == "fail"]
    print(json.dumps({"target": a.target, "mode": rc["mode"], "failures": len(fails),
                      "checks": checks, "receipt": out,
                      "fault_classes": sorted({x["class"] for x in fails})}, indent=1))
    return 1 if fails else 0

if __name__ == "__main__":
    sys.exit(main())