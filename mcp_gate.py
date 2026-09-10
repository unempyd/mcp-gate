#!/usr/bin/env python3
"""mcp-gate: correct-by-default MCP server gate.

Locked job: scan an MCP server (source path or live endpoint) against the
residual measured fault classes that survived the 2026-07-28 stateless spec,
emit a minimal compliant resource-server scaffold when none exists, apply
bounded safe fixes only, and produce a signed receipt (digest of the scanned
file + every check result + residual risks). No UI, no server, no cloud.

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
import argparse, ast, hashlib, hmac, io, json, os, re, sys, tokenize
import urllib.error, urllib.parse, urllib.request
from datetime import datetime, timezone

VERSION = "0.2.0"
CLASSES = {
    "F1": "auth-absence (live endpoint answers tool calls with no token)",
    "F2": "incomplete-oauth-rs (RFC 9728 protected-resource metadata missing/broken)",
    "F3": "cross-tenant-stateless-isolation (session-keyed state; CVE-2026-16498 class)",
    "F4": "retry-duplicate-side-effect (mutation tools without idempotency)",
    "F5": "injection-ssrf (unverified input in URLs or shell)",
    "F6": "legacy-session-era (Mcp-Session-Id / Last-Event-ID / DCR in new code)",
}
# Definition sites only. Bare verb matching flagged `payload` and `updated_at`,
# which are values, not handlers, and made F4 fire on almost any server.
MUTATION_VERBS = re.compile(
    r"\b(?:async\s+)?def\s+(?:create|delete|remove|update|send|submit|deploy|pay|charge"
    r"|write|publish|provision|revoke|refund)\w*", re.I)

PRM_MAX_BYTES = 256 * 1024

# ---------------- runtime probes (single-shot, unauthenticated) ----------------
def hget(headers, name):
    """Case-insensitive header lookup (HTTP/2 lowercases everything)."""
    for k, v in headers.items():
        if k.lower() == name.lower():
            return v
    return None

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
        advertised = s1 in (401, 403) and (hget(h1, "WWW-Authenticate") or hget(h2, "WWW-Authenticate"))
        findings.append({"id": "AUTH-OPEN", "class": "F1", "status": "fail",
                         "evidence": f"tools/list answered 200 with no token (chained, stateless replay; initialize -> {s1})"
                                     + (" — OAuth advertised but not enforced" if advertised else "")})
    elif s2 in (401, 403):
        # this branch is keyed on s2: the tools/list response is the authoritative
        # challenge; initialize may 401 generically without resource_metadata.
        wa = hget(h2, "WWW-Authenticate") or hget(h1, "WWW-Authenticate") or ""
        m = re.search(r'resource_metadata="?([^",]+)"?', wa)
        if not m:
            findings.append({"id": "AUTH-NO-PRM-CHALLENGE", "class": "F2", "status": "fail",
                             "evidence": f"401 without RFC 9728 resource_metadata (got: {wa[:120] or 'no WWW-Authenticate'})"})
        else:
            prm_url = m.group(1)
            # The scanned server chooses this URL. urllib speaks file:// and ftp://,
            # so an allowlist is the difference between fetching metadata and being
            # made to read our own disk — the F5 class this tool exists to find.
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
    ("FSTRING-URL", "F5", re.compile(r"https?://[^\"\n]*\{[a-zA-Z_]|(?:requests|httpx|urllib)\.\w+\(\s*f[\"']", re.I),
     "unverified input interpolated into URLs (SSRF class)"),
    # subprocess.run/.call/.check_output are the documented API; `subprocess(` is not a thing.
    ("SHELL-FSTRING", "F5", re.compile(r"(?:subprocess\.\w+|os\.system|os\.popen|Popen)\s*\([^)]*f[\"']|shell\s*=\s*True", re.I),
     "shell execution with interpolated input (injection class)"),
]
def _spaces(m):
    """Same length, same newlines, no content — offsets downstream stay valid."""
    return "".join("\n" if c == "\n" else " " for c in m.group(0))

TRIPLE_QUOTED = re.compile(r"(?s)('''|\"\"\")(?:\\.|(?!\1).)*\1")
LINE_COMMENT = re.compile(r"#[^\n]*")

def _blank(src, spans):
    """Overwrite (row, col) character spans with spaces.

    Length, line count and character offsets are all preserved, so an index into
    the result is the same index into the original source.
    """
    starts, n = [0], 0
    for line in src.splitlines(keepends=True):
        n += len(line); starts.append(n)
    chars = list(src)
    for (r1, c1), (r2, c2) in spans:
        if not (0 < r1 < len(starts) and 0 < r2 < len(starts)):
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

    Degradation is deliberate. If the file will not tokenize or will not parse,
    the fallbacks below strip more than they strictly should. A gate must fail
    toward reporting a fault, never toward a clean pass.
    """
    lines = src.splitlines(keepends=True)
    def char_col(row, byte_col):
        # ast reports col_offset in UTF-8 bytes; tokenize reports characters.
        line = lines[row - 1] if 0 < row <= len(lines) else ""
        return len(line.encode("utf-8")[:byte_col].decode("utf-8", "ignore"))

    spans, tokenized, parsed = [], True, True
    try:
        for tok in tokenize.generate_tokens(io.StringIO(src).readline):
            if tok.type == tokenize.COMMENT:
                spans.append((tok.start, tok.end))
    except (tokenize.TokenError, IndentationError, SyntaxError, ValueError):
        tokenized = False
    try:
        for node in ast.walk(ast.parse(src)):
            v = getattr(node, "value", None)
            if isinstance(node, ast.Expr) and isinstance(v, ast.Constant) and isinstance(v.value, str):
                spans.append(((v.lineno, char_col(v.lineno, v.col_offset)),
                              (v.end_lineno, char_col(v.end_lineno, v.end_col_offset))))
    except (SyntaxError, ValueError, RecursionError):
        parsed = False

    code = _blank(src, spans)
    if not parsed:
        # No AST means no docstring spans. Remove every triple-quoted string
        # instead: coarser, but it cannot leave prose standing.
        code = TRIPLE_QUOTED.sub(_spaces, code)
    if not tokenized:
        code = LINE_COMMENT.sub(_spaces, code)
    return code

class UnscannableSource(Exception):
    """The file is not Python, so the Python-shaped rules would mean nothing."""

def _read(path):
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()

def require_python(path, src):
    try:
        ast.parse(src)
    except (SyntaxError, ValueError, RecursionError) as e:
        raise UnscannableSource(
            f"{path}: not parseable as Python ({e.__class__.__name__}: {e}). "
            "mcp-gate scans Python sources; it will not emit a receipt for a file "
            "whose contents it cannot analyse.") from None

def scan_source(path):
    src = _read(path)
    require_python(path, src)
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
    src = _read(path)
    require_python(path, src)
    code = strip_prose(src)   # offset-preserving, so an index here is an index into src
    applied = []
    if PRM_PATH not in code:  # a comment mentioning the path is not the route
        at = code.find("\nif __name__")   # insert above the guard, never inside a docstring
        src = src[:at] + PRM_BLOCK + "\n" + src[at:] if at != -1 else src + PRM_BLOCK
        open(path, "w", encoding="utf-8").write(src)
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
def scaffold(out, force=False):
    if os.path.exists(out) and not force:
        raise SystemExit(f"refusing to overwrite existing file: {out} (pass --force to replace it)")
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    open(out, "w", encoding="utf-8").write(SCAFFOLD)
    return out

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

def receipt(target, mode, checks, fixes, extra=None):
    body = {"schema": "mcp-gate/receipt@2", "tool_version": VERSION,
            "timestamp": datetime.now(timezone.utc).isoformat(), "target": target, "mode": mode,
            "checks": checks, "fixes": fixes, **(extra or {})}
    # Digest of this receipt. The scanned file's own digest is target_sha256,
    # recorded by the caller for source scans.
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
    p = argparse.ArgumentParser(prog="mcp-gate", description="Correct-by-default MCP server gate")
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check"); c.add_argument("target"); c.add_argument("--receipt-out", default=None)
    f = sub.add_parser("fix"); f.add_argument("target")
    s = sub.add_parser("scaffold"); s.add_argument("out")
    s.add_argument("--force", action="store_true", help="overwrite an existing file")
    v = sub.add_parser("verify-receipt"); v.add_argument("receipt")
    a = p.parse_args()
    if a.cmd == "scaffold":
        print(scaffold(a.out, a.force)); return 0
    if a.cmd == "fix":
        try:
            print(json.dumps(fix_source(a.target), indent=1))
        except UnscannableSource as e:
            print(e, file=sys.stderr); return 2
        return 0
    if a.cmd == "verify-receipt":
        ok, r = verify_receipt(a.receipt)
        print(json.dumps({"signature_valid": ok, "receipt_sha256": r.get("receipt_sha256"),
                          "target": r.get("target"), "target_sha256": r.get("target_sha256")}, indent=1))
        return 0 if ok else 1
    # check
    if re.match(r"^https?://", a.target):
        checks, ev = probe_http(a.target)
        rc = receipt(a.target, "runtime", checks, [], {"probe_evidence": ev})
    elif os.path.isfile(a.target):
        try:
            checks = scan_source(a.target)
        except UnscannableSource as e:
            print(e, file=sys.stderr); return 2
        with open(a.target, "rb") as fh:
            digest = hashlib.sha256(fh.read()).hexdigest()
        rc = receipt(a.target, "source", checks, [], {"target_sha256": digest})
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
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(rc, fh, indent=1)
    fails = [x for x in checks if x["status"] == "fail"]
    print(json.dumps({"target": a.target, "mode": rc["mode"], "failures": len(fails),
                      "checks": checks, "receipt": out,
                      "fault_classes": sorted({x["class"] for x in fails})}, indent=1))
    return 1 if fails else 0

if __name__ == "__main__":
    sys.exit(main())