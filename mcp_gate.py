#!/usr/bin/env python3
"""mcp-gate: did this MCP endpoint hand its tool list to an unauthenticated caller?

One question, measured one way: send `initialize`, then replay `tools/list`
with no token, and read the reply. The finding requires positive proof — a
JSON-RPC `result` came back — because JSON-RPC refuses inside a 200 response as
often as it refuses with a 401, and HTTP status alone proves nothing. The answer
is matched to the request id when the server echoes one; when nothing echoes it,
a result is preferred over an error, because failing toward "this endpoint served
something" is the safe direction for a gate.

Fault classes (only what has been observed in a real population):
  F1 auth-absence        endpoint returned a tools/list result with no token
  F2 incomplete-oauth-rs refused, but with no RFC 9728 challenge a client
                         could follow, or with metadata that does not resolve

Scope is deliberate. This probes endpoints; it does not read source. A server
distributed for stdio can still ship an HTTP mode — run it and probe that URL
like any other. See EVIDENCE.md for the measurement behind this scope.

The receipt records what was observed. Whether an open endpoint is a fault or
an intentionally public service is a judgement this tool does not make.
"""
import argparse, hashlib, hmac, ipaddress, json, os, re, socket, sys
import urllib.error, urllib.parse, urllib.request
from datetime import datetime, timezone

VERSION = "0.6.1"
DEMO_KEY = "mcp-gate-demo-key-not-a-secret"
PROTOCOL_VERSION = "2026-07-28"
CLASSES = {
    "F1": "auth-absence (tools/list returned a result with no token)",
    "F2": "incomplete-oauth-rs (no followable RFC 9728 challenge, or PRM broken)",
}
PRM_MAX_BYTES = 256 * 1024
BODY_SNIPPET = 5 * 1024 * 1024   # padding past this is an evasion, not an accident

def hget(headers, name):
    """Case-insensitive header lookup (HTTP/2 lowercases everything)."""
    for k, v in headers.items():
        if k.lower() == name.lower():
            return v
    return None

def collect_jsonrpc(body, content_type=""):
    """Every JSON-RPC object in a response body, in order.

    Streamable HTTP answers as either a JSON body or an SSE stream, and either
    may carry a batch, so a server can put a decoy ahead of the real answer.
    Returning all of them lets the caller pick the one it actually asked for.
    """
    out, text = [], (body or "").strip()

    def take(obj):
        if isinstance(obj, list):
            for o in obj:
                take(o)
        elif isinstance(obj, dict) and "jsonrpc" in obj:
            out.append(obj)

    if "text/event-stream" in (content_type or "").lower() or text.startswith("data:"):
        for line in text.splitlines():
            if line.startswith("data:"):
                try:
                    take(json.loads(line[5:].strip()))
                except ValueError:
                    continue
        return out
    try:
        take(json.loads(text))
    except ValueError:
        return out
    return out

def answer_for(objs, want_id):
    """The response to the request we sent.

    Prefer the object echoing our id. If nothing echoes it, fall back to any
    object at all — and prefer one carrying a result, because failing toward
    "this endpoint served something" is the safe direction for a gate.
    """
    for o in objs:
        if o.get("id") == want_id:
            return o
    for o in objs:
        if "result" in o:
            return o
    return objs[0] if objs else None

def _host_is_reachable_pivot(other_host, probe_host):
    """True when fetching other_host would reach somewhere the probed server
    should not be able to send us: a private, loopback or link-local address
    that is not simply the host we are already probing.

    This does not survive DNS rebinding between check and fetch; it stops the
    ordinary case of an endpoint pointing us at cloud metadata or an internal host.
    """
    if other_host and probe_host and other_host.lower() == probe_host.lower():
        return False
    try:
        infos = socket.getaddrinfo(other_host, None)
    except Exception:
        return False  # unresolvable: the fetch will fail on its own merits
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast):
            return True
    return False

class BlockedRedirect(Exception):
    """A redirect hop pointed somewhere we will not follow."""

class _GuardedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """The scanned server controls every hop, not just the first one.

    `probe_origin` is set for the probe itself: a finding is a claim about the
    URL the caller named, so being handed to a different origin — a different
    host *or port* — means we can no longer make that claim and must say so
    instead of silently re-targeting.
    """

    def __init__(self, probe_host, probe_origin=None):
        self.probe_host = probe_host
        self.probe_origin = probe_origin

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parts = urllib.parse.urlsplit(newurl)
        if parts.scheme.lower() not in ("http", "https"):
            raise BlockedRedirect(f"redirect to a non-http(s) URL: {newurl[:120]!r}")
        if _host_is_reachable_pivot(parts.hostname, self.probe_host):
            raise BlockedRedirect(f"redirect to a private or link-local address: {newurl[:120]!r}")
        if self.probe_origin and parts.netloc.lower() != self.probe_origin.lower():
            raise BlockedRedirect(f"redirect to a different origin: {newurl[:120]!r}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)

def guarded_opener(probe_host, probe_origin=None):
    return urllib.request.build_opener(_GuardedRedirectHandler(probe_host, probe_origin))

def fetch_prm(prm_url, probe_host, timeout):
    """Fetch protected-resource metadata, re-validating each redirect hop.

    Cross-host is allowed here: RFC 9728 metadata may legitimately be served
    somewhere other than the resource. Private targets are not.
    """
    req = urllib.request.Request(prm_url, headers={"User-Agent": f"mcp-gate/{VERSION}"})
    with guarded_opener(probe_host).open(req, timeout=timeout) as r:
        return json.loads(r.read(PRM_MAX_BYTES).decode("utf-8", "replace"))

# ---------------- runtime probe (single-shot, unauthenticated) ----------------
def probe_http(url, timeout=10):
    """One initialize, one tokenless tools/list replay, then the PRM checks."""
    findings, evidence = [], []
    _parts = urllib.parse.urlsplit(url)
    probe_host = _parts.hostname
    opener = guarded_opener(probe_host, probe_origin=_parts.netloc)

    def post(body, extra=None):
        """Returns (status, headers, text, final_url, truncated). Raises BlockedRedirect."""
        req = urllib.request.Request(url, data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json",
                     "Accept": "application/json, text/event-stream",
                     "User-Agent": f"mcp-gate/{VERSION} (correctness probe)", **(extra or {})})
        try:
            with opener.open(req, timeout=timeout) as r:
                raw = r.read(BODY_SNIPPET + 1)
                return (r.status, dict(r.headers), raw[:BODY_SNIPPET].decode("utf-8", "replace"),
                        r.url, len(raw) > BODY_SNIPPET)
        except BlockedRedirect:
            raise
        except urllib.error.HTTPError as e:
            raw = e.read(BODY_SNIPPET + 1) or b""
            return (e.code, dict(e.headers), raw[:BODY_SNIPPET].decode("utf-8", "replace"),
                    e.url, len(raw) > BODY_SNIPPET)
        except Exception as e:
            return None, {}, str(e), url, False

    def off_target(stage, e):
        evidence.append(f"{stage} -> refused: {e}")
        return [{"id": "REDIRECT-OFF-TARGET", "class": "F1", "status": "inconclusive",
                 "evidence": f"{e} — no posture claimed for {url}; re-run against that URL "
                             f"directly if you intended to probe it"}], evidence

    init = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": PROTOCOL_VERSION, "capabilities": {},
                       "clientInfo": {"name": "mcp-gate", "version": VERSION}}}
    try:
        s1, h1, b1, u1, _ = post(init)
    except BlockedRedirect as e:
        return off_target("POST initialize", e)
    evidence.append(f"POST initialize -> {s1}")
    if s1 is None:
        return [{"id": "NET", "class": "F1", "status": "inconclusive",
                 "evidence": f"unreachable: {b1} — no posture observable, no fault claimed"}], evidence
    if u1 and u1 != url:
        evidence.append(f"redirected within the same origin to {u1}")

    low, ctype1 = b1.lower(), (hget(h1, "Content-Type") or "").lower()
    if (s1 in (403, 429, 503) and "json" not in ctype1 and "jsonrpc" not in low
            and ("cloudflare" in low or "error 1010" in low or "access denied" in low
                 or "captcha" in low or "rate limit" in low)):
        # A non-JSON bot wall, not an MCP auth response. Requiring a non-JSON body
        # stops an MCP server buying an inconclusive by putting these words in JSON.
        return [{"id": "PROBE-BLOCKED", "class": "F1", "status": "inconclusive",
                 "evidence": f"endpoint returned {s1} from bot protection; auth posture untestable from here"}], evidence

    # Complete the handshake before asking for anything: a spec-strict server is
    # entitled to reject tools/list otherwise, which would read as inconclusive
    # and quietly under-test a server that may well be open.
    negotiated = PROTOCOL_VERSION
    init_rpc = answer_for(collect_jsonrpc(b1, ctype1), 1)
    if init_rpc and isinstance(init_rpc.get("result"), dict):
        negotiated = str(init_rpc["result"].get("protocolVersion") or PROTOCOL_VERSION)
        evidence.append(f"server negotiated protocolVersion {negotiated}")

    followup = {"MCP-Protocol-Version": negotiated}
    sess = hget(h1, "Mcp-Session-Id")
    if sess:
        evidence.append("session header issued (Mcp-Session-Id present)")
        followup["Mcp-Session-Id"] = sess
    if s1 == 200:
        try:
            post({"jsonrpc": "2.0", "method": "notifications/initialized"}, followup)
        except BlockedRedirect:
            pass  # best effort; the tools/list call below is the measurement

    try:
        s2, h2, b2, u2, truncated = post({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, followup)
    except BlockedRedirect as e:
        return off_target("tokenless tools/list", e)
    evidence.append(f"tokenless tools/list -> {s2}")
    if truncated:
        evidence.append(f"response body hit the {BODY_SNIPPET}-byte read cap and was truncated")

    rpc = answer_for(collect_jsonrpc(b2, hget(h2, "Content-Type")), 2)
    if s2 == 200 and rpc is not None and "result" in rpc:
        # Positive proof: the call succeeded without a token.
        result = rpc.get("result") or {}
        tools = result.get("tools") if isinstance(result, dict) else None
        if isinstance(tools, list):
            names = [t.get("name") for t in tools if isinstance(t, dict) and t.get("name")]
            served = f"{len(tools)} tool(s) served" + (f": {', '.join(names[:5])}" if names else "")
        else:
            served = "tools/list returned a JSON-RPC result"
        advertised = s1 in (401, 403) and (hget(h1, "WWW-Authenticate") or hget(h2, "WWW-Authenticate"))
        findings.append({"id": "AUTH-OPEN", "class": "F1", "status": "fail",
                         "evidence": f"tokenless tools/list -> 200 with a JSON-RPC result; {served}"
                                     + (" — OAuth advertised on initialize but not enforced" if advertised else "")})
    elif s2 == 200 and rpc is not None and "error" in rpc:
        # It refused, inside a 200. That is a real refusal, so F1 does not apply.
        err = rpc.get("error") or {}
        wa = hget(h2, "WWW-Authenticate") or hget(h1, "WWW-Authenticate") or ""
        detail = f"code={err.get('code')} message={str(err.get('message'))[:80]!r}"
        if wa:
            findings.append({"id": "AUTH-REFUSED", "class": "F2", "status": "pass",
                             "evidence": f"tools/list refused at the JSON-RPC layer ({detail}) with a challenge present"})
        else:
            findings.append({"id": "AUTH-REFUSED-NO-CHALLENGE", "class": "F2", "status": "fail",
                             "evidence": f"tools/list refused at the JSON-RPC layer ({detail}) with no "
                                         f"WWW-Authenticate header: a client cannot discover how to authenticate"})
    elif s2 == 200 and truncated:
        findings.append({"id": "RESPONSE-TRUNCATED", "class": "F1", "status": "inconclusive",
                         "evidence": f"tools/list -> 200 but the body exceeded the {BODY_SNIPPET}-byte "
                                     f"read cap and no JSON-RPC answer could be parsed; posture not observable"})
    elif s2 == 200:
        findings.append({"id": "NOT-MCP", "class": "F1", "status": "inconclusive",
                         "evidence": f"tools/list -> 200 but the body is not a JSON-RPC response "
                                     f"({(hget(h2, 'Content-Type') or 'no content-type')!r}); nothing about auth is observable"})
    elif s2 in (401, 403):
        # Keyed on s2: the tools/list response is the authoritative challenge;
        # initialize may 401 generically without resource_metadata.
        wa = hget(h2, "WWW-Authenticate") or hget(h1, "WWW-Authenticate") or ""
        m = re.search(r'resource_metadata="?([^",]+)"?', wa)
        if not m:
            findings.append({"id": "AUTH-NO-PRM-CHALLENGE", "class": "F2", "status": "fail",
                             "evidence": f"{s2} without RFC 9728 resource_metadata (got: {wa[:120] or 'no WWW-Authenticate'})"})
        else:
            prm_url = m.group(1)
            parts = urllib.parse.urlsplit(prm_url)
            # The scanned server chooses this URL. urllib speaks file:// and ftp://,
            # and a public endpoint pointing at 169.254.169.254 would make this tool
            # an SSRF pivot for whoever runs it.
            if parts.scheme.lower() not in ("http", "https"):
                findings.append({"id": "PRM-BAD-SCHEME", "class": "F2", "status": "fail",
                                 "evidence": f"resource_metadata is not an http(s) URL, refused unfetched: {prm_url[:120]!r}"})
            elif _host_is_reachable_pivot(parts.hostname, probe_host):
                findings.append({"id": "PRM-PRIVATE-TARGET", "class": "F2", "status": "fail",
                                 "evidence": f"resource_metadata points at a private or link-local address, "
                                             f"refused unfetched: {prm_url[:120]!r}"})
            else:
                try:
                    prm = fetch_prm(prm_url, probe_host, timeout)
                    if not isinstance(prm, dict):
                        raise ValueError("PRM document is not a JSON object")
                    ok = "authorization_servers" in prm or "resource" in prm
                    findings.append({"id": "OAUTH-POSTURE", "class": "F2",
                                     "status": "pass" if ok else "fail",
                                     "evidence": f"PRM fetched: {prm_url} -> keys={sorted(prm)[:6]}"})
                except BlockedRedirect as e:
                    findings.append({"id": "PRM-PRIVATE-TARGET", "class": "F2", "status": "fail",
                                     "evidence": f"resource_metadata {prm_url[:80]!r} {e}; refused unfetched"})
                except Exception:
                    findings.append({"id": "PRM-UNREACHABLE", "class": "F2", "status": "fail",
                                     "evidence": f"resource_metadata advertised but unfetchable: {prm_url}"})
    else:
        findings.append({"id": "POSTURE-UNDETERMINED", "class": "F1", "status": "inconclusive",
                         "evidence": f"initialize -> {s1}, tools/list -> {s2}: no interpretable auth posture"})
    return findings, evidence

# ---------------- receipt ----------------
class KeyUnavailable(Exception):
    """No usable signing key. Signing or verifying with an empty key would
    produce receipts anybody can forge, so this is refused rather than warned."""

def _signing_key():
    """$MCP_GATE_KEY, else a per-machine key. The scheme is symmetric: a receipt
    verifies only where its key is present, which is why CI must set it explicitly."""
    key = os.environ.get("MCP_GATE_KEY")
    if key:
        key = key.strip()
        if not key:
            raise KeyUnavailable("MCP_GATE_KEY is set but blank")
        return key

    kf = os.path.expanduser("~/.mcp-gate-key")
    if not os.path.exists(kf):
        # O_CREAT|O_EXCL on the final path publishes the file before the bytes
        # land, so a concurrent run could open it and read "". Write the key to a
        # private temp file first and publish it with an atomic link, so another
        # process sees either no file at all or a complete key.
        tmp = f"{kf}.{os.getpid()}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "w") as fh:
                fh.write(os.urandom(32).hex())
            try:
                os.link(tmp, kf)
            except FileExistsError:
                pass            # another run won; its key is already complete
            except OSError:
                os.replace(tmp, kf)   # filesystem without hardlinks
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass

    try:
        with open(kf, encoding="utf-8") as fh:
            key = fh.read().strip()
    except OSError as e:
        raise KeyUnavailable(f"cannot read {kf}: {e}") from None
    if not key:
        # A truncated or emptied key file reaches here too, not just a lost race.
        raise KeyUnavailable(
            f"{kf} is empty or truncated. Delete it and re-run, or set MCP_GATE_KEY. "
            f"Signing with an empty key would produce forgeable receipts.")
    return key

def _canon(body):
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()

def receipt(target, checks, evidence):
    key = _signing_key()
    # DEMO_KEY is published in the README so anyone can verify the demo fixtures.
    # Signing with it would let anyone mint a receipt this verifier accepts, so
    # receipts made with it are marked and never look authentic.
    body = {"schema": "mcp-gate/receipt@5", "tool_version": VERSION, "demo_key": key == DEMO_KEY,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target": target, "mode": "runtime",
            "checks": checks, "probe_evidence": evidence}
    body["receipt_sha256"] = hashlib.sha256(_canon(body)).hexdigest()
    body["hmac_sha256"] = hmac.new(key.encode(), _canon(body), hashlib.sha256).hexdigest()
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
        prog="mcp-gate", description="Did this MCP endpoint serve its tool list without a token?")
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check", help="probe an MCP endpoint URL")
    c.add_argument("target", help="http(s) URL of the MCP endpoint")
    c.add_argument("--receipt-out", default=None)
    c.add_argument("--timeout", type=float, default=10)
    v = sub.add_parser("verify-receipt", help="check a receipt's signature")
    v.add_argument("receipt")
    a = p.parse_args()

    if a.cmd == "verify-receipt":
        try:
            ok, r = verify_receipt(a.receipt)
        except KeyUnavailable as e:
            print(f"cannot verify: {e}", file=sys.stderr)
            return 2
        out = {"signature_valid": ok, "receipt_sha256": r.get("receipt_sha256"),
               "target": r.get("target"), "timestamp": r.get("timestamp")}
        try:
            age = datetime.now(timezone.utc) - datetime.fromisoformat(r["timestamp"])
            out["age_seconds"] = int(age.total_seconds())
        except Exception:
            out["age_seconds"] = None
        if r.get("demo_key"):
            out["WARNING"] = ("signed with the published demo key: proves nothing about "
                              "who produced it or what was probed")
        print(json.dumps(out, indent=1))
        return 0 if ok else 1

    if urllib.parse.urlsplit(a.target).scheme.lower() not in ("http", "https"):
        print(f"target must be an http(s) MCP endpoint URL, got: {a.target}\n"
              f"mcp-gate probes running endpoints. If a server is distributed for stdio,\n"
              f"start its HTTP mode and probe that URL.", file=sys.stderr)
        return 2

    checks, ev = probe_http(a.target, timeout=a.timeout)
    try:
        rc = receipt(a.target, checks, ev)
    except KeyUnavailable as e:
        print(f"cannot sign a receipt: {e}", file=sys.stderr)
        return 2
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
