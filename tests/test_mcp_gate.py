"""Regression suite for mcp-gate. Stdlib only: python3 -m unittest discover tests

The tool makes one accusation, so most of these tests are about the two ways it
could be wrong: calling a server open when it refused, or calling it safe when
it handed over the tool list. The first destroys trust in the receipt; the
second is the fault we exist to catch.
"""
import http.server
import json
import os
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
import importlib.util

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GATE_PATH = os.path.join(ROOT, "mcp_gate.py")
_spec = importlib.util.spec_from_file_location("mcp_gate", GATE_PATH)
gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gate)

DEMO_KEY = "mcp-gate-demo-key-not-a-secret"
TOOLS_RESULT = b'{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"list_items"},{"name":"delete_item"}]}}'


def run_cli(*args, key=DEMO_KEY):
    env = dict(os.environ, MCP_GATE_KEY=key)
    return subprocess.run([sys.executable, GATE_PATH, *args],
                          capture_output=True, text=True, env=env)


def ids(findings):
    return {f["id"] for f in findings}


def statuses(findings):
    return {f["status"] for f in findings}


class Base(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, code, body=b"", headers=(), content_type="application/json"):
        self.send_response(code)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except BrokenPipeError:
            pass  # expected when the probe truncates an oversized response

    def read_method(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}").get("method")


class ServerCase(unittest.TestCase):
    def probe(self, handler, **kw):
        srv = http.server.HTTPServer(("127.0.0.1", 0), handler)
        self.port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        return gate.probe_http(f"http://127.0.0.1:{self.port}/mcp", **kw)


class OpenServerIsCaught(ServerCase):
    def test_tools_list_result_with_no_token_is_a_fault(self):
        class H(Base):
            def do_POST(self):
                self.read_method()
                self.reply(200, TOOLS_RESULT)

        findings, _ = self.probe(H)
        self.assertIn("AUTH-OPEN", ids(findings))

    def test_evidence_records_what_was_actually_served(self):
        """The receipt must carry the proof, not just the accusation."""
        class H(Base):
            def do_POST(self):
                self.read_method()
                self.reply(200, TOOLS_RESULT)

        findings, _ = self.probe(H)
        ev = next(f for f in findings if f["id"] == "AUTH-OPEN")["evidence"]
        self.assertIn("2 tool(s) served", ev)
        self.assertIn("list_items", ev)

    def test_sse_framed_result_is_caught(self):
        """Streamable HTTP may answer as an event stream; the fault is the same."""
        class H(Base):
            def do_POST(self):
                self.read_method()
                self.reply(200, b"event: message\ndata: " + TOOLS_RESULT + b"\n\n",
                           content_type="text/event-stream")

        findings, _ = self.probe(H)
        self.assertIn("AUTH-OPEN", ids(findings))

    def test_empty_tool_list_still_counts_as_served(self):
        class H(Base):
            def do_POST(self):
                self.read_method()
                self.reply(200, b'{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}')

        findings, _ = self.probe(H)
        self.assertIn("AUTH-OPEN", ids(findings))

    def test_advertised_but_not_enforced_is_called_out(self):
        class H(Base):
            def do_POST(self):
                if self.read_method() == "initialize":
                    self.reply(401, b"", [("WWW-Authenticate", 'Bearer realm="mcp"')])
                else:
                    self.reply(200, TOOLS_RESULT)

        findings, _ = self.probe(H)
        self.assertIn("advertised on initialize but not enforced",
                      next(f for f in findings if f["id"] == "AUTH-OPEN")["evidence"])

    def test_session_header_is_replayed(self):
        class H(Base):
            def do_POST(self):
                if self.read_method() == "initialize":
                    self.reply(200, b'{"jsonrpc":"2.0","id":1,"result":{}}',
                               [("Mcp-Session-Id", "abc123")])
                elif self.headers.get("Mcp-Session-Id") == "abc123":
                    self.reply(200, TOOLS_RESULT)
                else:
                    self.reply(400, b"{}")

        findings, evidence = self.probe(H)
        self.assertIn("AUTH-OPEN", ids(findings))
        self.assertTrue(any("session header issued" in e for e in evidence))


class RefusalInsideA200IsNotOpen(ServerCase):
    """JSON-RPC refuses in the body as often as in the status line.

    Treating HTTP 200 as proof of service accused correctly-refusing servers.
    """

    def test_jsonrpc_error_is_not_auth_open(self):
        class H(Base):
            def do_POST(self):
                self.read_method()
                self.reply(200, b'{"jsonrpc":"2.0","id":2,"error":'
                                b'{"code":-32001,"message":"Unauthorized: missing bearer token"}}')

        findings, _ = self.probe(H)
        self.assertNotIn("AUTH-OPEN", ids(findings))
        self.assertIn("AUTH-REFUSED-NO-CHALLENGE", ids(findings))

    def test_jsonrpc_error_with_a_challenge_is_not_a_fault(self):
        class H(Base):
            def do_POST(self):
                self.read_method()
                self.reply(200, b'{"jsonrpc":"2.0","id":2,"error":{"code":-32001,"message":"Unauthorized"}}',
                           [("WWW-Authenticate", 'Bearer realm="mcp"')])

        findings, _ = self.probe(H)
        self.assertNotIn("AUTH-OPEN", ids(findings))
        self.assertEqual(statuses(findings), {"pass"})

    def test_sse_framed_error_is_not_auth_open(self):
        class H(Base):
            def do_POST(self):
                self.read_method()
                self.reply(200, b'data: {"jsonrpc":"2.0","id":2,"error":{"code":-32001,"message":"no"}}\n\n',
                           content_type="text/event-stream")

        findings, _ = self.probe(H)
        self.assertNotIn("AUTH-OPEN", ids(findings))


class NonMcpResponses(ServerCase):
    def test_html_landing_page_is_inconclusive_not_open(self):
        class H(Base):
            def do_POST(self):
                self.read_method()
                self.reply(200, b"<html><body>API Gateway</body></html>", content_type="text/html")

        findings, _ = self.probe(H)
        self.assertNotIn("AUTH-OPEN", ids(findings))
        self.assertIn("NOT-MCP", ids(findings))
        self.assertEqual(statuses(findings), {"inconclusive"})

    def test_empty_200_is_inconclusive(self):
        class H(Base):
            def do_POST(self):
                self.read_method()
                self.reply(200, b"")

        findings, _ = self.probe(H)
        self.assertNotIn("AUTH-OPEN", ids(findings))
        self.assertEqual(statuses(findings), {"inconclusive"})


class CompliantServerIsNotFailed(ServerCase):
    def test_rfc9728_challenge_with_resolvable_prm_passes(self):
        test = self

        class H(Base):
            def do_GET(self):
                self.reply(200, json.dumps({"resource": "http://x/mcp",
                                            "authorization_servers": ["https://as.example"]}).encode())

            def do_POST(self):
                self.read_method()
                wa = ('Bearer realm="mcp", resource_metadata='
                      f'"http://127.0.0.1:{test.port}/.well-known/oauth-protected-resource"')
                self.reply(401, b"", [("WWW-Authenticate", wa)])

        findings, _ = self.probe(H)
        self.assertNotIn("AUTH-NO-PRM-CHALLENGE", ids(findings))
        self.assertTrue(any(f["id"] == "OAUTH-POSTURE" and f["status"] == "pass" for f in findings))

    def test_tools_list_header_wins_over_initialize(self):
        test = self

        class H(Base):
            def do_POST(self):
                if self.read_method() == "initialize":
                    self.reply(401, b"", [("WWW-Authenticate", 'Bearer realm="mcp"')])
                else:
                    wa = ('Bearer realm="mcp", resource_metadata='
                          f'"http://127.0.0.1:{test.port}/.well-known/oauth-protected-resource"')
                    self.reply(401, b"", [("WWW-Authenticate", wa)])

            def do_GET(self):
                self.reply(200, json.dumps({"authorization_servers": ["https://as.example"]}).encode())

        findings, _ = self.probe(H)
        self.assertNotIn("AUTH-NO-PRM-CHALLENGE", ids(findings))

    def test_lowercase_header_is_found(self):
        class H(Base):
            def do_POST(self):
                self.read_method()
                self.reply(401, b"", [("www-authenticate", 'Bearer realm="mcp"')])

        findings, _ = self.probe(H)
        self.assertIn("AUTH-NO-PRM-CHALLENGE", ids(findings))


class IncompleteOAuth(ServerCase):
    def test_401_without_resource_metadata_is_f2(self):
        class H(Base):
            def do_POST(self):
                self.read_method()
                self.reply(401, b"", [("WWW-Authenticate", 'Bearer realm="mcp"')])

        findings, _ = self.probe(H)
        self.assertEqual(next(x for x in findings if x["id"] == "AUTH-NO-PRM-CHALLENGE")["class"], "F2")

    def test_unfetchable_prm_is_f2_not_a_pass(self):
        class H(Base):
            def do_POST(self):
                self.read_method()
                self.reply(401, b"", [("WWW-Authenticate",
                                       'Bearer realm="mcp", resource_metadata="http://127.0.0.1:1/prm"')])

        findings, _ = self.probe(H, timeout=2)
        self.assertIn("PRM-UNREACHABLE", ids(findings))


class ProbeSafety(ServerCase):
    def test_file_scheme_resource_metadata_is_refused_unfetched(self):
        canary = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        canary.write('{"authorization_servers":["CANARY"],"resource":"CANARY"}')
        canary.close()
        self.addCleanup(os.unlink, canary.name)

        class H(Base):
            def do_POST(self):
                self.read_method()
                self.reply(401, b"", [("WWW-Authenticate",
                                       f'Bearer realm="mcp", resource_metadata="file://{canary.name}"')])

        findings, _ = self.probe(H)
        self.assertIn("PRM-BAD-SCHEME", ids(findings))
        self.assertNotIn("CANARY", json.dumps(findings))

    def test_private_address_resource_metadata_is_refused_unfetched(self):
        """A public endpoint must not be able to use this tool as an SSRF pivot."""
        self.assertTrue(gate._host_is_reachable_pivot("169.254.169.254", "example.com"))
        self.assertTrue(gate._host_is_reachable_pivot("10.0.0.1", "example.com"))
        self.assertTrue(gate._host_is_reachable_pivot("127.0.0.1", "example.com"))
        # Probing localhost deliberately must still work.
        self.assertFalse(gate._host_is_reachable_pivot("127.0.0.1", "127.0.0.1"))

    def test_oversized_prm_does_not_hang_the_probe(self):
        class H(Base):
            def do_GET(self):
                blob = b'{"authorization_servers":["https://as.example"],"pad":"' + b"A" * (2 << 20) + b'"}'
                self.reply(200, blob)

            def do_POST(self):
                self.read_method()
                self.reply(401, b"", [("WWW-Authenticate",
                                       'Bearer realm="mcp", resource_metadata='
                                       f'"http://127.0.0.1:{self.server.server_address[1]}/prm"')])

        findings, _ = self.probe(H)
        self.assertTrue(ids(findings) & {"PRM-UNREACHABLE", "OAUTH-POSTURE"})


class NeverClaimUnobservedFaults(ServerCase):
    def test_unreachable_endpoint_is_inconclusive(self):
        findings, _ = gate.probe_http("http://127.0.0.1:1/mcp", timeout=2)
        self.assertTrue(findings)
        self.assertEqual(statuses(findings), {"inconclusive"})

    def test_bot_wall_is_inconclusive_not_a_fault(self):
        class H(Base):
            def do_POST(self):
                self.read_method()
                self.reply(403, b"<html>error 1010 cloudflare access denied</html>",
                           content_type="text/html")

        findings, _ = self.probe(H)
        self.assertIn("PROBE-BLOCKED", ids(findings))
        self.assertEqual(statuses(findings), {"inconclusive"})

    def test_a_json_403_cannot_buy_an_inconclusive(self):
        """Putting WAF words in a JSON body was a free skip past the F2 branch."""
        class H(Base):
            def do_POST(self):
                self.read_method()
                self.reply(403, b'{"note":"access denied"}')

        findings, _ = self.probe(H)
        self.assertNotIn("PROBE-BLOCKED", ids(findings))

    def test_unexpected_status_is_inconclusive(self):
        class H(Base):
            def do_POST(self):
                self.read_method()
                self.reply(500, b"{}")

        findings, _ = self.probe(H)
        self.assertIn("POSTURE-UNDETERMINED", ids(findings))
        self.assertEqual(statuses(findings), {"inconclusive"})

    def test_only_observed_fault_classes_exist(self):
        self.assertEqual(set(gate.CLASSES), {"F1", "F2"})


class EvidenceIntegrity(ServerCase):
    def test_cross_origin_redirect_is_refused_not_followed(self):
        """A finding is a claim about the URL the caller named. Being handed to
        another origin means we cannot make that claim — and following it read a
        tool list off a different machine while the receipt named the target."""
        class Internal(Base):
            def do_GET(self):
                self.reply(200, b'{"jsonrpc":"2.0","id":2,"result":'
                                b'{"tools":[{"name":"INTERNAL_SECRET_TOOL"}]}}')

            def do_POST(self):
                self.read_method()
                self.do_GET()

        internal = http.server.HTTPServer(("127.0.0.1", 0), Internal)
        threading.Thread(target=internal.serve_forever, daemon=True).start()
        self.addCleanup(internal.shutdown)
        iport = internal.server_address[1]

        class Redirector(Base):
            def do_POST(self):
                self.read_method()
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{iport}/mcp")
                self.send_header("Content-Length", "0")
                self.end_headers()

        findings, _ = self.probe(Redirector)
        self.assertIn("REDIRECT-OFF-TARGET", ids(findings))
        self.assertEqual(statuses(findings), {"inconclusive"})
        self.assertNotIn("INTERNAL_SECRET_TOOL", json.dumps(findings))

    def test_same_origin_redirect_is_followed_and_recorded(self):
        class H(Base):
            def do_POST(self):
                if self.path != "/v2/mcp":
                    self.send_response(302)
                    self.send_header("Location", "/v2/mcp")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                self.read_method()
                self.reply(200, TOOLS_RESULT)

            def do_GET(self):
                self.reply(200, TOOLS_RESULT)

        findings, evidence = self.probe(H)
        self.assertIn("AUTH-OPEN", ids(findings))
        self.assertTrue(any("same origin" in e for e in evidence), evidence)

    def test_unfollowed_307_is_not_read_as_a_posture(self):
        """urllib does not follow 307 on POST; the status must not be interpreted."""
        class H(Base):
            def do_POST(self):
                self.read_method()
                self.send_response(307)
                self.send_header("Location", "http://example.invalid/mcp")
                self.send_header("Content-Length", "0")
                self.end_headers()

        findings, _ = self.probe(H)
        self.assertNotIn("AUTH-OPEN", ids(findings))
        self.assertEqual(statuses(findings), {"inconclusive"})

    def test_collect_jsonrpc_rejects_non_jsonrpc_json(self):
        self.assertEqual(gate.collect_jsonrpc('{"tools": []}'), [])
        self.assertEqual(gate.collect_jsonrpc("not json"), [])
        self.assertEqual(gate.collect_jsonrpc(""), [])
        self.assertEqual(len(gate.collect_jsonrpc('{"jsonrpc":"2.0","id":1,"result":{}}')), 1)


class EvasionResistance(ServerCase):
    """Each of these was a working evasion reproduced against v0.4.0."""

    def test_decoy_error_in_first_sse_frame_does_not_hide_the_result(self):
        class H(Base):
            def do_POST(self):
                self.read_method()
                self.reply(200,
                           b'data: {"jsonrpc":"2.0","id":99,"error":{"code":-32001,"message":"no"}}\n\n'
                           b'data: ' + TOOLS_RESULT + b'\n\n',
                           content_type="text/event-stream")

        self.assertIn("AUTH-OPEN", ids(self.probe(H)[0]))

    def test_decoy_error_first_in_a_batch_does_not_hide_the_result(self):
        class H(Base):
            def do_POST(self):
                self.read_method()
                self.reply(200, b'[{"jsonrpc":"2.0","id":99,"error":{"code":-32001,"message":"no"}},'
                                b'{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"x"}]}}]')

        self.assertIn("AUTH-OPEN", ids(self.probe(H)[0]))

    def test_answer_is_selected_by_request_id(self):
        objs = [{"jsonrpc": "2.0", "id": 99, "error": {"code": -1}},
                {"jsonrpc": "2.0", "id": 2, "result": {"tools": []}}]
        self.assertIn("result", gate.answer_for(objs, 2))

    def test_answer_falls_back_toward_detection_when_no_id_matches(self):
        """If nothing echoes our id, prefer a result: fail toward reporting."""
        objs = [{"jsonrpc": "2.0", "id": 7, "error": {"code": -1}},
                {"jsonrpc": "2.0", "id": 8, "result": {"tools": []}}]
        self.assertIn("result", gate.answer_for(objs, 2))

    def test_truncated_body_is_reported_not_silently_unparseable(self):
        class H(Base):
            def do_POST(self):
                self.read_method()
                self.reply(200, b'{"jsonrpc":"2.0","id":2,"result":{"pad":"'
                                + b"A" * (gate.BODY_SNIPPET + 4096) + b'","tools":[]}}')

        findings, evidence = self.probe(H)
        self.assertIn("RESPONSE-TRUNCATED", ids(findings))
        self.assertEqual(statuses(findings), {"inconclusive"})
        self.assertTrue(any("read cap" in e for e in evidence))

    def test_prm_redirect_to_a_private_address_is_blocked(self):
        class Internal(Base):
            def do_GET(self):
                self.reply(200, b'{"authorization_servers":["INTERNAL"],"resource":"x"}')

        internal = http.server.HTTPServer(("127.0.0.1", 0), Internal)
        threading.Thread(target=internal.serve_forever, daemon=True).start()
        self.addCleanup(internal.shutdown)
        iport = internal.server_address[1]

        class Redirector(Base):
            def do_GET(self):
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{iport}/secret")
                self.send_header("Content-Length", "0")
                self.end_headers()

        redir = http.server.HTTPServer(("127.0.0.1", 0), Redirector)
        threading.Thread(target=redir.serve_forever, daemon=True).start()
        self.addCleanup(redir.shutdown)
        with self.assertRaises(gate.BlockedRedirect):
            gate.fetch_prm(f"http://127.0.0.1:{redir.server_address[1]}/prm", "victim.example", 5)


class ReviewFindings(ServerCase):
    """Each reproduced against v0.5.0 by an outside reviewer."""

    def test_truncation_is_measured_in_bytes_read_not_reencoded_chars(self):
        """Decoding with errors="replace" turns each bad byte into a 3-byte U+FFFD,
        so re-encoding a decoded string could report a body under the cap as over it."""
        payload = b"\xff" * (2 * 1024 * 1024)   # 2 MB raw, ~6 MB if re-encoded

        class H(Base):
            def do_POST(self):
                self.read_method()
                self.reply(200, payload, content_type="application/octet-stream")

        findings, evidence = self.probe(H)
        self.assertNotIn("RESPONSE-TRUNCATED", ids(findings))
        self.assertFalse(any("read cap" in e for e in evidence), evidence)

    def test_handshake_is_completed_before_asking_for_tools(self):
        seen = {"methods": [], "proto_header": None}

        class H(Base):
            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n) or b"{}")
                seen["methods"].append(body.get("method"))
                if body.get("method") == "tools/list":
                    seen["proto_header"] = self.headers.get("MCP-Protocol-Version")
                    self.reply(200, TOOLS_RESULT)
                elif body.get("method") == "initialize":
                    self.reply(200, b'{"jsonrpc":"2.0","id":1,"result":'
                                    b'{"protocolVersion":"2026-07-28"}}')
                else:
                    self.reply(202, b"")

        self.probe(H)
        self.assertIn("notifications/initialized", seen["methods"])
        self.assertLess(seen["methods"].index("notifications/initialized"),
                        seen["methods"].index("tools/list"))
        self.assertEqual(seen["proto_header"], "2026-07-28")

    def test_negotiated_protocol_version_is_echoed_back(self):
        seen = {}

        class H(Base):
            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n) or b"{}")
                if body.get("method") == "initialize":
                    self.reply(200, b'{"jsonrpc":"2.0","id":1,"result":'
                                    b'{"protocolVersion":"2025-06-18"}}')
                elif body.get("method") == "tools/list":
                    seen["hdr"] = self.headers.get("MCP-Protocol-Version")
                    self.reply(200, TOOLS_RESULT)
                else:
                    self.reply(202, b"")

        findings, evidence = self.probe(H)
        self.assertEqual(seen.get("hdr"), "2025-06-18")
        self.assertTrue(any("negotiated protocolVersion 2025-06-18" in e for e in evidence))

    def test_signing_key_refuses_an_empty_key_file(self):
        """The exact reviewer repro: the winner has created the file but not yet
        written it, so the loser used to read "" and sign forgeable receipts."""
        home = tempfile.mkdtemp()
        real_home, had = os.environ.get("HOME"), os.environ.pop("MCP_GATE_KEY", None)
        os.environ["HOME"] = home
        try:
            kf = os.path.join(home, ".mcp-gate-key")
            fd = os.open(kf, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)  # created, not written
            try:
                with self.assertRaises(gate.KeyUnavailable):
                    gate._signing_key()
            finally:
                os.close(fd)
        finally:
            if real_home is not None:
                os.environ["HOME"] = real_home
            if had is not None:
                os.environ["MCP_GATE_KEY"] = had

    def test_signing_key_is_published_atomically(self):
        """A reader must see either no file or a complete 64-hex key, never a
        half-written one."""
        home = tempfile.mkdtemp()
        real_home, had = os.environ.get("HOME"), os.environ.pop("MCP_GATE_KEY", None)
        os.environ["HOME"] = home
        try:
            key = gate._signing_key()
            self.assertEqual(len(key), 64)
            int(key, 16)
            kf = os.path.join(home, ".mcp-gate-key")
            self.assertFalse(os.stat(kf).st_mode & (stat.S_IRWXG | stat.S_IRWXO))
            # No temp file is left lying around.
            self.assertEqual([f for f in os.listdir(home) if f.endswith(".tmp")], [])
            # A second call is stable.
            self.assertEqual(gate._signing_key(), key)
        finally:
            if real_home is not None:
                os.environ["HOME"] = real_home
            if had is not None:
                os.environ["MCP_GATE_KEY"] = had

    def test_blank_env_key_is_refused(self):
        had = os.environ.get("MCP_GATE_KEY")
        os.environ["MCP_GATE_KEY"] = "   "
        try:
            with self.assertRaises(gate.KeyUnavailable):
                gate._signing_key()
        finally:
            if had is None:
                os.environ.pop("MCP_GATE_KEY", None)
            else:
                os.environ["MCP_GATE_KEY"] = had

    def test_cli_refuses_rather_than_tracebacks_on_an_empty_key(self):
        tmp = tempfile.mkdtemp()
        p = os.path.join(tmp, "r.json")
        json.dump({"schema": "x", "timestamp": "2026-01-01T00:00:00+00:00",
                   "hmac_sha256": "00"}, open(p, "w"))
        proc = run_cli("verify-receipt", p, key="   ")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("cannot verify", proc.stderr)
        self.assertNotIn("Traceback", proc.stderr)

    def test_refused_redirect_is_recorded_in_the_receipt(self):
        """A REDIRECT-OFF-TARGET receipt used to carry an empty probe_evidence."""
        class Elsewhere(Base):
            def do_GET(self):
                self.reply(200, TOOLS_RESULT)

            def do_POST(self):
                self.read_method()
                self.reply(200, TOOLS_RESULT)

        other = http.server.HTTPServer(("127.0.0.1", 0), Elsewhere)
        threading.Thread(target=other.serve_forever, daemon=True).start()
        self.addCleanup(other.shutdown)
        oport = other.server_address[1]

        class Redirector(Base):
            def do_POST(self):
                self.read_method()
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{oport}/mcp")
                self.send_header("Content-Length", "0")
                self.end_headers()

        findings, evidence = self.probe(Redirector)
        self.assertIn("REDIRECT-OFF-TARGET", ids(findings))
        self.assertTrue(evidence, "probe_evidence must not be blank")
        self.assertTrue(any("refused" in e for e in evidence), evidence)


class DemoKeyIsNotTrustMaterial(unittest.TestCase):
    def _with_key(self, value, fn):
        had = os.environ.get("MCP_GATE_KEY")
        os.environ["MCP_GATE_KEY"] = value
        try:
            return fn()
        finally:
            if had is None:
                os.environ.pop("MCP_GATE_KEY", None)
            else:
                os.environ["MCP_GATE_KEY"] = had

    def test_receipts_signed_with_the_published_key_are_marked(self):
        body = self._with_key(gate.DEMO_KEY, lambda: gate.receipt("https://x/mcp", [], []))
        self.assertTrue(body["demo_key"])

    def test_a_real_key_produces_an_unmarked_receipt(self):
        body = self._with_key("an-actual-private-key", lambda: gate.receipt("https://x/mcp", [], []))
        self.assertFalse(body["demo_key"])

    def test_verifier_warns_loudly_about_a_demo_signed_receipt(self):
        body = self._with_key(gate.DEMO_KEY, lambda: gate.receipt(
            "https://victim.example/mcp",
            [{"id": "OAUTH-POSTURE", "class": "F2", "status": "pass", "evidence": "fabricated"}], []))
        tmp = tempfile.mkdtemp()
        p = os.path.join(tmp, "forged.json")
        json.dump(body, open(p, "w"))
        out = run_cli("verify-receipt", p).stdout
        self.assertIn('"signature_valid": true', out)
        self.assertIn("WARNING", out)
        self.assertIn("proves nothing", out)

    def test_verifier_reports_receipt_age(self):
        out = run_cli("verify-receipt", os.path.join(ROOT, "demo", "open-server.receipt.json")).stdout
        self.assertIn("age_seconds", out)


class Receipts(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name
        self.addCleanup(self._tmp.cleanup)

    def test_shipped_demo_receipts_verify_under_the_documented_key(self):
        for name in ("open-server", "compliant-server"):
            proc = run_cli("verify-receipt", os.path.join(ROOT, "demo", f"{name}.receipt.json"))
            self.assertIn('"signature_valid": true', proc.stdout, name)

    def test_shipped_tampered_fixture_fails(self):
        proc = run_cli("verify-receipt", os.path.join(ROOT, "demo", "tampered.receipt.json"))
        self.assertIn('"signature_valid": false', proc.stdout)
        self.assertEqual(proc.returncode, 1)

    def test_editing_a_finding_breaks_the_signature(self):
        src = json.load(open(os.path.join(ROOT, "demo", "open-server.receipt.json")))
        src["checks"][0]["status"] = "pass"
        p = os.path.join(self.tmp, "edited.json")
        json.dump(src, open(p, "w"))
        self.assertIn('"signature_valid": false', run_cli("verify-receipt", p).stdout)

    def test_receipt_records_the_probe_evidence(self):
        body = json.load(open(os.path.join(ROOT, "demo", "open-server.receipt.json")))
        self.assertEqual(body["schema"], "mcp-gate/receipt@5")
        self.assertEqual(body["mode"], "runtime")
        self.assertTrue(any("tools/list" in e for e in body["probe_evidence"]))

    def test_generated_key_is_not_group_or_world_readable(self):
        home = tempfile.mkdtemp()
        real_home, had_key = os.environ.get("HOME"), os.environ.pop("MCP_GATE_KEY", None)
        os.environ["HOME"] = home
        try:
            gate._signing_key()
            mode = os.stat(os.path.join(home, ".mcp-gate-key")).st_mode
            self.assertFalse(mode & (stat.S_IRWXG | stat.S_IRWXO), oct(mode))
        finally:
            if real_home is not None:
                os.environ["HOME"] = real_home
            if had_key is not None:
                os.environ["MCP_GATE_KEY"] = had_key


class Cli(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name
        self.addCleanup(self._tmp.cleanup)

    def test_open_endpoint_exits_one(self):
        class H(Base):
            def do_POST(self):
                self.read_method()
                self.reply(200, TOOLS_RESULT)

        srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        out = os.path.join(self.tmp, "r.json")
        proc = run_cli("check", f"http://127.0.0.1:{srv.server_address[1]}/mcp", "--receipt-out", out)
        self.assertEqual(proc.returncode, 1)
        self.assertTrue(os.path.exists(out))

    def test_inconclusive_only_exits_zero(self):
        out = os.path.join(self.tmp, "r.json")
        proc = run_cli("check", "http://127.0.0.1:1/mcp", "--receipt-out", out, "--timeout", "2")
        self.assertEqual(proc.returncode, 0)
        self.assertIn('"failures": 0', proc.stdout)

    def test_a_file_path_is_rejected_with_guidance(self):
        p = os.path.join(self.tmp, "server.py")
        open(p, "w").write("X = 1\n")
        proc = run_cli("check", p)
        self.assertEqual(proc.returncode, 2)
        self.assertIn("http(s) MCP endpoint URL", proc.stderr)
        self.assertIn("stdio", proc.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
