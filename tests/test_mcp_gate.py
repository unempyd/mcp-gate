"""Regression suite for mcp-gate. Stdlib only: python3 -m unittest discover tests

The tool asks one question — does this endpoint enforce authentication — so the
tests are mostly about the two ways that can go wrong: calling a compliant
server open, or calling an open server compliant. The second is the one that
matters, and the first is the one that destroys trust in the tool.
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


def run_cli(*args, key=DEMO_KEY):
    env = dict(os.environ, MCP_GATE_KEY=key)
    return subprocess.run([sys.executable, GATE_PATH, *args],
                          capture_output=True, text=True, env=env)


def ids(findings):
    return {f["id"] for f in findings}


class Base(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, code, body=b"", headers=()):
        self.send_response(code)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Type", "application/json")
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
    """Stands up a loopback server and probes it."""
    handler = None

    def probe(self, handler=None, **kw):
        srv = http.server.HTTPServer(("127.0.0.1", 0), handler or self.handler)
        self.port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        return gate.probe_http(f"http://127.0.0.1:{self.port}/mcp", **kw)


class OpenServerIsCaught(ServerCase):
    def test_tokenless_tools_list_200_is_a_fault(self):
        class H(Base):
            def do_POST(self):
                self.read_method()
                self.reply(200, b'{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}')

        findings, _ = self.probe(H)
        self.assertIn("AUTH-OPEN", ids(findings))
        self.assertTrue(any(f["status"] == "fail" for f in findings))

    def test_advertised_but_not_enforced_is_called_out(self):
        """401 on initialize, then serves tools anyway — the flagship case."""
        class H(Base):
            def do_POST(self):
                if self.read_method() == "initialize":
                    self.reply(401, b"", [("WWW-Authenticate", 'Bearer realm="mcp"')])
                else:
                    self.reply(200, b'{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}')

        findings, _ = self.probe(H)
        self.assertIn("AUTH-OPEN", ids(findings))
        self.assertIn("advertised but not enforced",
                      next(f for f in findings if f["id"] == "AUTH-OPEN")["evidence"])

    def test_session_header_is_replayed(self):
        """A server issuing a session id must not be able to dodge the replay."""
        class H(Base):
            def do_POST(self):
                if self.read_method() == "initialize":
                    self.reply(200, b"{}", [("Mcp-Session-Id", "abc123")])
                elif self.headers.get("Mcp-Session-Id") == "abc123":
                    self.reply(200, b'{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}')
                else:
                    self.reply(400, b"{}")

        findings, evidence = self.probe(H)
        self.assertIn("AUTH-OPEN", ids(findings))
        self.assertTrue(any("session header issued" in e for e in evidence))


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
        """Regression: reading initialize's header first failed compliant servers."""
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
        """HTTP/2 lowercases header names."""
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
        f = next(x for x in findings if x["id"] == "AUTH-NO-PRM-CHALLENGE")
        self.assertEqual(f["class"], "F2")

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
        """A scanned server must not be able to make the scanner read its own disk."""
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
        self.assertNotIn("OAUTH-POSTURE", ids(findings))
        self.assertNotIn("CANARY", json.dumps(findings))

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
        # Truncated read yields invalid JSON, which is reported, not silently passed.
        self.assertTrue(ids(findings) & {"PRM-UNREACHABLE", "OAUTH-POSTURE"})


class NeverClaimUnobservedFaults(ServerCase):
    def test_unreachable_endpoint_is_inconclusive(self):
        findings, _ = gate.probe_http("http://127.0.0.1:1/mcp", timeout=2)
        self.assertTrue(findings)
        self.assertTrue(all(f["status"] == "inconclusive" for f in findings))

    def test_bot_wall_is_inconclusive_not_a_fault(self):
        class H(Base):
            def do_POST(self):
                self.read_method()
                self.reply(403, b"<html>error 1010 cloudflare access denied</html>")

        findings, _ = self.probe(H)
        self.assertIn("PROBE-BLOCKED", ids(findings))
        self.assertTrue(all(f["status"] == "inconclusive" for f in findings))

    def test_unexpected_shape_is_inconclusive(self):
        class H(Base):
            def do_POST(self):
                self.read_method()
                self.reply(500, b"{}")

        findings, _ = self.probe(H)
        self.assertIn("POSTURE-UNDETERMINED", ids(findings))
        self.assertTrue(all(f["status"] == "inconclusive" for f in findings))

    def test_only_observed_fault_classes_exist(self):
        """F3-F6 were never observed in a real population; they must not be back."""
        self.assertEqual(set(gate.CLASSES), {"F1", "F2"})


class Receipts(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name
        self.addCleanup(self._tmp.cleanup)

    def test_shipped_demo_receipts_verify_under_the_documented_key(self):
        for name in ("open-server", "compliant-server"):
            proc = run_cli("verify-receipt", os.path.join(ROOT, "demo", f"{name}.receipt.json"))
            self.assertIn('"signature_valid": true', proc.stdout, name)
            self.assertEqual(proc.returncode, 0)

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
        self.assertEqual(body["schema"], "mcp-gate/receipt@3")
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
                self.reply(200, b'{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}')

        srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        out = os.path.join(self.tmp, "r.json")
        proc = run_cli("check", f"http://127.0.0.1:{srv.server_address[1]}/mcp", "--receipt-out", out)
        self.assertEqual(proc.returncode, 1)
        self.assertTrue(os.path.exists(out))

    def test_unreachable_endpoint_exits_zero_with_no_fault_claimed(self):
        out = os.path.join(self.tmp, "r.json")
        proc = run_cli("check", "http://127.0.0.1:1/mcp", "--receipt-out", out, "--timeout", "2")
        self.assertEqual(proc.returncode, 0)
        self.assertIn('"failures": 0', proc.stdout)

    def test_a_file_path_is_rejected_with_guidance(self):
        """Source scanning is out of scope; say so instead of pretending."""
        p = os.path.join(self.tmp, "server.py")
        open(p, "w").write("X = 1\n")
        proc = run_cli("check", p)
        self.assertEqual(proc.returncode, 2)
        self.assertIn("http(s) MCP endpoint URL", proc.stderr)
        self.assertIn("stdio", proc.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
