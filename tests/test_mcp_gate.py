"""Regression suite for mcp-gate. Stdlib only: python3 -m unittest discover tests

Every test here corresponds to a defect that was once live in this tool. The
prose-stripping cases are the load-bearing ones: a gate that reports a clean
pass for a server with no authentication is worse than no gate at all.
"""
import ast
import asyncio
import http.server
import importlib.util
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import textwrap
import threading
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GATE_PATH = os.path.join(ROOT, "mcp_gate.py")
_spec = importlib.util.spec_from_file_location("mcp_gate", GATE_PATH)
gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gate)

DEMO_KEY = "mcp-gate-demo-key-not-a-secret"


def write(tmp, name, body):
    path = os.path.join(tmp, name)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(textwrap.dedent(body))
    return path


def ids(findings):
    return {f["id"] for f in findings}


def run_cli(*args, key=DEMO_KEY):
    env = dict(os.environ, MCP_GATE_KEY=key)
    return subprocess.run([sys.executable, GATE_PATH, *args],
                          capture_output=True, text=True, env=env)


class TmpCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name
        self.addCleanup(self._tmp.cleanup)


class ProseIsNotCode(TmpCase):
    """Prose describing a security posture must never satisfy a check for it."""

    def test_docstring_only_oauth_is_not_auth(self):
        p = write(self.tmp, "d.py", '''
            """A tidy MCP server.

            Posture: OAuth 2.1 resource server, bearer tokens verified upstream,
            RFC 9728 .well-known/oauth-protected-resource published.
            """
            def list_items():
                return ["alpha"]
        ''')
        self.assertIn("NO-OAUTH", ids(gate.scan_source(p)))

    def test_comment_only_oauth_is_not_auth(self):
        p = write(self.tmp, "c.py", '''
            # OAuth: bearer token verification
            def list_items():
                return ["alpha"]
        ''')
        self.assertIn("NO-OAUTH", ids(gate.scan_source(p)))

    def test_prm_path_in_a_comment_is_not_a_route(self):
        p = write(self.tmp, "p.py", '''
            def verify(request):
                token = request.headers["Authorization"].removeprefix("Bearer ")
                # TODO: add .well-known/oauth-protected-resource route
                return token
        ''')
        found = ids(gate.scan_source(p))
        self.assertIn("NO-PRM", found)
        self.assertNotIn("NO-OAUTH", found)

    def test_real_verification_and_real_route_pass_both(self):
        p = write(self.tmp, "ok.py", '''
            ROUTES = {"/.well-known/oauth-protected-resource": {"authorization_servers": ["https://as.example"]}}
            def verify(request):
                token = request.headers["Authorization"].removeprefix("Bearer ")
                return introspect(token)
        ''')
        found = ids(gate.scan_source(p))
        self.assertNotIn("NO-OAUTH", found)
        self.assertNotIn("NO-PRM", found)

    def test_prm_path_alone_is_not_token_verification(self):
        """The route path contains the substring 'oauth' but verifies nothing."""
        p = write(self.tmp, "prmonly.py", '''
            ROUTES = {"/.well-known/oauth-protected-resource": {"resource": "https://x/mcp"}}
        ''')
        self.assertIn("NO-OAUTH", ids(gate.scan_source(p)))

    def test_docstring_idempotency_does_not_suppress_f4(self):
        p = write(self.tmp, "idem.py", '''
            """Every mutating tool enforces idempotency."""
            def create_item(name):
                return {"created": name}
        ''')
        self.assertIn("NO-IDEMPOTENCY", ids(gate.scan_source(p)))

    def test_unparseable_source_still_strips_docstrings(self):
        """Regression: ast.parse failing used to skip blanking AND the fallback."""
        src = '"""OAuth 2.1 bearer access_token WWW-Authenticate."""\nprint "legacy"\n'
        with self.assertRaises(SyntaxError):
            ast.parse(src)
        list(__import__("tokenize").generate_tokens(io.StringIO(src).readline))  # tokenizes fine
        self.assertNotIn("OAuth", gate.strip_prose(src))

    def test_unparseable_source_is_refused_not_scanned(self):
        p = write(self.tmp, "py2.py", '''
            """OAuth 2.1 bearer access_token."""
            print "legacy"
        ''')
        with self.assertRaises(gate.UnscannableSource):
            gate.scan_source(p)

    def test_non_python_file_is_refused(self):
        """A .js file tokenizes as Python ('//' is an operator), so it would
        otherwise be scanned by Python-shaped rules and given a signed receipt."""
        p = write(self.tmp, "s.js", '''
            // oauth bearer token
            function listItems() { return ["alpha"]; }
        ''')
        with self.assertRaises(gate.UnscannableSource):
            gate.scan_source(p)


class StripProseMechanics(TmpCase):
    def test_offsets_and_line_count_are_preserved(self):
        src = open(os.path.join(ROOT, "demo", "server.py"), encoding="utf-8").read()
        out = gate.strip_prose(src)
        self.assertEqual(len(out), len(src))
        self.assertEqual(out.count("\n"), src.count("\n"))

    def test_value_string_literals_survive(self):
        src = open(os.path.join(ROOT, "demo", "server.py"), encoding="utf-8").read()
        self.assertIn(gate.PRM_PATH, gate.strip_prose(src))

    def test_docstring_text_is_removed(self):
        src = open(os.path.join(ROOT, "demo", "server.py"), encoding="utf-8").read()
        self.assertNotIn("OAuth 2.1 resource server", gate.strip_prose(src))

    def test_non_ascii_line_blanks_the_right_characters(self):
        """ast reports col_offset in UTF-8 bytes; indexing characters shifts the span."""
        src = 'e = "ééé"\n"OAuth bearer access_token"\nTAIL = 1\n'
        out = gate.strip_prose(src)
        self.assertNotIn("OAuth", out)
        self.assertIn("TAIL = 1", out)
        self.assertEqual(len(out), len(src))

    def test_hash_inside_a_string_is_not_treated_as_a_comment(self):
        src = 'URL = "https://h/x#/.well-known/oauth-protected-resource"\n'
        self.assertIn(gate.PRM_PATH, gate.strip_prose(src))


class ScannerRulePrecision(TmpCase):
    def test_payload_is_not_a_mutation_handler(self):
        p = write(self.tmp, "pay.py", '''
            def list_items(prefix):
                payload = {"prefix": prefix}
                updated_at = None
                return payload, updated_at
        ''')
        self.assertNotIn("NO-IDEMPOTENCY", ids(gate.scan_source(p)))

    def test_mutation_handler_definition_is_flagged(self):
        p = write(self.tmp, "del.py", '''
            def delete_item(name):
                return {"deleted": name}
        ''')
        self.assertIn("NO-IDEMPOTENCY", ids(gate.scan_source(p)))

    def test_idempotency_key_clears_the_finding(self):
        p = write(self.tmp, "ok4.py", '''
            def delete_item(name, idempotency_key):
                return {"deleted": name, "key": idempotency_key}
        ''')
        self.assertNotIn("NO-IDEMPOTENCY", ids(gate.scan_source(p)))

    def test_subprocess_run_fstring_is_flagged(self):
        p = write(self.tmp, "sh.py", '''
            import subprocess
            def go(name):
                subprocess.run(f"echo {name}")
        ''')
        self.assertIn("SHELL-FSTRING", ids(gate.scan_source(p)))

    def test_subprocess_check_output_fstring_is_flagged(self):
        p = write(self.tmp, "sh2.py", '''
            import subprocess
            def go(name):
                subprocess.check_output(f"cat {name}")
        ''')
        self.assertIn("SHELL-FSTRING", ids(gate.scan_source(p)))

    def test_fstring_url_is_flagged(self):
        p = write(self.tmp, "u.py", '''
            import requests
            def go(host):
                requests.get(f"https://{host}/x")
        ''')
        self.assertIn("FSTRING-URL", ids(gate.scan_source(p)))


class ShippedFixtures(unittest.TestCase):
    def test_scaffold_fixture_reports_no_token_verification(self):
        """It publishes RFC 9728 metadata but verifies no token; saying so is the point."""
        found = ids(gate.scan_source(os.path.join(ROOT, "demo", "server.py")))
        self.assertIn("NO-OAUTH", found)

    def test_broken_fixture_flags_its_four_classes(self):
        found = ids(gate.scan_source(os.path.join(ROOT, "demo", "broken.py")))
        for check in ("DCR-ENABLED", "SESSION-KEYED-STATE", "NO-IDEMPOTENCY",
                      "FSTRING-URL", "SHELL-FSTRING"):
            self.assertIn(check, found)


class BoundedFix(TmpCase):
    TARGET = '''
        from aiohttp import web
        async def tools(request):
            return web.json_response({"tools": []})
    '''

    def test_fix_inserts_and_is_idempotent(self):
        p = write(self.tmp, "t.py", self.TARGET)
        self.assertTrue(gate.fix_source(p))
        self.assertEqual(gate.fix_source(p), [])

    def test_inserted_handler_runs(self):
        try:
            from yarl import URL
            import aiohttp.web  # noqa: F401  (the inserted handler imports it lazily)
        except ImportError:
            self.skipTest("aiohttp/yarl not installed")
        p = write(self.tmp, "t.py", self.TARGET)
        gate.fix_source(p)
        ns = {}
        exec(compile(open(p, encoding="utf-8").read(), p, "exec"), ns)

        class Req:
            url = URL("https://api.example.com/mcp")
            headers = {}

        resp = asyncio.run(ns["_prm_handler"](Req()))
        self.assertEqual(resp.status, 200)
        self.assertEqual(json.loads(resp.body.decode())["scopes_supported"], ["mcp:tools"])

        class Resp:
            status = 401
            headers = {}

        async def handler(_):
            return Resp()

        out = asyncio.run(ns["_auth_challenge"](Req(), handler))
        self.assertIn('resource_metadata="https://api.example.com/%s"' % gate.PRM_PATH,
                      out.headers["WWW-Authenticate"])

    def test_marker_inside_a_docstring_is_not_the_insertion_point(self):
        """A column-0 `if __name__` in a docstring used to capture the insertion."""
        p = os.path.join(self.tmp, "doc.py")
        with open(p, "w", encoding="utf-8") as fh:
            fh.write('"""Usage:\n\nif __name__ == "__main__":\n    main()\n"""\n'
                     'def verify(request):\n'
                     '    return request.headers["Authorization"].removeprefix("Bearer ")\n\n'
                     'if __name__ == "__main__":\n    verify(None)\n')
        self.assertTrue(gate.fix_source(p))
        body = open(p, encoding="utf-8").read()
        self.assertGreater(body.index("mcp-gate bounded fix"), body.index('"""', 3))
        self.assertNotIn("NO-PRM", ids(gate.scan_source(p)))


class Scaffold(TmpCase):
    def test_scaffold_writes_a_file(self):
        out = os.path.join(self.tmp, "s.py")
        gate.scaffold(out)
        self.assertTrue(os.path.exists(out))

    def test_scaffold_refuses_to_clobber(self):
        out = os.path.join(self.tmp, "existing.py")
        with open(out, "w", encoding="utf-8") as fh:
            fh.write("REAL_IMPLEMENTATION = 1\n")
        with self.assertRaises(SystemExit):
            gate.scaffold(out)
        self.assertIn("REAL_IMPLEMENTATION", open(out, encoding="utf-8").read())

    def test_force_overwrites(self):
        out = os.path.join(self.tmp, "existing.py")
        with open(out, "w", encoding="utf-8") as fh:
            fh.write("REAL_IMPLEMENTATION = 1\n")
        gate.scaffold(out, force=True)
        self.assertNotIn("REAL_IMPLEMENTATION", open(out, encoding="utf-8").read())


class _Base(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, code, body, headers=()):
        blob = json.dumps(body).encode()
        self.send_response(code)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(blob)))
        self.end_headers()
        self.wfile.write(blob)


def serve(handler_cls):
    srv = http.server.HTTPServer(("127.0.0.1", 0), handler_cls)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


class RuntimeProbe(unittest.TestCase):
    def test_compliant_tools_list_challenge_is_not_failed(self):
        """The 401 branch is keyed on tools/list, so its header is authoritative."""
        port_box = {}

        class H(_Base):
            def do_GET(self):
                self._json(200, {"resource": "https://x/mcp",
                                 "authorization_servers": ["https://as.example"]})

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                method = json.loads(self.rfile.read(n) or b"{}").get("method")
                if method == "initialize":
                    wa = 'Bearer realm="mcp"'            # generic, no resource_metadata
                else:
                    wa = ('Bearer realm="mcp", resource_metadata='
                          '"http://127.0.0.1:%d/.well-known/oauth-protected-resource"' % port_box["p"])
                self._json(401, {}, [("WWW-Authenticate", wa)])

        srv = serve(H)
        port_box["p"] = srv.server_address[1]
        try:
            findings, _ = gate.probe_http("http://127.0.0.1:%d/mcp" % port_box["p"])
        finally:
            srv.shutdown()
        found = ids(findings)
        self.assertNotIn("AUTH-NO-PRM-CHALLENGE", found)
        self.assertTrue(any(f["id"] == "OAUTH-POSTURE" and f["status"] == "pass" for f in findings))

    def test_tokenless_tools_list_200_is_caught(self):
        class H(_Base):
            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                self.rfile.read(n)
                self._json(200, {"jsonrpc": "2.0", "id": 2, "result": {"tools": []}})

        srv = serve(H)
        try:
            findings, _ = gate.probe_http("http://127.0.0.1:%d/mcp" % srv.server_address[1])
        finally:
            srv.shutdown()
        self.assertIn("AUTH-OPEN", ids(findings))

    def test_file_scheme_resource_metadata_is_refused_unfetched(self):
        """A scanned server must not be able to make the scanner read its own disk."""
        canary = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        canary.write('{"authorization_servers": ["CANARY"], "resource": "CANARY"}')
        canary.close()
        self.addCleanup(os.unlink, canary.name)

        class H(_Base):
            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                self.rfile.read(n)
                wa = 'Bearer realm="mcp", resource_metadata="file://%s"' % canary.name
                self._json(401, {}, [("WWW-Authenticate", wa)])

        srv = serve(H)
        try:
            findings, _ = gate.probe_http("http://127.0.0.1:%d/mcp" % srv.server_address[1])
        finally:
            srv.shutdown()
        found = ids(findings)
        self.assertIn("PRM-BAD-SCHEME", found)
        self.assertNotIn("OAUTH-POSTURE", found)
        self.assertNotIn("CANARY", json.dumps(findings))

    def test_unreachable_endpoint_claims_no_fault(self):
        findings, _ = gate.probe_http("http://127.0.0.1:1/mcp", timeout=2)
        self.assertTrue(all(f["status"] == "inconclusive" for f in findings))


class Receipts(TmpCase):
    def test_roundtrip_verifies(self):
        target = write(self.tmp, "t.py", "X = 1\n")
        out = os.path.join(self.tmp, "r.json")
        run_cli("check", target, "--receipt-out", out)
        proc = run_cli("verify-receipt", out)
        self.assertIn('"signature_valid": true', proc.stdout)
        self.assertEqual(proc.returncode, 0)

    def test_target_digest_matches_the_scanned_bytes(self):
        target = write(self.tmp, "t.py", "X = 1\n")
        out = os.path.join(self.tmp, "r.json")
        run_cli("check", target, "--receipt-out", out)
        body = json.load(open(out))
        import hashlib
        self.assertEqual(body["target_sha256"],
                         hashlib.sha256(open(target, "rb").read()).hexdigest())
        self.assertEqual(body["schema"], "mcp-gate/receipt@2")

    def test_any_edit_breaks_the_signature(self):
        target = write(self.tmp, "t.py", "X = 1\n")
        out = os.path.join(self.tmp, "r.json")
        run_cli("check", target, "--receipt-out", out)
        body = json.load(open(out))
        body["checks"] = []
        json.dump(body, open(out, "w"))
        proc = run_cli("verify-receipt", out)
        self.assertIn('"signature_valid": false', proc.stdout)
        self.assertEqual(proc.returncode, 1)

    def test_shipped_demo_receipts_verify_under_the_documented_demo_key(self):
        for name in ("server.py.receipt.json", "broken.py.receipt.json"):
            proc = run_cli("verify-receipt", os.path.join(ROOT, "demo", name))
            self.assertIn('"signature_valid": true', proc.stdout, name)

    def test_shipped_tampered_fixture_fails(self):
        proc = run_cli("verify-receipt", os.path.join(ROOT, "demo", "tampered.receipt.json"))
        self.assertIn('"signature_valid": false', proc.stdout)
        self.assertEqual(proc.returncode, 1)

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


class ExitCodes(TmpCase):
    def test_clean_target_exits_zero(self):
        target = write(self.tmp, "clean.py", '''
            ROUTES = {"/.well-known/oauth-protected-resource": {"authorization_servers": ["https://as.example"]}}
            def verify(request):
                return introspect(request.headers["Authorization"].removeprefix("Bearer "))
        ''')
        out = os.path.join(self.tmp, "r.json")
        self.assertEqual(run_cli("check", target, "--receipt-out", out).returncode, 0)

    def test_faulty_target_exits_one(self):
        target = write(self.tmp, "bad.py", "def list_items():\n    return []\n")
        out = os.path.join(self.tmp, "r.json")
        self.assertEqual(run_cli("check", target, "--receipt-out", out).returncode, 1)

    def test_missing_target_exits_two(self):
        self.assertEqual(run_cli("check", os.path.join(self.tmp, "nope.py")).returncode, 2)

    def test_unscannable_target_exits_two_and_writes_no_receipt(self):
        """It must not exit 0: a gate that green-lights an unreadable file is a hole."""
        target = write(self.tmp, "app.js", "// oauth bearer\nfunction f() {}\n")
        proc = run_cli("check", target)
        self.assertEqual(proc.returncode, 2)
        self.assertIn("not parseable as Python", proc.stderr)
        self.assertFalse(os.path.exists(target + ".receipt.json"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
