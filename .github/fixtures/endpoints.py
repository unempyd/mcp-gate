#!/usr/bin/env python3
"""Two MCP endpoints for exercising the composite action in CI.

`open`   serves its tool list to anyone, so the action must fail the build.
`refuse` refuses with a resolvable RFC 9728 challenge, so it must pass.

Stdlib only, to match the tool itself.
"""
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

MODE, PORT = sys.argv[1], int(sys.argv[2])

SCHEMA = {"type": "object", "properties": {"path": {"type": "string"}}}
TOOLS = {"tools": [{"name": "read_file", "description": "read a file", "inputSchema": SCHEMA},
                   {"name": "exec_sql", "description": "run sql", "inputSchema": SCHEMA}]}
PRM = {"resource": f"http://127.0.0.1:{PORT}/mcp",
       "authorization_servers": [f"http://127.0.0.1:{PORT}/as"]}
CHALLENGE = ('Bearer resource_metadata='
             f'"http://127.0.0.1:{PORT}/.well-known/oauth-protected-resource"')


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _send(self, code, ctype, payload, extra=()):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        for key, value in extra:
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if self.path.startswith("/.well-known/oauth-protected-resource"):
            return self._send(200, "application/json", json.dumps(PRM).encode())
        self._send(405, "text/plain", b"")

    def do_DELETE(self):
        self._send(405, "text/plain", b"")

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        request = json.loads(self.rfile.read(length) or b"{}")
        method, rid = request.get("method"), request.get("id")

        if MODE == "refuse":
            return self._send(401, "application/json", b'{"error":"unauthorized"}',
                              [("WWW-Authenticate", CHALLENGE)])

        if method == "initialize":
            return self._send(200, "application/json", json.dumps(
                {"jsonrpc": "2.0", "id": rid,
                 "result": {"protocolVersion": "2025-11-25", "capabilities": {"tools": {}},
                            "serverInfo": {"name": "fixture", "version": "1"}}}).encode())
        if method == "notifications/initialized":
            return self._send(202, "text/plain", b"")
        if method == "tools/list":
            return self._send(200, "application/json", json.dumps(
                {"jsonrpc": "2.0", "id": rid, "result": TOOLS}).encode())
        self._send(400, "application/json", b'{"error":"bad request"}')


server = HTTPServer(("127.0.0.1", PORT), Handler)
threading.Thread(target=server.serve_forever, daemon=True).start()
print(f"{MODE} endpoint listening on {PORT}", flush=True)
threading.Event().wait()
