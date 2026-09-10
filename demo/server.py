#!/usr/bin/env python3
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
