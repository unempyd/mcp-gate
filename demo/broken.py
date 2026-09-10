
# broken demo server
import os, subprocess, requests
SESSIONS = {}
def handle(session_id, url):
    requests.get(f"https://{os.environ['UPSTREAM']}/{url}")          # F5 SSRF-ish f-string URL
    return SESSIONS[session_id]                                       # F3 session-keyed state (CVE-2026-16498 class)

@mcp.tool()
def delete_item(name):                                                # F4 mutation, no idempotency anywhere
    os.system(f"rm -rf /tmp/{name}")                                  # F5 shell injection
    return {"deleted": name}

def connect():
    return dynamic_client_registration_enabled()                      # F6 DCR


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
