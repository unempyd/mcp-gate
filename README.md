# X190

Does this MCP endpoint enforce authentication?

That is the whole tool. It sends `initialize`, replays `tools/list` with no
token, and records what came back. If the server hands its tool list to an
unauthenticated caller, that is the finding. If it refuses, the refusal is
checked for an RFC 9728 challenge a client can actually follow.

Single file, Python 3 stdlib only, zero dependencies.

## Why only that

We probed the 74 HTTP endpoints among the first 100 servers in the official MCP
registry on 2026-09-10. Every fault observed was auth absence (F1) or a broken
OAuth resource-server posture (F2). Nothing else was observed, so nothing else
is checked.

The headline rate from that run is **suspended pending a re-measurement**: the
probe of the day treated HTTP 200 as proof the tool list was served, and
JSON-RPC routinely refuses *inside* a 200. The probe now requires a JSON-RPC
`result` echoing the request id before it will claim anything. What survives unqualified is that 25 endpoints
refused and published resolvable RFC 9728 metadata, 4 refused with a broken or
absent challenge, and one advertised OAuth correctly and then served its tools
without a token anyway. See [EVIDENCE.md](EVIDENCE.md).

```
F1  auth-absence         tools/list returned a JSON-RPC result with no token
F2  incomplete-oauth-rs  refused, but with no RFC 9728 challenge a client could
                         follow, or with metadata that does not resolve
```

## Usage

```bash
python3 X190.py check https://host/mcp        # probe -> signed receipt
python3 X190.py check http://127.0.0.1:3000/mcp
python3 X190.py verify-receipt x.receipt.json
```

Exit codes: `0` = pass, or inconclusive only; `1` = at least one fault;
`2` = the target is not an http(s) URL.

### Servers distributed for stdio

A package that declares stdio transport can still ship an HTTP mode. In our
measurement of the registry's local-transport population, 3 of 23 npm packages
shipped a network-listening MCP surface, and all three could serve MCP without
authentication in a documented configuration — while the registry listed no
endpoint to probe.

If you ship or run such a server, start its HTTP mode and probe that URL like
any other. The fault is the same fault; only the discovery is different.

## Receipts

A receipt records the target, the checks, the raw probe evidence, and a
timestamp — including what could not be determined.

`hmac_sha256` signs the body with `$X190_KEY`, falling back to a
per-machine key at `~/.X190-key` (created 0600).

**What a receipt proves, exactly:** that someone holding the key produced this
byte-for-byte content. Nothing else. The scheme is symmetric, so a party who
can verify a receipt can also mint one — which means a receipt is tamper
evidence for your own archive, *not* an attestation you can hand to a third
party as proof. Two unrelated organisations cannot use it to distinguish an
authentic result from a fabricated one, because doing so would require sharing
the secret that lets either of them fabricate. If you need transferable proof,
this design cannot give it to you; that would need public-key signatures and a
key you publish.

Receipts signed with the published demo key are marked `"demo_key": true` and
the verifier warns about them, because that key is in this README and anyone
can sign anything with it. Set `X190_KEY` to a real secret anywhere you
intend to verify receipts later, including CI.

The receipts under `demo/` were produced against loopback servers in this
repository's own tests and are signed with a published constant, so anyone can
verify them:

```bash
X190_KEY=X190-demo-key-not-a-secret python3 X190.py verify-receipt demo/open-server.receipt.json
X190_KEY=X190-demo-key-not-a-secret python3 X190.py verify-receipt demo/tampered.receipt.json  # -> false, exit 1
```

That key is a demo constant, not a secret.

## GitHub Action

```yaml
- uses: unempyd/X190@v0.7.0
  with:
    target: https://your-host/mcp
    gate-key: ${{ secrets.X190_KEY }}
```

The step fails the build when a fault is found. Read
`steps.<id>.outputs.failures` to gate on the count yourself instead.

## Tests

```bash
python3 -m unittest discover -s tests
```

Stdlib only, no outbound network: the tests stand up loopback servers.

## What a finding asserts

`AUTH-OPEN` is an observation, not a verdict: at this timestamp, from this
network position, the endpoint returned a JSON-RPC `result` for `tools/list`
sent with no credentials, and the receipt says how many tools came back.

It does not assert that this is a mistake. A deliberately public MCP server is
a legitimate design. The receipt is evidence of what the endpoint did; whether
that is a fault is the operator's call.

## What this is NOT

Not a gateway, agent runtime, identity provider, or hosted platform. Not a
source-code scanner — earlier versions shipped one, and the measurement above
is why it was removed: every fault in the population was observable at the
endpoint, and none of the affected servers published source to scan. Not a
replacement for the official conformance suite.

## Methodology honesty

Probes are single-shot and chained (`initialize`, then a tokenless
`tools/list`). They establish posture at one timestamp from one network
position — not full OAuth conformance.

- A `pass` means the endpoint refused an unauthenticated tool call **then**,
  **from here**, and published resolvable metadata. It is not an audit, and it
  says nothing about token validation, scopes, or authorisation once a token is
  actually presented.
- Bot walls, dead endpoints and unexpected protocol shapes report
  `inconclusive`. The tool never claims a fault it did not observe. A bot wall
  must look like one: a 403 carrying a JSON body no longer counts, so an MCP
  server cannot buy an inconclusive by putting "access denied" in its JSON.
- The handshake is completed before anything is asked for — `initialize`, then
  `notifications/initialized`, then `tools/list` carrying the protocol version
  the server negotiated. A spec-strict server that would otherwise reject the
  request is measured rather than filed as inconclusive.
- Every request this tool makes — the probe itself and the metadata fetch —
  goes through one guarded opener that re-validates each redirect hop. Neither
  will follow a redirect to a private or link-local address, so a scanned server
  cannot use this tool to reach into the network of whoever runs it. This does
  not survive DNS rebinding between the check and the connection.
- The probe additionally refuses to leave the origin you named. A finding is a
  claim about a specific endpoint, so a redirect to a different host or port
  reports `REDIRECT-OFF-TARGET` / inconclusive rather than quietly measuring
  something else and filing it under your target. Same-origin redirects are
  followed and recorded.
- Receipts are HMAC-signed, not PKI. Anyone holding the key can mint one; they
  are tamper-evidence for an archive, not third-party attestation.
- **A receipt has no freshness.** It carries a timestamp and nothing binds it to
  now, so a genuine passing receipt can be presented long after the posture
  changed. `verify-receipt` reports `age_seconds`; decide your own staleness
  policy. Nothing here proves an endpoint is *currently* closed.
- **An endpoint can single out this prober.** The probe sends a `X190/...`
  User-Agent from one IP; a server that returns a clean 401 to it and its tool
  list to everyone else passes. This is reproduced in our own testing and is
  inherent to remote black-box probing — a receipt records what the endpoint
  returned *to us, then*, not what it returns to everyone.
- **An endpoint can pass CI by redirecting away.** A 302 to a different host or
  port reports `REDIRECT-OFF-TARGET` / inconclusive, which does not fail the
  gate. That verdict is deliberate — a finding cannot be attributed to an origin
  the caller did not name, and legitimate deployments redirect
  `host/mcp` to `mcp.host/mcp`, so failing here would manufacture false
  positives. The refusal and the URL are recorded in the receipt; re-run against
  the destination if you meant to probe it.
- **An endpoint can force an inconclusive result.** A response padded past the
  5 MB read cap is reported `RESPONSE-TRUNCATED` / inconclusive, and inconclusive
  findings do not fail the gate. The tool will not claim a fault it could not
  observe, so a server that refuses to be readable is recorded as unread rather
  than as safe. Read the findings, not just the exit code.
- Probing sends unauthenticated requests to whatever URL you pass. Only probe
  endpoints you are authorised to probe.
