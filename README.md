# mcp-gate

Does this MCP endpoint enforce authentication?

That is the whole tool. It sends `initialize`, replays `tools/list` with no
token, and records what came back. If the server hands its tool list to an
unauthenticated caller, that is the finding. If it refuses, the refusal is
checked for an RFC 9728 challenge a client can actually follow.

Single file, Python 3 stdlib only, zero dependencies.

## Why only that

We measured the first 100 servers in the official MCP registry on 2026-09-10.
Of the 74 exposing HTTP endpoints, **40 served their tool list with no token
at all**. One returned a textbook RFC 9728 challenge on `initialize` and then
served `tools/list` tokenlessly anyway — advertised, not enforced.

Every fault observed in that population was auth absence (F1) or a broken
OAuth resource-server posture (F2). Nothing else was observed, so nothing else
is checked. See [EVIDENCE.md](EVIDENCE.md) for the measurement and for what
the scope deliberately excludes.

```
F1  auth-absence         endpoint answers tool calls with no token
F2  incomplete-oauth-rs  401 without RFC 9728 resource_metadata, or PRM broken
```

## Usage

```bash
python3 mcp_gate.py check https://host/mcp        # probe -> signed receipt
python3 mcp_gate.py check http://127.0.0.1:3000/mcp
python3 mcp_gate.py verify-receipt x.receipt.json
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

`hmac_sha256` signs the body with `$MCP_GATE_KEY`, falling back to a
per-machine key at `~/.mcp-gate-key` (created 0600). The scheme is symmetric:
**a receipt verifies only where its key is present.** Set `MCP_GATE_KEY`
explicitly anywhere you intend to verify receipts later, including CI.

The receipts under `demo/` were produced against loopback servers in this
repository's own tests and are signed with a published constant, so anyone can
verify them:

```bash
MCP_GATE_KEY=mcp-gate-demo-key-not-a-secret python3 mcp_gate.py verify-receipt demo/open-server.receipt.json
MCP_GATE_KEY=mcp-gate-demo-key-not-a-secret python3 mcp_gate.py verify-receipt demo/tampered.receipt.json  # -> false, exit 1
```

That key is a demo constant, not a secret.

## GitHub Action

```yaml
- uses: unempyd/mcp-gate@v0.3.0
  with:
    target: https://your-host/mcp
    gate-key: ${{ secrets.MCP_GATE_KEY }}
```

The step fails the build when a fault is found. Read
`steps.<id>.outputs.failures` to gate on the count yourself instead.

## Tests

```bash
python3 -m unittest discover -s tests
```

Stdlib only, no outbound network: the tests stand up loopback servers.

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
  **from here**, and published resolvable metadata. It is not an audit.
- Bot walls, dead endpoints and unexpected protocol shapes report
  `inconclusive`. The tool never claims a fault it did not observe.
- The PRM document is fetched only over http(s), with a size cap. A scanned
  server does not get to choose what the scanner reads.
- Receipts are HMAC-signed, not PKI. Anyone holding the key can mint one; they
  are tamper-evidence for an archive, not third-party attestation.
- Probing sends unauthenticated requests to whatever URL you pass. Only probe
  endpoints you are authorised to probe.
