# mcp-gate

Correct-by-default gate for MCP servers: scan (source or live endpoint),
scaffold a compliant baseline, apply bounded safe fixes, emit a signed
receipt. Single file, Python 3 stdlib only, zero dependencies.

The job it does (frozen): enforce the residual measured fault classes that
survived the MCP 2026-07-28 stateless spec — auth absence, incomplete OAuth
resource-server posture (RFC 9728), session-keyed state (CVE-2026-16498
class), mutation tools without idempotency, injection/SSRF patterns,
legacy-session-era constructs — and emit a signed receipt (digest of the
scanned file + every check result + residual risks).

## Usage

```bash
python3 mcp_gate.py scaffold server.py          # compliant baseline (no DCR, CIMD-ready)
python3 mcp_gate.py scaffold server.py --force  # ... overwriting an existing file
python3 mcp_gate.py check ./server.py           # source scan -> signed receipt
python3 mcp_gate.py check https://host/mcp      # chained runtime probe -> signed receipt
python3 mcp_gate.py fix ./server.py             # bounded safe fixes (F2 today)
python3 mcp_gate.py verify-receipt x.receipt.json
```

Exit codes: `0` = pass (or inconclusive only), `1` = at least one fault found,
`2` = target error — missing, or not analysable. Source scanning is
**Python-only**: a file that does not parse as Python is refused with exit 2
rather than scanned by rules that would not describe it.

## Receipts

A receipt records what was checked, what was found, and what the tool could
not determine. Two digests, which are not the same thing:

- `target_sha256` — the scanned file's own bytes (source scans only).
- `receipt_sha256` — a digest of the receipt body itself.

`hmac_sha256` signs the whole body with `$MCP_GATE_KEY`, falling back to a
per-machine key at `~/.mcp-gate-key` (created 0600). The scheme is symmetric:
**a receipt verifies only where its key is present.** Set `MCP_GATE_KEY`
explicitly anywhere you intend to verify receipts later, including CI —
otherwise each machine signs with a key nothing else has.

The receipts committed under `demo/` are signed with a published constant so
that anyone can verify them:

```bash
MCP_GATE_KEY=mcp-gate-demo-key-not-a-secret python3 mcp_gate.py verify-receipt demo/server.py.receipt.json
MCP_GATE_KEY=mcp-gate-demo-key-not-a-secret python3 mcp_gate.py verify-receipt demo/tampered.receipt.json  # -> false, exit 1
```

That key is a demo constant, not a secret. Never use it to sign anything real.

## GitHub Action

```yaml
- uses: unempyd/mcp-gate@v0.2.0
  with:
    target: ./src/mcp_server.py
    gate-key: ${{ secrets.MCP_GATE_KEY }}
```

The step **fails the build when the gate finds a fault** (the tool's exit code
is propagated). Read `steps.<id>.outputs.failures` if you want to gate on the
count yourself instead.

## Tests

```bash
python3 -m unittest discover -s tests
```

Stdlib only, no network access required — the runtime-probe tests stand up
loopback HTTP servers. Every test corresponds to a defect that was once live
in this tool.

## What this is NOT

A correctness gate + signed receipt — not a full gateway, agent runtime,
identity provider, or hosted platform. It does not proxy your traffic, hold
your credentials, run your servers, or replace the official conformance
suite; it enforces the residual fault classes those tools don't cover and
issues a receipt you can archive.

## Methodology honesty

Runtime checks are single-shot chained probes (initialize then a tokenless
tools/list replay): they prove posture, not full OAuth conformance. Bot walls,
dead endpoints, and unexpected protocol shapes are reported `inconclusive` —
never as faults.

Source checks are deterministic heuristics for the six frozen fault classes,
not a type checker, and they read code only: comments and docstrings are
blanked before matching, so prose describing a posture never satisfies a check
for it. The scaffold reports `NO-OAUTH` against itself for exactly this
reason — it publishes RFC 9728 metadata but delegates token verification, and
the gate will not take the docstring's word for it.

Known limits, stated rather than hidden:

- **Heuristics cut both ways.** `NO-OAUTH` looks for a token-verification
  surface in the file it is given. A server that verifies tokens in a
  middleware module, a reverse proxy, or a framework dependency will be
  flagged despite being correct. Read the evidence string, not just the count.
- **One file at a time.** There is no cross-module analysis, so a genuine
  route registered in another file is invisible here.
- **Runtime probes observe, they do not authenticate.** A `pass` means the
  posture was correct at that timestamp, from this network position.
- **Receipts are HMAC-signed, not PKI.** Anyone holding the key can mint one.
  They are tamper-evidence for an archive, not third-party attestation.
- **Probes are unauthenticated single shots against whatever URL you pass.**
  Only scan endpoints you are authorised to scan; the receipt records what was
  probed and when.
