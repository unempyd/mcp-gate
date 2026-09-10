# mcp-gate

Correct-by-default gate for MCP servers: scan (source or live endpoint),
scaffold a compliant baseline, apply bounded safe fixes, emit a signed
receipt. Single file, Python 3 stdlib only, zero dependencies.

The job it does (frozen): enforce the residual measured fault classes that
survived the MCP 2026-07-28 stateless spec — auth absence, incomplete OAuth
resource-server posture (RFC 9728), session-keyed state (CVE-2026-16498
class), mutation tools without idempotency, injection/SSRF patterns,
legacy-session-era constructs — and emit a signed receipt (artifact hash +
every check result + residual risks).

## Usage

```bash
python3 mcp_gate.py scaffold server.py          # compliant baseline (no DCR, CIMD-ready)
python3 mcp_gate.py check ./server.py           # source scan -> signed receipt
python3 mcp_gate.py check https://host/mcp      # chained runtime probe -> signed receipt
python3 mcp_gate.py fix ./server.py             # bounded safe fixes (F2 today)
python3 mcp_gate.py verify-receipt x.receipt.json
```

Exit codes: 0 = pass/inconclusive-only, 1 = at least one fault found,
2 = target error. Receipts verify with the key at `~/.mcp-gate-key`
or `$MCP_GATE_KEY`.

## GitHub Action

```yaml
- uses: your-org/mcp-gate@main
  with:
    target: ./src/mcp_server.py
    min-gate: ${{ secrets.MCP_GATE_KEY }}
```

## What this is NOT

A correctness gate + signed receipt — not a full gateway, agent runtime,
identity provider, or hosted platform. It does not proxy your traffic, hold
your credentials, run your servers, or replace the official conformance
suite; it enforces the residual fault classes those tools don't cover and
issues a receipt you can archive.

## Methodology honesty

Runtime checks are single-shot chained probes (initialize then a tokenless
tools/list replay): they prove posture, not full OAuth conformance. Source
checks are deterministic heuristics for the six frozen fault classes, not a
type checker; comments and docstrings are blanked before matching, so prose
describing a posture never satisfies a check (the scaffold reports `NO-OAUTH`
for exactly this reason: it publishes RFC 9728 metadata but delegates token
verification). Bot walls, dead endpoints, and unexpected protocol shapes are
reported `inconclusive` — never as faults. The receipt records the probe
timestamp and raw evidence for exactly this reason.