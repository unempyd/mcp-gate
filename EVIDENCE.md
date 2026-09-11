# Evidence

Why this tool checks what it checks, what the checks can and cannot prove, and
which numbers are currently unsafe to quote.

Individual servers and packages are not named here. The rates are the finding;
attributing faults to specific third parties is a disclosure matter, handled
privately with operators, not published in a repository.

## Population

Official MCP registry, `registry.modelcontextprotocol.io/v0/servers?version=latest&limit=100`,
frozen 2026-09-10T02:30:29Z.

```
100  servers
 74  expose an HTTP endpoint
 26  local transport only (no endpoint published)
```

**Sampling limit:** the registry returns servers in name order, so these 100
are the alphabetical head, not a random sample. One publisher accounts for 17
of the 26 local-transport entries. Rates below describe this population only.

## The original measurement, and why its headline number is suspended

All 74 HTTP endpoints were probed on 2026-09-10 with a chained unauthenticated
replay: `initialize`, then `tools/list` with no token. 77 signed receipts were
produced. The reported result was 40 of 74 serving their tool list with no
token.

**That number is not currently safe to quote.** The probe that produced it
treated HTTP 200 on `tools/list` as proof the tool list had been served, and
discarded the response body. JSON-RPC conventionally reports application errors
inside a 200 response, so a server answering
`{"jsonrpc":"2.0","error":{"code":-32001,"message":"Unauthorized"}}` — a
correct refusal — was recorded as open. So was any non-MCP endpoint returning
200, such as a proxy landing page.

The receipts did not record response bodies, so the original run cannot be
reclassified after the fact. The corrected probe (v0.4.0) requires a JSON-RPC
`result` before claiming F1. Re-running the measurement with it is the single
highest-value piece of evidence outstanding for this project.

What survives from the original run without qualification:

- 25 endpoints refused and published RFC 9728 metadata that resolved. A pass
  requires positive evidence, so these are unaffected by the bug.
- 4 endpoints refused with a broken or absent challenge (F2).
- Fault classes observed across all 77 receipts: F1 and F2 only.
- One endpoint returned a correct RFC 9728 challenge on `initialize` and then
  answered `tools/list` without a token. This one was verified by hand, twice.
  It is why the probe replays rather than stopping at the challenge.

### The re-measurement must be run with v0.9.0 or later

v0.4.0 fixed the error that over-reported. v0.9.0 fixed five that
*under*-reported, all in the same place: the probe read the wire more narrowly
than a real MCP client does. It missed a tool list delivered across several
SSE `data:` lines, one returned under a 2xx that was not literally 200, one
sent compressed, one served as concatenated gzip members, and one whose
payload contained a Unicode line separator.
Each was confirmed by standing up a server the official MCP SDK lists tools
from with no credentials, and watching the probe of the day call it
`inconclusive`.

Consequence for the record: an `inconclusive` from a probe older than v0.9.0
is weaker than it looks — it may be an open endpoint the probe could not read,
not an endpoint whose posture was genuinely unobservable. `fail` and `pass`
results are unaffected, since both rest on positive evidence that these bugs
could only suppress. The outstanding re-measurement should therefore be run
with v0.9.0 or later, and its `inconclusive` bucket compared against the
original run's rather than assumed equivalent.

## Why there is no source scanner

Two independent grounds.

**Four of six classes were never observed.** F3 (session-keyed state), F4
(mutation tools without idempotency), F5 (injection/SSRF patterns) and F6
(legacy-session constructs) appear in zero of the 77 receipts. They were derived
from reading the spec, not from measuring anything.

**The servers with the fault do not ship source.** All verified-open servers are
remote-only registry entries: no npm package, no PyPI package, no container
image. Of the 27 packages declared anywhere in the population, 24 are npm, 2 are
OCI and 1 is PyPI — so the Python scanner that existed covered the ecosystem
with the least presence in the evidence.

## The local-transport population

The 26 local-transport servers were unmeasured, so they were measured. All 23
npm packages were downloaded and read statically; nothing was executed.

```
23   npm packages inspected (2 OCI images and 1 package-less entry not inspected)
25   of 25 declared packages declare transport: stdio       none declare http
19   contain no network listener at all                     F1 structurally impossible
 1   binds an ephemeral loopback port for an OAuth callback  not an MCP surface
 3   ship an HTTP MCP transport
```

Of those 3, **all 3 can serve MCP with no authentication** in a configuration
their own documentation describes: one binds all interfaces with no auth and no
host guard; one authenticates only when an optional environment variable is set,
and it is unset by default; one runs HTTP as its *default* mode and ships
first-class public-tunnel options that remove its loopback-only protection.

The fault exists there too, at roughly 3 in 23 — but it is the same fault. A
server in HTTP mode is an HTTP endpoint, and this tool probes it like any other.
What differs is discovery: the registry publishes no URL, so nobody looks.

That gap is not closed by a source scanner. Static detection would have to
separate an unauthenticated MCP route from an ephemeral loopback OAuth callback
— a distinction made here by reading code, and one a pattern matcher gets wrong
in the direction that destroys trust in a security tool.

## What a finding does and does not assert

`AUTH-OPEN` asserts an observation: at this timestamp, from this network
position, the endpoint returned a JSON-RPC `result` for `tools/list` sent with
no credentials, and the receipt records how many tools came back.

It does not assert that this is a mistake. A deliberately public MCP server is
a legitimate design, and at least one operator in the original population
described themselves as keyless by intent. The receipt is evidence of what the
endpoint did; whether that is a fault is the operator's call.

`OAUTH-POSTURE` pass asserts that the endpoint refused an unauthenticated tool
call **then**, **from there**, and published metadata that resolved. It is not
an audit, and it says nothing about token validation, scope enforcement, or
authorisation once a token is presented.

## What remains unknown

- The true F1 rate in the population, pending a re-run with the corrected probe.
- Rates outside the alphabetical head of the registry.
- Whether any of the 3 HTTP-capable local packages are deployed in their
  unauthenticated configuration. Shipping a capability is not running it.
- The 2 OCI images, which were not inspected.
- Whether the 25 endpoints that passed still pass. A receipt is a timestamp.
- Whether unauthenticated MCP endpoints exist outside the registry at a rate
  worth measuring. No evidence has been gathered on this.
