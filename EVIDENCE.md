# Evidence

Why this tool checks what it checks, and why it stopped checking everything else.

Individual servers and packages are not named here. The rates are the finding;
attributing faults to specific third parties is a disclosure matter, handled
privately with the operators, not published in a repository.

## Population

Official MCP registry, `registry.modelcontextprotocol.io/v0/servers?version=latest&limit=100`,
frozen 2026-09-10T02:30:29Z.

```
100  servers
 74  expose an HTTP endpoint
 26  local transport only (no endpoint published)
```

**Sampling limit, stated up front:** the registry returns servers in name
order, so these 100 are the alphabetical head, not a random sample. One
publisher accounts for 17 of the 26 local-transport entries. Rates below
describe this population; generalising them to the whole registry is not
supported by this measurement.

## The measured problem

All 74 HTTP endpoints were probed with a chained unauthenticated replay:
`initialize`, then `tools/list` with no token. 77 signed receipts were
produced (75 real endpoints plus 2 loopback controls).

```
40   served tools/list with HTTP 200 and no token          F1
25   refused, published resolvable RFC 9728 metadata       pass
 3   refused without resource_metadata in the challenge    F2
 1   advertised resource_metadata that would not resolve   F2
 6   no interpretable posture (dead, flapping, bot wall)   inconclusive
```

Fault classes actually observed across all 77 receipts: **F1 (42), F2 (4)**.

One endpoint returned a correct RFC 9728 challenge on `initialize` and then
served `tools/list` tokenlessly. A single-shot check that stops at the
challenge scores it compliant; the chained replay does not. This is why the
probe replays.

## Why there is no source scanner

Earlier versions scanned source for six fault classes. The measurement does not
support that, on two independent grounds.

**Four of the six classes were never observed.** F3 (session-keyed state),
F4 (mutation tools without idempotency), F5 (injection/SSRF patterns) and
F6 (legacy-session constructs) appear in zero of the 77 receipts. They were
derived from reading the spec, not from measuring anything. Checks without
evidence produce findings without meaning.

**The servers with the fault do not ship source.** All 36 verified-open servers
are remote-only registry entries: no npm package, no PyPI package, no container
image. There is no artifact to scan, in any language. Of the 27 packages
declared anywhere in the population, 24 are npm, 2 are OCI images, and 1 is
PyPI — so the scanner that existed covered the ecosystem with the least
presence in the evidence.

## The local-transport population

The 26 local-transport servers were unmeasured, so we measured them. All 23 npm
packages were downloaded and read statically; nothing was executed.

```
23   npm packages inspected (2 OCI images and 1 package-less entry not inspected)
25   of 25 declared packages declare transport: stdio       none declare http
19   contain no network listener at all                     F1 structurally impossible
 1   binds an ephemeral loopback port for an OAuth callback  not an MCP surface
 3   ship an HTTP MCP transport
```

Of those 3, **all 3 can serve MCP with no authentication** in a configuration
their own documentation describes: one binds all interfaces with no auth and no
host guard; one authenticates only when an optional environment variable is
set, and that variable is unset by default; one runs HTTP as its *default* mode
and ships first-class public-tunnel options that remove its loopback-only
protection.

So the fault does exist in the local population, at roughly 3 in 23 — but it is
the same fault. A server in HTTP mode is an HTTP endpoint, and this tool probes
it like any other. What differs is discovery: the registry publishes no URL, so
nobody thinks to look.

That gap is real and is not closed by a source scanner. Static detection here
requires distinguishing an unauthenticated MCP route from, say, an ephemeral
loopback OAuth callback — a distinction we made by reading the code, and one a
pattern matcher gets wrong in exactly the direction that destroys trust in a
security tool. Until that can be done reliably, the honest answer is to say so
and probe the running server.

## What remains unknown

- Rates outside the alphabetical head of the registry.
- Whether any of the 3 HTTP-capable local packages are actually deployed in
  their unauthenticated configuration; shipping the capability is not the same
  as running it.
- The 2 OCI images, which were not inspected.
- Whether the 25 endpoints that passed still pass. A receipt is a timestamp,
  not a subscription.
