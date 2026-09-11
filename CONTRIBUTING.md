# Contributing

## Getting it running

```bash
git clone https://github.com/unempyd/X190.git
cd X190
python3 -m unittest discover -s tests
```

No dependencies, no build step, no fixtures to download. The tests stand up
loopback servers and never touch the network.

## The bar for a change

**A check is only added when something has been observed.** X190 carries two
fault classes because those are the two that appeared in a real population.
Four others were removed after a measurement found zero instances. A pull
request that adds a check needs evidence that the fault exists somewhere, not
an argument that it could.

**A finding needs positive proof.** X190 reports auth-absence only when a
JSON-RPC result came back. HTTP status alone was once treated as proof, and it
made the tool accuse servers that were correctly refusing. If your change makes
a claim, it must be from something observed, not something absent.

**Anything unclear is inconclusive.** Bot walls, dead endpoints, unreadable
bodies and off-target redirects are all reported without claiming a fault. When
in doubt, the tool says it does not know.

**Failing toward reporting beats failing toward clean.** Where a judgement call
exists, prefer the branch that surfaces a possible problem over the one that
stays quiet.

## Tests

Every fix carries a test that was red before it. If you are fixing something,
write the test that reproduces it first and include it. The suite is organised
around the two ways the tool can lie: calling a refusing server open, and
calling an open server safe.

Run them on the oldest supported Python if you can. CI runs 3.9, 3.11 and 3.13.

## Scope

X190 probes endpoints. It does not read source, publish attestations, monitor
continuously, or manage servers. Those are not on a roadmap, and proposals for
them will be declined without evidence that someone needs them. `EVIDENCE.md`
explains why the scope is this narrow.

## Claims

The README states what a receipt does and does not prove, and lists the ways an
endpoint can evade or mislead the probe. Those statements are load-bearing. If a
change makes one of them untrue, update it in the same pull request.
