# Security

## Reporting a vulnerability in X190

Open a [private security advisory](https://github.com/unempyd/X190/security/advisories/new).
That route is private until published, so it is the right one for anything that
would let X190 mislead a reader or reach somewhere it should not.

If you cannot use advisories, open a normal
[issue](https://github.com/unempyd/X190/issues) and say only that you have a
security report without the details. Someone will open an advisory for you.

Please include what you did, what happened, and what you expected. A proof of
concept that reproduces is worth more than a description.

## What counts

X190 makes one accusation about somebody else's server, and it runs on your
machine while doing it. The reports that matter most are:

- **A finding that is wrong.** X190 calling a refusing endpoint open, or calling
  an open endpoint safe. Either one destroys the point of the tool.
- **An endpoint influencing the scanner.** X190 following a redirect, a metadata
  URL, or a response somewhere it should not go, or reading something it should
  not read.
- **A receipt that lies.** A receipt that verifies when it should not, or a key
  handled in a way that lets somebody else mint one.

Six such defects have been found and fixed so far. The record is in the commit
history, and the limits that remain are in the README under
"Methodology honesty" — including the ones that cannot be fixed, like an
operator recognising the probe's User-Agent.

## What does not count

- That an endpoint you probed is unauthenticated. That is X190 working.
- The published demo key, `X190-demo-key-not-a-secret`. It is in the README on
  purpose so anyone can verify the demo fixtures. Receipts signed with it are
  marked `"demo_key": true` and the verifier warns.
- The limits already documented in the README. If you can make one of them
  worse than documented, that does count.

## Supported versions

The latest release. X190 is a single file with no dependencies, so upgrading is
replacing one file.
