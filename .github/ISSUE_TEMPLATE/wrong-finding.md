---
name: X190 reported the wrong thing
about: A finding that is false, or a fault X190 missed
labels: correctness
---

**What X190 reported**

Paste the `checks` block, or the whole receipt.

**What the endpoint actually does**

How you know. A `curl` that shows the real behaviour is ideal.

**Which way it was wrong**

- [ ] Called an endpoint open when it refuses
- [ ] Called an endpoint fine when it serves its tool list without a token
- [ ] Reported inconclusive when the posture was readable
- [ ] Something else

**Version**

`X190 --help` prints nothing useful for this; run `python3 -c "import X190; print(X190.VERSION)"`
or paste the `tool_version` from the receipt.
