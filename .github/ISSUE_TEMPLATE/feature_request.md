---
name: Feature request
about: A new rule, or a change to how a head works
labels: enhancement
---

**The problem**

What bad outcome isn't currently caught, or what good command is currently
blocked.

**Which head does this belong to**

- `risk` (general risk avoidance): universally bad practice, regardless of
  org or environment
- `policy` (governance policy): a fixed org-defined invariant
- `judgement` (contextual bad decisions): needs live state to tell safe from
  dangerous

If it's `risk` or `policy`, the change may belong in
[tirith](https://github.com/sheeki03/tirith) or
[cupcake](https://github.com/eqtylab/cupcake) rather than here. cerberus
only owns the `judgement` rule scripts.

**What the check would look at**

Command text alone, or live state (git, kubectl context, the hook payload)?
The latter is what `judgement` exists for.

**Commands that should still be allowed**

False positives are the main cost of a new rule, so this part matters.
