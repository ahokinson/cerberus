# Design notes

A single guard is a single point of failure. Each head fails open on its
own: a missing binary, a broken policy store, or a crash means that head
allows, because no individual check should be able to halt every Bash call
by breaking.

The system as a whole fails closed instead. `health` runs at every
`SessionStart` and checks that the enabled heads are actually enforcing:
that `tirith`, `opa`, and `cupcake` are on `$PATH`; that a synthetic
`rm -rf /` still gets blocked by cupcake's stock builtins; that the rules
directory exists and isn't empty, and that `sandbox-integrity.rhai` still
denies both a synthetic `dangerouslyDisableSandbox: true` event *and* a
synthetic `Write` to a Claude `settings.json`; that cerberus's cupcake store
has its own policies installed, and that a synthetic `Write` to
cerberus's rule-scripts path is still denied by `guard-self-protection.rego`
specifically (proving cerberus's *own* policy content, not just that
cupcake itself works); and that the tirith overlay file exists and its
`cerberus-guard-self-tamper` rule still fires. Rule and policy content lives
on disk rather than only in the binary, so those checks are what catch
content an agent edited or deleted out from under the guard — sandbox
protection in particular has two independent canaries (SANDBOX-001/003 in
`judgement`, CERB-POL-001/004 in `policy`) because there are multiple shapes
of the same attack, and covering one proves nothing about the others. If any
of it fails, `health` writes a sentinel and `gate` denies every guarded tool
until the guard is repaired. `cerberus doctor` explains what failed and retests; see
[Diagnosing a degraded guard](doctor.md).

The three heads aren't redundant with each other either. Risk avoidance,
governance policy, and contextual judgement are different questions, so a
command can pass one and still fail another. Pattern scanning has no idea
what your org's release process is. A fixed policy has no idea whether your
kubectl context happens to be pointed at production right now. `judgement`
covers that gap.
