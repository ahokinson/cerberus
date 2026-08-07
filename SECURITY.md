# Security

## What cerberus is for

cerberus guards against an agent making a bad call: a destructive command it
didn't think through, a `terraform destroy` against the wrong workspace, a
force-push over someone else's commits. It is a seatbelt for an agent that
is trying to do the right thing.

## What cerberus is not

It is not a sandbox, and it is not a boundary against an adversary who
already has shell access on the machine. Anyone or anything able to run
arbitrary commands can also edit `config.toml`, delete the rule scripts, or
replace the binary on `$PATH`. cerberus raises the cost of a mistake. It
does not contain an attacker.

Two specific limits worth knowing:

- **Detection is best-effort.** `rules::shell`'s tokenizer is quote-aware
  and splits on shell operators, but it is not a POSIX parser. A command
  obfuscated on purpose (base64, variable indirection, `eval`) can get past
  the pattern and rule checks. The checks are tuned to catch plausible
  mistakes, not deliberate evasion.
- **Heads fail open individually.** A missing binary, a broken policy store,
  or a rule script that won't compile means that head allows. No single
  check can halt every Bash call by breaking.

The system compensates by failing closed as a whole. `cerberus health` runs
at every `SessionStart` and verifies that each enabled head is actually
enforcing, including a synthetic `rm -rf /` through cupcake and a synthetic
`dangerouslyDisableSandbox: true` through the rule scripts. If any check
fails it writes a sentinel, and `cerberus gate` then denies every Bash call
until `cerberus init` repairs things. A guard that has quietly stopped
working is treated as worse than no guard.

## Reporting a vulnerability

Open a [security advisory](https://github.com/ahokinson/cerberus/security/advisories/new)
rather than a public issue.

Things worth reporting: a way to get a command past a shipped rule that the
rule plainly intends to catch, a way to make `health` report healthy while a
head isn't enforcing, or a way to clear the degraded sentinel without
repairing the underlying cause. Obfuscated-command bypasses are interesting
if the obfuscation is something an agent would plausibly produce on its own.

## Supported versions

Only the latest release gets fixes. cerberus is pre-1.0 and there are no
maintained release branches.
