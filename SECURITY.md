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

## Layered policy sources are a trust boundary

`cerberus source add`/`sync` (see README's "Layered policy sources") clones
and runs a remote repo's `.rhai`/`.rego` content at the same trust level as
cerberus's own shipped rules — it executes against every guarded tool call,
the same as the content in this repo. A compromised or malicious source
repo is a real attack surface, not a hypothetical one: it can add an
always-allow rule, or a rule that exfiltrates data through its own logic.
Only add a source you'd trust to the same degree as cerberus itself. `add`
and `sync --yes` are both explicit, human-initiated actions specifically so
that never happens silently — a plain `cerberus init`/`cerberus guard`
never fetches anything, and `sync` without `--yes` only shows what would
change.

Before anything is installed, `.rego` content is run through `opa check`.
This is a syntax/compile gate, not a semantic one: it catches a source repo
that's broken or obviously malformed, and rejects the entire `add`/`sync`
if it fails — nothing is installed, `config.toml` isn't touched. It does
**not** catch a policy that parses cleanly but is deliberately malicious
(an intentional always-allow rule reads as perfectly valid Rego). If `opa`
isn't on `$PATH`, validation is skipped with a warning rather than blocking
the operation — cerberus doesn't require `opa` merely to accept a source,
only to enforce the `policy` head itself.

## The audit log persists command text to disk

`[audit] enabled = true` (see README's "Audit log") writes each denied/asked
call's raw `tool_input` — which can include a full Bash command line — to
`${XDG_STATE_HOME:-$HOME/.local/state}/guard/audit.jsonl` in plaintext.
Anything typed inline into a guarded command (a bearer token, a database
URL with embedded credentials) ends up in that file. It's off by default
for exactly this reason, is never transmitted anywhere by cerberus itself,
and treating that file with the same care as shell history is the right
mental model.

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
