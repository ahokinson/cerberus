# Heads and rules

Rule content is the one thing cerberus itself owns and ships, across all
three heads. Each head's content lives in its own canonical directory in
this repo, embedded into the binary at compile time, and `cerberus init`
writes it out to the right runtime location for that head.

## judgement

`judgement` runs every `*.rhai` script it finds in
`${XDG_CONFIG_HOME:-$HOME/.config}/cerberus/rules/`, calling each script's
`check(cmd, cwd, input)` function and denying on the first one that returns
a string. The canonical scripts live in this repo's [`rules/`](../crates/cerberus/rules/)
directory.

Four ship with cerberus. Every one of them runs through `judgement`, since
that's the only head that can see live process, git, and settings state, but
they serve different purposes. Each carries its purpose as a comment at the
top of its file:

- **git-safety** *(general risk avoidance)*. Protects against irreversible
  loss of work: branch switches or discards with uncommitted changes,
  force-pushing over remote commits your local history doesn't have,
  force-deleting a branch with unmerged commits, rebasing or amending
  history already pushed upstream, and `git clean -f` actually removing
  files (it stays quiet on a no-op clean).
- **environment-awareness** *(contextual bad decisions)*. Blocks
  `kubectl delete` or `terraform destroy`/`apply` while the active context
  or workspace name looks like production.
- **release-hygiene** *(governance policy)*. Blocks `npm publish` and
  `cargo publish` when the working tree has uncommitted changes, so what
  ships always matches a real commit.
- **sandbox-integrity** *(governance policy)*. Blocks the agent from
  weakening its own sandbox three ways: setting the Bash tool's
  `dangerouslyDisableSandbox` flag (SANDBOX-001), running a shell command
  that edits the `sandbox` config in a Claude `settings.json` (SANDBOX-002),
  or pointing a file-writing tool at a Claude `settings.json` at all
  (SANDBOX-003). That last one is unconditional — a `Write` replaces the
  whole file, so the dangerous edit is exactly the one that deletes the
  sandbox block and never mentions it. Those decisions belong to a human.
  SANDBOX-001 and SANDBOX-003 double as `health`'s canaries for the
  judgement head.

To add a personal rule, drop a `.rhai` file into the runtime rules
directory. Nothing needs rebuilding, and re-running `init` leaves it alone,
since `init` only ever writes the four shipped filenames. See
[CONTRIBUTING.md](../CONTRIBUTING.md) for the native function API available to
scripts: git state, kubectl/terraform context, tokenizing.

## policy

`policy` hands cupcake the hook payload verbatim, evaluated against a store
cerberus owns outright at
`${XDG_CONFIG_HOME:-$HOME/.config}/cerberus/cupcake/`, passed to
`cupcake eval` via `--global-config`. cerberus's own policies live in its
`policies/claude/cerberus/` directory there. The canonical `.rego` files
live in this repo's [`policies/cupcake/`](../crates/cerberus/policies/cupcake/) directory.

The `claude/` path segment is cupcake's addressing rather than a Claude Code
assumption: cupcake scans `policies/<harness>/` and only that, so a policy
outside it is never evaluated. It matches the `--harness claude` cerberus
passes deliberately, every harness's payload having been normalized into
Claude's wire format at the edge.

cerberus used to write into the user's own `~/.config/cupcake` instead,
behind a reserved `custom/cerberus/` subdirectory that existed purely to
avoid colliding with their onboarded policies. It owns its store now, so
that reservation is gone — and so is any chance of cerberus disturbing a
cupcake setup you maintain yourself.

Four ship with cerberus, all payload-only governance invariants: cupcake
never sees live git/process/settings state, so anything needing that stays
`judgement`'s job.

- **CERB-POL-001 sandbox-integrity**. Defense-in-depth mirror of
  judgement's SANDBOX-001 (`dangerouslyDisableSandbox`). Worth the overlap:
  `judgement` can be legitimately disabled in `config.toml` without
  `health` calling it degraded, so this keeps the single highest-value
  invariant enforced by an independent mechanism either way.
- **CERB-POL-002 webfetch-ssrf**. Denies a WebFetch targeting a cloud
  instance metadata endpoint (`169.254.169.254` and friends) — classic
  SSRF-to-credential-theft, and a gap `risk` structurally cannot cover
  since WebFetch never runs through Bash.
- **CERB-POL-003 ci-trust-boundary**. Denies a file-writing tool pointed at
  a CI/CD pipeline definition (`.github/workflows/`, `.gitlab-ci.yml`,
  `.circleci/config.yml`) or a git hook — the same trust-boundary shape as
  SANDBOX-003, applied to CI instead of Claude's own settings.
- **CERB-POL-004 guard-self-protection**. Denies a file-writing tool
  pointed at cerberus's, tirith's, or cupcake's own runtime configuration.
  This is `health`'s canary for the policy head's global-store content.

## risk

`risk` scans Bash command strings via tirith, which ships its own
extensive built-in detections that already apply with zero configuration.
cerberus adds an overlay on top of those, applied via `TIRITH_POLICY_ROOT` —
but **only** in repos that have no `.tirith/policy.yaml` of their own; a
repo or team's own tirith policy always wins over cerberus's overlay (and so
does not receive it).

That overlay is **composed**, not copied. tirith reads exactly one policy
file and its schema has no `extends`/`import`, so natively a machine can
have cerberus's rules or its own or a team's — never all three. `cerberus
init` merges them:

1. [`policies/tirith/policy.yaml`](../crates/cerberus/policies/tirith/policy.yaml), cerberus's
   embedded base
2. `${XDG_CONFIG_HOME:-$HOME/.config}/cerberus/tirith/*.yaml` — your own
   fragments, the risk head's counterpart to dropping a `.rhai` file into
   the rules directory. No rebuild, and `init` never touches them
3. each configured source's `tirith/*.yaml`, with rule ids prefixed by the
   source name so two teams can both ship a `no-force-push`

**A layer can tighten the posture but never loosen it.** `fail_mode`,
`allow_bypass_env_noninteractive`, and `schema_version` come from cerberus's
base and nowhere else — a layer setting one is reported and ignored — and
`paranoia` merges as a maximum. A fragment that won't parse is skipped
rather than fatal, so cerberus's own rules keep enforcing regardless.

## Verifying an injected rule actually fires

The tiering trap below applies to **every** layer, not just cerberus's own,
and it is the thing most likely to bite you: a rule can validate cleanly,
install correctly, and still never run. A rule may therefore declare
`examples_bad:` — commands it is supposed to catch — and `cerberus source
add`/`sync` runs each through the real `tirith check` against the real
composed policy, warning about any rule that never fires:

```
warning: rule 'team-no-uninstalling-ripgrep' did not fire for any of its own
examples_bad. ... It is installed, but it is not enforcing anything.
```

Rules that declare no examples aren't reported — cerberus has no way to
guess a command that ought to trip them — so declaring one is the difference
between a rule you've checked and a rule you're hoping about.

Only one custom rule ships in cerberus's base, not several — a hard-won
constraint, not a
choice. `tirith check` (what `risk` actually calls) only evaluates
`custom_rules` once tirith's own built-in tier-1 detections have already
escalated analysis past tier 1; a pattern with no overlap in tirith's own
~150 built-in categories (an early draft targeted nested
`--dangerously-skip-permissions` sessions and `git --no-verify`) never gets
evaluated in production at all, even though `tirith rule test` reports it
firing — that command tests a named rule directly, bypassing tirith's own
tiering entirely, and is not equivalent to what `guard` actually runs.
Verify any future addition here against real `tirith check` output, not
just `tirith rule test`; see [CONTRIBUTING.md](../CONTRIBUTING.md).

- **cerberus-guard-self-tamper**. Removing cerberus's, tirith's, or
  cupcake's own configuration, or uninstalling their binaries. Survives
  specifically because `rm -rf`/`*-uninstall` commands already trip one of
  tirith's own built-in categories, escalating analysis regardless of
  severity/paranoia filtering. Tirith-side counterpart to CERB-POL-004 —
  this is `health`'s canary for the risk head's overlay content.

Per-session deny counts are written to
`${XDG_STATE_HOME:-$HOME/.local/state}/guard/violations-<session_id>.state`
for [pharos](https://github.com/ahokinson/pharos)'s statusline to read,
keyed by head name (`risk`/`policy`/`judgement`).
