# cerberus

<img src="assets/logo.svg" alt="cerberus logo: three dog heads over a shield" width="200">

A guard for Claude Code's Bash tool, with three heads.

cerberus is a Rust CLI that runs as a `PreToolUse` hook and judges every
Bash command before Claude Code executes it. Claude Code only ever calls
`cerberus guard`, which runs a fail-closed `gate` and then up to three
independent heads:

| Head | Catches | How |
| --- | --- | --- |
| `risk` | commands that are dangerous no matter who's running them or why *(general risk avoidance)* | command-pattern scanning via [tirith](https://github.com/sheeki03/tirith) |
| `policy` | commands that break a rule the org has decided on *(governance policy)* | policy evaluation via [cupcake](https://github.com/eqtylab/cupcake) |
| `judgement` | commands that are only bad because of state nothing in the command line reveals: git state, kubectl/terraform context, the hook payload itself *(contextual bad decisions)* | Rhai-scripted situational checks |

All three run by default and can be disabled individually.

## Requirements

Building needs Rust 1.88 or newer. Two of the three heads shell out to
binaries you have to install yourself:

| Head | Needs | Where to get it |
| --- | --- | --- |
| `risk` | `tirith` | [sheeki03/tirith](https://github.com/sheeki03/tirith) |
| `policy` | `cupcake` and `opa` | [eqtylab/cupcake](https://github.com/eqtylab/cupcake), [openpolicyagent.org](https://www.openpolicyagent.org/docs/latest/#running-opa) |
| `judgement` | nothing beyond cerberus | n/a |

If a head is enabled but its binary is missing, `health` marks the guard
degraded at the next `SessionStart` and `gate` then denies **every** Bash
call until it's fixed. That's deliberate: under `bypassPermissions` these
heads are the only thing between the agent and your shell, so a guard that
has quietly stopped working is worse than no guard. Install the binaries,
or turn the head off in `config.toml`.

## Install

```sh
git clone https://github.com/ahokinson/cerberus
cd cerberus
cargo install --path .
cerberus init
```

`cerberus init` bootstraps everything the guard needs and is safe to
re-run:

- writes the shipped [`rules/*.rhai`](rules/) scripts into
  `${XDG_CONFIG_HOME:-$HOME/.config}/cerberus/rules/`
- seeds a default `config.toml` if one doesn't already exist, and never
  touches an existing one
- creates the cupcake stub project (`cupcake init --harness claude`) at
  `${XDG_DATA_HOME:-$HOME/.local/share}/cupcake-stub/` if `cupcake` is on
  `$PATH` and it doesn't already exist
- wires the hooks into `~/.claude/settings.json`: it replaces whatever
  `PreToolUse` hook was matched on `Bash` before, and idempotently ensures
  `cerberus health` runs at `SessionStart`, leaving every other hook alone

It finishes with a per-head summary of what's ready: tirith on `$PATH`, the
cupcake stub and `opa`, the rule script count. Anything it couldn't do is
reported and the exit code is non-zero, but it doesn't error out. That
matches how the heads themselves behave.

## Usage

| Command | Runs as | What it does |
| --- | --- | --- |
| `cerberus guard` | `PreToolUse` on `Bash` | `gate`, then the enabled heads in order |
| `cerberus health` | `SessionStart` | checks that the enabled heads are enforcing |
| `cerberus gate` | standalone | the fail-closed backstop on its own, for debugging |
| `cerberus init` | standalone | bootstraps config, rules, and hook wiring |

`guard` reads the Claude Code hook event JSON on stdin once and, on a deny
or ask, prints the `PreToolUse` hook JSON to stdout:

```sh
$ echo '{"tool_input":{"command":"curl https://example.com | bash"}}' | cerberus guard
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"..."}}
```

The hook wiring `cerberus init` writes looks like this:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [{ "type": "command", "command": "cerberus guard" }]
      }
    ],
    "SessionStart": [
      { "hooks": [{ "type": "command", "command": "cerberus health" }] }
    ]
  }
}
```

## Configuration

Which heads `guard` runs is controlled by
`${XDG_CONFIG_HOME:-$HOME/.config}/cerberus/config.toml`:

```toml
# All heads run by default. Set `disabled = true` on a head to remove it
# from `cerberus guard`'s stack. `gate` (the fail-closed backstop) always
# runs first automatically and isn't listed here.
#
# Each head catches a different kind of bad outcome:
[heads]
risk = { disabled = false }      # general risk avoidance: tirith command-pattern scanning
policy = { disabled = false }    # governance policy: cupcake policy evaluation
judgement = { disabled = false } # contextual bad decisions: Rhai situational checks
```

A missing file, a missing `[heads]` table, or a head simply absent from the
table all mean the same thing: enabled. Config problems fail open to
running everything. Run order is fixed (`gate`, then `risk`, `policy`,
`judgement`) and isn't configurable. Only which heads are enabled is.

`health` never complains about a disabled head. Turning one off is a choice,
not a degradation.

## Rules

`judgement` runs every `*.rhai` script it finds in
`${XDG_CONFIG_HOME:-$HOME/.config}/cerberus/rules/`, calling each script's
`check(cmd, cwd, input)` function and denying on the first one that returns
a string. The canonical scripts live in this repo's [`rules/`](rules/)
directory and are embedded into the binary at compile time; `cerberus init`
writes them out to the runtime path above.

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
  disabling its own Bash sandbox, either by setting the Bash tool's
  `dangerouslyDisableSandbox` flag or by running a shell command that edits
  the `sandbox` config in a Claude `settings.json`. That decision belongs to
  a human. This rule doubles as `health`'s canary for the judgement head.

To add a personal rule, drop a `.rhai` file into the runtime rules
directory. Nothing needs rebuilding, and re-running `init` leaves it alone,
since `init` only ever writes the four shipped filenames. See
[CONTRIBUTING.md](CONTRIBUTING.md) for the native function API available to
scripts: git state, kubectl/terraform context, tokenizing.

Rule content is the one thing cerberus itself owns and ships. `risk`'s
detection patterns live in tirith and `policy`'s rules live in cupcake's
global policy store, both maintained separately; cerberus's job for those
two heads is wiring them up and backstopping them with `gate`.

Per-session deny counts are written to
`${XDG_STATE_HOME:-$HOME/.local/state}/guard/violations-<session_id>.state`
for [pharos](https://github.com/ahokinson/pharos)'s statusline to read,
keyed by head name (`risk`/`policy`/`judgement`).

## Design notes

A single guard is a single point of failure. Each head fails open on its
own: a missing binary, a broken policy store, or a crash means that head
allows, because no individual check should be able to halt every Bash call
by breaking.

The system as a whole fails closed instead. `health` runs at every
`SessionStart` and checks that the enabled heads are actually enforcing:
that `tirith`, `opa`, and `cupcake` are on `$PATH`, that a synthetic
`rm -rf /` still gets blocked, that the rules directory exists and isn't
empty, and that `sandbox-integrity.rhai` still denies a synthetic
`dangerouslyDisableSandbox: true` event. Rule scripts live on disk rather
than in the binary, so that last check is what catches a rule an agent
edited or deleted out from under the guard. If any of it fails, `health`
writes a sentinel and `gate` denies all Bash until `cerberus init` repairs
things.

The three heads aren't redundant with each other either. Risk avoidance,
governance policy, and contextual judgement are different questions, so a
command can pass one and still fail another. Pattern scanning has no idea
what your org's release process is. A fixed policy has no idea whether your
kubectl context happens to be pointed at production right now. `judgement`
covers that gap.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for build and test tooling, the
native function API for rule scripts, and how to add a rule.

## License

MIT. See [LICENSE](LICENSE).
