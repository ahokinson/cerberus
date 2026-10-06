# Installing

## Requirements

Building needs Rust 1.88 or newer. Two of the three heads shell out to
binaries you have to install yourself:

| Head | Needs | Where to get it |
| --- | --- | --- |
| `risk` | `tirith` | [sheeki03/tirith](https://github.com/sheeki03/tirith) |
| `policy` | `cupcake` and `opa` | [eqtylab/cupcake](https://github.com/eqtylab/cupcake), [openpolicyagent.org](https://www.openpolicyagent.org/docs/latest/#running-opa) |
| `judgement` | nothing beyond cerberus | n/a |

If a head is enabled but its binary is missing, `health` marks the guard
degraded at the next `SessionStart` and `gate` then denies **every guarded
tool** until it's fixed. That's deliberate: under `bypassPermissions` these
heads are the only thing between the agent and your machine, so a guard that
has quietly stopped working is worse than no guard. The read-only tools are
outside the matcher and keep working, so the agent can still read enough to
explain what broke. Install the binaries, or turn the head off in
`config.toml`.

## Install

```sh
git clone https://github.com/ahokinson/cerberus
cd cerberus
cargo install --path crates/cerberus
cerberus init
```

`cerberus init` bootstraps everything the guard needs and is safe to
re-run:

- writes the shipped [`rules/*.rhai`](../crates/cerberus/rules/) scripts into
  `${XDG_CONFIG_HOME:-$HOME/.config}/cerberus/rules/`
- seeds a default `config.toml` if one doesn't already exist, and never
  touches an existing one
- creates a cupcake project (`cupcake init --harness claude`) at
  `${XDG_DATA_HOME:-$HOME/.local/share}/cerberus/cupcake/` if `cupcake` is
  on `$PATH` and it doesn't already exist
- bootstraps **cerberus's own** cupcake store at
  `${XDG_CONFIG_HOME:-$HOME/.config}/cerberus/cupcake/` if it doesn't
  already exist, and writes the shipped
  [`policies/cupcake/*.rego`](../crates/cerberus/policies/cupcake/) into its
  `policies/claude/cerberus/` directory — always refreshed. **cerberus never
  reads or writes your own `~/.config/cupcake`.** Both locations are passed
  to `cupcake eval` explicitly (`--policy-dir`, `--global-config`), so
  nothing depends on the working directory or an inherited `XDG_CONFIG_HOME`
- creates `${XDG_CONFIG_HOME:-$HOME/.config}/cerberus/tirith/` for your own
  tirith rule fragments, and never writes into it
- composes the tirith overlay — the shipped
  [`policies/tirith/policy.yaml`](../crates/cerberus/policies/tirith/) base plus your fragments
  plus every configured source's — into a cerberus-owned tirith policy root,
  always refreshed
- removes the directories earlier versions created at the top level of
  `$XDG_DATA_HOME` (`cupcake-stub/`, `cerberus-tirith-overlay/`,
  `cupcake-global-init-home/`), reporting each by name
- wires the hooks into `~/.claude/settings.json`, idempotently. **cerberus
  owns no hook slot.** The only hooks it will ever add, move, or remove are
  ones running `cerberus guard` or `cerberus health`; it puts each at the
  front of its event so the guard runs first, and leaves every other hook
  exactly where it found it — including one that happens to share a matcher
- wires the same hooks into `~/.codex/hooks.json` if `codex` is on `$PATH`,
  with the identical remove-then-prepend idempotency guarantee, and sets
  `[features] codex_hooks = true` in `~/.codex/config.toml` (Codex's hooks
  are silent no-ops without it), preserving every other key already there
- wires `cerberus guard` into `~/.cursor/hooks.json`'s
  `beforeShellExecution` and `beforeMCPExecution` events if a `~/.cursor`
  directory exists. Cursor's own hooks are additive across scope layers,
  so this only ever adds cerberus's entry, never touching anyone else's
- writes the shipped [`templates/hermes/`](../crates/cerberus/templates/hermes/)
  plugin into `~/.hermes/plugins/cerberus/` if `hermes` is on `$PATH`,
  always refreshed
- writes the shipped
  [`templates/opencode/cerberus-guard.ts`](../crates/cerberus/templates/opencode/)
  plugin into `~/.config/opencode/plugin/` if `opencode` is on `$PATH`,
  always refreshed

It finishes with a per-head summary of what's ready: tirith on `$PATH` and
whether the overlay was written and how many rules composed into it, the
cupcake project/store and `opa` and how many of cerberus's own policies are
installed, and the rule script count. Anything it couldn't do is reported and the exit code is non-zero,
but it doesn't error out. That matches how the heads themselves behave.
