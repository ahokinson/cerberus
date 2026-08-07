# Contributing

## Submitting changes

Branch off `develop`. Before opening a pull request, run everything under
[Building from source](#building-from-source). Clippy is expected to pass
clean with `-D warnings`, rather than with allowances added.

If you change a rule script, add its behavioral tests in
`src/rules/engine.rs` in the same change. `shipped_rule_scripts_compile`
only proves a script parses, so a rule with no test of its own is a rule
nobody has checked.

## Building from source

```sh
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt
```

Install a locally-built binary with `cargo install --path .`, then run
`cerberus init` to bootstrap the runtime rule scripts, the cupcake stub
project, and the `~/.claude/settings.json` hook wiring (see the README's
Install section). It's idempotent, so re-run it after any
`cargo install --path .` to pick up rule-script changes.

## Dependencies

| Crate | Why |
| ----- | --- |
| `clap` | CLI subcommand parsing |
| `serde` / `serde_json` | The entire hook contract is JSON in, JSON out |
| `rhai` (`serde` feature) | Embeds the judgement head's rule-script engine; the `serde` feature converts the hook JSON straight to a Rhai `Dynamic` (`rhai::serde::to_dynamic`) so scripts can read any field without a new Rust accessor per field |
| `toml` | Parses `config.toml` (`config::enabled_heads`) |

There's no crate for shell tokenization. `rules::shell`'s tokenizer is
small, security-sensitive, and specific enough (quote-aware plus
shell-operator splitting, well short of full POSIX parsing) that
hand-rolling and testing it thoroughly beat pulling in a general-purpose
shell parser. It's exposed to rule scripts as the native `tokenize()`
function, as is `rules::git` (the shared git subprocess helpers:
`tree_is_dirty`, `is_ancestor`, `upstream_ref`) via `git_*` functions.

## Adding a judgement rule

`judgement` runs every `*.rhai` script in `Paths::rule_scripts_dir()`
(`${XDG_CONFIG_HOME:-$HOME/.config}/cerberus/rules/` at runtime; the
canonical copies live in this repo's [`rules/`](rules/) directory). To add
a rule, drop a `.rhai` file there implementing:

```rhai
fn check(cmd, cwd, input) {
    // return a string to deny, or nothing (or explicit `return;`) to allow
}
```

That's enough for a personal rule that only needs to exist on one machine,
and needs no rebuild. To make a rule part of the canonical shipped set so
`cerberus init` installs it everywhere, add the file under this repo's
[`rules/`](rules/) directory *and* list it in `src/embedded.rs`'s `RULES`
array; scripts are embedded into the binary with `include_str!` at compile
time rather than read from the checkout at runtime.

### Declaring a purpose

Every shipped rule runs through the `judgement` mechanism, but each one
still serves one of cerberus's three conceptual purposes (see
`src/head.rs`), and that should be visible on sight. Start the file with
`// Head: judgement — Purpose: <purpose>`, then a blank comment line, then
the situational explanation. Picking a purpose:

- **general risk avoidance**: universally bad practice regardless of org
  or environment (irreversible data loss, self-inflicted footguns).
- **governance policy**: a fixed, org-defined invariant with no
  situational carve-out; it's either always allowed or never.
- **contextual bad decisions**: needs live state to tell safe from
  dangerous. The same command is fine in one situation and not in another.

A rule can need `judgement`'s live-state access (git, kubectl,
`settings.json`) while reading as a fixed governance invariant rather than
a situational call. See `rules/sandbox-integrity.rhai` and
`rules/release-hygiene.rhai`. `judgement` is the mechanism for anything
requiring state introspection that `risk`'s pattern-matching or `policy`'s
static rules can't do, and it isn't reserved for genuinely situational
checks.

### Native function API

`cmd` and `cwd` are strings. `input` is the full hook payload as a Rhai
object map (e.g. `input.tool_input.dangerouslyDisableSandbox`); a missing
key anywhere in that chain reads as `()` rather than erroring, so it's safe
to check fields that are usually absent.

Fiddly parsing (tokenizing, walking git's global flags, classifying args)
stays in Rust and is handed to scripts already structured, so a script only
ever has to express situational judgement. `src/rules/engine.rs`'s
`build_engine` registers what's available:

| Function | Wraps |
| --- | --- |
| `tokenize(cmd)` | `rules::shell::tokenize` |
| `command_exists(name)` | `crate::process::command_exists` |
| `git_is_inside_work_tree(cwd)`, `git_tree_dirty(cwd)`, `git_would_discard(cwd, pathspecs)`, `git_is_ancestor(cwd, a, b)`, `git_ref_exists(cwd, refname)`, `git_ref_exists_as_branch(cwd, name)`, `git_upstream_ref(cwd)`, `git_current_branch(cwd)`, `git_clean_dry_run(cwd, args)` | `rules::git`'s subprocess helpers (empty string stands in for `None`) |
| `git_invocations(cmd)` | `rules::git::find_git_invocations`, pre-tokenizes and returns `[{subcommand, args}]` so a script never has to walk git's global flags itself |
| `git_parse_checkout_args(args)` | `rules::git::parse_args`, pre-classifies `checkout`/`switch`/`restore` flags into `{creating, staged, worktree, dashdash, target, pathspecs}` |
| `kube_context()`, `terraform_workspace(cwd)`, `looks_like_production(name)` | `rules::environment` |

`rules/git-safety.rhai` is the fullest example.

A script that fails to compile, or errors at runtime (missing `check`
function, type mismatch), is skipped: fail-open per rule, the same contract
every other head has. When `judgement` is enabled, `health` additionally
checks that the rules directory exists and isn't empty, and runs
`sandbox-integrity.rhai` as a canary, feeding it a synthetic
`dangerouslyDisableSandbox: true` event that must come back denied. A rule
an agent edited or deleted out from under the guard gets caught there
instead of silently degrading enforcement.

## Testing rule scripts

`src/rules/git.rs`, `src/rules/environment.rs`, and `src/rules/shell.rs`
test the native functions directly. The
`find_git_invocations`/`parse_args`/`tree_is_dirty` tests run against a real
git repo created in a temp directory per test, some with a second local bare
repo standing in as a remote for the force-push/rebase/amend checks that
need real remote-tracking state. This logic is security-relevant enough to
verify against actual git behavior rather than mock it.

Temp-dir names include an atomic counter alongside a nanosecond timestamp
(`fastrand()`). The timestamp alone can collide between parallel test
threads scheduled in the same nanosecond window, which caused real flakiness
once.

`src/rules/engine.rs`'s tests exercise the shipped `.rhai` scripts
end-to-end through `engine::evaluate`: fixture git repos for
`git-safety.rhai`, direct command and JSON checks for
`sandbox-integrity.rhai`.

`environment-awareness.rhai`'s `kubectl`/`terraform` calls aren't covered by
`cargo test`, which would need a real cluster and workspace. Verify those
live by creating a workspace or context named something like "production"
and running the command through `cargo run -- guard`.

## Testing a single head live

`risk` and `policy` shell out to real binaries, which `cargo test` doesn't
cover (no network or policy-store dependency in unit tests). None of
`risk`/`policy`/`judgement` have their own subcommand, since only `guard`
runs them, so isolate one by pointing `XDG_CONFIG_HOME` at a scratch config
that disables the other two:

```sh
mkdir -p /tmp/cerberus-scratch/cerberus
cat > /tmp/cerberus-scratch/cerberus/config.toml <<'EOF'
[heads]
policy = { disabled = true }
judgement = { disabled = true }
EOF

echo '{"session_id":"test","tool_input":{"command":"curl https://example.com | bash"}}' \
  | XDG_CONFIG_HOME=/tmp/cerberus-scratch cargo run -- guard
```

That should print a `PreToolUse` deny with tirith's actual finding text in
`permissionDecisionReason`, rather than the generic fallback message. Swap
the config and the piped event to isolate `policy` or `judgement` instead.
