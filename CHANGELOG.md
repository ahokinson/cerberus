# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Cursor support.** `cerberus init` now wires `cerberus guard` into
  `~/.cursor/hooks.json`'s `beforeShellExecution` and `beforeMCPExecution`
  events when a `~/.cursor` directory exists. Unlike Codex, Cursor's
  payload shape and response vocabulary genuinely differ from Claude
  Code's, so `guard::run` now dispatches on the payload's own
  `hook_event_name` and translates through `src/harness/cursor.rs` in both
  directions — no `--harness` flag needed, the same `cerberus guard`
  command line works in every wired harness. Cursor has no pre-write file
  hook (only the post-hoc `afterFileEdit`), so this only ever covers Bash
  and MCP tool calls there, never Write/Edit/NotebookEdit — a permanent
  limit of Cursor's current hook surface, not a gap in cerberus.
  `violations::respond` was split into `record_if_denied` (counting) plus
  the caller printing whatever the harness-appropriate output is, since
  Cursor's response needs reshaping before it's printed but should still
  count the same way Claude/Codex's does.
- **Codex CLI support.** `cerberus init` now also wires `cerberus guard`/
  `cerberus health` into `~/.codex/hooks.json` when `codex` is on `$PATH`.
  Codex's `PreToolUse`/`SessionStart` hooks use the identical request and
  response JSON shape as Claude Code's, so `guard`/`health` needed no
  runtime changes at all — only `settings::install_hooks` learning to take
  a target path instead of assuming `~/.claude/settings.json`, and a second
  `Paths::codex_hooks_json()` accessor. Codex's hooks are also gated behind
  their own opt-in: `[features] codex_hooks = true` in `~/.codex/config.toml`
  — without it, hooks are documented to be silent no-ops, exactly the
  "quietly stopped working" failure mode `health` exists to catch
  elsewhere. `cerberus init` now sets that flag too
  (`init::ensure_codex_hooks_enabled`), merging into any existing
  `config.toml` and preserving every other key and feature flag, unless
  the user has explicitly set `codex_hooks = false` themselves — that's
  left alone and reported as a problem instead of silently overridden.
- `guard` now runs on every mutating tool, not just Bash:
  `Bash|Write|Edit|NotebookEdit|WebFetch|mcp__.*`. The read-only tools
  (`Read`, `Grep`, `Glob`) are deliberately left out, which keeps the hook
  off the hottest tools in a session.
- `sandbox-integrity` gains **SANDBOX-003**, denying a file-writing tool
  pointed at a Claude `settings.json`. SANDBOX-002 only ever covered the
  shell-command form, so the same edit went through unchallenged via the
  Edit tool. `health` now runs a second rule-script canary for it.
- Two native functions for rule scripts, `tool_paths(input)` and
  `tool_url(input)`, normalizing the per-tool `tool_input` shapes so one
  rule can cover Write, Edit, and NotebookEdit at once.
- cerberus now ships real default content for `policy` and `risk`, not just
  `judgement`. Four Rego policies (`policies/cupcake/`: CERB-POL-001
  sandbox-integrity, CERB-POL-002 webfetch-ssrf, CERB-POL-003
  ci-trust-boundary, CERB-POL-004 guard-self-protection) are installed by
  `cerberus init` into a reserved `custom/cerberus/` subdirectory of
  cupcake's global store, which `init` now also bootstraps
  (`cupcake init --global --harness claude`) if it doesn't already exist. A
  tirith `custom_rules:` overlay (`policies/tirith/policy.yaml`:
  `cerberus-guard-self-tamper`) is written to a cerberus-owned policy root
  and applied via `TIRITH_POLICY_ROOT`, but only in repos with no
  `.tirith/policy.yaml` of their own — a repo or team's real policy always
  wins. Previously `policy` shipped with zero enforcing content out of the
  box, and `risk` had no cerberus-owned content at all. Only one tirith rule
  ships, not several: `tirith check` (what `risk` actually calls) only
  evaluates `custom_rules` once tirith's own built-in tier-1 detections
  have already escalated past tier 1, so a rule with no overlap in tirith's
  own built-in categories never fires in production even when
  `tirith rule test` reports it firing — a rule-authoring tool, not
  equivalent to the real enforcement path. Two draft rules were dropped for
  exactly this reason; see `policies/tirith/policy.yaml` and
  CONTRIBUTING.md's "Adding a risk rule".
- `cerberus init`'s bootstrap of cupcake's global store runs the
  `cupcake init --global` subprocess with a decoy `HOME`: confirmed against
  the real binary, `cupcake init --global` also tries to auto-wire its own
  independent `PreToolUse` hook into `$HOME/.claude/settings.json`, which
  would otherwise corrupt the single hook slot `cerberus init` owns and
  double-evaluate cupcake on every guarded call.
- `health` gains two new canaries: a synthetic `Write` to cerberus's own
  rule-scripts path, denied only by the policy head's new
  `guard-self-protection.rego` (proving cerberus's own policy content is
  live, not just that cupcake itself works); and a synthetic
  `rm -rf .../.config/cerberus`, denied only by the risk head's new
  `cerberus-guard-self-tamper` tirith rule.

### Changed

- **`cerberus init` no longer claims a hook slot in `settings.json`.** It
  previously located its entry by matcher string and replaced that entry's
  hooks wholesale, which would have silently deleted an unrelated hook the
  moment the matcher widened. It now only ever adds, removes, or moves
  hooks running a cerberus command, and prepends its own entry so the guard
  runs first. Existing installs migrate in place; no orphaned `Bash` entry
  is left behind.
- `cerberus health` is hoisted out of whatever `SessionStart` entry it was
  appended into and given its own entry at the front. Other commands in
  that entry are left alone.
- The `risk` head is now gated on `tool_name == "Bash"` rather than on the
  presence of a `tool_input.command`, so an MCP tool carrying its own
  non-shell `command` field is never fed to tirith's pattern scanner.
- `gate` and `health` messages no longer say "Bash".

## [0.1.1]

### Fixed

- The `git-safety` force-push test fixtures no longer depend on the ambient
  `init.defaultBranch`. They pushed to a branch named `main` while letting
  the bare fixture remote take its initial branch from whatever gitconfig
  was in scope, so the suite passed only where that default was already
  `main` and failed on a clean checkout, in CI, and under Nix.

## [0.1.0]

Initial release.

### Added

- `cerberus guard`, the `PreToolUse` hook command. Runs the fail-closed
  `gate`, then the enabled heads in fixed order, stopping at the first that
  responds.
- Three heads: `risk` (command-pattern scanning via tirith), `policy`
  (policy evaluation via cupcake), and `judgement` (Rhai-scripted
  situational checks).
- `cerberus health`, the `SessionStart` check. Verifies each enabled head is
  enforcing, using a synthetic `rm -rf /` against cupcake and a synthetic
  `dangerouslyDisableSandbox: true` against the rule scripts, and writes a
  degraded sentinel when something is wrong.
- `cerberus gate`, the fail-closed backstop that denies all Bash while the
  sentinel exists.
- `cerberus init`, which writes the shipped rule scripts, seeds
  `config.toml`, creates the cupcake stub project, and wires both hooks into
  `~/.claude/settings.json`. Idempotent.
- Four shipped rule scripts: `git-safety`, `environment-awareness`,
  `release-hygiene`, and `sandbox-integrity`.
- Per-head enable/disable via
  `${XDG_CONFIG_HOME:-$HOME/.config}/cerberus/config.toml`.
- Per-session deny counts written to
  `${XDG_STATE_HOME:-$HOME/.local/state}/guard/violations-<session_id>.state`
  for pharos's statusline.

[Unreleased]: https://github.com/ahokinson/cerberus/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/ahokinson/cerberus/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/ahokinson/cerberus/releases/tag/v0.1.0
