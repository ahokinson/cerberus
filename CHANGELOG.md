# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **opencode support.** `cerberus init` now writes a single TypeScript
  plugin (`harness-templates/opencode/cerberus-guard.ts`, embedded as
  `embedded::OPENCODE_PLUGIN`) into `~/.config/opencode/plugins/` when
  `opencode` is on `$PATH`. Like Hermes, opencode plugins run in-process
  rather than as a subprocess given JSON on stdin — here an in-process
  `tool.execute.before` TypeScript hook that shells out to the real
  `cerberus guard` binary via Bun's `$` shell (piping stdin through
  `new Response(payload)`, since Bun's `$` has no dedicated `.stdin()`
  method). Unlike the other three harnesses, opencode has no per-tool
  matcher of its own — the hook fires for every tool call — so the plugin
  carries its own allowlist (`bash`/`edit`/`write`/`webfetch` →
  `Bash`/`Edit`/`Write`/`WebFetch`) doing the job `GUARD_MATCHER` does
  elsewhere. opencode's own tool-arg field names are camelCase
  (`filePath`); the plugin remaps them to the snake_case shape
  (`file_path`) every existing rule already expects. Verified end-to-end
  against the real `cerberus` binary via Bun, including a synthetic `edit`
  on a Claude `settings.json` correctly triggering SANDBOX-003 through the
  camelCase remapping — though the plugin API details themselves are
  cerberus's best effort against opencode's docs, not exhaustively
  confirmed for every built-in tool's argument shape.
- **Hermes Agent support.** `cerberus init` now writes a small Python
  plugin (`harness-templates/hermes/`, embedded as
  `embedded::HERMES_PLUGIN`) into `~/.hermes/plugins/cerberus/` when
  `hermes` is on `$PATH`. Hermes's best-documented integration surface is
  an in-process Python `pre_tool_call` callback, not a subprocess/stdin
  contract like Claude Code, Codex CLI, and Cursor — Hermes does have a
  config.yaml-driven shell-hook path too, but its exact stdin/stdout
  contract isn't documented anywhere, so cerberus targets the Python path
  instead. The whole adapter lives in the plugin itself, which shells out
  to the real `cerberus guard` binary and translates both directions;
  `cerberus guard`/`cerberus health` needed zero changes. Hermes's registry
  has around 86 tools with no per-tool matcher of its own, so the plugin
  carries a `GUARDED_TOOLS` allowlist mapping the handful cerberus guards
  (`terminal`, `write_file`, `patch`) to their canonical
  `Bash`/`Write`/`Edit` names, confirmed from Hermes's own tools reference
  — deliberately excluding tools like `process` whose argument shape isn't
  confirmed to be a real shell command, and passing `tool_input` through
  unchanged rather than guessing at a field-name remap. The plugin's
  manifest is a best effort against Hermes's documented plugin-discovery
  conventions, not verified against the real `hermes-agent` binary —
  `cerberus init` says so explicitly and points at `hermes doctor`.
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

- **`cerberus init` no longer wires Claude Code unconditionally.** It now
  checks `command_exists("claude")` first, matching the detection gate
  Codex/Hermes/opencode already use, and skips `settings.json` (with a
  message, not an error) when Claude Code isn't on `$PATH`. It previously
  wrote `~/.claude/settings.json` regardless of whether Claude Code was
  present, the one harness not already following its own rule.
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
