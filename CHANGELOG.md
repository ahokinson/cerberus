# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **cerberus owns its runtime layout, and no longer touches your cupcake
  install.** Everything cerberus creates now lives under a single
  `cerberus/` namespace: `$XDG_DATA_HOME/cerberus/{cupcake,tirith,
  cupcake-init-home}` and `$XDG_CONFIG_HOME/cerberus/{rules,tirith,cupcake}`.
  The three former top-level directories (`cupcake-stub/`,
  `cerberus-tirith-overlay/`, `cupcake-global-init-home/`) are removed by
  `cerberus init`, reported by name.

  Two of those names existed only as workarounds. `cupcake eval` takes
  `--policy-dir`, so cerberus no longer runs it with `current_dir` set to a
  stub project to satisfy cwd-based discovery; and it takes
  `--global-config`, so cerberus's policies live in a store it owns
  (`$XDG_CONFIG_HOME/cerberus/cupcake/`) instead of being written into the
  user's `~/.config/cupcake` behind a reserved `custom/cerberus/`
  subdirectory. That reservation existed purely to avoid colliding with a
  user's own onboarded policies; with a store of its own there is nothing to
  collide with, so the policies sit at `policies/claude/cerberus/`. The
  `claude/` segment stays because it is cupcake's addressing — the global
  phase scans `policies/<harness>/` and only that, so a policy outside it is
  never evaluated — and it matches the `--harness claude` cerberus passes
  deliberately, every harness's payload having been normalized into Claude's
  wire format at the edge.

  Both flags were verified against cupcake 0.5.2, where `--help` is
  misleading on each: `--policy-dir` wants the project root's `.cupcake`
  directory rather than the `policies` directory inside it (cupcake derives
  the root as its parent), and `--global-config` is documented as a "file
  path" but must be an existing absolute directory — and is honored by
  `eval` while being silently ignored by `verify`/`inspect`. Getting either
  wrong fails open, so `shipped_cupcake_policies_evaluate_correctly_end_to_end`
  now runs through the real `cupcake::evaluate` instead of re-implementing
  the subprocess call, and asserts the store lands where the redirect
  intends. `cupcake init` still scaffolds both locations rather than
  cerberus writing them from embedded content: it produces
  `policies/claude/system/evaluate.rego`, the WASM entrypoint the engine
  compiles against, and a hand-rolled copy would pin cerberus to one cupcake
  version and turn a cupcake upgrade into a silently degraded policy head.

  `guard-self-protection.rego` and `cerberus-guard-self-tamper` both key on
  directory names, so both were updated; the collapse to one namespace made
  each simpler rather than longer.

### Added

- **Custom tirith rules, injected through cerberus.** tirith reads exactly
  one policy file and its schema has no `extends`/`import`, so natively a
  machine can have cerberus's rules or its own or a team's — never all
  three. `cerberus init` now *composes* the overlay
  (`src/integrations/tirith/compose.rs`) from cerberus's embedded base, the
  user's own `$XDG_CONFIG_HOME/cerberus/tirith/*.yaml` fragments (the risk
  head's counterpart to dropping a `.rhai` file into the rules directory),
  and every configured source's, rather than writing one embedded blob.

  A layer can tighten the posture but never loosen it: `fail_mode`,
  `allow_bypass_env_noninteractive`, and `schema_version` come from the base
  and a layer setting one is reported and ignored, while `paranoia` merges
  as a maximum. A fragment that won't parse is skipped rather than fatal, so
  cerberus's own rules — and `health`'s canary — survive anything a fragment
  contains. Output is deterministic because `init`, `source sync`, and the
  guard-time self-heal all regenerate the file independently and have to
  agree; the self-heal recomposes rather than rewriting a fixed blob, which
  would otherwise silently strip a team's rules for the rest of a session.

- **Sources cover all three heads, and load from a GitHub slug.** A source
  repo may now carry `tirith/*.yaml` alongside `rules/*.rhai` and
  `policies/*.rego`; `add`/`sync`/`remove` install it and recompose the
  overlay, with each source's rule ids prefixed by the source name so two
  teams can both ship a `no-force-push`. `cerberus source add
  ahokinson/cerberus-rules` now works — a GitHub `owner/repo` slug or a
  `gh:`/`github:` prefix expands to a URL, and the source is named after the
  repository unless `--name` says otherwise. The two-argument
  `add <name> <git-url>` form is unchanged. `add`/`sync`/`list` report
  per-head counts.

- **Injected tirith rules are checked for whether they can actually fire.**
  `tirith check` only consults `custom_rules` once tirith's own built-in
  detections have escalated a command past tier 1, so a rule matching
  nothing tirith already finds interesting never runs in production — even
  though `tirith rule validate` accepts it and `tirith rule test` reports it
  firing. That trap cost this project two of its own three original rules;
  layering makes it far worse, since a source can ship any number and
  "cerberus installed your team's rules and they enforce nothing" is exactly
  the silent failure the rest of this design exists to prevent. A rule may
  now declare `examples_bad:`, and `source add`/`sync` run each through the
  real `tirith check` against the real composed policy
  (`tirith::rules_that_never_fire`, attributing findings via tirith's
  `custom_rule_id`), warning about any rule that never fires. Rules without
  examples aren't reported as broken, just unverified.

### Fixed

- **The risk head never self-healed its own overlay.** `evaluate`/`health`
  required `tirith_overlay_policy_file().is_file()` before ever trying to
  use or verify it — a totally missing overlay silently skipped cerberus's
  own rules with no error, and a present-but-broken one (a symlink into a
  read-only store path, which `tirith` refuses to read and silently falls
  back to its own built-ins only, dropping every custom rule) looked fine
  to that check and stayed broken forever. Both now self-heal: `check`
  reports tirith's own `policy_path_used`, and if it doesn't match the
  overlay file, cerberus rewrites it from `embedded::TIRITH_POLICY` and
  retries once. `write_tirith_overlay` itself also had to change to make
  this safe — `fs::write` follows a symlink to its target rather than
  replacing it, so it now removes whatever's at the path first.
- **`git-safety` judged the wrong repository.** The rule took the working
  directory straight from the hook payload's `cwd`, ignoring `git -C <dir>`
  and any `cd` earlier on the command line, so CONTEXT-001/002 inspected
  whichever repo the agent happened to be sitting in rather than the one the
  command targets. That produced false positives (a clean target repo denied
  because the session's repo was dirty) and, more seriously, false negatives
  (a dirty target repo allowed because the session's repo was clean).
  `find_git_invocations` now records each invocation's `dir` and the script
  resolves it via the new `resolve_dir` before checking, so every invocation
  on a line is judged against the repo it actually runs in.

### Added

- **`opa check` gate on layered policy sources.** `cerberus source
  add`/`sync --yes` now run any `.rego` a source ships through `opa check`
  (`src/sources/mod.rs`'s `check_rego`) before installing anything. A file
  `opa` rejects aborts the whole operation — nothing is installed and
  `config.toml` isn't touched, versus previously surfacing only as a
  `cupcake` error at guard time (or a silently degraded `policy` head). A
  missing `opa` binary skips the check with a warning (`RegoCheck::Skipped`)
  rather than blocking the source, mirroring the rest of cerberus's
  don't-require-a-binary-you-didn't-ask-for stance. This closes the gap
  flagged when layered policy sources first landed (see below): "no
  uniqueness/validity check on team `.rego` package names." Note this is a
  syntax/compile gate, not a semantic one — a deliberately malicious but
  syntactically valid policy (an always-allow rule, say) still parses
  cleanly; see SECURITY.md.
- **Structured audit log.** `[audit] enabled = true` in `config.toml` (off
  by default — see SECURITY.md) records every deny/ask decision as a JSON
  line in `${XDG_STATE_HOME:-~/.local/state}/guard/audit.jsonl` via
  `audit::record`, called from `guard::run` right beside the existing
  `violations::record_if_denied`, reusing the same in-scope `head`/`input`/
  `output`/`is_cursor` rather than re-deriving anything. Each record carries
  a schema version, timestamp, session id, head, tool name, decision,
  reason, the raw `tool_input`, and a `harness` field that can currently
  only distinguish Cursor from everything else (Claude Code, Codex, Hermes,
  and opencode all produce byte-identical hook JSON with no
  harness-identifying field of their own — a real fix needs each harness
  template to set one before invoking `cerberus guard`). `cerberus audit
  tail/summary/export` reads it back — `summary --since <duration>` groups
  counts by head, tool, and the `RULE-ID` extracted from the leading token
  of each deny reason, entirely as an in-process scan (no DB, matching
  `violations::read_counts`'s existing scale). The log rotates once at
  10 MiB (a single `.1` generation, no background process). Off-by-default
  and fail-closed-on-config-error, deliberately the opposite direction from
  the heads' fail-open-to-enabled default: this is the first feature where
  cerberus persists real command/tool-input text, which can carry inline
  secrets, to disk.
- **Layered policy sources.** `cerberus source add/remove/list/sync` (new
  `src/sources/` module) let a named external git repo of `rules/*.rhai`
  and/or `policies/*.rego` stack on top of a machine's personal rules —
  turning cerberus from a per-developer tool into one a team can share a
  policy source for. `add` clones into
  `${XDG_CACHE_HOME:-~/.cache}/cerberus/sources/<name>/`, resolves `--ref`
  (or the remote's default branch via `origin/HEAD`) to a commit, installs
  into `rules/sources/<name>/` and cupcake's global store under
  `custom/cerberus/sources/<name>/` (nested inside cerberus's own reserved
  subtree, so `guard-self-protection.rego`'s existing self-tamper regex
  covers it for free), and pins the resolved SHA in a new `[[sources]]`
  array-of-tables in `config.toml`. `rules::evaluate` checks each
  configured source's directory as an additive OR-of-denials layer after
  the top-level rules, via the same `engine::evaluate` unmodified — a
  machine with no sources configured pays zero cost, since that function
  already returns `None` on a missing directory. Trust model: a plain
  `cerberus init`/`cerberus guard` never touches the network, only `source
  sync` does, and applying an update always requires `--yes` — without it,
  `sync` only fetches and prints the pending commit log and a diffstat
  scoped to `rules/`/`policies/`. `config.rs` gained a typed
  deserialize-mutate-reserialize write path (`upsert_source`/
  `remove_source`) for `config.toml`, a deliberate departure from
  `init::ensure_codex_hooks_enabled`'s generic-`toml::Value` patch: simpler
  and type-safe, at the accepted cost of dropping comments and any
  unmodeled top-level key on a write (acceptable here since, unlike Codex's
  shared config file, this one is cerberus's own). A source `name` is
  restricted to a safe slug before ever being joined into a path, since a
  hand-edited `config.toml` is untrusted input the same way any other
  external content cerberus reads is.
- **opencode support.** `cerberus init` writes a single TypeScript plugin
  (`harness-templates/opencode/cerberus-guard.ts`, embedded as
  `embedded::OPENCODE_PLUGIN`) into `~/.config/opencode/plugin/` when
  `opencode` is on `$PATH`. opencode plugins run in-process rather than as
  a subprocess given JSON on stdin, so the plugin's `tool.execute.before`
  hook shells out to the real `cerberus guard` binary via Bun's `$` shell,
  piping stdin through `new Response(payload)` since Bun's `$` has no
  `.stdin()` method. opencode has no per-tool matcher of its own, so the
  plugin carries its own allowlist (`bash`/`edit`/`write`/`webfetch` →
  `Bash`/`Edit`/`Write`/`WebFetch`), the job `GUARD_MATCHER` does
  elsewhere. Its argument field names are camelCase (`filePath`); the
  plugin remaps them to the snake_case shape (`file_path`) every rule
  expects. Verified against the real `cerberus` binary via Bun, including
  a synthetic `edit` on a Claude `settings.json` that correctly triggers
  SANDBOX-003 through the remap, though the plugin API itself is a best
  effort against opencode's docs, not exhaustively confirmed for every
  built-in tool's argument shape.
- **Hermes Agent support.** `cerberus init` writes a small Python plugin
  (`harness-templates/hermes/`, embedded as `embedded::HERMES_PLUGIN`)
  into `~/.hermes/plugins/cerberus/` when `hermes` is on `$PATH`. Hermes's
  best-documented integration point is an in-process Python
  `pre_tool_call` callback, not a subprocess given JSON on stdin like
  Claude Code, Codex CLI, and Cursor. (Hermes also has a config.yaml-driven
  shell-hook path, but its stdin/stdout contract isn't documented
  anywhere, so cerberus targets the Python path instead.) The plugin
  shells out to the real `cerberus guard` binary and translates both
  directions; `guard`/`health` needed no changes. Hermes's registry has
  around 86 tools with no per-tool matcher of its own, so the plugin
  carries a `GUARDED_TOOLS` allowlist mapping the handful cerberus guards
  (`terminal`, `write_file`, `patch`) to their canonical
  `Bash`/`Write`/`Edit` names, confirmed from Hermes's own tools
  reference. `process` is excluded since its argument shape isn't
  confirmed to be a real shell command, and `tool_input` is passed through
  unchanged rather than guessing at a field-name remap. The plugin's
  manifest follows Hermes's documented plugin-discovery format but hasn't
  been checked against the real binary; `cerberus init` says so and points
  at `hermes doctor`.
- **Cursor support.** `cerberus init` wires `cerberus guard` into
  `~/.cursor/hooks.json`'s `beforeShellExecution` and `beforeMCPExecution`
  events when a `~/.cursor` directory exists. Cursor's payload shape and
  response vocabulary differ from Claude Code's, so `guard::run` now
  dispatches on the payload's own `hook_event_name` and translates both
  directions through `src/harness/cursor.rs`. No `--harness` flag is
  needed: the same `cerberus guard` command line works in every wired
  harness. Cursor has no pre-write file hook, only the post-hoc
  `afterFileEdit`, so this covers Bash and MCP calls only, never
  Write/Edit/NotebookEdit, a permanent limit of Cursor's hook surface,
  not a gap in cerberus. `violations::respond` was split into
  `record_if_denied` (counting) plus the caller printing whatever output
  the harness needs, since Cursor's response needs reshaping before
  printing but should still count the same way Claude/Codex's does.
- **Codex CLI support.** `cerberus init` also wires `cerberus guard`/
  `cerberus health` into `~/.codex/hooks.json` when `codex` is on `$PATH`.
  Codex's `PreToolUse`/`SessionStart` hooks use the identical request and
  response shape as Claude Code's, so `guard`/`health` needed no runtime
  changes, only `settings::install_hooks` taking a target path instead of
  assuming `~/.claude/settings.json`, and a second
  `Paths::codex_hooks_json()` accessor. Codex's hooks are also gated
  behind their own opt-in, `[features] codex_hooks = true` in
  `~/.codex/config.toml`; without it, hooks are documented to be silent
  no-ops, the same "quietly stopped working" failure mode `health` exists
  to catch elsewhere. `cerberus init` now sets that flag too
  (`init::ensure_codex_hooks_enabled`), merging into any existing
  `config.toml` and preserving every other key and feature flag unless the
  user set `codex_hooks = false` explicitly, in which case it's left alone
  and reported as a problem instead.
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
