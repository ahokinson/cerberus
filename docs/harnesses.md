# Harnesses

The three heads have no idea which harness triggered them. Each harness's
own wire format and hook-registration mechanism gets normalized at the
edge, in `cerberus guard` and `cerberus init`; the rules, the policies,
and the tirith overlay all run once, unmodified, no matter where the call
came from. `cerberus init` wires whichever of these are actually
installed, each behind its own detection check, so running it on a
machine without a given harness doesn't touch that harness's files at
all:

- **Claude Code** — `~/.claude/settings.json`, wired if `claude` is on
  `$PATH`. The first harness cerberus supported, and still the shape its
  internal payload is built around.
- **Codex CLI** — `~/.codex/hooks.json`, wired if `codex` is on `$PATH`.
  Codex's `PreToolUse`/`SessionStart` hooks use Claude's exact
  request/response shape (confirmed against OpenAI's own docs), so
  `guard`/`health` run unmodified here too. Codex's hooks are opt-in
  though: `cerberus init` also sets `[features] codex_hooks = true` in
  `~/.codex/config.toml`, since hooks are documented to be silent no-ops
  without it.
- **Cursor** — `~/.cursor/hooks.json`, wired if a `~/.cursor` directory
  exists. `beforeShellExecution`/`beforeMCPExecution` send a real payload
  shape and expect a real response vocabulary (`permission`, not
  `permissionDecision`), so `guard` translates both directions through
  `crates/cerberus/src/harnesses/cursor.rs`, dispatched off the payload's own
  `hook_event_name`, no `--harness` flag needed. Cursor has no pre-write
  file hook, only the post-hoc `afterFileEdit`, so this covers Bash and
  MCP calls only; Write/Edit/NotebookEdit aren't guardable there yet.
- **Hermes Agent** — `~/.hermes/plugins/cerberus/`, wired if `hermes` is
  on `$PATH`. Hermes's best-documented integration point is an in-process
  Python `pre_tool_call` callback rather than a subprocess given JSON on
  stdin, so `cerberus init` writes a small Python plugin
  ([`templates/hermes/`](../crates/cerberus/templates/hermes/)) that shells
  out to the real `cerberus guard` binary instead. It allowlists the
  handful of Hermes's ~86 tools cerberus actually guards (`terminal`,
  `write_file`, `patch`), mapped to their `Bash`/`Write`/`Edit` names. Its
  manifest follows Hermes's documented plugin-discovery format but hasn't
  been checked against the real binary; `cerberus init` says so and
  points at `hermes doctor`.
- **opencode** — `~/.config/opencode/plugin/cerberus-guard.ts`, wired if
  `opencode` is on `$PATH`. Same problem as Hermes, same fix: an
  in-process `tool.execute.before` hook rather than a subprocess
  contract, so a plugin shells out to `cerberus guard` via Bun's `$`.
  opencode has no per-tool matcher at all, so the plugin allowlists
  `bash`/`edit`/`write`/`webfetch` itself, and remaps opencode's camelCase
  argument names (`filePath`) to the snake_case shape every rule expects.
  Checked end to end against the real `cerberus` binary: a fake `edit` on
  a Claude `settings.json` correctly tripped SANDBOX-003 through that
  remap.

More harnesses land as `cerberus init` learns to wire them.

## Scope

`guard` is wired to the tools that change something or reach the network:

```
Bash | Write | Edit | NotebookEdit | WebFetch | mcp__.*
```

`Read`, `Grep`, `Glob`, and the rest are deliberately absent. Nothing they
do is worth denying, and keeping the hook off the hottest tools in a session
is what lets `guard` stay a subprocess-per-call design with no cache.

Guarding more than Bash isn't cosmetic. `sandbox-integrity` has always
blocked a shell command that edits the sandbox configuration in a Claude
`settings.json`; while the hook was Bash-only, the agent could reach the
exact same outcome by using the Edit tool instead of `sed`, and the guard
never saw the call.

The heads are not equally general. `policy` is tool-agnostic — cupcake gets
the hook payload verbatim. `judgement` sees every guarded tool. `risk` stays
**Bash-only by design**: tirith scans shell command strings, and there's
nothing meaningful to hand it for a `Write` or a `WebFetch`.
