# Usage

| Command | Runs as | What it does |
| --- | --- | --- |
| `cerberus guard` | `PreToolUse` on the guarded tools | `gate`, then the enabled heads in order |
| `cerberus health` | `SessionStart` | checks that the enabled heads are enforcing |
| `cerberus doctor` | standalone, in a terminal | diagnoses a degraded guard, prints the fix for each failure, and retests; clears the degraded sentinel only when every check passes (`--json` for scripts) |
| `cerberus gate` | standalone | the fail-closed backstop on its own, for debugging |
| `cerberus init` | standalone | bootstraps config, rules, and hook wiring |
| `cerberus source add/remove/list/sync` | standalone | manages layered policy sources — see [Layered policy sources](sources.md) |
| `cerberus trust` | standalone | approves (or, if the directory is gone, withdraws) the repo you're in's `.cerberus/` — see [Repo-local rules](repos.md) |
| `cerberus violations <session>` | standalone | prints a session's deny counts per head |
| `cerberus audit tail/summary/decisions/allows/rules/export` | standalone | inspects the decision record — see [Audit log](audit.md) |

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
        "matcher": "Bash|Write|Edit|NotebookEdit|WebFetch|mcp__.*",
        "hooks": [{ "type": "command", "command": "cerberus guard" }]
      }
    ],
    "SessionStart": [
      { "hooks": [{ "type": "command", "command": "cerberus health" }] }
    ]
  }
}
```

Both entries go at the front of their array; anything else already in
`PreToolUse` or `SessionStart` keeps its place.
