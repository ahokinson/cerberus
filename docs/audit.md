# Audit log

Off by default. Once `[audit] enabled = true` in `config.toml`, every
deny/ask decision is appended as a JSON line to
`${XDG_STATE_HOME:-$HOME/.local/state}/guard/audit.jsonl` — head, tool,
decision, the reason, and the raw `tool_input` that triggered it. It's off
by default specifically because that last field can contain inline secrets
(a bearer token typed into a `curl` command, say); turning it on is a
deliberate choice, not a default one. See [SECURITY.md](../SECURITY.md).

```sh
cerberus audit tail -n 20
cerberus audit summary --since 7d
cerberus audit export --format csv --out blocked-this-week.csv
```

This is deliberately not telemetry — nothing here phones home. It exists so
a team lead can point at "N blocked this week, by category" as a concrete
case for why the guard is worth running, using a plain local log rather
than any new server or dashboard.
