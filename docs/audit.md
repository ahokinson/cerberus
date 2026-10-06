# Audit log

Off by default. cerberus keeps a small local database at
`${XDG_STATE_HOME:-$HOME/.local/state}/cerberus/cerberus.db` (a
[turso](https://github.com/tursodatabase/turso) file, SQLite-compatible). It
always holds per-session deny counts (`cerberus violations`), which contain no
command text. Once `[audit] enabled = true` in `config.toml` it also holds the
decision record:

- **Deny and ask decisions** are one row each: head, tool, decision, the rule
  id, the reason, the working directory, a command `shape` (the program plus
  subcommand, e.g. `git push`, with no arguments), and the raw `tool_input`
  that triggered it. It's off by default specifically because that last field
  can contain inline secrets (a bearer token typed into a `curl` command,
  say); turning it on is a deliberate choice, not a default one. See
  [SECURITY.md](../SECURITY.md).
- **Allows** are never rows. Each one bumps a per-day counter keyed by tool,
  shape and directory, so no `tool_input` is stored and the file stays small
  however busy the machine is.

Rows and counters older than 90 days are deleted on the next write. A call
stopped by the degraded-state gate is not recorded.

```sh
cerberus audit tail -n 20
cerberus audit summary --since 7d
cerberus audit decisions
cerberus audit export --format csv --out blocked-this-week.csv
```

`decisions` is the one to read when deciding whether to tighten or loosen a
rule. It groups the record by rule and by command shape, then calls out rules
that keep blocking one shape across several sessions (likely too tight) and
shapes that are blocked in some forms but still allowed often (likely too
loose).

Every `cerberus guard` call is its own process and the database allows one
process at a time, so concurrent calls wait briefly for each other. If a write
can't get in within about half a second it is dropped: auditing never delays
or changes a guard decision.

This is deliberately not telemetry — nothing here phones home. It exists so
a team lead can point at "N blocked this week, by category" as a concrete
case for why the guard is worth running, using a plain local file rather
than any new server or dashboard.
