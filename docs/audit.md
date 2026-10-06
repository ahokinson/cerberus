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
loose). Each rule line names the file that defines it, when it has one.
`--since 7d` narrows everything to a recent window.

Give it a rule id from the report to see what that rule actually stopped,
newest first, with the session, directory and command:

```sh
cerberus audit decisions SANDBOX-001
```

That's usually what settles it: the same harmless command over and over means
loosen the rule, a real attempt means leave it alone.

## Looking past what was blocked

Two more commands read the same record for what the blocks don't show.

`cerberus audit allows` surveys the allow counters:

- **Never blocked, but common:** shell commands allowed often (20 or more
  times) that no rule has ever stopped. A frequent `curl` or `ssh` here is a
  rule you don't have.
- **New commands:** shapes first seen in the window (the last 7 days unless
  `--since` says otherwise). It says so, rather than listing everything, when
  the record isn't older than the window.
- **Run from many directories**, and **run outside any project** (from
  `$HOME` itself or a system directory like `/etc`).
- **Tools:** how often each tool ran, with its blocked count, flagging any
  tool that has never been blocked. This is where an MCP tool running
  constantly with no rule on it shows up.

`cerberus audit rules` lists every rule found in your rule scripts, cerberus
policies and tirith fragments (sources included) with how often it fired and
when it last did, then the ones that never have. It also says how many days
the record covers, because a rule that hasn't fired in two days tells you
nothing. A rule that fired but has no file, such as one of tirith's built-ins,
is listed as such.

Both only work from shapes: an allow keeps no arguments, so they can say
*what kind* of command ran unchecked, not what it was.

## Querying the database directly

The file is plain SQLite as far as readers go (checked with Python's
`sqlite3`), so anything can open it read-only. Tables: `decisions` (one row per
deny/ask), `allows` (per-day counts by `tool_name`, `shape`, `cwd`) and
`violations` (per-session counts by head).

```sh
DB=${XDG_STATE_HOME:-$HOME/.local/state}/cerberus/cerberus.db
sqlite3 "file:$DB?mode=ro" "select rule, count(*) from decisions group by rule order by 2 desc"
sqlite3 "file:$DB?mode=ro" "select shape, sum(n) from allows group by shape order by 2 desc limit 20"
```

Every `cerberus guard` call is its own process and the database allows one
process at a time, so concurrent calls wait briefly for each other. If a write
can't get in within about half a second it is dropped: auditing never delays
or changes a guard decision.

This is deliberately not telemetry — nothing here phones home. It exists so
a team lead can point at "N blocked this week, by category" as a concrete
case for why the guard is worth running, using a plain local file rather
than any new server or dashboard.
