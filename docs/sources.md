# Layered policy sources

A source is a named, independently syncable git repo carrying content for
**all three heads**, stacked on top of a machine's own rules — the mechanism
for turning cerberus from a per-developer tool into a team one, without
cerberus ever pulling anything on its own initiative:

| In the repo | Head | Installed to |
| --- | --- | --- |
| `rules/*.rhai` (flat) | `judgement` | `…/cerberus/rules/sources/<name>/` |
| `policies/**/*.rego` (may nest) | `policy` | `…/cerberus/cupcake/policies/claude/cerberus/sources/<name>/` |
| `tirith/*.yaml` (flat) | `risk` | composed into the overlay; see [risk](heads.md#risk) |

```sh
cerberus source add ahokinson/cerberus-rules      # a GitHub owner/repo slug
cerberus source add gh:myorg/policies --ref v1.2.0
cerberus source add team git@example.com:myorg/cerberus-policies.git
cerberus source list
cerberus source sync            # fetches and shows any pending update's log/diffstat
cerberus source sync --yes      # applies it
cerberus source remove team
```

The one-argument form takes a GitHub `owner/repo` slug or any git URL and
names the source after the repository; `--name` overrides that, and the
two-argument `add <name> <git-url>` form still works.

The `tirith/*.yaml` half is the reason this is worth using rather than
wiring each tool up by hand: tirith reads exactly one policy file and has no
`extends`/`import` of its own, so cerberus composing every source's
fragments into that file is something you cannot do natively at all.

`add` clones the repo, resolves `--ref` (or the remote's default branch) to
a commit, validates what it ships — `.rego` with `opa check`, `tirith/*.yaml`
by composing the candidate policy and running `tirith rule validate` over it
(each skipped with a warning if its binary isn't on `$PATH`; a validation
*failure*, unlike a skip, aborts the whole operation — nothing is installed
and `config.toml` isn't touched) — installs all three kinds, pins the
resolved commit in `config.toml`, and recomposes the tirith overlay. Every
source's rules are checked the same way the top-level ones are — any source
that denies, denies, alongside your own rules — but a plain
`cerberus guard`/`cerberus init` never touches the network: **only `sync`
does**, and applying an update always requires `--yes`, showing the pending
commit log and a diffstat first.
Remote content that executes against every guarded tool call should never
change on a machine without a human asking for it.

A source repo just needs any of `rules/`, `policies/`, `tirith/` at its
root, mirroring cerberus's own layout — `policies/` may nest by category
(subdirectories install as-is), `rules/` and `tirith/` must stay flat — see
[CONTRIBUTING.md](../CONTRIBUTING.md) for the package-naming convention a
source's `.rego` files should follow.
