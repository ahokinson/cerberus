# Diagnosing a degraded guard

When a guard is degraded, `gate` denies every guarded tool until it's fixed
(see [Design notes](design.md)). `cerberus doctor` says why, and retests.

Run it **in a terminal, not through the agent**. While the guard is degraded,
`gate` blocks the agent's own Bash tool, so the agent can't run it. The deny
message says the same.

```sh
$ cerberus doctor
sentinel: PRESENT (set 4m ago)
  recorded: policy (governance policy): opa (cupcake's Rego engine) not on PATH

ok   risk.tirith              tirith on PATH
ok   risk.overlay             tirith overlay blocks the canary
FAIL policy.opa               opa (cupcake's Rego engine) not on PATH
                             fix: install opa, or fix the PATH the hook runs under (the nix wrapper provides it)
ok   policy.cupcake           cupcake on PATH
skip policy.canary            opa, cupcake or its project missing
...

Still degraded (1 problem); sentinel kept, reason refreshed. Fix the above, then run `cerberus doctor` again.
```

## What it does

`doctor` runs every probe `health` runs, each one independently. A failure
never hides the next, and a canary whose prerequisite already failed is shown
as `skip` instead of failing a second time for the same reason. Each result is
one of:

| Status | Meaning |
| --- | --- |
| `ok` | The probe passed. |
| `FAIL` | The guard is degraded because of this. It carries the cause and a fix. |
| `warn` | Worth fixing, but not why the guard is degraded. |
| `skip` | Not probed: the head is disabled, or a prerequisite failed. |

It then hands the result to the same code SessionStart uses to write or clear
the degraded sentinel. If every probe passed, the sentinel is cleared and
`doctor` says so; start a new session. If anything failed, the sentinel is
rewritten with the fresh reason and `doctor` exits `1`.

There is no flag to clear the sentinel without the checks passing. A way to
do that would be a way to turn off the guard, which
[SECURITY.md](../SECURITY.md) treats as a vulnerability.

## Checks

| Id | Head | Passes when |
| --- | --- | --- |
| `risk.tirith` | risk | `tirith` is on `PATH` |
| `risk.overlay` | risk | the composed overlay blocks a known-dangerous command |
| `policy.opa`, `policy.cupcake` | policy | the binary is on `PATH` |
| `policy.project` | policy | cerberus's cupcake project exists |
| `policy.canary` | policy | cupcake blocks a halt command end to end |
| `policy.store` | policy | cerberus's own cupcake store exists |
| `policy.self_protection` | policy | cerberus's shipped policies block a write to the rule scripts |
| `judgement.rules` | judgement | rule scripts exist and still block both sandbox-weakening canaries |

Checks for a head that's disabled in `config.toml` don't run.

`doctor` also reports things `health` can't see, because `health` only runs
once the hooks are already wired. These are always `warn`, never `FAIL`:

| Id | Warns when |
| --- | --- |
| `config` | `config.toml` doesn't parse. Defaults apply meanwhile, so every head stays enabled. |
| `hooks.claude`, `hooks.codex`, `hooks.cursor` | the guard or health hook is missing from that harness's hooks file |
| `plugin.hermes`, `plugin.opencode` | the plugin is missing, for a harness that's installed |
| `repo.cerberus` | the repo you ran it in has a `.cerberus/` that isn't approved, or has changed since it was (the approved copy still enforces). Reported `ok` when approved and current. See [repo-local rules](repos.md). |
| `repo.native` | the repo has its own `.tirith/policy.yaml` or `.cupcake/`, which cerberus deliberately doesn't read |

## JSON

`cerberus doctor --json` prints the same result as one JSON object, with the
same exit code:

```json
{
  "healthy": false,
  "sentinel_before": { "reason": "...", "age_seconds": 240 },
  "checks": [
    { "id": "policy.opa", "head": "policy", "status": "fail",
      "summary": "...", "detail": null, "fix": "install opa, ..." }
  ]
}
```
