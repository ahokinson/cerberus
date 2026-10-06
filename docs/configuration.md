# Configuration

Which heads `guard` runs is controlled by
`${XDG_CONFIG_HOME:-$HOME/.config}/cerberus/config.toml`:

```toml
# All heads run by default. Set `disabled = true` on a head to remove it
# from `cerberus guard`'s stack. `gate` (the fail-closed backstop) always
# runs first automatically and isn't listed here.
#
# Each head catches a different kind of bad outcome:
[heads]
risk = { disabled = false }      # general risk avoidance: tirith command-pattern scanning
policy = { disabled = false }    # governance policy: cupcake policy evaluation
judgement = { disabled = false } # contextual bad decisions: Rhai situational checks
```

A missing file, a missing `[heads]` table, or a head simply absent from the
table all mean the same thing: enabled. Config problems fail open to
running everything. Run order is fixed (`gate`, then `risk`, `policy`,
`judgement`) and isn't configurable. Only which heads are enabled is.

`health` never complains about a disabled head. Turning one off is a choice,
not a degradation.
