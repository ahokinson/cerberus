---
name: Bug report
about: Something cerberus got wrong
labels: bug
---

**What happened**

Which head was involved, if you know: `risk`, `policy`, `judgement`, or
`gate`.

**The command**

The Bash command that was allowed or denied. If a rule fired, quote the
`permissionDecisionReason` text.

**What you expected instead**

**Reproducing it**

Piping the hook event straight into `cerberus guard` is usually the fastest
repro:

```sh
echo '{"session_id":"test","cwd":"/path","tool_input":{"command":"..."}}' | cerberus guard
```

**Environment**

- cerberus version (`cerberus --version`)
- OS
- `tirith`, `cupcake`, `opa` versions, if the relevant head uses them
- Output of `cerberus health`
