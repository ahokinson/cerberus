# Repo-local rules: `.cerberus/`

cerberus owns what its three heads enforce. A repo's own `.tirith/policy.yaml`
and `.cupcake/` are **never read**, so neither can displace cerberus's rules or
quietly stand in for them. A repo gets one door instead, and it is locked until
a human opens it.

```
.cerberus/
  judgements/*.rhai     flat      judgement head
  policies/**/*.rego    may nest  policy head
  risks/*.yaml          flat      risk head
```

The names are the heads'. `judgements/` and `risks/` must stay flat for the same
reason a source's do: the loaders read one directory level, and a nested file
would install but never run. `policies/` may nest.

## Approving it

```sh
cd ~/work/app
cerberus trust
```

A cloned repo is untrusted input that would run on every guarded tool call (a
Rhai script executes code), so nothing in `.cerberus/` enforces anything until
`cerberus trust` is run inside that repo. It copies the directory aside,
validates the copy with the same checks a source gets (`opa check` over the
Rego, the composed tirith policy through `tirith rule validate`, and the
flat-layout rule), prints the **full content** of everything added or changed
since the last approval, and asks `[y/N]`. Only a yes records the repo in
`config.toml`, and what is recorded is the copy that was shown, so an edit to
the live directory mid-review changes nothing. Nothing is recorded if
validation fails. Symlinked files are skipped, never followed.

The agent cannot approve its own rules. `cerberus trust` refuses unless both
stdin and stdout are a terminal, and the agent's shell has none. That is the
gate; SANDBOX-004 additionally blocks the plain command line, but it is a string
match and not relied on. The snapshots live under cerberus's own directories,
which CERB-POL-004 protects.

## What is enforced is a snapshot

`trust` copies the approved content into cerberus's data directory and the heads
enforce **that copy**, never the live directory. So:

- what runs is exactly what you reviewed, with no gap between check and use;
- editing `.cerberus/` (you, a teammate's pull, an agent) changes nothing until
  `cerberus trust` is run again;
- deleting `.cerberus/` loosens nothing either. Running `cerberus trust` in a
  repo whose directory is gone withdraws the approval.

`cerberus doctor` run in the repo says which of these it is: unapproved,
approved and current, or changed since approval (listing the files).

## How each head layers it

| Head | How the repo's content is applied |
| --- | --- |
| judgement | The approved `judgements/` is the last layer after your rules and any sources', an OR of denials like the rest. |
| policy | cupcake layers natively: its global store (cerberus's policies) runs first, with absolute precedence over the project phase. The approved `policies/` rides in a per-repo cupcake project passed as `--policy-dir`. cerberus's global store is never copied. |
| risk | tirith reads exactly one file and cannot layer, so the repo gets its own composed overlay: cerberus's base, your fragments, every source's, then the repo's `risks/` last, with rule ids prefixed `repo-`. |

A repo's layer can only add. The tirith composition refuses a fragment that
tries to loosen the base posture (`fail_mode`, `paranoia`, and so on), and the
judgement and policy heads are deny-only stacks.

A repo's `policies/` use cupcake's project-phase package prefix,
`cupcake.policies.<name>`, not the `cupcake.global.policies...` a source's use.

## What cerberus deliberately ignores

If the repo has its own `.tirith/policy.yaml` or `.cupcake/`, `cerberus doctor`
says so (`repo.native`), so nobody assumes they are enforcing. Move what should
apply into `.cerberus/` and run `cerberus trust`.

## Limits worth knowing

- **Scope follows where the call runs and what it touches.** A repo's approved
  layer applies to a call whose `cwd` is inside the repo (at any depth; a `.git`
  made inside it does not shed the approval), whose `file_path`, `notebook_path`
  or `path` is inside it, or whose command `cd`s into it. So `cd /tmp` followed
  by an Edit of a file in the repo is still covered. Other ways a command can
  reach a repo (`git -C`, an absolute path as an argument) are not read.
  Judgement applies every approved repo the call touches. Policy and risk each
  read a single store, so they use the first touched repo that ships `policies/`
  or `risks/`, the shell's own repo first.
- **Moving from a repo's own `.tirith/policy.yaml`.** Before `.cerberus/`, a
  repo's tirith policy replaced cerberus's overlay in that repo. It is now
  ignored, so a stricter team posture there stops applying until its rules are
  moved into `.cerberus/risks/` and approved. `cerberus doctor` flags it.
- **Runaway scripts.** A Rhai script is cut off after a fixed operation budget
  and fails open for that script alone.
