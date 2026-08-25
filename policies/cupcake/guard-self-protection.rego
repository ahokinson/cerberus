# Head: policy — Purpose: governance policy
#
# CERB-POL-004 — the agent may not use a file-writing tool to edit
# cerberus's, tirith's, or cupcake's own runtime configuration: cerberus's
# rule scripts/config.toml, its tirith policy overlay, or the cupcake
# project stub / global policy store. This is `health`'s canary for the
# policy head's global-store content specifically (as opposed to
# CERB-POL-001, which mirrors an existing judgement canary) — see
# src/health.rs's global_policy_canary_blocked. Do not remove or weaken
# without updating it. The command-text form of the same concern
# (`rm -rf ~/.config/cerberus`, uninstalling the binaries) is tirith's
# `cerberus-guard-self-tamper` custom rule, not duplicated here — this
# rule is deliberately structural/path-only, matching cupcake's role.
#
# The path match is keyed on cerberus's distinctive directory/file names
# only (`cerberus/rules`, `cerberus/config.toml`, `cupcake-stub`,
# `cerberus-tirith-overlay`, the global store's reserved
# `custom/cerberus/` subdirectory), not on an assumed `~/.config/...`
# prefix. `Paths` derives every one of these roots from
# `XDG_CONFIG_HOME`/`XDG_DATA_HOME`, which can point anywhere — verified
# live against a sandbox using non-dotted XDG roots, where a prefix-based
# match silently failed to recognize its own paths. Also deliberately
# narrower than a bare `.tirith/policy.yaml` or `.cupcake/` match: those
# would catch a *project's own* tirith/cupcake config, which a human may
# legitimately want the agent to edit and has nothing to do with cerberus.

# METADATA
# scope: package
# title: Guard self-protection (file-writing tools)
# custom:
#   severity: CRITICAL
#   routing:
#     required_events: ["PreToolUse"]
#     required_tools: ["Write", "Edit", "NotebookEdit"]
package cupcake.global.policies.cerberus.guard_self_protection

import rego.v1

guarded_path(path) if {
	regex.match(`cerberus/rules/|cerberus/config\.toml|cupcake-stub/|cerberus-tirith-overlay/|cupcake/policies/claude/custom/cerberus/`, path)
}

halt contains decision if {
	some field in ["file_path", "notebook_path"]
	path := input.tool_input[field]
	guarded_path(path)
	decision := {
		"rule_id": "CERB-POL-004",
		"reason": "Blocked: writing to cerberus's, tirith's, or cupcake's own runtime configuration. Changing what the guard enforces is a human's call, not the agent's.",
		"severity": "CRITICAL",
	}
}
