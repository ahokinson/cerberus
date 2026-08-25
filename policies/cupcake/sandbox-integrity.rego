# Head: policy — Purpose: governance policy
#
# CERB-POL-001 — defense-in-depth mirror of judgement's SANDBOX-001
# (rules/sandbox-integrity.rhai). Denies dangerouslyDisableSandbox purely
# from the hook payload, so this invariant still holds even if the
# judgement head is disabled (a valid, undegraded config per
# config::enabled_heads) or its rule scripts are tampered with. See
# src/health.rs's global_policy_canary_blocked. Do not remove or weaken
# without updating it.

# METADATA
# scope: package
# title: Sandbox integrity (policy-layer mirror of SANDBOX-001)
# custom:
#   severity: CRITICAL
#   routing:
#     required_events: ["PreToolUse"]
#     required_tools: ["Bash"]
package cupcake.global.policies.cerberus.sandbox_integrity

import rego.v1

halt contains decision if {
	input.tool_name == "Bash"
	input.tool_input.dangerouslyDisableSandbox == true
	decision := {
		"rule_id": "CERB-POL-001",
		"reason": "Blocked: the agent may not disable its own Bash sandbox (dangerouslyDisableSandbox). That decision belongs to a human.",
		"severity": "CRITICAL",
	}
}
