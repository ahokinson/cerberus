# Head: policy — Purpose: governance policy
#
# CERB-POL-003 — a file-writing tool (Write/Edit/NotebookEdit) pointed at a
# CI/CD pipeline definition or a git hook. Same shape of concern as
# judgement's SANDBOX-003: these files are a trust boundary an agent
# editing code shouldn't get to move on its own, since a changed workflow
# file can grant itself secrets/permissions on the next run. Unconditional:
# no situational carve-out, matching this head's governance-policy purpose.

# METADATA
# scope: package
# title: CI/CD and git-hook trust boundary
# custom:
#   severity: HIGH
#   routing:
#     required_events: ["PreToolUse"]
#     required_tools: ["Write", "Edit", "NotebookEdit"]
package cupcake.global.policies.cerberus.ci_trust_boundary

import rego.v1

touches_ci_path(path) if {
	regex.match(`(^|/)\.github/workflows/|(^|/)\.gitlab-ci\.yml$|(^|/)\.circleci/config\.yml$|(^|/)\.git/hooks/`, path)
}

deny contains decision if {
	some field in ["file_path", "notebook_path"]
	path := input.tool_input[field]
	touches_ci_path(path)
	decision := {
		"rule_id": "CERB-POL-003",
		"reason": "Blocked: editing a CI/CD pipeline definition or git hook. These run with elevated trust on the next push/commit, so changes to them are a human's call.",
		"severity": "HIGH",
	}
}
