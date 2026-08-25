# Head: policy — Purpose: governance policy
#
# CERB-POL-002 — WebFetch targeting cloud instance metadata / link-local
# addresses. Classic SSRF-to-credential-theft: a WebFetch reaching
# 169.254.169.254 (AWS/GCP/Azure metadata) or metadata.google.internal can
# exfiltrate the host's own cloud credentials. tirith can't see this: it
# only scans Bash command strings, and WebFetch never runs through Bash.

# METADATA
# scope: package
# title: WebFetch SSRF to cloud metadata endpoints
# custom:
#   severity: HIGH
#   routing:
#     required_events: ["PreToolUse"]
#     required_tools: ["WebFetch"]
package cupcake.global.policies.cerberus.webfetch_ssrf

import rego.v1

deny contains decision if {
	input.tool_name == "WebFetch"
	regex.match(`(169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.com|100\.100\.100\.200)`, input.tool_input.url)
	decision := {
		"rule_id": "CERB-POL-002",
		"reason": "Blocked: WebFetch targeting a cloud instance metadata endpoint. This is a classic SSRF path to steal the host's own cloud credentials.",
		"severity": "HIGH",
	}
}
