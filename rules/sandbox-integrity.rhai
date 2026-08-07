// Head: judgement — Purpose: governance policy
//
// Blocks the two ways an agent could weaken its own Bash sandbox:
//
// - SANDBOX-001: setting the Bash tool's own `dangerouslyDisableSandbox`
//   escape hatch. The tool's own instructions actively encourage flipping
//   this on the moment a command looks sandbox-blocked. This rule denies
//   unconditionally, no situational carve-out, because the agent itself
//   must never be the one making that call.
// - SANDBOX-002: a shell command that directly edits the sandbox
//   config in a Claude settings.json, a more persistent bypass than the
//   per-call flag above. There's no safe dry-run for an arbitrary
//   sed/jq/python mutation, so this errs toward more scrutiny: any
//   write-shaped command touching a Claude settings path that also
//   mentions "sandbox" gets blocked, even if it would, on inspection,
//   have been benign.
//
// This is also the SessionStart health check's canary for the rule-script
// layer: a synthetic `dangerouslyDisableSandbox: true` event must be
// denied by this rule at every SessionStart, or the guard is considered
// degraded and the fail-closed backstop denies all Bash. Do not remove or
// weaken SANDBOX-001 without updating that canary.

fn check(cmd, cwd, input) {
    if input.tool_input.dangerouslyDisableSandbox == true {
        return "Blocked (SANDBOX-001): the agent may not disable its own Bash sandbox (`dangerouslyDisableSandbox`). If a command genuinely needs to run unsandboxed, that decision belongs to a human, not the agent.";
    }

    let touches_settings = cmd.contains(".claude/settings.json") || cmd.contains(".claude/settings.local.json");
    if !touches_settings {
        return;
    }

    let write_shaped = cmd.contains(">") || cmd.contains("tee");
    let in_place_edit = (cmd.contains("sed") || cmd.contains("perl")) &&
        (cmd.contains(" -i") || cmd.contains("-i "));
    if !(write_shaped || in_place_edit) {
        return;
    }

    if cmd.to_lower().contains("sandbox") {
        return "Blocked (SANDBOX-002): this command looks like it would edit the sandbox configuration in a Claude `settings.json` file. That configuration must only be changed by a human, never by the agent itself.";
    }
}
