// Head: judgement — Purpose: governance policy
//
// Blocks the three ways an agent could weaken its own sandbox:
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
// - SANDBOX-003: the same edit made with a file-writing tool instead of a
//   shell command. SANDBOX-002 was trivially defeated by reaching for Edit
//   rather than `sed`, which is what put every mutating tool behind
//   `cerberus guard` in the first place.
//
//   Unlike SANDBOX-002 this does *not* require the payload to mention
//   "sandbox". A Write replaces the whole file, so the dangerous edit is
//   precisely the one that deletes the sandbox block and therefore never
//   contains the word. The cost is that the agent can't edit a Claude
//   settings.json at all; that file holds the sandbox, permission, and hook
//   configuration that cerberus itself depends on, so a human should be
//   making those changes anyway.
//
// This is also the SessionStart health check's canary for the rule-script
// layer: synthetic `dangerouslyDisableSandbox: true` (SANDBOX-001) and
// settings.json Write (SANDBOX-003) events must both be denied by this rule
// at every SessionStart, or the guard is considered degraded and the
// fail-closed backstop denies every tool cerberus guards. Do not remove or
// weaken either without updating `src/health.rs`'s canaries.

// Claude's settings files, the ones holding sandbox/permission/hook config.
// Matched as a suffix so both the user-level (`~/.claude/`) and the
// project-level (`<repo>/.claude/`) copies are covered.
fn is_claude_settings(path) {
    path.contains(".claude/settings.json") || path.contains(".claude/settings.local.json")
}

// Tools that replace or mutate file contents. Read and Grep name a path too
// (see `tool_paths`), and reading settings.json is fine.
fn is_writing_tool(name) {
    name == "Write" || name == "Edit" || name == "NotebookEdit"
}

fn check(cmd, cwd, input) {
    if input.tool_input.dangerouslyDisableSandbox == true {
        return "Blocked (SANDBOX-001): the agent may not disable its own Bash sandbox (`dangerouslyDisableSandbox`). If a command genuinely needs to run unsandboxed, that decision belongs to a human, not the agent.";
    }

    if is_writing_tool(input.tool_name) {
        for path in tool_paths(input) {
            if is_claude_settings(path) {
                return "Blocked (SANDBOX-003): the agent may not write to a Claude `settings.json`. That file holds the sandbox, permission, and hook configuration the guard itself depends on, so changing it is a human's call. Ask for the edit you want made.";
            }
        }
    }

    if !is_claude_settings(cmd) {
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
