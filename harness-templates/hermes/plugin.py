"""cerberus's Hermes Agent plugin.

Hermes's best-documented integration surface is an in-process Python
`pre_tool_call` callback, not a subprocess/stdin contract the way Claude
Code, Codex CLI, and Cursor all are (Hermes does have a config.yaml-driven
shell-hook path too, but its exact stdin/stdout contract isn't documented
anywhere cerberus's authors could find — this plugin sidesteps that
uncertainty entirely). So the whole adapter lives here: this file shells
out to the real `cerberus guard` binary on every tool call, translating
Hermes's callback arguments into the same Claude-Code-shaped JSON envelope
cerberus's Rust binary already understands, and translating cerberus's
decision back into Hermes's `{"action": ...}` vocabulary. `cerberus guard`
itself needs no Hermes awareness at all.

This plugin's manifest (`plugin.yaml`) and this file's own name are cerberus's
best effort against Hermes's documented plugin-discovery conventions, not
verified against the real `hermes-agent` binary. If Hermes doesn't pick this
plugin up, run `hermes hooks list` / `hermes doctor` to see why, and check
this repo's issue tracker or file one.
"""

import json
import os
import subprocess

# The Hermes tool names cerberus guards, mapped to the canonical
# Claude-Code-shaped tool_name every existing rule/policy already
# understands. Hermes's own registry has ~86 tools (per its tools
# reference); without this allowlist, cerberus would spawn a subprocess on
# every single one of them, including the hot read-only path — the same
# reason Claude Code's, Codex's, and Cursor's own matchers exclude
# Read/Grep/Glob.
#
# Confirmed from Hermes's tools reference
# (https://hermes-agent.nousresearch.com/docs/reference/tools-reference):
# "terminal" (shell execution) and the file toolset's "write_file"/"patch".
# Deliberately conservative: Hermes's "process" tool isn't confirmed to run
# arbitrary shell commands (it may just manage already-running processes),
# so it's left unmapped rather than risk feeding something that isn't a
# shell command to tirith — the same caution cerberus's own
# `hook::bash_command` documents for MCP tools carrying an unrelated
# `command` field. The file toolset's exact argument field names also
# aren't confirmed, so `tool_input` is passed through unchanged rather than
# guessing at a field-name remap — a path-based rule like SANDBOX-003 only
# fires here if Hermes's `write_file`/`patch` args happen to use a
# `file_path`-shaped key, which is unverified.
GUARDED_TOOLS = {
    "terminal": "Bash",
    "write_file": "Write",
    "patch": "Edit",
}


def _cerberus_guard(payload):
    """Runs the real `cerberus guard` with `payload` on stdin, returning
    its parsed decision JSON, or None on any failure (missing binary,
    timeout, non-JSON output) — fail open, matching cerberus's own
    fail-open-per-head philosophy for a broken integration layer, since a
    broken plugin must never itself become the reason a call goes
    ungoverned in a way that looks like it was reviewed.
    """
    try:
        proc = subprocess.run(
            ["cerberus", "guard"],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if not proc.stdout.strip():
        return None
    try:
        return json.loads(proc.stdout)
    except ValueError:
        return None


def _on_pre_tool_call(tool_name, args, task_id, **kwargs):
    canonical_tool_name = GUARDED_TOOLS.get(tool_name)
    if canonical_tool_name is None:
        return None

    payload = {
        "session_id": task_id,
        "cwd": kwargs.get("cwd", os.getcwd()),
        "hook_event_name": "PreToolUse",
        "tool_name": canonical_tool_name,
        "tool_input": args,
    }
    decision = _cerberus_guard(payload)
    if decision is None:
        return None

    hook_output = decision.get("hookSpecificOutput", {})
    permission = hook_output.get("permissionDecision")
    reason = hook_output.get("permissionDecisionReason", "")

    if permission == "deny":
        return {"action": "block", "message": reason}
    if permission == "ask":
        return {"action": "approve", "message": reason}
    return None


def register(ctx):
    ctx.register_hook("pre_tool_call", _on_pre_tool_call)
