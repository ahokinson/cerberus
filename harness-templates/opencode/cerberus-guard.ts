import type { Plugin } from "@opencode-ai/plugin"

/**
 * cerberus's opencode plugin.
 *
 * opencode plugins run in-process (Bun), not as a subprocess given a JSON
 * hook payload on stdin the way Claude Code, Codex CLI, and Cursor all
 * are. The whole adapter lives here: shells out to the real
 * `cerberus guard` binary on `tool.execute.before` and translates both
 * directions. `cerberus guard` itself needs no opencode-specific code.
 *
 * opencode has no per-tool matcher config like the other three harnesses:
 * `tool.execute.before` fires for *every* tool call, so GUARDED_TOOLS
 * below does the job cerberus's own GUARD_MATCHER does elsewhere, keeping
 * cerberus off the hot read path (read/glob/grep/list/...) instead of
 * spawning a subprocess on every single tool call.
 *
 * This file is a best effort against opencode's documented plugin API,
 * not verified against the real opencode binary:
 *   - opencode's own built-in tool names ("bash", "edit", "write",
 *     "webfetch") are confirmed from opencode's docs/tool reference.
 *   - The camelCase→snake_case remapping (`filePath` -> `file_path`) is
 *     confirmed only for "edit"'s args in opencode's own examples;
 *     applied to "write" too by analogy, not independently confirmed.
 *   - Piping JSON to `cerberus guard` via `new Response(payload)` as
 *     shell input follows Bun's documented "Response as stdin" shell
 *     redirection, since Bun's `$` has no dedicated `.stdin()` method.
 * If any of this drifts from opencode's actual behavior, this plugin
 * fails open (see the try/catch below) rather than silently mis-blocking.
 */

const GUARDED_TOOLS: Record<string, string> = {
  bash: "Bash",
  edit: "Edit",
  write: "Write",
  webfetch: "WebFetch",
}

function toCanonicalToolInput(tool: string, args: Record<string, unknown>): Record<string, unknown> {
  if (tool !== "edit" && tool !== "write") return args
  const { filePath, ...rest } = args as { filePath?: string; [key: string]: unknown }
  if (filePath === undefined) return args
  return { file_path: filePath, ...rest }
}

export const CerberusGuard: Plugin = async ({ $, directory }) => {
  return {
    "tool.execute.before": async (
      input: { tool: string; sessionID?: string },
      output: { args: Record<string, unknown> },
    ) => {
      const toolName = GUARDED_TOOLS[input.tool]
      if (!toolName) return

      const payload = JSON.stringify({
        session_id: input.sessionID,
        cwd: directory,
        hook_event_name: "PreToolUse",
        tool_name: toolName,
        tool_input: toCanonicalToolInput(input.tool, output.args),
      })

      let stdout = ""
      try {
        const result = await $`cerberus guard < ${new Response(payload)}`.quiet().nothrow()
        stdout = result.stdout.toString().trim()
      } catch {
        // cerberus not on PATH, or the shell call itself failed: fail
        // open, matching cerberus's own fail-open-per-head philosophy for
        // a broken integration layer. A broken plugin must never itself
        // become the reason a call goes ungoverned in a way that looks
        // like it was reviewed.
        return
      }
      if (!stdout) return

      let decision: { hookSpecificOutput?: { permissionDecision?: string; permissionDecisionReason?: string } }
      try {
        decision = JSON.parse(stdout)
      } catch {
        return
      }

      const permission = decision?.hookSpecificOutput?.permissionDecision
      const reason = decision?.hookSpecificOutput?.permissionDecisionReason ?? "Blocked by cerberus"
      if (permission === "deny" || permission === "ask") {
        throw new Error(reason)
      }
    },
  }
}
