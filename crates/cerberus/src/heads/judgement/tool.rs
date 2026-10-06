use serde_json::Value;

/// The `tool_input` keys that name a filesystem path, in the fixed order
/// [`paths`] reports them.
///
/// Keying on the field name rather than on a per-tool table is deliberate.
/// It covers the built-in tools (`file_path` for Read/Write/Edit,
/// `notebook_path` for NotebookEdit, `path` for Glob/Grep) with one rule,
/// and it extends for free to MCP tools that follow the same naming
/// convention, which a hardcoded tool list never could.
const PATH_KEYS: [&str; 3] = ["file_path", "notebook_path", "path"];

fn tool_input_str<'a>(input: &'a Value, key: &str) -> Option<&'a str> {
    input
        .get("tool_input")?
        .get(key)?
        .as_str()
        .filter(|s| !s.is_empty())
}

/// Every filesystem path this hook event's `tool_input` names.
///
/// This is what lets a rule script ask "what file is this call about?"
/// without caring which tool is asking, so a rule about a sensitive path
/// covers Write, Edit, and NotebookEdit at once instead of needing a branch
/// per tool. Returns empty for a tool that names no path at all (Bash,
/// WebFetch); such a rule should be looking at `cmd` or [`url`] instead.
pub fn paths(input: &Value) -> Vec<String> {
    PATH_KEYS
        .iter()
        .filter_map(|key| tool_input_str(input, key))
        .map(String::from)
        .collect()
}

/// The URL this hook event's `tool_input` names, for WebFetch and any MCP
/// tool using the same key.
pub fn url(input: &Value) -> Option<String> {
    tool_input_str(input, "url").map(String::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn event(tool: &str, tool_input: Value) -> Value {
        json!({ "tool_name": tool, "tool_input": tool_input })
    }

    #[test]
    fn reads_file_path_for_the_file_tools() {
        for tool in ["Read", "Write", "Edit"] {
            let input = event(tool, json!({ "file_path": "/repo/src/main.rs" }));
            assert_eq!(paths(&input), vec!["/repo/src/main.rs".to_string()]);
        }
    }

    #[test]
    fn reads_notebook_path_for_notebook_edit() {
        let input = event("NotebookEdit", json!({ "notebook_path": "/repo/a.ipynb" }));
        assert_eq!(paths(&input), vec!["/repo/a.ipynb".to_string()]);
    }

    #[test]
    fn reads_path_for_the_search_tools() {
        for tool in ["Glob", "Grep"] {
            let input = event(tool, json!({ "pattern": "*.rs", "path": "/repo/src" }));
            assert_eq!(paths(&input), vec!["/repo/src".to_string()]);
        }
    }

    #[test]
    fn reads_paths_from_an_mcp_tool_following_the_convention() {
        let input = event("mcp__fs__write", json!({ "file_path": "/repo/x" }));
        assert_eq!(paths(&input), vec!["/repo/x".to_string()]);
    }

    #[test]
    fn reports_multiple_path_keys_in_a_fixed_order() {
        let input = event("mcp__odd__tool", json!({ "path": "/b", "file_path": "/a" }));
        assert_eq!(paths(&input), vec!["/a".to_string(), "/b".to_string()]);
    }

    #[test]
    fn is_empty_for_tools_that_name_no_path() {
        assert_eq!(
            paths(&event("Bash", json!({ "command": "ls" }))),
            Vec::<String>::new()
        );
        assert_eq!(paths(&json!({})), Vec::<String>::new());
    }

    #[test]
    fn ignores_empty_and_non_string_values() {
        assert_eq!(
            paths(&event("Write", json!({ "file_path": "" }))),
            Vec::<String>::new()
        );
        assert_eq!(
            paths(&event("Write", json!({ "file_path": 7 }))),
            Vec::<String>::new()
        );
    }

    #[test]
    fn reads_the_url_for_webfetch() {
        let input = event("WebFetch", json!({ "url": "https://example.com" }));
        assert_eq!(url(&input), Some("https://example.com".to_string()));
    }

    #[test]
    fn url_is_none_when_absent_or_empty() {
        assert_eq!(url(&event("Bash", json!({ "command": "ls" }))), None);
        assert_eq!(url(&event("WebFetch", json!({ "url": "" }))), None);
        assert_eq!(url(&json!({})), None);
    }
}
