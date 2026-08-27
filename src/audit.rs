use crate::config;
use crate::head::Head;
use crate::hook::{permission_decision, permission_reason, str_field, tool_name};
use crate::paths::Paths;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

const SCHEMA_VERSION: u32 = 1;

/// Rotate the live log out of the way once it crosses this size, rather
/// than growing it forever. One generation only (see
/// `Paths::audit_log_rotated_file`) — this is a local debugging/visibility
/// aid, not a long-term archive.
const ROTATE_AT_BYTES: u64 = 10 * 1024 * 1024;

/// One line of `audit.jsonl`: everything about a single non-allow decision.
/// `v` is a schema version so a future format change can tell old and new
/// records apart. `tool_input` is echoed verbatim from the hook payload
/// rather than re-normalized per tool, trading a slightly bigger record for
/// full forensic detail without a per-tool special case here.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AuditRecord {
    pub v: u32,
    pub ts: u64,
    pub session_id: Option<String>,
    pub head: String,
    pub tool_name: Option<String>,
    pub decision: String,
    pub reason: Option<String>,
    pub tool_input: Value,
    pub harness: String,
}

/// Seconds since the Unix epoch, `now`. Exposed so `main.rs`'s
/// `audit summary --since` can compute a cutoff the same way [`record`]
/// stamps a record's `ts`, without either side re-deriving the epoch call.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Records one non-allow decision to the audit log, if audit logging is
/// enabled (`config::audit_enabled`; off by default, see `src/config.rs`).
/// A no-op otherwise, and fails silently on any I/O error — a broken audit
/// write must never affect a guard decision, same contract as
/// `violations::record`.
///
/// `harness` can currently only distinguish Cursor from everything else:
/// Claude Code, Codex, Hermes, and opencode all produce byte-identical hook
/// JSON today with no harness-identifying field of their own. A team running
/// a mixed toolset can't yet tell those four apart from the log alone; a
/// real fix needs each harness template to set an identifying env var
/// before invoking `cerberus guard`.
pub fn record(paths: &Paths, head: Head, input: &Value, output: &str, is_cursor: bool) {
    if !config::audit_enabled(paths) {
        return;
    }
    let record = AuditRecord {
        v: SCHEMA_VERSION,
        ts: now_secs(),
        session_id: str_field(input, "session_id").map(String::from),
        head: head.name().to_string(),
        tool_name: tool_name(input).map(String::from),
        decision: permission_decision(output).unwrap_or_default(),
        reason: permission_reason(output),
        tool_input: input.get("tool_input").cloned().unwrap_or(Value::Null),
        harness: if is_cursor { "cursor" } else { "claude" }.to_string(),
    };
    let _ = append(paths, &record);
}

fn rotate_if_needed(paths: &Paths) -> io::Result<()> {
    let path = paths.audit_log_file();
    if let Ok(meta) = fs::metadata(&path)
        && meta.len() > ROTATE_AT_BYTES
    {
        fs::rename(&path, paths.audit_log_rotated_file())?;
    }
    Ok(())
}

fn append(paths: &Paths, record: &AuditRecord) -> io::Result<()> {
    let path = paths.audit_log_file();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    rotate_if_needed(paths)?;
    let line = serde_json::to_string(record).map_err(|e| io::Error::other(format!("{e}")))?;
    let mut file = OpenOptions::new().create(true).append(true).open(&path)?;
    writeln!(file, "{line}")
}

/// Reads every record still on disk, rotated generation first, oldest to
/// newest. A line that fails to parse (partial write, format change) is
/// skipped rather than failing the whole read.
pub fn read_records(paths: &Paths) -> Vec<AuditRecord> {
    let mut records = Vec::new();
    for path in [paths.audit_log_rotated_file(), paths.audit_log_file()] {
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        records.extend(
            text.lines()
                .filter_map(|line| serde_json::from_str::<AuditRecord>(line).ok()),
        );
    }
    records
}

/// Parses a simple `<n><unit>` duration (`"7d"`, `"12h"`, `"30m"`, `"90s"`)
/// into seconds. Hand-rolled rather than a pulling in a date/duration crate,
/// consistent with this codebase's stated minimalism elsewhere (see
/// `rules::shell`'s hand-rolled tokenizer) — `cerberus audit summary` only
/// ever needs "how far back," not calendar arithmetic.
pub fn parse_duration(input: &str) -> Option<u64> {
    let input = input.trim();
    if input.len() < 2 {
        return None;
    }
    let (num, unit) = input.split_at(input.len() - 1);
    let n: u64 = num.parse().ok()?;
    match unit {
        "s" => Some(n),
        "m" => Some(n * 60),
        "h" => Some(n * 3600),
        "d" => Some(n * 86400),
        _ => None,
    }
}

fn looks_like_rule_id(s: &str) -> bool {
    !s.is_empty()
        && s.contains('-')
        && s.chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '-')
}

/// Extracts the leading rule/policy id from a deny reason, e.g.
/// `"Blocked (SANDBOX-001): ..."` -> `"SANDBOX-001"`, or a bare
/// `"CERB-POL-004: ..."` -> `"CERB-POL-004"`. Every shipped rule/policy
/// reason carries one of these two shapes. Returns `None` for a reason with
/// neither, rather than guessing.
pub fn rule_id(reason: &str) -> Option<String> {
    if let Some(start) = reason.find('(')
        && let Some(len) = reason[start + 1..].find(')')
    {
        let candidate = &reason[start + 1..start + 1 + len];
        if looks_like_rule_id(candidate) {
            return Some(candidate.to_string());
        }
    }
    let first_token = reason
        .split(|c: char| c.is_whitespace() || c == ':')
        .next()?;
    looks_like_rule_id(first_token).then(|| first_token.to_string())
}

/// The "N blocked this week, top categories" view `cerberus audit summary`
/// prints: plain counts grouped a few different ways over an in-process scan
/// of every record newer than a cutoff. No index or database — expected
/// volume (only non-allow decisions) is realistically dozens to low hundreds
/// a week even for an active team, the same "parse the whole flat file into
/// memory" scale `violations::read_counts` already operates at, one level up.
#[derive(Default, Debug, PartialEq)]
pub struct Summary {
    pub total: usize,
    pub by_head: BTreeMap<String, usize>,
    pub by_tool: BTreeMap<String, usize>,
    pub by_rule: BTreeMap<String, usize>,
}

pub fn summarize(records: &[AuditRecord], since_ts: u64) -> Summary {
    let mut summary = Summary::default();
    for record in records.iter().filter(|r| r.ts >= since_ts) {
        summary.total += 1;
        *summary.by_head.entry(record.head.clone()).or_default() += 1;
        if let Some(tool) = &record.tool_name {
            *summary.by_tool.entry(tool.clone()).or_default() += 1;
        }
        if let Some(id) = record.reason.as_deref().and_then(rule_id) {
            *summary.by_rule.entry(id).or_default() += 1;
        }
    }
    summary
}

pub fn export_json(records: &[AuditRecord]) -> String {
    serde_json::to_string_pretty(records).unwrap_or_default()
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// A flattened subset of each record (no `tool_input`, which is arbitrary
/// nested JSON and doesn't fit a spreadsheet cell cleanly) — for full detail
/// use [`export_json`] instead.
pub fn export_csv(records: &[AuditRecord]) -> String {
    let mut out = String::from("ts,session_id,head,tool_name,decision,reason,harness\n");
    for r in records {
        out.push_str(&format!(
            "{},{},{},{},{},{},{}\n",
            r.ts,
            csv_escape(r.session_id.as_deref().unwrap_or("")),
            csv_escape(&r.head),
            csv_escape(r.tool_name.as_deref().unwrap_or("")),
            csv_escape(&r.decision),
            csv_escape(r.reason.as_deref().unwrap_or("")),
            csv_escape(&r.harness),
        ));
    }
    out
}

/// Writes `text` to `out` if given, otherwise prints it to stdout. Shared by
/// `cerberus audit export`'s JSON/CSV branches in `main.rs`.
pub fn write_export(text: &str, out: Option<&Path>) -> io::Result<()> {
    match out {
        Some(path) => fs::write(path, text),
        None => {
            print!("{text}");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn scratch_paths(name: &str) -> Paths {
        let root =
            std::env::temp_dir().join(format!("cerberus-audit-test-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        Paths {
            state_home: root.join("state"),
            data_home: root.join("data"),
            config_home: root.join("config"),
            cache_home: root.join("cache"),
            home: root.join("home"),
        }
    }

    fn sample_record(ts: u64, head: &str, reason: &str) -> AuditRecord {
        AuditRecord {
            v: SCHEMA_VERSION,
            ts,
            session_id: Some("s1".into()),
            head: head.into(),
            tool_name: Some("Bash".into()),
            decision: "deny".into(),
            reason: Some(reason.into()),
            tool_input: json!({"command": "rm -rf /"}),
            harness: "claude".into(),
        }
    }

    #[test]
    fn record_is_a_no_op_when_audit_disabled() {
        let paths = scratch_paths("disabled");
        let input = json!({"session_id": "s1", "tool_name": "Bash"});
        let output = r#"{"hookSpecificOutput":{"permissionDecision":"deny","permissionDecisionReason":"nope"}}"#;
        record(&paths, Head::Risk, &input, output, false);
        assert!(read_records(&paths).is_empty());
        assert!(!paths.audit_log_file().exists());
    }

    #[test]
    fn record_appends_a_line_when_enabled() {
        let paths = scratch_paths("enabled");
        fs::create_dir_all(paths.config_file().parent().unwrap()).unwrap();
        fs::write(paths.config_file(), "[audit]\nenabled = true\n").unwrap();

        let input = json!({
            "session_id": "s1",
            "tool_name": "Bash",
            "tool_input": {"command": "rm -rf /"},
        });
        let output = r#"{"hookSpecificOutput":{"permissionDecision":"deny","permissionDecisionReason":"Blocked (SANDBOX-001): danger"}}"#;
        record(&paths, Head::Risk, &input, output, false);

        let records = read_records(&paths);
        assert_eq!(records.len(), 1);
        let r = &records[0];
        assert_eq!(r.head, "risk");
        assert_eq!(r.decision, "deny");
        assert_eq!(r.reason.as_deref(), Some("Blocked (SANDBOX-001): danger"));
        assert_eq!(r.harness, "claude");
        assert_eq!(r.tool_name.as_deref(), Some("Bash"));
    }

    #[test]
    fn parse_duration_understands_each_unit() {
        assert_eq!(parse_duration("30s"), Some(30));
        assert_eq!(parse_duration("5m"), Some(300));
        assert_eq!(parse_duration("2h"), Some(7200));
        assert_eq!(parse_duration("7d"), Some(7 * 86400));
        assert_eq!(parse_duration("7x"), None);
        assert_eq!(parse_duration(""), None);
        assert_eq!(parse_duration("d"), None);
    }

    #[test]
    fn rule_id_extracts_parenthesized_and_bare_ids() {
        assert_eq!(
            rule_id("Blocked (SANDBOX-001): danger"),
            Some("SANDBOX-001".to_string())
        );
        assert_eq!(
            rule_id("CERB-POL-004: self-tamper"),
            Some("CERB-POL-004".to_string())
        );
        assert_eq!(rule_id("no id in here"), None);
    }

    #[test]
    fn summarize_groups_by_head_tool_and_rule_and_respects_the_cutoff() {
        let records = vec![
            sample_record(100, "risk", "Blocked (SANDBOX-001): danger"),
            sample_record(200, "policy", "CERB-POL-004: self-tamper"),
            sample_record(50, "risk", "Blocked (SANDBOX-001): danger"),
        ];
        let summary = summarize(&records, 100);
        assert_eq!(summary.total, 2, "the record at ts=50 is before the cutoff");
        assert_eq!(summary.by_head.get("risk"), Some(&1));
        assert_eq!(summary.by_head.get("policy"), Some(&1));
        assert_eq!(summary.by_tool.get("Bash"), Some(&2));
        assert_eq!(summary.by_rule.get("SANDBOX-001"), Some(&1));
        assert_eq!(summary.by_rule.get("CERB-POL-004"), Some(&1));
    }

    #[test]
    fn export_csv_escapes_commas_and_quotes_in_reason() {
        let records = vec![sample_record(1, "risk", "reason, with a \"quote\"")];
        let csv = export_csv(&records);
        assert!(csv.contains("\"reason, with a \"\"quote\"\"\""));
    }

    #[test]
    fn export_json_round_trips_through_read_records_shape() {
        let records = vec![sample_record(1, "risk", "Blocked (SANDBOX-001): danger")];
        let json_text = export_json(&records);
        let parsed: Vec<AuditRecord> = serde_json::from_str(&json_text).unwrap();
        assert_eq!(parsed, records);
    }

    #[test]
    fn rotation_moves_the_oversized_file_out_of_the_way() {
        let paths = scratch_paths("rotate");
        let path = paths.audit_log_file();
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, "x".repeat((ROTATE_AT_BYTES + 1) as usize)).unwrap();

        rotate_if_needed(&paths).unwrap();

        assert!(!path.exists());
        assert!(paths.audit_log_rotated_file().exists());
    }
}
