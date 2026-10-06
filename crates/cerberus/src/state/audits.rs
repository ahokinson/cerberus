use super::stores::{self, AllowCount};
use crate::config;
use crate::config::Paths;
use crate::domain::Head;
use crate::domain::{bash_command, permission_decision, permission_reason, str_field, tool_name};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// One row of the `decisions` table: everything about a single deny or ask.
/// `tool_input` is echoed verbatim from the hook payload for a deny or
/// ask, trading a slightly bigger record for full forensic detail without a
/// per-tool special case here. Allows are never stored as records at all (see
/// [`record_allow`]).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AuditRecord {
    pub ts: u64,
    pub session_id: Option<String>,
    pub head: String,
    pub tool_name: Option<String>,
    pub decision: String,
    pub reason: Option<String>,
    pub tool_input: Value,
    pub harness: String,
    pub rule: Option<String>,
    pub cwd: Option<String>,
    pub shape: Option<String>,
}

/// Commands whose first non-flag argument names what they do, so
/// `git push` and `git log` are different shapes while `ls -la` and `ls` are
/// not. Anything else collapses to its program name.
const SUBCOMMAND_PROGRAMS: &[&str] = &[
    "git",
    "docker",
    "npm",
    "pnpm",
    "yarn",
    "cargo",
    "go",
    "kubectl",
    "gh",
    "nix",
    "systemctl",
    "brew",
    "pip",
    "helm",
    "terraform",
];

/// The coarse "kind" of a call: for Bash, the program (plus subcommand for
/// the programs in [`SUBCOMMAND_PROGRAMS`]), for any other tool, its name.
/// Arguments, paths and leading `VAR=value` assignments are dropped, which is
/// what makes a shape safe to keep for an allow.
pub fn shape(input: &Value) -> Option<String> {
    let Some(command) = bash_command(input) else {
        return tool_name(input).map(String::from);
    };
    let mut words = command
        .split_whitespace()
        .skip_while(|w| w.contains('=') && !w.starts_with('-'));
    let program = words.next()?;
    let program = program.rsplit('/').next().unwrap_or(program);
    if SUBCOMMAND_PROGRAMS.contains(&program)
        && let Some(sub) = words.find(|w| !w.starts_with('-'))
    {
        return Some(format!("{program} {sub}"));
    }
    Some(program.to_string())
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
/// enabled (`config::audit_enabled`; off by default, see `config/settings.rs`).
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
    let reason = permission_reason(output);
    let record = AuditRecord {
        ts: now_secs(),
        session_id: str_field(input, "session_id").map(String::from),
        head: head.name().to_string(),
        tool_name: tool_name(input).map(String::from),
        decision: permission_decision(output).unwrap_or_default(),
        rule: reason.as_deref().and_then(rule_id),
        reason,
        tool_input: input.get("tool_input").cloned().unwrap_or(Value::Null),
        harness: if is_cursor { "cursor" } else { "claude" }.to_string(),
        cwd: str_field(input, "cwd").map(String::from),
        shape: shape(input),
    };
    let _ = stores::insert_decision(paths, &record);
}

/// Counts that every enabled head allowed a call. Same contract as
/// [`record`]: off unless audit is enabled, silent on I/O errors. An allow is
/// never kept as a record: only a per-day counter of its tool, `shape` and
/// directory, so no `tool_input` (and nothing a user typed inline) is stored.
pub fn record_allow(paths: &Paths, input: &Value) {
    if !config::audit_enabled(paths) {
        return;
    }
    let _ = stores::bump_allow(
        paths,
        now_secs(),
        tool_name(input),
        shape(input).as_deref(),
        str_field(input, "cwd"),
    );
}

/// Every stored deny/ask, oldest first.
pub fn read_records(paths: &Paths) -> stores::Result<Vec<AuditRecord>> {
    stores::decisions(paths)
}

/// The per-day allow counters, for [`group`].
pub fn read_allows(paths: &Paths) -> stores::Result<Vec<AllowCount>> {
    stores::allows(paths)
}

/// Parses a simple `<n><unit>` duration (`"7d"`, `"12h"`, `"30m"`, `"90s"`)
/// into seconds. Hand-rolled rather than a pulling in a date/duration crate,
/// consistent with this codebase's stated minimalism elsewhere (see
/// `judgement::shell`'s hand-rolled tokenizer) — `cerberus audit summary` only
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
    // tirith's ids are lower-case (`curl_pipe_shell`), which the upper-case
    // convention below would reject, so the risk head tags them explicitly.
    if let Some(start) = reason.find("(rule: ")
        && let Some(len) = reason[start + 7..].find(')')
    {
        return Some(reason[start + 7..start + 7 + len].to_string());
    }
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
/// of every deny/ask row newer than a cutoff. Allows aren't rows (see
/// `stores`), and denies are realistically dozens to low hundreds a week even
/// for an active team, so the scan stays small.
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
        if let Some(id) = record_rule(record) {
            *summary.by_rule.entry(id).or_default() += 1;
        }
    }
    summary
}

/// The record's rule id: the stored one, else recovered from the reason for
/// records written before `rule` existed.
fn record_rule(record: &AuditRecord) -> Option<String> {
    record
        .rule
        .clone()
        .or_else(|| record.reason.as_deref().and_then(rule_id))
}

/// A rule needs at least this many hits, across at least
/// [`LOOSEN_MIN_SESSIONS`] sessions, on a single shape before it's called a
/// loosening candidate: one noisy afternoon isn't a pattern.
const LOOSEN_MIN_HITS: usize = 5;
const LOOSEN_MIN_SESSIONS: usize = 3;
/// A shape that is both allowed and blocked is a tightening candidate once
/// the allowed side is at least this big.
const TIGHTEN_MIN_ALLOWS: usize = 5;

#[derive(Default, Debug, PartialEq)]
pub struct RuleStat {
    pub rule: String,
    pub hits: usize,
    pub asks: usize,
    pub shapes: BTreeSet<String>,
    pub sessions: BTreeSet<String>,
}

#[derive(Default, Debug, PartialEq)]
pub struct ShapeStat {
    pub shape: String,
    pub allows: usize,
    pub blocks: usize,
}

/// What `cerberus audit decisions` prints: decisions clustered by rule and by
/// command shape, with the clusters that suggest a rule is too loose or too
/// tight called out.
#[derive(Default, Debug, PartialEq)]
pub struct Report {
    pub allows: usize,
    pub blocks: usize,
    pub rules: Vec<RuleStat>,
    pub shapes: Vec<ShapeStat>,
    pub loosen: Vec<String>,
    pub tighten: Vec<String>,
}

pub fn group(records: &[AuditRecord], allows: &[AllowCount], since_ts: u64) -> Report {
    let mut report = Report::default();
    let mut rules: BTreeMap<String, RuleStat> = BTreeMap::new();
    let mut shapes: BTreeMap<String, ShapeStat> = BTreeMap::new();
    for a in allows.iter().filter(|a| a.day >= since_ts / 86400) {
        let n = a.n as usize;
        report.allows += n;
        let shape = if a.shape.is_empty() { "?" } else { &a.shape };
        shapes
            .entry(shape.to_string())
            .or_insert_with(|| ShapeStat {
                shape: shape.to_string(),
                ..Default::default()
            })
            .allows += n;
    }
    for r in records.iter().filter(|r| r.ts >= since_ts) {
        report.blocks += 1;
        let shape = r.shape.clone().unwrap_or_else(|| "?".to_string());
        let stat = shapes.entry(shape.clone()).or_insert_with(|| ShapeStat {
            shape: shape.clone(),
            ..Default::default()
        });
        stat.blocks += 1;
        let rule = record_rule(r).unwrap_or_else(|| format!("({} head, no id)", r.head));
        let stat = rules.entry(rule.clone()).or_insert_with(|| RuleStat {
            rule,
            ..Default::default()
        });
        stat.hits += 1;
        if r.decision == "ask" {
            stat.asks += 1;
        }
        stat.shapes.insert(shape);
        if let Some(session) = &r.session_id {
            stat.sessions.insert(session.clone());
        }
    }

    for stat in rules.values() {
        if stat.hits >= LOOSEN_MIN_HITS
            && stat.sessions.len() >= LOOSEN_MIN_SESSIONS
            && stat.shapes.len() == 1
        {
            let shape = stat.shapes.iter().next().unwrap();
            let verb = if stat.asks == stat.hits {
                "asked"
            } else {
                "blocked"
            };
            report.loosen.push(format!(
                "{} {verb} {} times, always on `{shape}`, across {} sessions",
                stat.rule,
                stat.hits,
                stat.sessions.len()
            ));
        }
    }
    for stat in shapes.values() {
        if stat.blocks > 0 && stat.allows >= TIGHTEN_MIN_ALLOWS {
            report.tighten.push(format!(
                "`{}` was blocked {} times but allowed {} times",
                stat.shape, stat.blocks, stat.allows
            ));
        }
    }

    report.rules = rules.into_values().collect();
    report.rules.sort_by_key(|a| std::cmp::Reverse(a.hits));
    report.shapes = shapes.into_values().collect();
    report
        .shapes
        .sort_by_key(|a| std::cmp::Reverse(a.allows + a.blocks));
    report
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
    let mut out =
        String::from("ts,session_id,head,tool_name,decision,reason,harness,rule,cwd,shape\n");
    for r in records {
        out.push_str(&format!(
            "{},{},{},{},{},{},{},{},{},{}\n",
            r.ts,
            csv_escape(r.session_id.as_deref().unwrap_or("")),
            csv_escape(&r.head),
            csv_escape(r.tool_name.as_deref().unwrap_or("")),
            csv_escape(&r.decision),
            csv_escape(r.reason.as_deref().unwrap_or("")),
            csv_escape(&r.harness),
            csv_escape(r.rule.as_deref().unwrap_or("")),
            csv_escape(r.cwd.as_deref().unwrap_or("")),
            csv_escape(r.shape.as_deref().unwrap_or("")),
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
            ts,
            session_id: Some("s1".into()),
            head: head.into(),
            tool_name: Some("Bash".into()),
            decision: "deny".into(),
            reason: Some(reason.into()),
            tool_input: json!({"command": "rm -rf /"}),
            harness: "claude".into(),
            rule: None,
            cwd: None,
            shape: Some("rm".into()),
        }
    }

    fn enabled_paths(name: &str) -> Paths {
        let paths = scratch_paths(name);
        fs::create_dir_all(paths.config_file().parent().unwrap()).unwrap();
        fs::write(paths.config_file(), "[audit]\nenabled = true\n").unwrap();
        paths
    }

    #[test]
    fn record_is_a_no_op_when_audit_disabled() {
        let paths = scratch_paths("disabled");
        let input = json!({"session_id": "s1", "tool_name": "Bash"});
        let output = r#"{"hookSpecificOutput":{"permissionDecision":"deny","permissionDecisionReason":"nope"}}"#;
        record(&paths, Head::Risk, &input, output, false);
        assert!(read_records(&paths).unwrap().is_empty());
        assert!(!paths.database_file().exists());
    }

    #[test]
    fn record_stores_a_row_when_enabled() {
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

        let records = read_records(&paths).unwrap();
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
    fn shape_keeps_the_program_and_subcommand_but_no_arguments() {
        let bash = |c: &str| shape(&json!({"tool_name": "Bash", "tool_input": {"command": c}}));
        assert_eq!(bash("ls -la /etc"), Some("ls".into()));
        assert_eq!(bash("/usr/bin/git -C x push --force"), Some("git x".into()));
        assert_eq!(bash("git push origin main"), Some("git push".into()));
        assert_eq!(bash("TOKEN=hunter2 cargo test"), Some("cargo test".into()));
        assert_eq!(
            shape(&json!({"tool_name": "Write", "tool_input": {"file_path": "/x"}})),
            Some("Write".into())
        );
    }

    #[test]
    fn record_allow_counts_per_day_and_stores_no_input() {
        let input = json!({
            "session_id": "s1", "tool_name": "Bash", "cwd": "/work",
            "tool_input": {"command": "curl -H 'Authorization: x' https://a"},
        });
        let off = scratch_paths("allow-off");
        record_allow(&off, &input);
        assert!(!off.database_file().exists());

        let on = enabled_paths("allow-on");
        for _ in 0..3 {
            record_allow(&on, &input);
        }
        let allows = read_allows(&on).unwrap();
        assert_eq!(allows.len(), 1, "same day, tool, shape and cwd is one row");
        let a = &allows[0];
        assert_eq!(
            (a.tool_name.as_str(), a.shape.as_str(), a.cwd.as_str(), a.n),
            ("Bash", "curl", "/work", 3)
        );
        assert!(read_records(&on).unwrap().is_empty());
        let bytes = fs::read(on.database_file()).unwrap();
        assert!(
            !String::from_utf8_lossy(&bytes).contains("Authorization"),
            "an allow must not leave its input in the database"
        );
    }

    #[test]
    fn deny_records_carry_rule_and_keep_their_input() {
        let paths = enabled_paths("deny-rule");
        let input = json!({"tool_name": "Bash", "tool_input": {"command": "rm -rf build"}});
        let output = r#"{"hookSpecificOutput":{"permissionDecision":"deny","permissionDecisionReason":"Blocked (SANDBOX-001): danger"}}"#;
        record(&paths, Head::Judgement, &input, output, false);
        let r = &read_records(&paths).unwrap()[0];
        assert_eq!(r.rule.as_deref(), Some("SANDBOX-001"));
        assert_eq!(r.tool_input["command"], "rm -rf build");
        assert_eq!(r.shape.as_deref(), Some("rm"));
    }

    #[test]
    fn writes_prune_rows_past_retention() {
        let paths = enabled_paths("retention");
        let mut old = sample_record(1, "risk", "Blocked (X-1): old");
        old.tool_input = Value::Null;
        stores::insert_decision(&paths, &old).unwrap();
        stores::bump_allow(&paths, 1, Some("Bash"), Some("ls"), None).unwrap();

        let fresh = sample_record(now_secs(), "risk", "Blocked (X-1): new");
        stores::insert_decision(&paths, &fresh).unwrap();
        stores::bump_allow(&paths, now_secs(), Some("Bash"), Some("ls"), None).unwrap();

        let kept = read_records(&paths).unwrap();
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].reason.as_deref(), Some("Blocked (X-1): new"));
        assert_eq!(read_allows(&paths).unwrap().len(), 1);
    }

    #[test]
    fn concurrent_writers_all_land() {
        let paths = std::sync::Arc::new(enabled_paths("concurrent"));
        let input = json!({"tool_name": "Bash", "cwd": "/w", "tool_input": {"command": "ls"}});
        std::thread::scope(|scope| {
            for _ in 0..4 {
                scope.spawn(|| {
                    for _ in 0..10 {
                        record_allow(&paths, &input);
                    }
                });
            }
        });
        let total: u64 = read_allows(&paths).unwrap().iter().map(|a| a.n).sum();
        assert_eq!(total, 40);
    }

    #[test]
    fn rule_id_reads_the_tirith_tag() {
        assert_eq!(
            rule_id("Blocked by tirith: [HIGH] Pipe (rule: curl_pipe_shell)"),
            Some("curl_pipe_shell".to_string())
        );
    }

    #[test]
    fn group_flags_a_concentrated_rule_to_loosen_and_a_mixed_shape_to_tighten() {
        let mut records = Vec::new();
        for i in 0..5 {
            let mut r = sample_record(100, "judgement", "Blocked (GIT-001): x");
            r.session_id = Some(format!("s{i}"));
            r.shape = Some("git push".into());
            r.rule = Some("GIT-001".into());
            records.push(r);
        }
        let allows = vec![AllowCount {
            day: 0,
            tool_name: "Bash".into(),
            shape: "git push".into(),
            cwd: "/w".into(),
            n: 6,
        }];
        let report = group(&records, &allows, 0);
        assert_eq!((report.allows, report.blocks), (6, 5));
        assert_eq!(report.rules[0].rule, "GIT-001");
        assert_eq!(report.loosen.len(), 1);
        assert!(report.loosen[0].contains("GIT-001") && report.loosen[0].contains("git push"));
        assert_eq!(report.tighten.len(), 1);
        assert!(report.tighten[0].contains("git push"));
    }

    #[test]
    fn group_stays_quiet_below_the_thresholds() {
        let records = vec![sample_record(100, "risk", "Blocked (X-1): y")];
        let report = group(&records, &[], 0);
        assert!(report.loosen.is_empty() && report.tighten.is_empty());
        assert_eq!(group(&records, &[], 200).blocks, 0);
    }
}
