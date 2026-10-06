//! Reads of the decision record that look past what was blocked: what ran
//! unchecked (`audit allows`) and which rules never earn their keep
//! (`audit rules`). Pure functions over the rows `stores` returns, so the
//! thresholds are testable without a database.

use super::audits::{AuditRecord, looks_like_rule_id, record_rule};
use super::stores::AllowCount;
use crate::config::Paths;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

const SECS_PER_DAY: u64 = 86400;

/// A shape allowed at least this often and never blocked is worth a look.
const UNGUARDED_MIN_ALLOWS: u64 = 20;
/// A shape run from at least this many directories counts as widely spread.
const SPREAD_MIN_CWDS: usize = 3;
/// How far back "new" reaches when the caller gives no window.
const NOVELTY_DEFAULT_SECS: u64 = 7 * SECS_PER_DAY;
/// Rows per section.
pub const LIST_LIMIT: usize = 10;
/// How deep [`declared_rules`] looks under each rule directory.
const SEARCH_DEPTH: usize = 4;

/// Directories a project is never in; an allowed command run from one of
/// these (or from `$HOME` itself) was running outside any project.
const SYSTEM_PREFIXES: &[&str] = &[
    "/etc", "/usr", "/var", "/opt", "/boot", "/root", "/sys", "/proc", "/dev",
];

#[derive(Debug, PartialEq)]
pub struct ShapeLine {
    pub shape: String,
    pub allows: u64,
    pub cwds: usize,
}

#[derive(Debug, PartialEq)]
pub struct NewShape {
    pub shape: String,
    pub first_day: u64,
    pub allows: u64,
}

#[derive(Debug, PartialEq)]
pub struct ToolLine {
    pub tool: String,
    pub allows: u64,
    pub blocked: u64,
    /// Never blocked, in any period.
    pub unguarded: bool,
}

#[derive(Default, Debug, PartialEq)]
pub struct AllowsReport {
    pub total: u64,
    /// Common shell shapes that no rule has ever stopped.
    pub unguarded: Vec<ShapeLine>,
    /// Shapes first seen inside the window. `None` when the record is no
    /// older than the window, since then everything would be "new".
    pub novel: Option<Vec<NewShape>>,
    /// Shapes run from the most distinct directories.
    pub spread: Vec<ShapeLine>,
    /// Shapes run from `$HOME` itself or a system directory.
    pub outside: Vec<ShapeLine>,
    pub tools: Vec<ToolLine>,
}

fn is_shell(tool: &str) -> bool {
    tool.is_empty() || tool == "Bash"
}

fn is_outside_project(cwd: &str, home: &str) -> bool {
    if cwd.is_empty() {
        return false;
    }
    let cwd = cwd.trim_end_matches('/');
    cwd.is_empty()
        || (!home.is_empty() && cwd == home.trim_end_matches('/'))
        || SYSTEM_PREFIXES
            .iter()
            .any(|p| cwd == *p || cwd.starts_with(&format!("{p}/")))
}

fn top<T>(mut lines: Vec<T>, key: impl Fn(&T) -> u64) -> Vec<T> {
    lines.sort_by_key(|l| std::cmp::Reverse(key(l)));
    lines.truncate(LIST_LIMIT);
    lines
}

/// `since_ts` windows the counts (0 = everything kept). "Blocked" and "new"
/// look at the whole record instead, because a shape blocked last month is
/// not unguarded and one first seen last month is not new.
pub fn allows_report(
    allows: &[AllowCount],
    records: &[AuditRecord],
    home: &str,
    since_ts: u64,
    now: u64,
) -> AllowsReport {
    let window_day = since_ts / SECS_PER_DAY;
    let blocked_shapes: BTreeSet<&str> =
        records.iter().filter_map(|r| r.shape.as_deref()).collect();
    let mut blocked_by_tool: BTreeMap<&str, u64> = BTreeMap::new();
    for r in records.iter().filter(|r| r.ts >= since_ts) {
        *blocked_by_tool
            .entry(r.tool_name.as_deref().unwrap_or(""))
            .or_default() += 1;
    }
    let ever_blocked_tools: BTreeSet<&str> = records
        .iter()
        .filter_map(|r| r.tool_name.as_deref())
        .collect();

    let novelty_start = if since_ts == 0 {
        now.saturating_sub(NOVELTY_DEFAULT_SECS)
    } else {
        since_ts
    } / SECS_PER_DAY;
    let oldest_day = allows.iter().map(|a| a.day).min();

    #[derive(Default)]
    struct Acc {
        allows: u64,
        cwds: BTreeSet<String>,
        outside_allows: u64,
        outside_cwds: BTreeSet<String>,
        first_day: u64,
        recent_allows: u64,
    }
    let mut shapes: BTreeMap<&str, Acc> = BTreeMap::new();
    let mut tools: BTreeMap<&str, u64> = BTreeMap::new();
    let mut report = AllowsReport::default();

    for a in allows {
        let in_window = a.day >= window_day;
        if in_window {
            report.total += a.n;
            *tools.entry(&a.tool_name).or_default() += a.n;
        }
        if !is_shell(&a.tool_name) || a.shape.is_empty() {
            continue;
        }
        let acc = shapes.entry(&a.shape).or_insert_with(|| Acc {
            first_day: u64::MAX,
            ..Default::default()
        });
        acc.first_day = acc.first_day.min(a.day);
        if a.day >= novelty_start {
            acc.recent_allows += a.n;
        }
        if in_window {
            acc.allows += a.n;
            acc.cwds.insert(a.cwd.clone());
            if is_outside_project(&a.cwd, home) {
                acc.outside_allows += a.n;
                acc.outside_cwds.insert(a.cwd.clone());
            }
        }
    }

    report.unguarded = top(
        shapes
            .iter()
            .filter(|(s, a)| a.allows >= UNGUARDED_MIN_ALLOWS && !blocked_shapes.contains(*s))
            .map(|(s, a)| ShapeLine {
                shape: s.to_string(),
                allows: a.allows,
                cwds: a.cwds.len(),
            })
            .collect(),
        |l| l.allows,
    );

    report.novel = oldest_day.filter(|d| *d < novelty_start).map(|_| {
        top(
            shapes
                .iter()
                .filter(|(_, a)| a.first_day >= novelty_start)
                .map(|(s, a)| NewShape {
                    shape: s.to_string(),
                    first_day: a.first_day,
                    allows: a.recent_allows,
                })
                .collect(),
            |l| l.allows,
        )
    });

    report.spread = top(
        shapes
            .iter()
            .filter(|(_, a)| a.cwds.len() >= SPREAD_MIN_CWDS)
            .map(|(s, a)| ShapeLine {
                shape: s.to_string(),
                allows: a.allows,
                cwds: a.cwds.len(),
            })
            .collect(),
        |l| l.cwds as u64,
    );

    report.outside = top(
        shapes
            .iter()
            .filter(|(_, a)| a.outside_allows > 0)
            .map(|(s, a)| ShapeLine {
                shape: s.to_string(),
                allows: a.outside_allows,
                cwds: a.outside_cwds.len(),
            })
            .collect(),
        |l| l.allows,
    );

    report.tools = top(
        tools
            .iter()
            .map(|(t, n)| ToolLine {
                tool: if t.is_empty() { "Bash" } else { t }.to_string(),
                allows: *n,
                blocked: blocked_by_tool.get(t).copied().unwrap_or(0),
                unguarded: !ever_blocked_tools.contains(t),
            })
            .collect(),
        |l| l.allows,
    );
    report
}

/// One rule, as known from its file and from the record.
#[derive(Debug, PartialEq)]
pub struct RuleLine {
    pub rule: String,
    /// `None` for a rule seen in the record with no file of its own, such as
    /// one of tirith's built-ins.
    pub file: Option<PathBuf>,
    pub hits: usize,
    pub last_hit: Option<u64>,
}

fn walk(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut paths: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
    paths.sort();
    for path in paths {
        if path.is_dir() {
            if depth > 0 {
                walk(&path, depth - 1, out);
            }
        } else {
            out.push(path);
        }
    }
}

/// Rhai rules name themselves in their deny text, `"Blocked (ENV-001): …"`.
fn rhai_ids(text: &str) -> Vec<String> {
    let mut ids = Vec::new();
    let mut rest = text;
    while let Some(open) = rest.find('(') {
        let after = &rest[open + 1..];
        let Some(close) = after.find(')') else { break };
        if looks_like_rule_id(&after[..close]) {
            ids.push(after[..close].to_string());
        }
        rest = after;
    }
    ids
}

/// Rego rules carry `"rule_id": "CERB-POL-001"` in their decision object.
fn rego_ids(text: &str) -> Vec<String> {
    text.split("rule_id")
        .skip(1)
        .filter_map(|tail| {
            let value = tail.split_once(':')?.1;
            let start = value.find('"')? + 1;
            let len = value[start..].find('"')?;
            Some(value[start..start + len].to_string())
        })
        .collect()
}

/// tirith custom rules are `- id: name` entries.
fn yaml_ids(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim_start().trim_start_matches("- ").trim_start();
            let value = line.strip_prefix("id:")?.trim();
            let value = value.trim_matches(|c| c == '"' || c == '\'');
            (!value.is_empty()).then(|| value.to_string())
        })
        .collect()
}

/// Every rule defined under the rule directories: Rhai scripts, Rego
/// policies and tirith fragments, sources included. First file wins when two
/// define the same id.
pub fn declared_rules(paths: &Paths) -> Vec<(String, PathBuf)> {
    type Extract = fn(&str) -> Vec<String>;
    let roots: [(PathBuf, &[&str], Extract); 3] = [
        (paths.rule_scripts_dir(), &["rhai"], rhai_ids),
        (paths.cupcake_policies_dir(), &["rego"], rego_ids),
        (paths.tirith_fragments_dir(), &["yaml", "yml"], yaml_ids),
    ];
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for (dir, exts, extract) in roots {
        let mut files = Vec::new();
        walk(&dir, SEARCH_DEPTH, &mut files);
        for file in files {
            let ext = file.extension().and_then(|e| e.to_str()).unwrap_or("");
            if !exts.contains(&ext) {
                continue;
            }
            let Ok(text) = fs::read_to_string(&file) else {
                continue;
            };
            for id in extract(&text) {
                if seen.insert(id.clone()) {
                    out.push((id, file.clone()));
                }
            }
        }
    }
    out
}

/// Every declared rule plus every rule that has fired, with how often and
/// how recently. Most-fired first, then alphabetical.
pub fn rule_inventory(
    declared: &[(String, PathBuf)],
    records: &[AuditRecord],
    since_ts: u64,
) -> Vec<RuleLine> {
    let mut lines: BTreeMap<String, RuleLine> = declared
        .iter()
        .map(|(id, file)| {
            (
                id.clone(),
                RuleLine {
                    rule: id.clone(),
                    file: Some(file.clone()),
                    hits: 0,
                    last_hit: None,
                },
            )
        })
        .collect();
    for r in records.iter().filter(|r| r.ts >= since_ts) {
        let Some(id) = record_rule(r) else { continue };
        let line = lines.entry(id.clone()).or_insert_with(|| RuleLine {
            rule: id,
            file: None,
            hits: 0,
            last_hit: None,
        });
        line.hits += 1;
        line.last_hit = line.last_hit.max(Some(r.ts));
    }
    let mut lines: Vec<RuleLine> = lines.into_values().collect();
    lines.sort_by(|a, b| b.hits.cmp(&a.hits).then_with(|| a.rule.cmp(&b.rule)));
    lines
}

/// How many days the record reaches back, from its oldest row of any kind:
/// what makes "never fired" mean something.
pub fn history_days(allows: &[AllowCount], records: &[AuditRecord], now: u64) -> Option<u64> {
    let oldest = allows
        .iter()
        .map(|a| a.day * SECS_PER_DAY)
        .chain(records.iter().map(|r| r.ts))
        .min()?;
    Some(now.saturating_sub(oldest) / SECS_PER_DAY)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const NOW: u64 = 100 * SECS_PER_DAY;

    fn allow(day: u64, tool: &str, shape: &str, cwd: &str, n: u64) -> AllowCount {
        AllowCount {
            day,
            tool_name: tool.into(),
            shape: shape.into(),
            cwd: cwd.into(),
            n,
        }
    }

    fn block(ts: u64, tool: &str, shape: &str, rule: &str) -> AuditRecord {
        AuditRecord {
            ts,
            session_id: Some("s".into()),
            head: "judgement".into(),
            tool_name: Some(tool.into()),
            decision: "deny".into(),
            reason: Some(format!("Blocked ({rule}): x")),
            tool_input: Value::Null,
            harness: "claude".into(),
            rule: Some(rule.into()),
            cwd: None,
            shape: Some(shape.into()),
        }
    }

    #[test]
    fn unguarded_lists_busy_shapes_nothing_ever_blocked() {
        let allows = vec![
            allow(90, "Bash", "curl", "/w", 30),
            allow(90, "Bash", "git push", "/w", 40),
            allow(90, "Bash", "ls", "/w", 5),
        ];
        let records = vec![block(1, "Bash", "git push", "G-1")];
        let r = allows_report(&allows, &records, "/home/u", 0, NOW);
        let names: Vec<_> = r.unguarded.iter().map(|l| l.shape.as_str()).collect();
        assert_eq!(names, vec!["curl"], "git push was blocked, ls is rare");
    }

    #[test]
    fn novelty_needs_history_older_than_the_window() {
        let fresh_only = vec![allow(99, "Bash", "ls", "/w", 1)];
        assert_eq!(allows_report(&fresh_only, &[], "", 0, NOW).novel, None);

        let allows = vec![
            allow(10, "Bash", "ls", "/w", 5),
            allow(99, "Bash", "ls", "/w", 5),
            allow(98, "Bash", "terraform apply", "/w", 3),
        ];
        let novel = allows_report(&allows, &[], "", 0, NOW).novel.unwrap();
        assert_eq!(
            novel,
            vec![NewShape {
                shape: "terraform apply".into(),
                first_day: 98,
                allows: 3
            }],
            "ls was seen long before the window"
        );
    }

    #[test]
    fn spread_and_outside_project_use_directories() {
        let allows = vec![
            allow(90, "Bash", "make", "/a", 1),
            allow(90, "Bash", "make", "/b", 1),
            allow(90, "Bash", "make", "/c", 1),
            allow(90, "Bash", "make", "/d", 1),
            allow(90, "Bash", "cat", "/home/u", 4),
            allow(90, "Bash", "cat", "/etc/nginx", 2),
            allow(90, "Bash", "cat", "/home/u/proj", 9),
        ];
        let r = allows_report(&allows, &[], "/home/u", 0, NOW);
        assert_eq!(r.spread[0].shape, "make");
        assert_eq!(r.spread[0].cwds, 4);
        assert_eq!(r.outside.len(), 1);
        assert_eq!(
            (r.outside[0].shape.as_str(), r.outside[0].allows),
            ("cat", 6)
        );
    }

    #[test]
    fn tool_inventory_counts_non_shell_tools_and_flags_the_unguarded() {
        let allows = vec![
            allow(90, "Bash", "ls", "/w", 10),
            allow(90, "Write", "Write", "/w", 7),
            allow(90, "mcp__db__query", "mcp__db__query", "/w", 50),
        ];
        let records = vec![block(1, "Write", "Write", "W-1")];
        let r = allows_report(&allows, &records, "", 0, NOW);
        let by: BTreeMap<_, _> = r.tools.iter().map(|t| (t.tool.as_str(), t)).collect();
        assert_eq!(r.total, 67);
        assert_eq!(r.tools[0].tool, "mcp__db__query");
        assert!(by["mcp__db__query"].unguarded);
        assert!(!by["Write"].unguarded);
        assert_eq!(by["Write"].blocked, 1);
        assert!(r.unguarded.iter().all(|l| l.shape != "Write"), "shell only");
    }

    #[test]
    fn the_window_limits_counts_but_not_what_counts_as_blocked() {
        let allows = vec![
            allow(10, "Bash", "curl", "/w", 50),
            allow(95, "Bash", "curl", "/w", 25),
        ];
        let r = allows_report(&allows, &[], "", 90 * SECS_PER_DAY, NOW);
        assert_eq!(r.total, 25);
        let old_block = vec![block(1, "Bash", "curl", "C-1")];
        assert!(
            allows_report(&allows, &old_block, "", 0, NOW)
                .unguarded
                .is_empty()
        );
    }

    #[test]
    fn ids_are_extracted_per_file_kind() {
        assert_eq!(
            rhai_ids(r#""Blocked (ENV-001): x" + (cmd) + "(not an id)""#),
            vec!["ENV-001"]
        );
        assert_eq!(
            rego_ids(r#"{"rule_id": "CERB-POL-001", "reason": "r"}"#),
            vec!["CERB-POL-001"]
        );
        assert_eq!(
            yaml_ids("custom_rules:\n  - id: my-rule\n    pattern: x\n  - id: \"other\"\n"),
            vec!["my-rule", "other"]
        );
    }

    #[test]
    fn inventory_marks_rules_that_never_fired_and_keeps_unfiled_ones() {
        let declared = vec![
            ("A-1".to_string(), PathBuf::from("a.rhai")),
            ("B-1".to_string(), PathBuf::from("b.rhai")),
        ];
        let records = vec![
            block(50, "Bash", "x", "A-1"),
            block(80, "Bash", "x", "A-1"),
            block(60, "Bash", "x", "curl_pipe_shell"),
        ];
        let lines = rule_inventory(&declared, &records, 0);
        let got: Vec<_> = lines.iter().map(|l| (l.rule.as_str(), l.hits)).collect();
        assert_eq!(got, vec![("A-1", 2), ("curl_pipe_shell", 1), ("B-1", 0)]);
        assert_eq!(lines[0].last_hit, Some(80));
        assert_eq!(lines[1].file, None);
        assert_eq!(rule_inventory(&declared, &records, 70)[0].hits, 1);
    }

    #[test]
    fn declared_rules_reads_every_rule_directory() {
        let root =
            std::env::temp_dir().join(format!("cerberus-survey-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let paths = Paths {
            state_home: root.join("state"),
            data_home: root.join("data"),
            config_home: root.join("config"),
            cache_home: root.join("cache"),
            home: root.join("home"),
        };
        fs::create_dir_all(paths.rule_scripts_dir().join("sources/t")).unwrap();
        fs::write(
            paths.rule_scripts_dir().join("a.rhai"),
            r#""Blocked (A-1): x""#,
        )
        .unwrap();
        fs::write(
            paths.rule_scripts_dir().join("sources/t/b.rhai"),
            r#""Blocked (A-1): dup" "Blocked (B-1): y""#,
        )
        .unwrap();
        fs::create_dir_all(paths.cupcake_policies_dir()).unwrap();
        fs::write(
            paths.cupcake_policies_dir().join("p.rego"),
            r#""rule_id": "CERB-POL-9""#,
        )
        .unwrap();
        fs::create_dir_all(paths.tirith_fragments_dir()).unwrap();
        fs::write(
            paths.tirith_fragments_dir().join("t.yaml"),
            "- id: frag-rule\n",
        )
        .unwrap();

        let ids: Vec<_> = declared_rules(&paths)
            .into_iter()
            .map(|(id, _)| id)
            .collect();
        assert_eq!(ids, vec!["A-1", "B-1", "CERB-POL-9", "frag-rule"]);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn history_days_spans_from_the_oldest_row() {
        let allows = vec![allow(90, "Bash", "ls", "/w", 1)];
        let records = vec![block(80 * SECS_PER_DAY, "Bash", "x", "A-1")];
        assert_eq!(history_days(&allows, &records, NOW), Some(20));
        assert_eq!(history_days(&[], &[], NOW), None);
    }
}
