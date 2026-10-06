use super::args::{AuditCommand, ExportFormat};
use crate::config::Paths;
use crate::state::audits as audit;
use crate::state::surveys;

pub fn run(paths: &Paths, action: AuditCommand) -> i32 {
    let records = match audit::read_records(paths) {
        Ok(records) => records,
        Err(e) => {
            eprintln!("couldn't read the decision database: {e}");
            return 1;
        }
    };
    match action {
        AuditCommand::Tail { lines } => {
            let start = records.len().saturating_sub(lines);
            for r in &records[start..] {
                println!(
                    "{} [{}] {} {} — {}",
                    r.ts,
                    r.head,
                    r.tool_name.as_deref().unwrap_or("?"),
                    r.decision,
                    r.reason.as_deref().unwrap_or("")
                );
            }
            0
        }
        AuditCommand::Summary { since } => {
            let Some(window) = audit::parse_duration(&since) else {
                eprintln!(
                    "couldn't parse --since '{since}' (expected e.g. \"7d\", \"12h\", \"30m\")"
                );
                return 1;
            };
            let cutoff = audit::now_secs().saturating_sub(window);
            let summary = audit::summarize(&records, cutoff);
            println!("{} blocked in the last {since}", summary.total);
            for (head, count) in &summary.by_head {
                println!("  head {head}: {count}");
            }
            for (tool, count) in &summary.by_tool {
                println!("  tool {tool}: {count}");
            }
            for (rule, count) in &summary.by_rule {
                println!("  rule {rule}: {count}");
            }
            0
        }
        AuditCommand::Decisions { rule, since } => {
            let now = audit::now_secs();
            let Some(cutoff) = window_start(since.as_deref(), now) else {
                return 1;
            };
            if let Some(rule) = rule {
                return drill_down(paths, &records, &rule, cutoff, now);
            }
            let allows = match audit::read_allows(paths) {
                Ok(allows) => allows,
                Err(e) => {
                    eprintln!("couldn't read the decision database: {e}");
                    return 1;
                }
            };
            let report = audit::group(&records, &allows, cutoff);
            println!("{} allowed, {} blocked", report.allows, report.blocks);
            for rule in &report.rules {
                println!(
                    "  rule {}: {} blocked across {} shapes, {} sessions",
                    rule.rule,
                    rule.hits,
                    rule.shapes.len(),
                    rule.sessions.len()
                );
                if let Some(file) = audit::rule_source(paths, &rule.rule) {
                    println!("    defined in {}", file.display());
                }
            }
            for (title, lines) in [("loosen", &report.loosen), ("tighten", &report.tighten)] {
                if lines.is_empty() {
                    continue;
                }
                println!("candidates to {title}:");
                for line in lines {
                    println!("  {line}");
                }
            }
            0
        }
        AuditCommand::Allows { since } => {
            let now = audit::now_secs();
            let Some(cutoff) = window_start(since.as_deref(), now) else {
                return 1;
            };
            let allows = match audit::read_allows(paths) {
                Ok(allows) => allows,
                Err(e) => {
                    eprintln!("couldn't read the decision database: {e}");
                    return 1;
                }
            };
            let home = paths.home.to_string_lossy();
            print_allows(&surveys::allows_report(
                &allows, &records, &home, cutoff, now,
            ));
            0
        }
        AuditCommand::Rules => {
            let now = audit::now_secs();
            let allows = audit::read_allows(paths).unwrap_or_default();
            let lines = surveys::rule_inventory(&surveys::declared_rules(paths), &records, 0);
            match surveys::history_days(&allows, &records, now) {
                Some(days) => println!("record covers {days} days"),
                None => println!("nothing recorded yet"),
            }
            let (fired, silent): (Vec<_>, Vec<_>) = lines.iter().partition(|l| l.hits > 0);
            println!("fired:");
            for l in fired {
                let last = l.last_hit.map(|ts| audit::ago(now, ts)).unwrap_or_default();
                println!(
                    "  {}: {} times, last {last}{}",
                    l.rule,
                    l.hits,
                    source_of(l)
                );
            }
            println!("never fired:");
            for l in silent {
                println!("  {}{}", l.rule, source_of(l));
            }
            0
        }
        AuditCommand::Export { format, out } => {
            let text = match format {
                ExportFormat::Json => audit::export_json(&records),
                ExportFormat::Csv => audit::export_csv(&records),
            };
            match audit::write_export(&text, out.as_deref()) {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("couldn't write export: {e}");
                    1
                }
            }
        }
    }
}

/// How many of a rule's newest rows `decisions <rule>` lists.
const DRILL_DOWN_LIMIT: usize = 50;

fn drill_down(
    paths: &Paths,
    records: &[audit::AuditRecord],
    rule: &str,
    cutoff: u64,
    now: u64,
) -> i32 {
    let rows = audit::for_rule(records, rule, cutoff);
    if rows.is_empty() {
        println!("no blocked calls for {rule}");
        return 0;
    }
    println!("{} blocked by {rule}", rows.len());
    if let Some(file) = audit::rule_source(paths, rule) {
        println!("defined in {}", file.display());
    }
    for r in rows.iter().take(DRILL_DOWN_LIMIT) {
        println!(
            "  {:>8}  {}  {}  {}",
            audit::ago(now, r.ts),
            r.session_id.as_deref().unwrap_or("-"),
            r.cwd.as_deref().unwrap_or("-"),
            audit::describe(r)
        );
    }
    if rows.len() > DRILL_DOWN_LIMIT {
        println!("  … and {} older", rows.len() - DRILL_DOWN_LIMIT);
    }
    0
}

/// The timestamp a `--since` window starts at: 0 when none was given, `None`
/// (after saying why) when it doesn't parse.
fn window_start(since: Option<&str>, now: u64) -> Option<u64> {
    let Some(since) = since else { return Some(0) };
    match audit::parse_duration(since) {
        Some(window) => Some(now.saturating_sub(window)),
        None => {
            eprintln!("couldn't parse --since '{since}' (expected e.g. \"7d\", \"12h\", \"30m\")");
            None
        }
    }
}

fn source_of(line: &surveys::RuleLine) -> String {
    match &line.file {
        Some(file) => format!("  ({})", file.display()),
        None => "  (no rule file)".to_string(),
    }
}

fn print_allows(r: &surveys::AllowsReport) {
    println!("{} allowed", r.total);
    println!("never blocked, but common:");
    for l in &r.unguarded {
        println!(
            "  {}: {} allowed, {} directories",
            l.shape, l.allows, l.cwds
        );
    }
    match &r.novel {
        None => println!("new commands: the record isn't older than the window yet"),
        Some(novel) => {
            println!("new commands:");
            for n in novel {
                println!("  {}: {} allowed", n.shape, n.allows);
            }
        }
    }
    println!("run from many directories:");
    for l in &r.spread {
        println!(
            "  {}: {} directories, {} allowed",
            l.shape, l.cwds, l.allows
        );
    }
    println!("run outside any project ($HOME or a system directory):");
    for l in &r.outside {
        println!(
            "  {}: {} allowed across {} directories",
            l.shape, l.allows, l.cwds
        );
    }
    println!("tools:");
    for t in &r.tools {
        let note = if t.unguarded { "  (never blocked)" } else { "" };
        println!(
            "  {}: {} allowed, {} blocked{note}",
            t.tool, t.allows, t.blocked
        );
    }
}
