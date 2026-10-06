use super::args::{AuditCommand, ExportFormat};
use crate::config::Paths;
use crate::state::audits as audit;

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
        AuditCommand::Decisions => {
            let allows = match audit::read_allows(paths) {
                Ok(allows) => allows,
                Err(e) => {
                    eprintln!("couldn't read the decision database: {e}");
                    return 1;
                }
            };
            let report = audit::group(&records, &allows, 0);
            println!("{} allowed, {} blocked", report.allows, report.blocks);
            for rule in &report.rules {
                println!(
                    "  rule {}: {} blocked across {} shapes, {} sessions",
                    rule.rule,
                    rule.hits,
                    rule.shapes.len(),
                    rule.sessions.len()
                );
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
