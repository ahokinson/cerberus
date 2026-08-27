mod audit;
mod config;
mod embedded;
mod gate;
mod guard;
mod harness;
mod head;
mod health;
mod hook;
mod init;
mod integrations;
mod paths;
mod process;
mod rules;
mod settings;
mod sources;
mod violations;

use clap::{Parser, Subcommand, ValueEnum};
use paths::Paths;
use std::path::PathBuf;

/// A three-headed guard for Claude Code's tool calls
///
/// Each head catches a different kind of bad outcome: risk (general risk
/// avoidance), policy (governance policy), and judgement (contextual bad
/// decisions, where a call is only bad because of state nothing in the
/// payload reveals).
///
/// guard is the one command wired into PreToolUse, on the tools that change
/// something or reach the network: Bash, Write, Edit, NotebookEdit,
/// WebFetch, and MCP tools. It runs the fail-closed gate first, then
/// whichever heads are enabled in
/// ${XDG_CONFIG_HOME:-~/.config}/cerberus/config.toml, stopping at the
/// first one that responds. gate and health can also be run directly for
/// debugging.
#[derive(Parser)]
#[command(name = "cerberus", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Judge one tool call (the PreToolUse hook)
    ///
    /// Reads the hook event JSON on stdin. Runs gate, then the enabled
    /// heads in order, stopping at the first that responds. Prints the
    /// PreToolUse hook JSON on a deny or ask, and nothing on an allow.
    Guard,
    /// Run the fail-closed backstop alone
    ///
    /// Denies every guarded tool while a head is degraded. Always runs
    /// first inside guard; running it directly is mainly for debugging.
    Gate,
    /// Check that the enabled heads are enforcing (the SessionStart hook)
    ///
    /// Verifies each enabled head is doing its job rather than merely
    /// installed, using a synthetic dangerous command per head. Writes the
    /// degraded sentinel that gate reads when a check fails.
    Health,
    /// Bootstrap config, rule scripts, and hook wiring
    ///
    /// Writes the shipped rule scripts, seeds a default config.toml,
    /// ensures the cupcake stub project exists, and wires the hook commands
    /// into Claude Code's settings.json. Safe to re-run.
    Init,
    /// Manage layered policy sources (a team repo, cerberus-examples, ...)
    ///
    /// A source is a named, independently syncable git repo of
    /// rules/*.rhai and/or policies/*.rego that stacks on top of your
    /// personal rules. `add` clones and pins a commit; a plain `cerberus
    /// guard`/`cerberus init` never touches the network — only `sync` does.
    Source {
        #[command(subcommand)]
        action: SourceCommand,
    },
    /// Inspect the structured audit log (off by default; see config.toml)
    ///
    /// Once `[audit] enabled = true`, every deny/ask decision is recorded
    /// to ${XDG_STATE_HOME:-~/.local/state}/guard/audit.jsonl. These
    /// subcommands read that log; they don't change whether it's kept.
    Audit {
        #[command(subcommand)]
        action: AuditCommand,
    },
}

#[derive(Subcommand)]
enum SourceCommand {
    /// Clone a policy source, install it, and pin its resolved commit
    Add {
        /// A short name for this source (lowercase letters, digits, '-', '_')
        name: String,
        /// The git URL to clone
        git: String,
        /// Branch or tag to track (default: the remote's default branch)
        #[arg(long)]
        r#ref: Option<String>,
    },
    /// Remove a configured source and its installed rules/policies
    Remove {
        /// The source's name, as given to `add`
        name: String,
    },
    /// List configured sources
    List,
    /// Check for (and, with --yes, apply) updates
    ///
    /// Without --yes, fetches and shows any pending update's commit log and
    /// diffstat without changing anything on disk. With --yes, applies it:
    /// reinstalls the source's rules/policies and updates the pinned commit
    /// in config.toml.
    Sync {
        /// Only sync this source (default: every configured source)
        name: Option<String>,
        /// Apply a pending update instead of only reporting it
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum AuditCommand {
    /// Show the most recent audit log entries
    Tail {
        #[arg(short = 'n', long, default_value_t = 20)]
        lines: usize,
    },
    /// Summarize deny/ask decisions over a time window
    Summary {
        /// How far back to look, e.g. "7d", "12h", "30m"
        #[arg(long, default_value = "7d")]
        since: String,
    },
    /// Export the full audit log
    Export {
        #[arg(long, value_enum, default_value_t = ExportFormat::Json)]
        format: ExportFormat,
        /// Write to this file instead of stdout
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

#[derive(Clone, ValueEnum)]
enum ExportFormat {
    Json,
    Csv,
}

fn main() {
    let cli = Cli::parse();
    let paths = Paths::from_env();
    match cli.command {
        Command::Guard => guard::run(&paths),
        Command::Gate => gate::run(&paths.degraded_sentinel()),
        Command::Health => health::run(&paths),
        Command::Init => std::process::exit(init::run(&paths)),
        Command::Source { action } => std::process::exit(run_source(&paths, action)),
        Command::Audit { action } => std::process::exit(run_audit(&paths, action)),
    }
}

/// Surfaces the one `RegoCheck` outcome that isn't self-evident from the
/// success message alone: content installed without `opa` on hand to check
/// it. `NotApplicable`/`Passed` need no comment.
fn warn_if_rego_unvalidated(check: sources::RegoCheck) {
    if check == sources::RegoCheck::Skipped {
        eprintln!(
            "  warning: opa not on PATH, so this source's .rego policies were installed unvalidated"
        );
    }
}

fn run_source(paths: &Paths, action: SourceCommand) -> i32 {
    match action {
        SourceCommand::Add { name, git, r#ref } => {
            match sources::add(paths, &name, &git, r#ref.as_deref()) {
                Ok(sources::AddOutcome { source, rego_check }) => {
                    println!(
                        "source '{}' added: {}{}",
                        source.name,
                        source.git,
                        source
                            .pinned
                            .as_deref()
                            .map(|p| format!(" @ {p}"))
                            .unwrap_or_default()
                    );
                    warn_if_rego_unvalidated(rego_check);
                    0
                }
                Err(e) => {
                    eprintln!("couldn't add source '{name}': {e}");
                    1
                }
            }
        }
        SourceCommand::Remove { name } => match sources::remove(paths, &name) {
            Ok(true) => {
                println!("source '{name}' removed");
                0
            }
            Ok(false) => {
                println!("no source named '{name}'");
                1
            }
            Err(e) => {
                eprintln!("couldn't remove source '{name}': {e}");
                1
            }
        },
        SourceCommand::List => {
            let configured = sources::list(paths);
            if configured.is_empty() {
                println!("no policy sources configured");
            }
            for s in configured {
                println!(
                    "{}  {}{}{}",
                    s.name,
                    s.git,
                    s.git_ref
                        .as_deref()
                        .map(|r| format!(" @ {r}"))
                        .unwrap_or_default(),
                    s.pinned
                        .as_deref()
                        .map(|p| format!(" (pinned {p})"))
                        .unwrap_or_default(),
                );
            }
            0
        }
        SourceCommand::Sync { name, yes } => {
            let results = sources::sync(paths, name.as_deref(), yes);
            if results.is_empty() {
                eprintln!("no matching policy source configured");
                return 1;
            }
            let mut exit_code = 0;
            for r in results {
                match r.status {
                    sources::SyncStatus::UpToDate => println!("{}: up to date", r.name),
                    sources::SyncStatus::Applied {
                        from,
                        to,
                        rego_check,
                    } => {
                        println!(
                            "{}: updated {} -> {to}",
                            r.name,
                            from.as_deref().unwrap_or("(none)")
                        );
                        warn_if_rego_unvalidated(rego_check);
                    }
                    sources::SyncStatus::PendingConfirmation {
                        from,
                        to,
                        log,
                        diffstat,
                    } => {
                        exit_code = 1;
                        println!(
                            "{}: update available {} -> {to}",
                            r.name,
                            from.as_deref().unwrap_or("(none)")
                        );
                        if !log.is_empty() {
                            println!("{log}");
                        }
                        if !diffstat.is_empty() {
                            println!("{diffstat}");
                        }
                        println!("  (run `cerberus source sync {} --yes` to apply)", r.name);
                    }
                    sources::SyncStatus::Failed(e) => {
                        exit_code = 1;
                        eprintln!("{}: {e}", r.name);
                    }
                }
            }
            exit_code
        }
    }
}

fn run_audit(paths: &Paths, action: AuditCommand) -> i32 {
    match action {
        AuditCommand::Tail { lines } => {
            let records = audit::read_records(paths);
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
            let records = audit::read_records(paths);
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
        AuditCommand::Export { format, out } => {
            let records = audit::read_records(paths);
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
