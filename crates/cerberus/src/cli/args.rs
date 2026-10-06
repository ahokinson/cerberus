use clap::{Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum SourceCommand {
    /// Clone a policy source, install it, and pin its resolved commit
    ///
    /// Takes a GitHub owner/repo slug or any git URL:
    ///
    ///   cerberus source add ahokinson/cerberus-rules
    ///   cerberus source add gh:myorg/policies --ref v1.2.0
    ///   cerberus source add https://gitlab.example.com/team/policies.git
    ///
    /// The source's name is the repository's, unless --name says otherwise.
    /// The older two-argument form (`add <name> <git-url>`) still works.
    Add {
        /// An owner/repo slug, a git URL, or — in the two-argument form —
        /// the source's name
        spec: String,
        /// The git URL to clone, when naming the source explicitly
        git: Option<String>,
        /// Branch or tag to track (default: the remote's default branch)
        #[arg(long)]
        r#ref: Option<String>,
        /// Override the source name (lowercase letters, digits, '-', '_')
        #[arg(long)]
        name: Option<String>,
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
pub enum AuditCommand {
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
    /// Group decisions by rule and command shape to guide tightening or loosening
    ///
    /// Lists the rules that block most, with the file that defines each, then
    /// rules that block one command shape repeatedly across sessions
    /// (candidates to loosen), then shapes that are blocked in some forms but
    /// still allowed often (candidates to tighten). Give a rule id to see the
    /// calls it actually stopped, newest first. Needs `[audit] enabled = true`.
    Decisions {
        /// A rule id from the report, e.g. SANDBOX-001, to list its blocked calls
        rule: Option<String>,
        /// Only look this far back, e.g. "7d", "12h" (default: everything kept)
        #[arg(long)]
        since: Option<String>,
    },
    /// Survey what was allowed: unguarded, new, spread out, or outside a project
    ///
    /// Reads the counters kept for every allowed call. Lists common shell
    /// commands no rule has ever stopped, commands first seen recently
    /// (the last 7 days unless --since says otherwise), commands run from
    /// many directories or from $HOME or a system directory, and how often
    /// each tool ran, flagging tools that were never blocked. Needs
    /// `[audit] enabled = true`.
    Allows {
        /// Only count this far back, e.g. "7d", "12h" (default: everything kept)
        #[arg(long)]
        since: Option<String>,
    },
    /// List every rule with how often it fired, and which never have
    ///
    /// Reads the rule scripts, policies and tirith fragments on disk and
    /// compares them to the deny record, so a rule that never fires stands
    /// out, as does one that fires constantly. Prints how many days the
    /// record covers, since "never fired" means little over a short span.
    Rules,
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
pub enum ExportFormat {
    Json,
    Csv,
}
