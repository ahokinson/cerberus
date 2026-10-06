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
