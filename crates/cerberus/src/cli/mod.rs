mod args;
mod audits;
mod sources;
mod trust;

use crate::config::Paths;
use crate::service::{doctors, gates, guards, healths, inits};
use crate::state::violations;
use args::{AuditCommand, SourceCommand};
use clap::{Parser, Subcommand};

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
    /// Diagnose a degraded guard, then retest it
    ///
    /// Run it in a terminal: while the guard is degraded, gate blocks the
    /// agent's own Bash tool. Runs every health probe independently, prints
    /// each result with the fix, and rewrites or clears the degraded sentinel
    /// by the same rule SessionStart uses. The sentinel is cleared only when
    /// every check passes. Exits 1 while anything is still failing.
    Doctor {
        /// Print machine-readable JSON instead of text
        #[arg(long)]
        json: bool,
    },
    /// Bootstrap config, rule scripts, and hook wiring
    ///
    /// Writes the shipped rule scripts, seeds a default config.toml,
    /// ensures cerberus's cupcake project and policy store exist, composes
    /// the tirith overlay, and wires the hook commands into Claude Code's
    /// settings.json. Safe to re-run.
    Init,
    /// Print a session's deny counts per head
    ///
    /// One `head=count` line each for risk, policy and judgement, zero for
    /// a head that never denied. Counts are kept whether or not auditing is
    /// enabled. For a statusline or script to read.
    Violations {
        /// The session id from the hook event
        session: String,
    },
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
    /// Approve this repo's .cerberus/ directory
    ///
    /// A repo can carry its own judgements/*.rhai, policies/**/*.rego and
    /// risks/*.yaml in a .cerberus/ directory at its root. None of it
    /// enforces anything until a human runs this inside the repo: it
    /// validates the directory, shows what changed since the last approval,
    /// and snapshots it. cerberus enforces that snapshot, not the live
    /// directory, so later edits (by anyone, an agent included) change
    /// nothing until `trust` is run again. If the directory has been
    /// deleted, running it withdraws the approval.
    ///
    /// A repo's own .tirith/ and .cupcake/ are never read.
    Trust,
    /// Inspect the decision record (off by default; see config.toml)
    ///
    /// Once `[audit] enabled = true`, every deny/ask decision is recorded,
    /// and every allow is counted, in
    /// ${XDG_STATE_HOME:-~/.local/state}/cerberus/cerberus.db. These
    /// subcommands read it; they don't change whether it's kept.
    Audit {
        #[command(subcommand)]
        action: AuditCommand,
    },
}

pub fn run() {
    let cli = Cli::parse();
    let paths = Paths::from_env();
    match cli.command {
        Command::Guard => guards::run(&paths),
        Command::Gate => gates::run(&paths.degraded_sentinel()),
        Command::Health => healths::run(&paths),
        Command::Doctor { json } => std::process::exit(doctors::run(&paths, json)),
        Command::Init => std::process::exit(inits::run(&paths)),
        Command::Violations { session } => match violations::read_counts(&paths, &session) {
            Ok(c) => println!(
                "risk={}\npolicy={}\njudgement={}",
                c.risk, c.policy, c.judgement
            ),
            Err(e) => {
                eprintln!("couldn't read the state database: {e}");
                std::process::exit(1);
            }
        },
        Command::Source { action } => std::process::exit(sources::run(&paths, action)),
        Command::Trust => std::process::exit(trust::run(&paths)),
        Command::Audit { action } => std::process::exit(audits::run(&paths, action)),
    }
}
