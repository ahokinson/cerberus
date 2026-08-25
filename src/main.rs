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
mod violations;

use clap::{Parser, Subcommand};
use paths::Paths;

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
}

fn main() {
    let cli = Cli::parse();
    let paths = Paths::from_env();
    match cli.command {
        Command::Guard => guard::run(&paths),
        Command::Gate => gate::run(&paths.degraded_sentinel()),
        Command::Health => health::run(&paths),
        Command::Init => std::process::exit(init::run(&paths)),
    }
}
