/// Everything `health` and `doctor` learn about the machine, behind one
/// seam: which binaries exist, which stores are installed, and what each
/// head's canary does. The real implementation shells out to tirith, cupcake
/// and opa; tests substitute a fake, so the check logic (independent probes,
/// skips, fix hints) is testable on a machine with none of them installed.
pub trait Environment {
    fn command_exists(&self, bin: &str) -> bool;

    /// Risk head: the composed overlay blocks a known-dangerous command.
    fn tirith_overlay_blocks(&self) -> bool;

    fn cupcake_project_installed(&self) -> bool;
    fn cupcake_global_installed(&self) -> bool;

    /// Policy head: cupcake blocks a halt command end to end.
    fn cupcake_blocks_halt(&self) -> bool;

    /// Policy head: cerberus's own shipped policies block a write to the
    /// rule-scripts path.
    fn cupcake_blocks_self_write(&self) -> bool;

    /// Judgement head: `None` when the rule scripts load and block the
    /// canaries, else the problem text.
    fn rule_scripts_problem(&self) -> Option<String>;
}
