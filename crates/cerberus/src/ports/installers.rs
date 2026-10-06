use crate::config::Paths;
use crate::domain::Check;

/// One agent harness cerberus can guard: how to tell it's present, how to
/// wire the guard into it, and how to verify that wiring later.
/// Implemented once per harness in `harnesses`; `init` loops over them
/// instead of repeating a detect-install-report block for each.
pub trait HarnessInstaller {
    /// Whether `init` should wire this harness: it's installed on this machine.
    fn detected(&self, paths: &Paths) -> bool;

    /// The line `init` prints when `detected` is false.
    fn skipped(&self) -> &'static str;

    /// Writes the wiring, printing one line per artifact as it goes.
    /// Returns the problems that should make `init` exit non-zero.
    fn install(&self, paths: &Paths) -> Vec<String>;

    /// Whether `doctor` should expect the wiring to exist. Defaults to
    /// [`HarnessInstaller::detected`]; a harness whose hooks matter even
    /// when its binary isn't on this shell's PATH overrides it.
    fn expected(&self, paths: &Paths) -> bool {
        self.detected(paths)
    }

    /// `doctor`'s verdict on the existing wiring. Never degrades the guard.
    fn check(&self, paths: &Paths) -> Check;
}
