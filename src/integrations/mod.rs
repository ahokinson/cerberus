//! Wrappers around the external tools two of the three heads delegate to:
//! `tirith` (`risk`, command-pattern scanning) and `cupcake` (`policy`,
//! policy evaluation). `judgement` has no entry here, since it runs
//! in-process via `rules::engine` rather than an external binary.

pub mod cupcake;
pub mod tirith;
