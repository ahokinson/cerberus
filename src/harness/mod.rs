//! Adapters for guarding harnesses whose hook mechanism isn't shaped like
//! Claude Code's. Codex CLI needs none of this — its wire format already
//! matches Claude's exactly, byte for byte (see `settings::install_hooks`,
//! shared verbatim) — so this module currently holds only Cursor's.

pub mod cursor;
