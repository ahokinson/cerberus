# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1]

### Fixed

- The `git-safety` force-push test fixtures no longer depend on the ambient
  `init.defaultBranch`. They pushed to a branch named `main` while letting
  the bare fixture remote take its initial branch from whatever gitconfig
  was in scope, so the suite passed only where that default was already
  `main` and failed on a clean checkout, in CI, and under Nix.

## [0.1.0]

Initial release.

### Added

- `cerberus guard`, the `PreToolUse` hook command. Runs the fail-closed
  `gate`, then the enabled heads in fixed order, stopping at the first that
  responds.
- Three heads: `risk` (command-pattern scanning via tirith), `policy`
  (policy evaluation via cupcake), and `judgement` (Rhai-scripted
  situational checks).
- `cerberus health`, the `SessionStart` check. Verifies each enabled head is
  enforcing, using a synthetic `rm -rf /` against cupcake and a synthetic
  `dangerouslyDisableSandbox: true` against the rule scripts, and writes a
  degraded sentinel when something is wrong.
- `cerberus gate`, the fail-closed backstop that denies all Bash while the
  sentinel exists.
- `cerberus init`, which writes the shipped rule scripts, seeds
  `config.toml`, creates the cupcake stub project, and wires both hooks into
  `~/.claude/settings.json`. Idempotent.
- Four shipped rule scripts: `git-safety`, `environment-awareness`,
  `release-hygiene`, and `sandbox-integrity`.
- Per-head enable/disable via
  `${XDG_CONFIG_HOME:-$HOME/.config}/cerberus/config.toml`.
- Per-session deny counts written to
  `${XDG_STATE_HOME:-$HOME/.local/state}/guard/violations-<session_id>.state`
  for pharos's statusline.

[Unreleased]: https://github.com/ahokinson/cerberus/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/ahokinson/cerberus/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/ahokinson/cerberus/releases/tag/v0.1.0
