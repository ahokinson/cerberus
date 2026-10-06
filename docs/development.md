# Development

```sh
scripts/check.sh      # rustfmt, Clippy (-D warnings) and the full test suite
scripts/coverage.sh   # line coverage via cargo-llvm-cov, writes coverage/rust.lcov
cargo build
```

`nix develop` gives you the toolchain, `cargo-llvm-cov`, and tirith, cupcake
and opa, so the tests that exercise the real binaries run instead of skipping.

All three binaries are vendored in `nix/` as pinned upstream release binaries,
not taken from an upstream flake or from nixpkgs, so a build doesn't depend on
either one working. To bump one, change `version` in its file and replace the
per-platform hashes. Each upstream publishes a `.sha256` next to every asset;
convert it to SRI with `nix hash convert --hash-algo sha256 --to sri <hex>`.
After a bump, run `cerberus init` and `cerberus doctor` against the new
binaries: the canaries are what prove cupcake and opa still enforce.

For the rule-script API, and how to add a rule, a policy or a tirith rule, see
[CONTRIBUTING.md](../CONTRIBUTING.md).

## Layout

This is a Cargo workspace with one crate, `crates/cerberus`. `main.rs` is a
single call; everything else is the `cerberus` library, so tests and the fuzz target
call the same code the binary does.

```
crates/cerberus/
  rules/  policies/  templates/   # shipped content, embedded at build time
  src/
    cli/        argument parsing and one thin handler per command
    service/    what each command does: guards, gates, healths, doctors, inits
    domain/     plain types: Head, Check, hook events and verdicts
    ports/      the three seams (below)
    heads/      risk (tirith), policy (cupcake), judgement (rhai rules)
    harnesses/  claude, codex, cursor, hermes, opencode
    config/     Paths (every runtime location) and config.toml
    state/      the decision database and per-session deny counts
    sources/    layered policy sources
  tests/        binary-level tests
fuzz/           cargo-fuzz target
docs/           these pages
nix/            package.nix, plus tirith.nix, cupcake.nix and opa.nix
```

Dependencies point inward: `cli` calls `service`; `service` uses `heads`,
`harnesses`, `config`, `state` and `domain`; nothing below `service` calls up
into it. A port exists only where there are several implementations or a real
test seam:

| Port | Implemented by | Why it's a seam |
| --- | --- | --- |
| `HeadEvaluator` | `risk`, `policy`, `judgement` | `guard` walks the enabled heads in order and stops at the first answer |
| `HarnessInstaller` | one per harness | `init` and `doctor` loop over harnesses instead of repeating a block for each |
| `Environment` | the real machine, and a fake in tests | `health` and `doctor` can be tested without tirith, cupcake or opa installed |

## Tests

Unit tests sit beside the code. `crates/cerberus/tests/commands.rs` runs the
real binary against a scratch `HOME` and `XDG_*` tree with an empty `PATH`, so
it never depends on what's installed. Tests that need the real tirith, cupcake
or opa skip themselves when the binary is missing.

## Coverage

`scripts/coverage.sh` needs `cargo-llvm-cov` (`cargo install cargo-llvm-cov
--locked`, or `nix develop`). It only reports by default. Set
`COVERAGE_MIN_LINES` to fail below a threshold once there's a measured floor
to hold.

## Fuzzing

The `hook_event` target feeds arbitrary bytes through everything cerberus does
with input it doesn't control: hook event parsing, decision JSON, Cursor's
payload translation and the shell tokenizer the rules use.

```sh
rustup toolchain install nightly
cargo +nightly install cargo-fuzz --locked
cd fuzz && cargo +nightly fuzz run hook_event -- -max_total_time=60
```

`cargo-fuzz` needs nightly for its sanitizer instrumentation; the regular
toolchain stays on stable. The entry point is `crates/cerberus/src/fuzz.rs`,
compiled only under `--cfg fuzzing`.

## CI

GitHub Actions runs checks and coverage on pull requests to `develop` and
pushes to it. ClusterFuzzLite fuzzes for ten minutes on pull requests that
touch the crate, the fuzz target or its build files. CodeQL scans the Rust
sources, and the OpenSSF Scorecard workflow reports weekly. Dependabot opens
weekly update pull requests for Cargo and GitHub Actions.

Coverage uploads to Codecov only for same-repository runs, so forks never
receive the upload token. Maintainers need to add `CODECOV_TOKEN` as a
repository secret.
