#!/bin/sh
# Everything CI's Check job runs, in the order a failure is cheapest to find.
set -eu

cd "$(dirname "$0")/.."

cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
