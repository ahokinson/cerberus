#!/bin/sh
# Line coverage via cargo-llvm-cov. Writes coverage/rust.lcov for Codecov.
#
# Set COVERAGE_MIN_LINES to fail below a threshold (a percentage, e.g. 80).
# Unset, the run only reports; set it once the project has a measured floor
# to ratchet from.
set -eu

cd "$(dirname "$0")/.."
mkdir -p coverage

if [ -n "${COVERAGE_MIN_LINES:-}" ]; then
  cargo llvm-cov --workspace --fail-under-lines "$COVERAGE_MIN_LINES" \
    --lcov --output-path coverage/rust.lcov
else
  cargo llvm-cov --workspace --lcov --output-path coverage/rust.lcov
fi
cargo llvm-cov report
