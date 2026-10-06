#!/bin/bash -eu

cd "$SRC/cerberus"
cargo fuzz build -O

for target in fuzz/fuzz_targets/*.rs; do
  name="$(basename "${target%.rs}")"
  cp "fuzz/target/x86_64-unknown-linux-gnu/release/$name" "$OUT/$name"
done
