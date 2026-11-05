#!/bin/bash
# mutation_test.sh — runs mutation testing with cargo-mutants.
set -e

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

if ! command -v cargo-mutants &> /dev/null; then
    echo "Installing cargo-mutants..."
    cargo install cargo-mutants
fi

echo "Running mutation tests on agent-core..."
cargo mutants --package agent-core --no-shuffle 2>&1 | tee mutation_results.txt
echo "Done. Results in mutation_results.txt"
