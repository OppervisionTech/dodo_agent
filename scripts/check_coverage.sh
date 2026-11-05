#!/bin/bash
# check_coverage.sh — generates coverage report for dodo_agent.
# Uses cargo-tarpaulin (recommended) or cargo-llvm-cov as fallback.
set -e

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

THRESHOLD=90

if command -v cargo-tarpaulin &> /dev/null; then
    echo "Running coverage with cargo-tarpaulin..."
    cargo tarpaulin \
        --features linux \
        --out Html Lcov \
        --output-dir coverage/ \
        --timeout 120 \
        --exclude-files "*/target/*" \
        --workspace \
        2>&1

    COVERAGE=$(cargo tarpaulin --features linux --workspace --out Stdout 2>/dev/null \
        | grep "^[0-9]" | awk '{print $1}' | tr -d '%' || echo "0")
    echo "Coverage: ${COVERAGE}%"
elif command -v cargo-llvm-cov &> /dev/null; then
    echo "Running coverage with cargo-llvm-cov..."
    cargo llvm-cov --features linux --workspace --html --output-dir coverage/
else
    echo "Installing cargo-tarpaulin..."
    cargo install cargo-tarpaulin
    cargo tarpaulin --features linux --out Html --output-dir coverage/ --workspace
fi

echo "Coverage report: coverage/"
