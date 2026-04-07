#!/bin/bash
# security_audit.sh — runs static security analysis on dodo_agent.
set -e

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

echo "=== Running cargo audit ==="
if ! command -v cargo-audit &> /dev/null; then
    cargo install cargo-audit
fi
cargo audit

echo ""
echo "=== Running cargo deny ==="
if command -v cargo-deny &> /dev/null; then
    cargo deny check
else
    echo "cargo-deny not installed. Run: cargo install cargo-deny"
fi

echo ""
echo "=== Checking for unsafe code ==="
grep -rn "unsafe " crates/ --include="*.rs" \
    | grep -v "//.*unsafe\|#\[allow.*unsafe\|#\[cfg.*test\|_test.rs" \
    | head -20 || echo "No unsafe blocks found (excluding tests)"

echo ""
echo "Security audit complete."
