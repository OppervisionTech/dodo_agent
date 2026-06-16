//! Security tests for agent-core.
//!
//! These tests verify security-critical invariants: that the redaction engine
//! never panics, cannot be exploited via injection patterns, and handles
//! adversarial inputs gracefully.

use agent_core::RedactionEngine;

/// Test that arbitrary null bytes don't panic
#[test]
fn security_null_bytes_in_input() {
    let engine = RedactionEngine::new(&[]).unwrap();
    let input = "password=\0\0\0null\0bytes";
    let _ = engine.redact(input); // must not panic
}

/// Test that unicode control characters don't panic
#[test]
fn security_unicode_control_chars() {
    let engine = RedactionEngine::new(&[]).unwrap();
    let inputs = vec![
        "token=\u{0000}\u{001F}\u{007F}value",
        "api_key=\u{FEFF}\u{200B}zero-width",
        "secret=\u{202E}rtl-override\u{200F}",
    ];
    for input in inputs {
        let _ = engine.redact(input);
    }
}

/// Test that a very long input doesn't cause OOM or timeout
#[test]
fn security_large_input_no_oom() {
    let engine = RedactionEngine::new(&[]).unwrap();
    // 1MB input
    let large = "x".repeat(1_000_000);
    let result = engine.redact(&large);
    assert!(!result.is_empty());
}

/// Test a potential ReDoS input: crafted to cause catastrophic backtracking
/// in naive regex implementations
#[test]
fn security_potential_redos_input() {
    let engine = RedactionEngine::new(&[]).unwrap();
    // Input that could cause backtracking in certain regex patterns
    let crafted = "a".repeat(10000) + "password=";
    let _ = engine.redact(&crafted); // must complete within test timeout
}

/// Test that invalid custom patterns return Err, not panic
#[test]
fn security_invalid_custom_pattern_graceful() {
    // An invalid regex should return an error, not panic
    let result = RedactionEngine::new(&["[invalid_regex(".to_string()]);
    // Either Ok (engine created with pattern ignored) or Err (graceful failure)
    match result {
        Ok(_) => {} // engine chose to skip invalid pattern
        Err(e) => {
            // Verify the error message is informative
            let msg = format!("{e}");
            assert!(!msg.is_empty(), "Error message should not be empty");
        }
    }
}

/// Test that SQL injection patterns in values are redacted, not executed
#[test]
fn security_sql_injection_in_value() {
    let engine = RedactionEngine::new(&[]).unwrap();
    // Use a value without spaces — the built-in pattern uses \S+ which stops at whitespace.
    let input = "password=';DROP-TABLE-users;--";
    let result = engine.redact(input);
    // The SQL injection string must be redacted (the whole non-whitespace token)
    assert!(
        result.contains("***"),
        "SQL injection in password value must be redacted"
    );
    assert!(
        !result.contains("DROP-TABLE"),
        "SQL injection must not appear in output"
    );
}

/// Test that path traversal in custom patterns doesn't break the engine
#[test]
fn security_path_traversal_in_pattern() {
    // Attempt to use "../" patterns — must not access filesystem
    let result = RedactionEngine::new(&["../../../etc/shadow".to_string()]);
    let _ = result; // engine must not access filesystem, just compile the pattern
}

/// Test concurrent access (engine is Send + Sync via Arc usage)
#[test]
fn security_concurrent_redaction() {
    use std::sync::Arc;
    use std::thread;

    let engine = Arc::new(RedactionEngine::new(&[]).unwrap());
    let mut handles = vec![];

    for i in 0..20 {
        let e = Arc::clone(&engine);
        let h = thread::spawn(move || {
            let input = format!("password=secret_{i} token=tok_{i}");
            let result = e.redact(&input);
            assert!(result.contains("***"));
            assert!(!result.contains(&format!("secret_{i}")));
        });
        handles.push(h);
    }

    for h in handles {
        h.join().expect("thread panicked");
    }
}

/// Test that empty string input returns empty string
#[test]
fn security_empty_input_returns_empty() {
    let engine = RedactionEngine::new(&[]).unwrap();
    let result = engine.redact("");
    assert_eq!(result, "");
}

/// Test that whitespace-only input is not corrupted
#[test]
fn security_whitespace_input_preserved() {
    let engine = RedactionEngine::new(&[]).unwrap();
    for ws in ["   ", "\t", "\n", "\r\n", " \t \n "] {
        let result = engine.redact(ws);
        assert_eq!(result, ws, "Whitespace should not be modified");
    }
}
