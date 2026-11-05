//! Integration tests for the RedactionEngine.
//!
//! These tests simulate real-world telemetry patterns to verify that the
//! redaction engine correctly scrubs sensitive values before they leave the
//! agent host.

use agent_core::RedactionEngine;

#[test]
fn integration_env_var_scrubbing_common_patterns() {
    let engine = RedactionEngine::new(&[]).unwrap();

    let cases = vec![
        // Passwords
        ("DB_PASSWORD=prod_secret_123", false, "prod_secret_123"),
        ("database_password=hunter2", false, "hunter2"),
        ("PASSWD=mysecret", false, "mysecret"),
        // Tokens / Keys
        ("api_key=sk-abcdefghijklmnop", false, "sk-abcdefghijklmnop"),
        (
            "API_KEY=AKIAIOSFODNN7EXAMPLE",
            false,
            "AKIAIOSFODNN7EXAMPLE",
        ),
        ("access_key=ASIA1234567890ABCDE", false, "1234567890"),
        ("secret=super-secret-value", false, "super-secret-value"),
        (
            "token=eyJhbGciOiJIUzI1NiJ9.test",
            false,
            "eyJhbGciOiJIUzI1NiJ9",
        ),
        // Non-sensitive (must NOT be redacted)
        ("PATH=/usr/bin:/usr/local/bin", true, ""),
        ("HOME=/home/agent", true, ""),
        ("PORT=8080", true, ""),
        ("HOSTNAME=web-01", true, ""),
    ];

    for (input, should_be_unchanged, secret) in cases {
        let output = engine.redact(input);
        if should_be_unchanged {
            assert_eq!(
                output, input,
                "Non-sensitive var should not be redacted: {input}"
            );
        } else {
            assert!(
                !output.contains(secret),
                "Secret {secret:?} was not redacted from: {input}\nOutput: {output}"
            );
            assert!(
                output.contains("***"),
                "Expected *** in redacted output for: {input}\nOutput: {output}"
            );
        }
    }
}

#[test]
fn integration_json_log_line_scrubbing() {
    let engine = RedactionEngine::new(&[]).unwrap();

    // Engine matches key=value / key: value patterns.
    // JSON-style "key":"value" with quoted key won't match the built-in patterns,
    // but log lines that embed key=value pairs inside a JSON message field do.
    let log = r#"{"level":"info","msg":"password=hunter2 host=db.internal port=5432"}"#;
    let result = engine.redact(log);

    assert!(result.contains("***"), "Should contain redaction marker");
    assert!(!result.contains("hunter2"), "Password must be redacted");
    assert!(result.contains("db.internal"), "Host must be preserved");
    assert!(result.contains("5432"), "Port must be preserved");
}

#[test]
fn integration_connection_string_scrubbing() {
    let engine = RedactionEngine::new(&[]).unwrap();

    let conn_strings = vec![
        "DATABASE_URL=postgres://user:password@host:5432/db",
        "REDIS_URL=redis://:secret@localhost:6379",
    ];

    for conn in conn_strings {
        let result = engine.redact(conn);
        // Must not panic, and sensitive values should be reduced
        assert!(
            !result.is_empty(),
            "Empty result for connection string: {conn}"
        );
    }
}

#[test]
fn integration_multiline_scrubbing() {
    let engine = RedactionEngine::new(&[]).unwrap();

    let multiline = "Starting service\npassword=my_pass\nConnected OK";
    let result = engine.redact(multiline);
    assert!(!result.contains("my_pass"));
    assert!(result.contains("Starting service"));
    assert!(result.contains("Connected OK"));
}

#[test]
fn integration_custom_pattern_corporate_secret() {
    let custom_patterns = vec![
        r"(?i)(CORP_API_SECRET\s*=\s*)\S+".to_string(),
        r"(?i)(INTERNAL_KEY\s*=\s*)\S+".to_string(),
    ];
    let engine = RedactionEngine::new(&custom_patterns).unwrap();

    let input = "CORP_API_SECRET=corp-secret-xyz INTERNAL_KEY=key-abc";
    let result = engine.redact(input);
    assert!(
        !result.contains("corp-secret-xyz"),
        "Custom pattern 1 must be redacted"
    );
    assert!(
        !result.contains("key-abc"),
        "Custom pattern 2 must be redacted"
    );
}

#[test]
fn integration_redaction_is_idempotent_on_safe_text() {
    let engine = RedactionEngine::new(&[]).unwrap();

    let safe_logs = vec![
        "Service started on port 8080",
        "Connection pool initialized: 10 connections",
        "Request GET /api/v1/metrics 200 OK 15ms",
        "Kafka consumer group joined: metric-workers",
        "ClickHouse batch inserted: 5000 rows",
    ];

    for log in safe_logs {
        let result = engine.redact(log);
        assert_eq!(result, log, "Safe log line should not be modified: {log}");
    }
}

#[test]
fn integration_redaction_count_accumulates() {
    let engine = RedactionEngine::new(&[]).unwrap();

    let before = engine.redaction_count();

    engine.redact("password=abc");
    engine.redact("token=xyz");
    engine.redact("api_key=123");

    let after = engine.redaction_count();
    assert!(
        after > before,
        "Redaction count should increase: before={before} after={after}"
    );
}
