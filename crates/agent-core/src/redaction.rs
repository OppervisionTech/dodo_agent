//! Redaction engine — strips secrets and sensitive values from telemetry data.
//!
//! Implements HU033 (env var and secret redaction). Every payload that may
//! contain user-controlled strings (logs, env vars, command lines) MUST be
//! passed through `RedactionEngine::redact()` before leaving the agent.

use std::sync::atomic::{AtomicU64, Ordering};

use regex::Regex;

use crate::RedactionError;

/// Placeholder that replaces redacted values.
const REDACTED: &str = "***";

/// A compiled set of redaction patterns.
///
/// Thread-safe and cheaply shareable (wrap in `Arc` if needed). The
/// internal counter tracks how many individual substitutions have been
/// applied across all calls to `redact()`.
pub struct RedactionEngine {
    /// Compiled regex patterns. Each pattern is expected to have at least
    /// one capture group that isolates the *value* portion (the part to
    /// replace with `***`).
    patterns: Vec<RedactionPattern>,

    /// Running count of substitutions applied (for self-metrics).
    redaction_count: AtomicU64,
}

/// A single redaction rule: compiled regex + a human-readable label.
struct RedactionPattern {
    regex: Regex,
    label: &'static str,
}

/// Internal helper — build a `RedactionPattern` from a raw regex string.
fn compile_builtin(pattern: &str, label: &'static str) -> Result<RedactionPattern, RedactionError> {
    let regex = Regex::new(pattern).map_err(|e| RedactionError::InvalidPattern(e.to_string()))?;
    Ok(RedactionPattern { regex, label })
}

impl RedactionEngine {
    /// Create a new redaction engine with the built-in patterns plus any
    /// additional custom patterns.
    ///
    /// Custom patterns should contain a capture group around the value to
    /// redact, e.g. `(?i)MY_SECRET\s*=\s*(\S+)`. If a custom pattern has
    /// no capture group the entire match is replaced.
    pub fn new(custom_patterns: &[String]) -> Result<Self, RedactionError> {
        let mut patterns = vec![
            // -----------------------------------------------------------------
            // Built-in patterns (always active)
            // -----------------------------------------------------------------

            // password/passwd/pwd = <value>
            compile_builtin(r"(?i)((?:password|passwd|pwd)\s*[=:]\s*)\S+", "password")?,
            // secret/token/api_key/apikey/access_key = <value>
            compile_builtin(
                r"(?i)((?:secret|token|api_key|apikey|access_key)\s*[=:]\s*)\S+",
                "secret_token",
            )?,
            // AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN = <value>
            compile_builtin(
                r"(?i)((?:AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN)\s*=\s*)\S+",
                "aws_credential",
            )?,
            // Bearer <token>
            compile_builtin(r"(?i)(Bearer\s+)[A-Za-z0-9\-._~+/]+=*", "bearer_token")?,
            // SSH keys: ssh-rsa <key> or ssh-ed25519 <key>
            compile_builtin(r"((?:ssh-rsa|ssh-ed25519)\s+)\S+", "ssh_key")?,
        ];

        // -----------------------------------------------------------------
        // Custom patterns
        // -----------------------------------------------------------------
        for (i, pat) in custom_patterns.iter().enumerate() {
            let regex = Regex::new(pat)?;
            // We leak a label string here — there will only be a small
            // fixed number of custom patterns, so this is acceptable.
            let label_str = format!("custom_{i}");
            let label: &'static str = Box::leak(label_str.into_boxed_str());
            patterns.push(RedactionPattern { regex, label });
        }

        tracing::info!(
            builtin_count = 5,
            custom_count = custom_patterns.len(),
            "redaction engine initialized"
        );

        Ok(Self {
            patterns,
            redaction_count: AtomicU64::new(0),
        })
    }

    /// Redact all sensitive values in `input` and return the sanitized string.
    ///
    /// For each pattern, the captured *key* prefix (group 1) is preserved and
    /// the remaining matched text (the value) is replaced with `***`.
    pub fn redact(&self, input: &str) -> String {
        let mut result = input.to_owned();

        for pattern in &self.patterns {
            let before_len = result.len();

            // Use the capture-group approach: group 1 is the key/prefix,
            // everything after group 1 within the full match is the value.
            let replaced = pattern
                .regex
                .replace_all(&result, |caps: &regex::Captures| {
                    if let Some(prefix) = caps.get(1) {
                        // Preserve the prefix (key=), replace value with ***
                        format!("{}{REDACTED}", prefix.as_str())
                    } else {
                        // No capture group — replace entire match
                        REDACTED.to_owned()
                    }
                });

            if replaced.len() != before_len || replaced.as_ref() != result.as_str() {
                // Count how many matches were replaced. We approximate by
                // counting actual regex matches.
                let match_count = pattern.regex.find_iter(&result).count() as u64;
                self.redaction_count
                    .fetch_add(match_count, Ordering::Relaxed);

                tracing::trace!(
                    pattern = pattern.label,
                    matches = match_count,
                    "redaction applied"
                );

                result = replaced.into_owned();
            }
        }

        result
    }

    /// Total number of individual redaction substitutions applied since
    /// this engine was created.
    pub fn redaction_count(&self) -> u64 {
        self.redaction_count.load(Ordering::Relaxed)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> RedactionEngine {
        RedactionEngine::new(&[]).expect("failed to create engine")
    }

    #[test]
    fn redacts_password_equals() {
        let e = engine();
        let input = "DB_PASSWORD=super_secret_123";
        let output = e.redact(input);
        assert_eq!(output, "DB_PASSWORD=***");
        assert!(!output.contains("super_secret_123"));
    }

    #[test]
    fn redacts_password_colon() {
        let e = engine();
        let input = "password: my-pass-123";
        let output = e.redact(input);
        assert_eq!(output, "password: ***");
    }

    #[test]
    fn redacts_api_key() {
        let e = engine();
        let input = "API_KEY=abcdef123456";
        let output = e.redact(input);
        assert_eq!(output, "API_KEY=***");
    }

    #[test]
    fn redacts_token() {
        let e = engine();
        let input = "my_token=xyz789 other_data";
        let output = e.redact(input);
        assert!(output.contains("***"));
        assert!(!output.contains("xyz789"));
        assert!(output.contains("other_data"));
    }

    #[test]
    fn redacts_aws_credentials() {
        let e = engine();
        let input = "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        let output = e.redact(input);
        assert_eq!(output, "AWS_SECRET_ACCESS_KEY=***");
    }

    #[test]
    fn redacts_bearer_token() {
        let e = engine();
        let input = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc";
        let output = e.redact(input);
        assert!(output.contains("Bearer ***"));
        assert!(!output.contains("eyJhbGciOiJIUzI1NiJ9"));
    }

    #[test]
    fn redacts_ssh_key() {
        let e = engine();
        let input = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7vbq user@host";
        let output = e.redact(input);
        assert!(output.starts_with("ssh-rsa ***"));
        assert!(!output.contains("AAAAB3NzaC1yc2EAAAADAQABAAABgQC7vbq"));
    }

    #[test]
    fn preserves_non_sensitive_text() {
        let e = engine();
        let input = "INFO 2026-03-08 server started on port 8080";
        let output = e.redact(input);
        assert_eq!(output, input);
    }

    #[test]
    fn case_insensitive() {
        let e = engine();
        let input = "PASSWORD=secret123";
        let output = e.redact(input);
        assert_eq!(output, "PASSWORD=***");

        let input2 = "Secret=hidden_value";
        let output2 = e.redact(input2);
        assert_eq!(output2, "Secret=***");
    }

    #[test]
    fn multiple_redactions_in_one_string() {
        let e = engine();
        let input = "password=abc123 token=xyz789 normal=ok";
        let output = e.redact(input);
        assert!(!output.contains("abc123"));
        assert!(!output.contains("xyz789"));
        assert!(output.contains("normal=ok"));
    }

    #[test]
    fn custom_pattern() {
        let custom = vec![r"(MY_CUSTOM_KEY\s*=\s*)\S+".to_string()];
        let e = RedactionEngine::new(&custom).expect("custom engine");
        let input = "MY_CUSTOM_KEY=secret_value other";
        let output = e.redact(input);
        assert_eq!(output, "MY_CUSTOM_KEY=*** other");
    }

    #[test]
    fn redaction_count_tracks() {
        let e = engine();
        assert_eq!(e.redaction_count(), 0);

        e.redact("password=abc");
        assert!(e.redaction_count() >= 1);

        e.redact("token=xyz api_key=abc");
        assert!(e.redaction_count() >= 3);
    }
}
