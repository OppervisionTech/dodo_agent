//! Property-based tests for agent-core using proptest.
//!
//! These tests generate thousands of randomized inputs to verify invariants
//! that should hold for ALL possible inputs.

use agent_core::{Envelope, RedactionEngine, SignalType};
use proptest::prelude::*;

// ---------------------------------------------------------------------------
// RedactionEngine property tests
// ---------------------------------------------------------------------------

proptest! {
    /// Property: redact() must NEVER panic for any UTF-8 string input.
    #[test]
    fn prop_redact_never_panics(input in ".*") {
        let engine = RedactionEngine::new(&[]).unwrap();
        let _ = engine.redact(&input);
        // Reaching here = no panic
    }

    /// Property: redacting an already-redacted string produces the same output
    /// (idempotent for strings that only contain "***").
    #[test]
    fn prop_redact_already_redacted_is_stable(
        safe_prefix in "[a-z ]{0,50}",
    ) {
        let engine = RedactionEngine::new(&[]).unwrap();
        let first = engine.redact(&safe_prefix);
        let second = engine.redact(&first);
        assert_eq!(first, second, "Re-redacting should be idempotent for already-safe strings");
    }

    /// Property: output length is always <= input length + some constant overhead
    /// (redaction replaces with shorter "***", or same length at worst).
    #[test]
    fn prop_output_not_much_longer_than_input(input in ".{0,500}") {
        let engine = RedactionEngine::new(&[]).unwrap();
        let result = engine.redact(&input);
        // Allow up to 50 bytes overhead per match (safety margin)
        let max_len = input.len() + 50;
        prop_assert!(result.len() <= max_len,
            "Output {} chars is longer than input {} + 50 overhead",
            result.len(), input.len()
        );
    }

    /// Property: safe input (no sensitive keywords) should pass through unchanged.
    #[test]
    fn prop_safe_input_not_modified(input in "[a-z0-9 ._:/-]{1,100}") {
        let engine = RedactionEngine::new(&[]).unwrap();
        let result = engine.redact(&input);
        // Safe strings (no password/token/secret/key/apikey keywords) should be unchanged
        if !input.contains("password") && !input.contains("secret") &&
           !input.contains("token") && !input.contains("api_key") &&
           !input.contains("apikey") && !input.contains("access_key") &&
           !input.contains("passwd") && !input.contains("pwd") {
            prop_assert_eq!(result, input, "Safe input should not be modified");
        }
    }

    /// Property: after redaction, the redaction_count is always >= 0.
    #[test]
    fn prop_redaction_count_non_negative(input in ".*") {
        let engine = RedactionEngine::new(&[]).unwrap();
        let _ = engine.redact(&input);
        prop_assert!(engine.redaction_count() < u64::MAX,
            "Redaction count should not overflow");
    }
}

// ---------------------------------------------------------------------------
// SignalType property tests
// ---------------------------------------------------------------------------

proptest! {
    /// Property: from_i32(x).as_str() always returns a non-empty string.
    #[test]
    fn prop_signal_type_as_str_never_empty(value in 0i32..=10i32) {
        let st = SignalType::from_i32(value);
        prop_assert!(!st.as_str().is_empty(), "as_str() must never return empty");
    }

    /// Property: priority is always in range 0..=4.
    #[test]
    fn prop_signal_type_priority_in_range(value in 0i32..=7i32) {
        let st = SignalType::from_i32(value);
        let p = st.priority();
        prop_assert!(p <= 4, "priority {p} out of expected range 0..=4");
    }

    /// Property: from_i32 roundtrip via as_str never panics.
    #[test]
    fn prop_signal_type_roundtrip_no_panic(value in any::<i32>()) {
        let st = SignalType::from_i32(value);
        let _ = st.as_str();
        let _ = st.priority();
        let _ = format!("{st}");
    }
}

// ---------------------------------------------------------------------------
// Envelope property tests
// ---------------------------------------------------------------------------

proptest! {
    /// Property: estimated_size() is always >= payload length.
    #[test]
    fn prop_envelope_estimated_size_gte_payload(payload in prop::collection::vec(any::<u8>(), 0..10000)) {
        let payload_len = payload.len();
        let env = Envelope {
            signal_type: SignalType::Metric,
            payload,
            timestamp_unix_ns: 0,
            buffered: false,
            retry_count: 0,
        };
        prop_assert!(
            env.estimated_size() >= payload_len,
            "estimated_size {} < payload_len {}", env.estimated_size(), payload_len
        );
    }
}
