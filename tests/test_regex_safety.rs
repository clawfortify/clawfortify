use std::time::{Duration, Instant};

/// Verify that all regex patterns in patterns.json compile and don't catastrophically
/// backtrack (ReDoS protection). Rust's regex crate uses Thompson NFA, so it's inherently
/// resistant to catastrophic backtracking, but we verify no pattern takes > 50ms on
/// adversarial input.
#[test]
fn all_patterns_compile() {
    let patterns_json = include_str!("../src/rules/patterns.json");
    let patterns: Vec<serde_json::Value> = serde_json::from_str(patterns_json).unwrap();

    for p in &patterns {
        let pattern_str = p["pattern"].as_str().unwrap();
        let name = p["name"].as_str().unwrap();
        assert!(
            regex::Regex::new(pattern_str).is_ok(),
            "Pattern '{}' failed to compile: {}",
            name,
            pattern_str
        );
    }
}

#[test]
fn no_catastrophic_backtracking() {
    let patterns_json = include_str!("../src/rules/patterns.json");
    let patterns: Vec<serde_json::Value> = serde_json::from_str(patterns_json).unwrap();

    // Adversarial inputs designed to trigger backtracking in naive engines
    let adversarial_inputs = [
        "a".repeat(10000),
        "aaaa".repeat(2500),
        format!("{}@{}", "a".repeat(5000), "b".repeat(5000)),
        " ".repeat(10000),
        "eval(".repeat(500),
        "curl ".repeat(500),
        format!("{}|{}", "x".repeat(5000), "y".repeat(5000)),
    ];

    for p in &patterns {
        let pattern_str = p["pattern"].as_str().unwrap();
        let name = p["name"].as_str().unwrap();
        let re = regex::Regex::new(pattern_str).unwrap();

        for (i, input) in adversarial_inputs.iter().enumerate() {
            let start = Instant::now();
            let _ = re.is_match(input);
            let elapsed = start.elapsed();
            assert!(
                elapsed < Duration::from_millis(50),
                "Pattern '{}' took {:?} on adversarial input #{} (max 50ms). Possible ReDoS.",
                name,
                elapsed,
                i
            );
        }
    }
}
