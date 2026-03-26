use std::path::Path;

fn scan(path: &str) -> clawfortify::core::types::ScanResult {
    clawfortify::core::orchestrator::scan(Path::new(path)).unwrap()
}

/// Accuracy benchmark: ensure 0% false-positive rate on all benign fixtures
/// (i.e., all benign skills score at or below Grade B)
#[test]
fn zero_false_positive_on_benign() {
    let benign_dir = "tests/fixtures/benign";
    let mut total = 0;
    let mut false_positives = 0;

    for entry in std::fs::read_dir(benign_dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().map(|e| e == "md").unwrap_or(false) {
            total += 1;
            let result = scan(path.to_str().unwrap());
            if result.risk_score.score > 25 {
                eprintln!(
                    "FALSE POSITIVE: {} scored {} (grade {:?})",
                    path.display(),
                    result.risk_score.score,
                    result.risk_score.grade,
                );
                false_positives += 1;
            }
        }
    }

    assert!(total >= 10, "Expected at least 10 benign fixtures, found {}", total);
    assert_eq!(
        false_positives, 0,
        "{}/{} benign fixtures triggered false positives",
        false_positives, total
    );
}

/// Accuracy benchmark: ensure 100% true-positive rate on all malicious fixtures
/// (i.e., all malicious skills score above Grade B)
#[test]
fn full_detection_on_malicious() {
    let malicious_dir = "tests/fixtures/malicious";
    let mut total = 0;
    let mut missed = 0;

    for entry in std::fs::read_dir(malicious_dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().map(|e| e == "md").unwrap_or(false) {
            total += 1;
            let result = scan(path.to_str().unwrap());
            if result.risk_score.score <= 25 {
                eprintln!(
                    "MISSED: {} scored only {} (grade {:?})",
                    path.display(),
                    result.risk_score.score,
                    result.risk_score.grade,
                );
                missed += 1;
            }
        }
    }

    assert!(total >= 10, "Expected at least 10 malicious fixtures, found {}", total);
    assert_eq!(
        missed, 0,
        "{}/{} malicious fixtures were not detected",
        missed, total
    );
}

/// Ensure each malicious fixture produces at least one finding
#[test]
fn all_malicious_have_findings() {
    let malicious_dir = "tests/fixtures/malicious";

    for entry in std::fs::read_dir(malicious_dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().map(|e| e == "md").unwrap_or(false) {
            let result = scan(path.to_str().unwrap());
            assert!(
                !result.risk_score.findings.is_empty(),
                "Malicious fixture {} produced zero findings",
                path.display()
            );
        }
    }
}
