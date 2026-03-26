use std::path::Path;
use std::time::Instant;

/// Performance benchmark: each scan must complete in under 100ms
#[test]
fn scan_under_100ms() {
    let fixtures = [
        "tests/fixtures/benign/weather-skill.md",
        "tests/fixtures/benign/docker-helper.md",
        "tests/fixtures/malicious/credential-stealer.md",
        "tests/fixtures/malicious/powershell-obfusc.md",
        "tests/fixtures/malicious/data-exfil.md",
    ];

    for fixture in &fixtures {
        let path = Path::new(fixture);
        assert!(path.exists(), "Fixture not found: {}", fixture);

        // Warm up (first run may be slower due to lazy init)
        let _ = clawfortify::core::orchestrator::scan(path);

        let start = Instant::now();
        let _ = clawfortify::core::orchestrator::scan(path);
        let elapsed = start.elapsed();

        assert!(
            elapsed.as_millis() < 100,
            "Scan of {} took {}ms (max 100ms)",
            fixture,
            elapsed.as_millis()
        );
    }
}

/// Performance benchmark: scanning all 20 fixtures must complete in under 500ms total
#[test]
fn batch_scan_under_500ms() {
    let dirs = ["tests/fixtures/benign", "tests/fixtures/malicious"];
    let mut paths = Vec::new();

    for dir in &dirs {
        for entry in std::fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.extension().map(|e| e == "md").unwrap_or(false) {
                paths.push(path);
            }
        }
    }

    assert!(paths.len() >= 20, "Expected at least 20 fixtures, found {}", paths.len());

    // Warm up
    for p in &paths {
        let _ = clawfortify::core::orchestrator::scan(p);
    }

    let start = Instant::now();
    for p in &paths {
        let _ = clawfortify::core::orchestrator::scan(p);
    }
    let elapsed = start.elapsed();

    assert!(
        elapsed.as_millis() < 500,
        "Batch scan of {} fixtures took {}ms (max 500ms)",
        paths.len(),
        elapsed.as_millis()
    );
}
