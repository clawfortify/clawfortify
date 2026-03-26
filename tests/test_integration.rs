use std::path::Path;

fn scan(path: &str) -> clawfortify::core::types::ScanResult {
    clawfortify::core::orchestrator::scan(Path::new(path)).unwrap()
}

mod benign {
    use super::*;

    fn assert_low_risk(fixture: &str) {
        let path = format!("tests/fixtures/benign/{}", fixture);
        let result = scan(&path);
        assert!(
            result.risk_score.score <= 25,
            "Benign fixture {} scored {} (grade {:?}), expected <= 25",
            fixture,
            result.risk_score.score,
            result.risk_score.grade,
        );
    }

    #[test]
    fn weather_skill() { assert_low_risk("weather-skill.md"); }
    #[test]
    fn todo_app() { assert_low_risk("todo-app.md"); }
    #[test]
    fn git_helper() { assert_low_risk("git-helper.md"); }
    #[test]
    fn markdown_formatter() { assert_low_risk("markdown-formatter.md"); }
    #[test]
    fn file_organizer() { assert_low_risk("file-organizer.md"); }
    #[test]
    fn code_reviewer() { assert_low_risk("code-reviewer.md"); }
    #[test]
    fn csv_analyzer() { assert_low_risk("csv-analyzer.md"); }
    #[test]
    fn docker_helper() { assert_low_risk("docker-helper.md"); }
    #[test]
    fn api_client() { assert_low_risk("api-client.md"); }
    #[test]
    fn translate_text() { assert_low_risk("translate-text.md"); }
}

mod malicious {
    use super::*;

    fn assert_high_risk(fixture: &str, min_score: u32) {
        let path = format!("tests/fixtures/malicious/{}", fixture);
        let result = scan(&path);
        assert!(
            result.risk_score.score >= min_score,
            "Malicious fixture {} scored {} (grade {:?}), expected >= {}",
            fixture,
            result.risk_score.score,
            result.risk_score.grade,
            min_score,
        );
    }

    fn assert_has_category(fixture: &str, category: &str) {
        let path = format!("tests/fixtures/malicious/{}", fixture);
        let result = scan(&path);
        let has = result
            .risk_score
            .findings
            .iter()
            .any(|f| f.category == category);
        assert!(
            has,
            "Malicious fixture {} missing expected category '{}'.\nCategories found: {:?}",
            fixture,
            category,
            result.risk_score.findings.iter().map(|f| &f.category).collect::<Vec<_>>(),
        );
    }

    #[test]
    fn credential_stealer_high_score() {
        assert_high_risk("credential-stealer.md", 26);
    }

    #[test]
    fn credential_stealer_has_categories() {
        assert_has_category("credential-stealer.md", "credential_theft");
        assert_has_category("credential-stealer.md", "remote_code_execution");
    }

    #[test]
    fn prompt_injection_detected() {
        assert_has_category("prompt-injection.md", "prompt_injection");
        assert_has_category("prompt-injection.md", "obfuscation");
    }

    #[test]
    fn rce_base64_detected() {
        assert_has_category("rce-base64.md", "obfuscation");
        assert_has_category("rce-base64.md", "remote_code_execution");
    }

    #[test]
    fn obfuscated_shell_detected() {
        assert_has_category("obfuscated-shell.md", "remote_code_execution");
        assert_has_category("obfuscated-shell.md", "data_exfiltration");
    }

    #[test]
    fn data_exfil_detected() {
        assert_has_category("data-exfil.md", "data_exfiltration");
        assert_has_category("data-exfil.md", "credential_theft");
    }

    #[test]
    fn agent_attack_detected() {
        assert_has_category("agent-attack.md", "agent_attack");
    }

    #[test]
    fn supply_chain_detected() {
        assert_has_category("supply-chain.md", "supply_chain");
    }

    #[test]
    fn crypto_miner_detected() {
        assert_has_category("crypto-miner.md", "cryptomining");
    }

    #[test]
    fn powershell_obfuscation_detected() {
        assert_has_category("powershell-obfusc.md", "obfuscation");
        assert_has_category("powershell-obfusc.md", "privilege_escalation");
    }
}
