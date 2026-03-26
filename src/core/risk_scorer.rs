use std::collections::HashMap;

use crate::core::types::{Finding, Grade, RiskScore};

const DECAY: [f64; 4] = [1.0, 0.6, 0.3, 0.1];

pub fn calculate_score(findings: Vec<Finding>) -> RiskScore {
    let mut rule_counts: HashMap<String, usize> = HashMap::new();
    let mut raw_score: f64 = 0.0;

    for f in &findings {
        let count = rule_counts.entry(f.rule_id.clone()).or_insert(0);
        let decay = if *count < DECAY.len() {
            DECAY[*count]
        } else {
            *DECAY.last().unwrap()
        };
        *count += 1;

        let severity_w = f.severity.weight() as f64;
        let region_w = f.region_type.weight(f.language.as_deref());
        let confidence = f.confidence;

        raw_score += severity_w * region_w * confidence * decay;
    }

    let score = (raw_score.min(100.0)) as u32;
    let grade = Grade::from_score(score);

    RiskScore {
        score,
        grade,
        findings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::types::{RegionType, Severity};

    fn make_finding(rule_id: &str, severity: Severity, region: RegionType) -> Finding {
        Finding {
            rule_id: rule_id.to_string(),
            title: "Test".to_string(),
            description: "Test".to_string(),
            severity,
            category: "test".to_string(),
            confidence: 1.0,
            region_type: region,
            language: None,
            line_number: None,
            evidence: None,
            fix: None,
            analysis_pass: "test".to_string(),
        }
    }

    #[test]
    fn empty_findings_gives_grade_a() {
        let result = calculate_score(vec![]);
        assert_eq!(result.score, 0);
        assert_eq!(result.grade, Grade::A);
    }

    #[test]
    fn single_critical_in_code_block() {
        let findings = vec![make_finding("TEST001", Severity::Critical, RegionType::CodeBlock)];
        let result = calculate_score(findings);
        assert_eq!(result.score, 27); // 30 * 0.9 * 1.0 * 1.0 = 27
        assert_eq!(result.grade, Grade::C);
    }

    #[test]
    fn same_rule_decays() {
        let findings = vec![
            make_finding("TEST001", Severity::High, RegionType::CodeBlock),
            make_finding("TEST001", Severity::High, RegionType::CodeBlock),
        ];
        let result = calculate_score(findings);
        // 1st: 15 * 0.9 * 1.0 = 13.5, 2nd: 15 * 0.9 * 0.6 = 8.1 => 21.6 => 21
        assert_eq!(result.score, 21);
        assert_eq!(result.grade, Grade::B);
    }

    #[test]
    fn prose_region_reduces_weight() {
        let findings = vec![make_finding("TEST001", Severity::High, RegionType::Prose)];
        let result = calculate_score(findings);
        // 15 * 0.2 * 1.0 * 1.0 = 3
        assert_eq!(result.score, 3);
        assert_eq!(result.grade, Grade::A);
    }
}
