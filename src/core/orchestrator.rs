use std::collections::HashMap;
use std::path::Path;

use crate::core::risk_scorer;
use crate::core::types::{Finding, PassSummary, ScanResult};
use crate::parsers::skill_parser;
use crate::passes::{behavioral_sandbox, community_intel, dependency_auditor, metadata_validator, prompt_injection, static_analysis};

pub fn scan(path: &Path) -> Result<ScanResult, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;

    let parsed = skill_parser::parse(&content)?;

    let mut all_findings: Vec<Finding> = Vec::new();
    let mut pass_summaries: HashMap<String, PassSummary> = HashMap::new();

    // Pass 2: Static Pattern Analysis
    let static_findings = static_analysis::analyze(&parsed);
    pass_summaries.insert(
        "static-analysis".to_string(),
        PassSummary {
            pass_name: "Static Pattern Analysis".to_string(),
            finding_count: static_findings.len(),
            status: "completed".to_string(),
        },
    );
    all_findings.extend(static_findings);

    // Pass 3: Metadata Validation
    let meta_findings = metadata_validator::validate(&parsed);
    pass_summaries.insert(
        "metadata-validator".to_string(),
        PassSummary {
            pass_name: "Metadata Validation".to_string(),
            finding_count: meta_findings.len(),
            status: "completed".to_string(),
        },
    );
    all_findings.extend(meta_findings);

    // Pass 4: Dependency Chain Audit
    let dep_findings = dependency_auditor::audit(&parsed);
    pass_summaries.insert(
        "dependency-auditor".to_string(),
        PassSummary {
            pass_name: "Dependency Chain Audit".to_string(),
            finding_count: dep_findings.len(),
            status: "completed".to_string(),
        },
    );
    all_findings.extend(dep_findings);

    // Pass 5: Prompt Injection Detection
    let inj_findings = prompt_injection::detect(&parsed);
    pass_summaries.insert(
        "prompt-injection".to_string(),
        PassSummary {
            pass_name: "Prompt Injection Detection".to_string(),
            finding_count: inj_findings.len(),
            status: "completed".to_string(),
        },
    );
    all_findings.extend(inj_findings);

    // Pass 6: Behavioral Sandbox
    let bhv_findings = behavioral_sandbox::analyze(&parsed);
    pass_summaries.insert(
        "behavioral-sandbox".to_string(),
        PassSummary {
            pass_name: "Behavioral Sandbox".to_string(),
            finding_count: bhv_findings.len(),
            status: "completed".to_string(),
        },
    );
    all_findings.extend(bhv_findings);

    // Pass 7: Community Intelligence
    let com_findings = community_intel::analyze(&parsed);
    pass_summaries.insert(
        "community-intel".to_string(),
        PassSummary {
            pass_name: "Community Intelligence".to_string(),
            finding_count: com_findings.len(),
            status: "completed".to_string(),
        },
    );
    all_findings.extend(com_findings);

    let risk_score = risk_scorer::calculate_score(all_findings);

    // Add parser pass summary
    pass_summaries.insert(
        "skill-parser".to_string(),
        PassSummary {
            pass_name: "Skill Parser".to_string(),
            finding_count: parsed.regions.len(),
            status: "completed".to_string(),
        },
    );

    Ok(ScanResult {
        skill_path: path.display().to_string(),
        risk_score,
        pass_summaries,
    })
}
