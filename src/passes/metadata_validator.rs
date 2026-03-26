use regex::Regex;

use crate::core::types::{Finding, ParsedSkill, RegionType, Severity};

const KNOWN_BINS: &[&str] = &[
    "curl", "wget", "git", "python", "python3", "node", "npm", "npx",
    "brew", "apt", "pip", "docker", "kubectl", "ssh", "scp", "rsync",
    "ffmpeg", "jq", "sed", "awk", "grep", "find", "cargo", "rustc",
];

pub fn validate(skill: &ParsedSkill) -> Vec<Finding> {
    let mut findings = Vec::new();
    let fm = &skill.frontmatter;
    let pass = "metadata-validator";

    if fm.name.is_none() {
        findings.push(Finding {
            rule_id: "META001".into(),
            title: "Missing skill name".into(),
            description: "SKILL.md frontmatter does not declare a name.".into(),
            severity: Severity::Medium,
            category: "metadata".into(),
            confidence: 1.0,
            region_type: RegionType::Frontmatter,
            language: None,
            line_number: Some(1),
            evidence: None,
            fix: Some("Add `name:` to the YAML frontmatter.".into()),
            analysis_pass: pass.into(),
        });
    }

    if let Some(desc) = &fm.description {
        if desc.len() < 10 {
            findings.push(Finding {
                rule_id: "META002".into(),
                title: "Vague description".into(),
                description: "Skill description is suspiciously short.".into(),
                severity: Severity::Low,
                category: "metadata".into(),
                confidence: 1.0,
                region_type: RegionType::Frontmatter,
                language: None,
                line_number: Some(1),
                evidence: Some(desc.clone()),
                fix: Some("Write a more detailed description (at least 10 characters).".into()),
                analysis_pass: pass.into(),
            });
        }
    } else {
        findings.push(Finding {
            rule_id: "META003".into(),
            title: "Missing description".into(),
            description: "SKILL.md frontmatter does not declare a description.".into(),
            severity: Severity::Medium,
            category: "metadata".into(),
            confidence: 1.0,
            region_type: RegionType::Frontmatter,
            language: None,
            line_number: Some(1),
            evidence: None,
            fix: Some("Add `description:` to the YAML frontmatter.".into()),
            analysis_pass: pass.into(),
        });
    }

    if let Some(version) = &fm.version {
        let semver_re = Regex::new(r"^\d+\.\d+\.\d+").unwrap();
        if !semver_re.is_match(version) {
            findings.push(Finding {
                rule_id: "META004".into(),
                title: "Invalid version format".into(),
                description: "Version does not follow semver format.".into(),
                severity: Severity::Low,
                category: "metadata".into(),
                confidence: 1.0,
                region_type: RegionType::Frontmatter,
                language: None,
                line_number: Some(1),
                evidence: Some(version.clone()),
                fix: Some("Use semver format: `version: X.Y.Z` (e.g., `1.0.0`).".into()),
                analysis_pass: pass.into(),
            });
        }
    }

    // Check for undeclared binaries
    let declared_bins: Vec<String> = fm
        .metadata
        .as_ref()
        .and_then(|m| m.openclaw.as_ref())
        .and_then(|o| o.requires.as_ref())
        .map(|r| r.bins.clone())
        .unwrap_or_default();

    for bin in KNOWN_BINS {
        if declared_bins.iter().any(|b| b == bin) {
            continue;
        }
        let bin_re = Regex::new(&format!(r"\b{}\b", regex::escape(bin))).unwrap();
        let used_in_code = skill
            .code_blocks
            .iter()
            .any(|cb| bin_re.is_match(&cb.content));
        if used_in_code {
            findings.push(Finding {
                rule_id: "META005".into(),
                title: format!("Undeclared binary: {}", bin),
                description: format!(
                    "Skill uses '{}' in code but does not declare it in requires.bins.",
                    bin
                ),
                severity: Severity::Low,
                category: "metadata".into(),
                confidence: 0.8,
                region_type: RegionType::CodeBlock,
                language: None,
                line_number: None,
                evidence: None,
                fix: Some(format!(
                    "Add '{}' to `metadata.openclaw.requires.bins` in frontmatter.",
                    bin
                )),
                analysis_pass: pass.into(),
            });
        }
    }

    // Check for undeclared env vars
    let declared_env: Vec<String> = fm
        .metadata
        .as_ref()
        .and_then(|m| m.openclaw.as_ref())
        .and_then(|o| o.requires.as_ref())
        .map(|r| r.env.clone())
        .unwrap_or_default();

    let env_re = Regex::new(r"\$\{?([A-Z][A-Z0-9_]+)\}?").unwrap();
    for cb in &skill.code_blocks {
        for cap in env_re.captures_iter(&cb.content) {
            let var = &cap[1];
            if var.len() > 2 && !declared_env.iter().any(|e| e == var) {
                findings.push(Finding {
                    rule_id: "META006".into(),
                    title: format!("Undeclared env var: {}", var),
                    description: format!(
                        "References environment variable ${} but does not declare it in requires.env.",
                        var
                    ),
                    severity: Severity::Low,
                    category: "metadata".into(),
                    confidence: 0.7,
                    region_type: RegionType::CodeBlock,
                    language: cb.language.clone(),
                    line_number: Some(cb.line_start),
                    evidence: Some(cap[0].to_string()),
                    fix: Some(format!(
                        "Add '{}' to `metadata.openclaw.requires.env` in frontmatter.",
                        var
                    )),
                    analysis_pass: pass.into(),
                });
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use crate::parsers::skill_parser;

    use super::*;

    #[test]
    fn detects_missing_name() {
        let content = "---\ndescription: test\n---\n\n# Hello\n";
        let parsed = skill_parser::parse(content).unwrap();
        let findings = validate(&parsed);
        assert!(findings.iter().any(|f| f.rule_id == "META001"));
    }

    #[test]
    fn detects_missing_description() {
        let content = "---\nname: test\n---\n\n# Hello\n";
        let parsed = skill_parser::parse(content).unwrap();
        let findings = validate(&parsed);
        assert!(findings.iter().any(|f| f.rule_id == "META003"));
    }

    #[test]
    fn detects_undeclared_binary() {
        let content = "---\nname: test\ndescription: test skill\n---\n\n```bash\ncurl https://example.com\n```\n";
        let parsed = skill_parser::parse(content).unwrap();
        let findings = validate(&parsed);
        assert!(findings.iter().any(|f| f.title.contains("curl")));
    }

    #[test]
    fn no_finding_when_binary_declared() {
        let content = "---\nname: test\ndescription: test skill\nmetadata:\n  openclaw:\n    requires:\n      bins:\n        - curl\n---\n\n```bash\ncurl https://example.com\n```\n";
        let parsed = skill_parser::parse(content).unwrap();
        let findings = validate(&parsed);
        assert!(!findings.iter().any(|f| f.title.contains("Undeclared binary: curl")));
    }
}
