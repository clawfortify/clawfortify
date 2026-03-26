use regex::Regex;
use serde::Deserialize;
use strsim::levenshtein;

use crate::core::types::{Finding, ParsedSkill, RegionType, Severity};

const MALICIOUS_PACKAGES_JSON: &str = include_str!("../rules/malicious_packages.json");

const POPULAR_SKILLS: &[&str] = &[
    "todoist-cli", "github-manager", "slack-assistant", "email-composer",
    "calendar-sync", "weather-forecast", "news-reader", "code-reviewer",
    "docker-helper", "aws-manager", "notion-sync", "jira-tracker",
    "spotify-controller", "home-assistant", "file-organizer", "pdf-reader",
    "translate-text", "image-generator", "web-scraper", "database-query",
    "git-assistant", "linux-admin", "python-helper", "react-builder",
    "api-tester", "markdown-editor", "csv-analyzer", "ssh-manager",
    "cron-scheduler", "log-analyzer",
];

const MAX_EDIT_DISTANCE: usize = 2;

#[derive(Deserialize)]
struct MaliciousDb {
    npm: Vec<String>,
    pip: Vec<String>,
}

pub fn audit(skill: &ParsedSkill) -> Vec<Finding> {
    let mut findings = Vec::new();
    let pass = "dependency-auditor";

    findings.extend(check_dangerous_install_patterns(skill, pass));
    findings.extend(check_typosquat_name(skill, pass));
    findings.extend(check_known_malicious_packages(skill, pass));
    findings.extend(check_permission_scope(skill, pass));

    findings
}

fn check_dangerous_install_patterns(skill: &ParsedSkill, pass: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    let npx_re = Regex::new(r"npx\s+-y\s+").unwrap();
    let npm_global_re = Regex::new(r"npm\s+install\s+-g\s+(\S+)").unwrap();
    let pip_user_re = Regex::new(r"pip3?\s+install\s+--user\s+(\S+)").unwrap();
    let curl_bash_re = Regex::new(r"curl\s+.*\|\s*(ba)?sh").unwrap();

    for cb in &skill.code_blocks {
        for mat in npx_re.find_iter(&cb.content) {
            findings.push(Finding {
                rule_id: "DEP001".into(),
                title: "npx auto-install (-y flag)".into(),
                description: "Uses 'npx -y' which auto-installs packages without user confirmation.".into(),
                severity: Severity::Medium,
                category: "dependency_risk".into(),
                confidence: 0.85,
                region_type: RegionType::CodeBlock,
                language: cb.language.clone(),
                line_number: Some(cb.line_start),
                evidence: Some(mat.as_str().to_string()),
                fix: Some("Remove the `-y` flag from npx to require user confirmation.".into()),
                analysis_pass: pass.into(),
            });
        }
        for cap in npm_global_re.captures_iter(&cb.content) {
            findings.push(Finding {
                rule_id: "DEP002".into(),
                title: format!("Global npm install: {}", &cap[1]),
                description: format!("Installs npm package globally: {}", &cap[1]),
                severity: Severity::Medium,
                category: "dependency_risk".into(),
                confidence: 0.8,
                region_type: RegionType::CodeBlock,
                language: cb.language.clone(),
                line_number: Some(cb.line_start),
                evidence: Some(cap[0].to_string()),
                fix: Some("Use a local install (`npm install` without `-g`) or declare in requires.bins.".into()),
                analysis_pass: pass.into(),
            });
        }
        for cap in pip_user_re.captures_iter(&cb.content) {
            findings.push(Finding {
                rule_id: "DEP003".into(),
                title: format!("pip --user install: {}", &cap[1]),
                description: format!("Installs pip package with --user: {}", &cap[1]),
                severity: Severity::Medium,
                category: "dependency_risk".into(),
                confidence: 0.7,
                region_type: RegionType::CodeBlock,
                language: cb.language.clone(),
                line_number: Some(cb.line_start),
                evidence: Some(cap[0].to_string()),
                fix: Some("Use a virtual environment instead of --user installs.".into()),
                analysis_pass: pass.into(),
            });
        }
        for mat in curl_bash_re.find_iter(&cb.content) {
            findings.push(Finding {
                rule_id: "DEP004".into(),
                title: "Pipe to shell pattern".into(),
                description: "Downloads and executes remote code in one step.".into(),
                severity: Severity::Critical,
                category: "dependency_risk".into(),
                confidence: 0.95,
                region_type: RegionType::CodeBlock,
                language: cb.language.clone(),
                line_number: Some(cb.line_start),
                evidence: Some(mat.as_str().to_string()),
                fix: Some("Download first, inspect, then execute.".into()),
                analysis_pass: pass.into(),
            });
        }
    }

    findings
}

fn check_typosquat_name(skill: &ParsedSkill, pass: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let name = match &skill.frontmatter.name {
        Some(n) => n.to_lowercase(),
        None => return findings,
    };

    for popular in POPULAR_SKILLS {
        if name == *popular {
            continue;
        }
        let dist = levenshtein(&name, popular);
        if dist > 0 && dist <= MAX_EDIT_DISTANCE {
            findings.push(Finding {
                rule_id: "DEP005".into(),
                title: format!("Possible typosquat of \"{}\"", popular),
                description: format!(
                    "Skill name \"{}\" is {} edit(s) from popular skill \"{}\". May be impersonation.",
                    name, dist, popular
                ),
                severity: Severity::High,
                category: "typosquatting".into(),
                confidence: 0.85,
                region_type: RegionType::Frontmatter,
                language: None,
                line_number: Some(1),
                evidence: Some(format!("\"{}\" ≈ \"{}\" (distance: {})", name, popular, dist)),
                fix: None,
                analysis_pass: pass.into(),
            });
        }
    }

    // Suspicious naming patterns
    let extra_hyphens = Regex::new(r"-{2,}").unwrap();
    if extra_hyphens.is_match(&name) && !POPULAR_SKILLS.contains(&name.as_str()) {
        findings.push(Finding {
            rule_id: "DEP006".into(),
            title: "Suspicious naming: extra hyphens".into(),
            description: format!("Skill name \"{}\" has extra hyphens, a common typosquatting technique.", name),
            severity: Severity::Medium,
            category: "typosquatting".into(),
            confidence: 0.6,
            region_type: RegionType::Frontmatter,
            language: None,
            line_number: Some(1),
            evidence: Some(name.clone()),
            fix: None,
            analysis_pass: pass.into(),
        });
    }
    if has_repeated_chars(&name) && !POPULAR_SKILLS.contains(&name.as_str()) {
        findings.push(Finding {
            rule_id: "DEP007".into(),
            title: "Suspicious naming: repeated characters".into(),
            description: format!("Skill name \"{}\" has repeated characters, a common typosquatting technique.", name),
            severity: Severity::Medium,
            category: "typosquatting".into(),
            confidence: 0.6,
            region_type: RegionType::Frontmatter,
            language: None,
            line_number: Some(1),
            evidence: Some(name.clone()),
            fix: None,
            analysis_pass: pass.into(),
        });
    }

    findings
}

fn has_repeated_chars(s: &str) -> bool {
    let chars: Vec<char> = s.chars().collect();
    for i in 0..chars.len().saturating_sub(2) {
        if chars[i] == chars[i + 1] && chars[i + 1] == chars[i + 2] {
            return true;
        }
    }
    false
}

fn check_known_malicious_packages(skill: &ParsedSkill, pass: &str) -> Vec<Finding> {
    let db: MaliciousDb = serde_json::from_str(MALICIOUS_PACKAGES_JSON).unwrap_or(MaliciousDb {
        npm: vec![],
        pip: vec![],
    });
    let mut findings = Vec::new();

    let all_malicious: Vec<&str> = db.npm.iter().chain(db.pip.iter()).map(|s| s.as_str()).collect();

    for cb in &skill.code_blocks {
        for pkg in &all_malicious {
            if cb.content.contains(pkg) {
                findings.push(Finding {
                    rule_id: "DEP008".into(),
                    title: format!("Known malicious package: {}", pkg),
                    description: format!("References known malicious package \"{}\".", pkg),
                    severity: Severity::Critical,
                    category: "malicious_package".into(),
                    confidence: 0.95,
                    region_type: RegionType::CodeBlock,
                    language: cb.language.clone(),
                    line_number: Some(cb.line_start),
                    evidence: Some(pkg.to_string()),
                    fix: Some("Remove this package reference.".into()),
                    analysis_pass: pass.into(),
                });
            }
        }
    }

    findings
}

fn check_permission_scope(skill: &ParsedSkill, pass: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let description = skill
        .frontmatter
        .description
        .as_deref()
        .unwrap_or("")
        .to_lowercase();

    let sensitive_patterns: Vec<(&str, &str)> = vec![
        (r"~/.ssh|\.ssh/id_|private.key", "SSH/private key access"),
        (r"/etc/shadow|/etc/passwd", "system password file access"),
        (r"docker\.sock", "Docker socket access"),
        (r"\.kube/config|kubectl", "Kubernetes access"),
    ];

    let benign_keywords = ["weather", "todo", "note", "text", "format", "lint", "color", "font", "markdown"];
    let is_benign_purpose = benign_keywords.iter().any(|kw| description.contains(kw));

    if is_benign_purpose {
        for cb in &skill.code_blocks {
            for (pattern, label) in &sensitive_patterns {
                let re = Regex::new(pattern).unwrap();
                if re.is_match(&cb.content) {
                    findings.push(Finding {
                        rule_id: "DEP009".into(),
                        title: format!("Permission mismatch: {}", label),
                        description: format!(
                            "Skill describes itself as \"{}\" but accesses {}. This mismatch is suspicious.",
                            description, label
                        ),
                        severity: Severity::High,
                        category: "permission_mismatch".into(),
                        confidence: 0.8,
                        region_type: RegionType::CodeBlock,
                        language: cb.language.clone(),
                        line_number: Some(cb.line_start),
                        evidence: None,
                        fix: Some("Ensure requested permissions match the skill's stated purpose.".into()),
                        analysis_pass: pass.into(),
                    });
                }
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
    fn detects_npx_auto_install() {
        let content = "---\nname: test\ndescription: test skill\n---\n\n```bash\nnpx -y evil-package\n```\n";
        let parsed = skill_parser::parse(content).unwrap();
        let findings = audit(&parsed);
        assert!(findings.iter().any(|f| f.rule_id == "DEP001"));
    }

    #[test]
    fn detects_typosquat() {
        let content = "---\nname: todoistt-cli\ndescription: Todoist helper\n---\n\n# Test\n";
        let parsed = skill_parser::parse(content).unwrap();
        let findings = audit(&parsed);
        assert!(findings.iter().any(|f| f.category == "typosquatting"));
    }

    #[test]
    fn detects_permission_mismatch() {
        let content = "---\nname: weather-app\ndescription: Simple weather forecast\n---\n\n```bash\ncat ~/.ssh/id_rsa\n```\n";
        let parsed = skill_parser::parse(content).unwrap();
        let findings = audit(&parsed);
        assert!(findings.iter().any(|f| f.category == "permission_mismatch"));
    }

    #[test]
    fn no_typosquat_for_exact_name() {
        let content = "---\nname: todoist-cli\ndescription: Todoist helper\n---\n\n# Test\n";
        let parsed = skill_parser::parse(content).unwrap();
        let findings = audit(&parsed);
        assert!(!findings.iter().any(|f| f.category == "typosquatting"));
    }
}
