use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

use crate::core::types::{Finding, ParsedSkill, RegionType, Severity};

const DB_FILENAME: &str = "clawfortify-community.db";

const KNOWN_MALICIOUS_HASHES: &[(&str, &str)] = &[
    ("d7a5f8c2e1b3a4f6", "ClawHavoc dropper variant A"),
    ("e3b0c44298fc1c14", "Known empty-payload attack stub"),
    ("a1b2c3d4e5f6a7b8", "Credential stealer template v1"),
];

pub fn analyze(skill: &ParsedSkill) -> Vec<Finding> {
    let mut findings = Vec::new();
    let pass = "community-intel";

    findings.extend(check_known_signatures(skill, pass));

    if let Some(db) = open_db() {
        findings.extend(check_local_reports(&db, skill, pass));
    }

    findings
}

fn content_hash(content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn check_known_signatures(skill: &ParsedSkill, pass: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let full_hash = content_hash(&skill.raw_content);
    let hash_prefix = &full_hash[..16.min(full_hash.len())];

    for (sig, desc) in KNOWN_MALICIOUS_HASHES {
        if hash_prefix == *sig {
            findings.push(Finding {
                rule_id: "COM001".into(),
                title: format!("Known malicious signature: {}", desc),
                description: format!(
                    "Content hash matches known malicious signature ({}).",
                    desc
                ),
                severity: Severity::Critical,
                category: "known_malicious".into(),
                confidence: 0.99,
                region_type: RegionType::Prose,
                language: None,
                line_number: Some(1),
                evidence: Some(format!("hash prefix: {}", hash_prefix)),
                fix: Some("Do not install this skill.".into()),
                analysis_pass: pass.into(),
            });
        }
    }

    for cb in &skill.code_blocks {
        let cb_hash = content_hash(&cb.content);
        let cb_prefix = &cb_hash[..16.min(cb_hash.len())];
        for (sig, desc) in KNOWN_MALICIOUS_HASHES {
            if cb_prefix == *sig {
                findings.push(Finding {
                    rule_id: "COM002".into(),
                    title: format!("Code block matches malicious signature: {}", desc),
                    description: format!(
                        "A code block's hash matches known malicious code ({}).",
                        desc
                    ),
                    severity: Severity::Critical,
                    category: "known_malicious".into(),
                    confidence: 0.95,
                    region_type: RegionType::CodeBlock,
                    language: cb.language.clone(),
                    line_number: Some(cb.line_start),
                    evidence: Some(format!("hash prefix: {}", cb_prefix)),
                    fix: Some("Do not install this skill.".into()),
                    analysis_pass: pass.into(),
                });
            }
        }
    }

    findings
}

fn check_local_reports(db: &Connection, skill: &ParsedSkill, pass: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    let name = match &skill.frontmatter.name {
        Some(n) => n,
        None => return findings,
    };

    let mut stmt = db
        .prepare("SELECT report_count, last_reason FROM skill_reports WHERE skill_name = ?1")
        .ok();

    if let Some(ref mut s) = stmt {
        if let Ok(mut rows) = s.query(params![name]) {
            while let Ok(Some(row)) = rows.next() {
                let count: i64 = row.get(0).unwrap_or(0);
                let reason: String = row.get(1).unwrap_or_default();

                if count >= 3 {
                    findings.push(Finding {
                        rule_id: "COM003".into(),
                        title: format!("Community-reported skill ({} reports)", count),
                        description: format!(
                            "Skill \"{}\" has been reported {} times by the community. Latest reason: {}",
                            name, count, reason
                        ),
                        severity: if count >= 10 { Severity::Critical } else { Severity::High },
                        category: "community_report".into(),
                        confidence: 0.7,
                        region_type: RegionType::Frontmatter,
                        language: None,
                        line_number: Some(1),
                        evidence: Some(format!("{} reports", count)),
                        fix: None,
                        analysis_pass: pass.into(),
                    });
                }
            }
        }
    }

    findings
}

fn open_db() -> Option<Connection> {
    let path = db_path()?;
    let conn = Connection::open(&path).ok()?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS skill_reports (
            skill_name TEXT PRIMARY KEY,
            report_count INTEGER DEFAULT 0,
            last_reason TEXT DEFAULT '',
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS known_authors (
            author_id TEXT PRIMARY KEY,
            trust_level INTEGER DEFAULT 0,
            verified INTEGER DEFAULT 0
        );"
    ).ok()?;
    Some(conn)
}

fn db_path() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        std::env::var("LOCALAPPDATA")
            .ok()
            .map(|p| PathBuf::from(p).join("clawfortify").join(DB_FILENAME))
    }
    #[cfg(not(target_os = "windows"))]
    {
        std::env::var("HOME")
            .ok()
            .map(|p| PathBuf::from(p).join(".cache").join("clawfortify").join(DB_FILENAME))
    }
}

/// Sync community intelligence from a remote endpoint (placeholder for future implementation)
pub fn sync_remote(_endpoint: &str) -> Result<usize, String> {
    Err("Remote sync not yet implemented. Use `clawfortify update-rules` in a future version.".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::skill_parser;

    #[test]
    fn no_false_positive_on_clean_skill() {
        let content = "---\nname: clean-skill\ndescription: A safe skill\n---\n\n# Clean\n\nHello world.\n";
        let parsed = skill_parser::parse(content).unwrap();
        let findings = analyze(&parsed);
        assert!(
            !findings.iter().any(|f| f.category == "known_malicious"),
            "Clean skill should not match any malicious signatures"
        );
    }
}
