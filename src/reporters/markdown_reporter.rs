use crate::core::types::{ScanResult, Severity};

pub fn to_markdown(result: &ScanResult) -> String {
    let mut md = String::new();

    md.push_str(&format!("# ClawFortify Scan Report\n\n"));
    md.push_str(&format!("**File:** {}\n\n", result.skill_path));
    md.push_str(&format!(
        "**Risk Score:** {}/100 | **Grade:** {} | **Findings:** {}\n\n",
        result.risk_score.score,
        result.risk_score.grade,
        result.risk_score.findings.len()
    ));
    md.push_str(&format!(
        "> {}\n\n",
        result.risk_score.grade.verdict()
    ));

    md.push_str("## Pass Summary\n\n");
    md.push_str("| Pass | Findings | Status |\n");
    md.push_str("|------|----------|--------|\n");
    let pass_order = [
        "skill-parser",
        "static-analysis",
        "metadata-validator",
        "dependency-auditor",
        "prompt-injection",
        "behavioral-sandbox",
        "community-intel",
    ];
    for key in &pass_order {
        if let Some(summary) = result.pass_summaries.get(*key) {
            md.push_str(&format!(
                "| {} | {} | {} |\n",
                summary.pass_name, summary.finding_count, summary.status
            ));
        }
    }
    md.push('\n');

    if result.risk_score.findings.is_empty() {
        md.push_str("## Findings\n\nNo findings detected.\n");
        return md;
    }

    md.push_str("## Findings\n\n");

    let mut by_severity: Vec<_> = result.risk_score.findings.iter().collect();
    by_severity.sort_by(|a, b| b.severity.cmp(&a.severity));

    for f in &by_severity {
        let icon = match f.severity {
            Severity::Critical => "🔴",
            Severity::High => "🟠",
            Severity::Medium => "🟡",
            Severity::Low => "🔵",
            Severity::Info => "⚪",
        };

        md.push_str(&format!(
            "### {} {} — {}\n\n",
            icon, f.severity, f.rule_id
        ));
        md.push_str(&format!("**{}**\n\n", f.title));
        md.push_str(&format!("{}\n\n", f.description));

        if let Some(line) = f.line_number {
            md.push_str(&format!(
                "- **Line:** {} | **Region:** {:?} | **Confidence:** {:.0}%\n",
                line,
                f.region_type,
                f.confidence * 100.0
            ));
        }
        if let Some(evidence) = &f.evidence {
            let short = if evidence.len() > 120 {
                format!("{}...", &evidence[..120])
            } else {
                evidence.clone()
            };
            md.push_str(&format!("- **Evidence:** `{}`\n", short));
        }
        if let Some(fix) = &f.fix {
            md.push_str(&format!("- **Fix:** {}\n", fix));
        }
        md.push('\n');
    }

    md
}

pub fn print_markdown(result: &ScanResult) {
    println!("{}", to_markdown(result));
}
