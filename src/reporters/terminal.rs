use owo_colors::OwoColorize;

use crate::core::types::{Grade, ScanResult, Severity};

pub fn print_report(result: &ScanResult) {
    println!();
    println!(
        "{}",
        "╭──────────────────────────────────────────────────────╮"
            .bright_cyan()
    );
    println!(
        "{}",
        "│  ClawFortify v0.1.0 — AI Skill Security Scanner      │"
            .bright_cyan()
    );
    println!(
        "{}",
        "╰──────────────────────────────────────────────────────╯"
            .bright_cyan()
    );
    println!();

    println!("  {} {}", "Scanning:".bold(), result.skill_path);
    println!();

    let pass_order = [
        ("skill-parser", "Parsing SKILL.md"),
        ("static-analysis", "Static Pattern Analysis"),
        ("metadata-validator", "Metadata Validation"),
        ("dependency-auditor", "Dependency Chain Audit"),
        ("prompt-injection", "Prompt Injection Detection"),
        ("behavioral-sandbox", "Behavioral Sandbox"),
        ("community-intel", "Community Intelligence"),
    ];

    for (i, (key, label)) in pass_order.iter().enumerate() {
        let pass_num = i + 1;
        let total = pass_order.len();
        if let Some(summary) = result.pass_summaries.get(*key) {
            let count_str = if *key == "skill-parser" {
                format!("{} regions", summary.finding_count)
            } else {
                format!(
                    "{} finding{}",
                    summary.finding_count,
                    if summary.finding_count == 1 { "" } else { "s" }
                )
            };
            println!(
                "  Pass {}/{} {} {} {}",
                pass_num,
                total,
                label,
                "...........".dimmed(),
                format!("✓ {}", count_str).green()
            );
        }
    }

    println!();

    let score = result.risk_score.score;
    let grade = result.risk_score.grade;

    let grade_colored = match grade {
        Grade::A => format!("{}", grade).green().to_string(),
        Grade::B => format!("{}", grade).bright_green().to_string(),
        Grade::C => format!("{}", grade).yellow().to_string(),
        Grade::D => format!("{}", grade).bright_red().to_string(),
        Grade::F => format!("{}", grade).red().to_string(),
    };

    let bar_len = (score as usize * 20) / 100;
    let bar_filled: String = "█".repeat(bar_len.min(20));
    let bar_empty: String = "░".repeat(20 - bar_len.min(20));

    println!(
        "{}",
        "╭── Risk Score ───────────────────────────────────────╮"
            .bright_cyan()
    );
    println!(
        "│                                                      │"
    );
    println!(
        "│        Score: {}/100          Grade: {} {}           │",
        score, bar_filled, grade_colored
    );
    println!(
        "│        {}{}                         │",
        bar_filled.dimmed(),
        bar_empty.dimmed()
    );
    println!(
        "│                                                      │"
    );
    println!("│  Verdict: {}     │", grade.verdict());
    println!(
        "│                                                      │"
    );
    println!(
        "{}",
        "╰──────────────────────────────────────────────────────╯"
            .bright_cyan()
    );

    let findings = &result.risk_score.findings;
    if findings.is_empty() {
        println!();
        println!("  {} No findings.", "✓".green());
        return;
    }

    println!();
    println!(
        "{}",
        format!("┌── Findings ({}) ─────────────────────────────────────┐", findings.len())
    );

    for f in findings {
        let severity_str = match f.severity {
            Severity::Critical => format!("✖ {}", f.severity).red().to_string(),
            Severity::High => format!("✖ {}", f.severity).bright_red().to_string(),
            Severity::Medium => format!("⚠ {}", f.severity).yellow().to_string(),
            Severity::Low => format!("ℹ {}", f.severity).blue().to_string(),
            Severity::Info => format!("ℹ {}", f.severity).dimmed().to_string(),
        };

        println!("│                                                      │");
        println!("│  {} {}", severity_str, f.rule_id.bold());
        if let Some(line) = f.line_number {
            println!(
                "│  Line {} ({:?}, {})",
                line,
                f.region_type,
                f.language.as_deref().unwrap_or("unknown")
            );
        }
        println!("│  {}", f.description);
        println!(
            "│  Confidence: {:.1} | Category: {}",
            f.confidence, f.category
        );
        if let Some(fix) = &f.fix {
            println!("│  Fix: {}", fix.dimmed());
        }
    }

    println!("│                                                      │");
    println!(
        "└──────────────────────────────────────────────────────┘"
    );
    println!();
}
