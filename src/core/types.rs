use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegionType {
    Frontmatter,
    CodeBlock,
    InlineCode,
    Heading,
    Prose,
    Link,
    HtmlComment,
}

impl RegionType {
    pub fn weight(&self, language: Option<&str>) -> f64 {
        match self {
            RegionType::CodeBlock => match language {
                Some("bash" | "sh" | "shell" | "zsh" | "powershell" | "pwsh" | "ps1") => 1.0,
                Some("python" | "python3" | "javascript" | "js" | "typescript" | "ts") => 0.95,
                _ => 0.9,
            },
            RegionType::Frontmatter => 0.85,
            RegionType::HtmlComment => 0.9,
            RegionType::InlineCode => 0.7,
            RegionType::Link => 0.6,
            RegionType::Heading => 0.3,
            RegionType::Prose => 0.2,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Region {
    pub region_type: RegionType,
    pub content: String,
    pub language: Option<String>,
    pub line_start: usize,
    pub line_end: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeBlock {
    pub content: String,
    pub language: Option<String>,
    pub line_start: usize,
    pub line_end: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn weight(&self) -> u32 {
        match self {
            Severity::Critical => 30,
            Severity::High => 15,
            Severity::Medium => 7,
            Severity::Low => 3,
            Severity::Info => 0,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
            Severity::Info => write!(f, "INFO"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub category: String,
    pub confidence: f64,
    pub region_type: RegionType,
    pub language: Option<String>,
    pub line_number: Option<usize>,
    pub evidence: Option<String>,
    pub fix: Option<String>,
    pub analysis_pass: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Grade {
    A,
    B,
    C,
    D,
    F,
}

impl fmt::Display for Grade {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Grade::A => write!(f, "A"),
            Grade::B => write!(f, "B"),
            Grade::C => write!(f, "C"),
            Grade::D => write!(f, "D"),
            Grade::F => write!(f, "F"),
        }
    }
}

impl Grade {
    pub fn from_score(score: u32) -> Self {
        match score {
            0..=10 => Grade::A,
            11..=25 => Grade::B,
            26..=50 => Grade::C,
            51..=75 => Grade::D,
            _ => Grade::F,
        }
    }

    pub fn verdict(&self) -> &'static str {
        match self {
            Grade::A => "SAFE — No significant risks detected",
            Grade::B => "LOW RISK — Safe to install with review",
            Grade::C => "MODERATE RISK — Review findings before installing",
            Grade::D => "HIGH RISK — Strongly recommend not installing",
            Grade::F => "BLOCKED — Critical threats detected, do not install",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScore {
    pub score: u32,
    pub grade: Grade,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Frontmatter {
    pub name: Option<String>,
    pub description: Option<String>,
    pub version: Option<String>,
    #[serde(default)]
    pub metadata: Option<FrontmatterMetadata>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FrontmatterMetadata {
    pub openclaw: Option<OpenClawMeta>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OpenClawMeta {
    pub requires: Option<OpenClawRequires>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OpenClawRequires {
    #[serde(default)]
    pub bins: Vec<String>,
    #[serde(default)]
    pub env: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedSkill {
    pub raw_content: String,
    pub frontmatter: Frontmatter,
    pub regions: Vec<Region>,
    pub code_blocks: Vec<CodeBlock>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatPattern {
    pub name: String,
    pub pattern: String,
    pub severity: Severity,
    pub category: String,
    pub title: String,
    pub description: String,
    #[serde(default)]
    pub code_only: bool,
    #[serde(default)]
    pub fix: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub skill_path: String,
    pub risk_score: RiskScore,
    pub pass_summaries: HashMap<String, PassSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassSummary {
    pub pass_name: String,
    pub finding_count: usize,
    pub status: String,
}
