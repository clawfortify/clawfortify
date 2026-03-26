use std::path::{Path, PathBuf};
use std::process;
use std::sync::mpsc;

use clap::{Parser, Subcommand, ValueEnum};
use notify::{EventKind, RecursiveMode, Watcher};

use clawfortify::cache::scan_cache::ScanCache;
use clawfortify::core::orchestrator;
use clawfortify::core::types::Severity;
use clawfortify::reporters::{json_reporter, markdown_reporter, sarif_reporter, terminal};

#[derive(Parser)]
#[command(
    name = "clawfortify",
    version,
    about = "AI Skill Security Scanner — scan SKILL.md files for threats before installation"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Scan a single skill directory or SKILL.md file
    Scan {
        /// Path to skill directory or SKILL.md file
        path: PathBuf,

        /// Output format
        #[arg(long, default_value = "terminal")]
        format: OutputFormat,

        /// Exit with non-zero code if findings at or above this severity
        #[arg(long)]
        fail_on: Option<FailOnLevel>,

        /// Write output to file instead of stdout
        #[arg(long, short)]
        output: Option<PathBuf>,
    },
    /// Audit all installed skills in ~/.cursor/skills/
    Audit {
        /// Output format
        #[arg(long, default_value = "terminal")]
        format: OutputFormat,
    },
    /// Watch a directory for skill file changes and re-scan automatically
    Watch {
        /// Directory to watch
        path: PathBuf,
    },
    /// Update threat detection rules from remote repository
    UpdateRules {
        /// Custom rules repository URL
        #[arg(long, default_value = "https://raw.githubusercontent.com/clawfortify/clawfortify/main/src/rules/patterns.json")]
        url: String,
    },
}

#[derive(Clone, ValueEnum)]
pub enum OutputFormat {
    Terminal,
    Json,
    Sarif,
    Markdown,
}

#[derive(Clone, ValueEnum)]
pub enum FailOnLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl FailOnLevel {
    fn to_severity(&self) -> Severity {
        match self {
            FailOnLevel::Low => Severity::Low,
            FailOnLevel::Medium => Severity::Medium,
            FailOnLevel::High => Severity::High,
            FailOnLevel::Critical => Severity::Critical,
        }
    }
}

pub fn run() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            path,
            format,
            fail_on,
            output,
        } => {
            let skill_path = resolve_skill_path(&path);
            match orchestrator::scan(&skill_path) {
                Ok(result) => {
                    let output_str = match format {
                        OutputFormat::Terminal => {
                            terminal::print_report(&result);
                            None
                        }
                        OutputFormat::Json => {
                            Some(json_reporter::to_json(&result))
                        }
                        OutputFormat::Sarif => {
                            let sarif = sarif_reporter::to_sarif(&result);
                            Some(serde_json::to_string_pretty(&sarif).unwrap())
                        }
                        OutputFormat::Markdown => {
                            Some(markdown_reporter::to_markdown(&result))
                        }
                    };

                    if let Some(content) = output_str {
                        if let Some(out_path) = &output {
                            std::fs::write(out_path, &content).unwrap_or_else(|e| {
                                eprintln!("Error writing to {}: {}", out_path.display(), e);
                                process::exit(1);
                            });
                        } else {
                            println!("{}", content);
                        }
                    }

                    if let Some(level) = fail_on {
                        let threshold = level.to_severity();
                        let has_violations = result
                            .risk_score
                            .findings
                            .iter()
                            .any(|f| f.severity >= threshold);
                        if has_violations {
                            process::exit(1);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    process::exit(1);
                }
            }
        }
        Commands::Audit { format } => {
            let skills_dir = dirs_skill_path();
            if !skills_dir.exists() {
                eprintln!("Skills directory not found: {}", skills_dir.display());
                process::exit(1);
            }

            let mut found_any = false;
            if let Ok(entries) = std::fs::read_dir(&skills_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        let skill_md = path.join("SKILL.md");
                        if skill_md.exists() {
                            found_any = true;
                            match orchestrator::scan(&skill_md) {
                                Ok(result) => match format {
                                    OutputFormat::Terminal => terminal::print_report(&result),
                                    OutputFormat::Json => json_reporter::print_json(&result),
                                    OutputFormat::Sarif => sarif_reporter::print_sarif(&result),
                                    OutputFormat::Markdown => markdown_reporter::print_markdown(&result),
                                },
                                Err(e) => {
                                    eprintln!("Error scanning {}: {}", skill_md.display(), e);
                                }
                            }
                        }
                    }
                }
            }

            if !found_any {
                println!("No skills found in {}", skills_dir.display());
            }
        }
        Commands::Watch { path } => {
            let dir = if path.is_dir() {
                path.clone()
            } else if path.is_file() {
                path.parent().unwrap_or(Path::new(".")).to_path_buf()
            } else {
                path.clone()
            };

            if !dir.exists() {
                eprintln!("Directory not found: {}", dir.display());
                process::exit(1);
            }

            println!("  Watching {} for SKILL.md changes...", dir.display());
            println!("  Press Ctrl+C to stop.\n");

            let mut cache = ScanCache::new(None);
            watch_scan_existing(&dir, &mut cache);

            let (tx, rx) = mpsc::channel();
            let mut watcher = notify::recommended_watcher(
                move |res: Result<notify::Event, notify::Error>| {
                    if let Ok(event) = res { let _ = tx.send(event); }
                },
            ).expect("Failed to create file watcher");

            watcher.watch(&dir, RecursiveMode::Recursive)
                .expect("Failed to watch directory");

            loop {
                match rx.recv() {
                    Ok(event) => {
                        if matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_)) {
                            for p in &event.paths {
                                if is_skill_file(p) {
                                    watch_rescan(p, &mut cache);
                                }
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
        }
        Commands::UpdateRules { url } => {
            update_rules(&url);
        }
    }
}

fn resolve_skill_path(path: &PathBuf) -> PathBuf {
    if path.is_file() {
        path.clone()
    } else if path.is_dir() {
        let skill_md = path.join("SKILL.md");
        if skill_md.exists() {
            skill_md
        } else {
            eprintln!(
                "No SKILL.md found in directory: {}",
                path.display()
            );
            process::exit(1);
        }
    } else {
        eprintln!("Path does not exist: {}", path.display());
        process::exit(1);
    }
}

fn dirs_skill_path() -> PathBuf {
    if let Some(home) = home_dir() {
        home.join(".cursor").join("skills")
    } else {
        PathBuf::from(".cursor/skills")
    }
}

fn home_dir() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        std::env::var("USERPROFILE").ok().map(PathBuf::from)
    }
    #[cfg(not(target_os = "windows"))]
    {
        std::env::var("HOME").ok().map(PathBuf::from)
    }
}

fn is_skill_file(path: &Path) -> bool {
    path.file_name()
        .map(|n| {
            let s = n.to_string_lossy();
            s == "SKILL.md" || s.ends_with(".skill.md")
        })
        .unwrap_or(false)
}

fn watch_scan_existing(dir: &Path, cache: &mut ScanCache) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let skill_md = path.join("SKILL.md");
                if skill_md.exists() {
                    watch_rescan(&skill_md, cache);
                }
            } else if is_skill_file(&path) {
                watch_rescan(&path, cache);
            }
        }
    }
}

fn watch_rescan(path: &Path, cache: &mut ScanCache) {
    let path_str = path.display().to_string();
    if let Ok(content) = std::fs::read_to_string(path) {
        if let Some(cached) = cache.get(&path_str, &content) {
            println!("[cached] {} — Grade {}, Score {}\n", path_str, cached.risk_score.grade, cached.risk_score.score);
            return;
        }
        match orchestrator::scan(path) {
            Ok(result) => {
                terminal::print_report(&result);
                cache.put(path_str, &content, result);
            }
            Err(e) => eprintln!("[error] {} — {}", path_str, e),
        }
    }
}

fn update_rules(url: &str) {
    use sha2::{Digest, Sha256};

    println!("Fetching rules from {}...", url);

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap_or_else(|e| {
            eprintln!("Failed to create HTTP client: {}", e);
            process::exit(1);
        });

    let response = client.get(url).send().unwrap_or_else(|e| {
        eprintln!("Failed to fetch rules: {}", e);
        process::exit(1);
    });

    if !response.status().is_success() {
        eprintln!("HTTP {}: Failed to download rules", response.status());
        process::exit(1);
    }

    let body = response.text().unwrap_or_else(|e| {
        eprintln!("Failed to read response body: {}", e);
        process::exit(1);
    });

    // Validate JSON structure
    let rules: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap_or_else(|e| {
        eprintln!("Invalid rules JSON: {}", e);
        process::exit(1);
    });

    // Compute and display SHA-256 hash for verification
    let mut hasher = Sha256::new();
    hasher.update(body.as_bytes());
    let hash = format!("{:x}", hasher.finalize());

    // Determine local rules path
    let local_path = rules_path();
    if let Some(parent) = local_path.parent() {
        std::fs::create_dir_all(parent).unwrap_or_else(|e| {
            eprintln!("Failed to create rules directory: {}", e);
            process::exit(1);
        });
    }

    // Backup existing rules
    if local_path.exists() {
        let backup = local_path.with_extension("json.bak");
        let _ = std::fs::copy(&local_path, &backup);
    }

    std::fs::write(&local_path, &body).unwrap_or_else(|e| {
        eprintln!("Failed to write rules to {}: {}", local_path.display(), e);
        process::exit(1);
    });

    println!("Updated {} rules.", rules.len());
    println!("SHA-256: {}", hash);
    println!("Saved to: {}", local_path.display());
}

fn rules_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        std::env::var("LOCALAPPDATA")
            .map(|p| PathBuf::from(p).join("clawfortify").join("patterns.json"))
            .unwrap_or_else(|_| PathBuf::from("patterns.json"))
    }
    #[cfg(not(target_os = "windows"))]
    {
        std::env::var("HOME")
            .map(|p| PathBuf::from(p).join(".config").join("clawfortify").join("patterns.json"))
            .unwrap_or_else(|_| PathBuf::from("patterns.json"))
    }
}
