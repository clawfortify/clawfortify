# ClawFortify

AI Skill Security Scanner for the OpenClaw ecosystem. Scans SKILL.md files for prompt injection, credential theft, remote code execution, supply chain attacks, and more — catching threats before installation.

## Why

In Feb 2026 researchers found 824+ malicious skills (~20% of ClawHub). ClawFortify runs a 7-pass analysis pipeline with **71 threat detection rules**, **Markdown region-aware matching** to reduce false positives, and a **weighted risk scoring engine**.

## Quick Start

```bash
# Scan a local skill
clawfortify scan ./my-skill/

# JSON output for CI/CD
clawfortify scan ./my-skill/ --format json --fail-on high

# Audit all installed skills
clawfortify audit
```

## 7-Pass Scanner Engine

| Pass | Module | What it catches |
|------|--------|-----------------|
| 1 | Skill Parser | Parses YAML frontmatter, extracts code blocks with region annotations |
| 2 | Static Analysis | 71 regex patterns: RCE, credential theft, obfuscation, supply chain, agent attacks |
| 3 | Metadata Validator | Undeclared binaries/env vars, missing descriptions, semver validation |
| 4 | Dependency Auditor | Typosquatting, malicious packages, dangerous install patterns |
| 5 | Prompt Injection | Instruction override, role hijack, hidden channels (zero-width, RTL, HTML comments) |
| 6 | Behavioral Sandbox | Static behavior inference: sensitive path access, data flow analysis |
| 7 | Community Intel | Author reputation, ClawHavoc signature matching, community reports |

## Key Innovation: Region-Aware Matching

Unlike other scanners that treat SKILL.md as plain text, ClawFortify parses Markdown structure and assigns risk weights per region:

| Region | Weight | Reason |
|--------|--------|--------|
| Code block (shell) | 1.0 | Directly executable |
| Code block (python/js) | 0.95 | Executable code |
| HTML comment | 0.9 | Hidden content, highly suspicious |
| Frontmatter | 0.85 | Read by agent systems |
| Inline code | 0.7 | May be executed by agents |
| Link | 0.6 | URL may point to malicious targets |
| Heading | 0.3 | Usually just labels |
| Prose | 0.2 | Documentation, low risk |

This means discussing `.env` in documentation text won't trigger the same alert as accessing `.env` in a bash code block.

## Risk Scoring

- Each **critical** finding: +30 points
- Each **high** finding: +15 points
- Each **medium** finding: +7 points
- Each **low** finding: +3 points
- Score capped at 100. Grades: A (0-10), B (11-25), C (26-50), D (51-75), F (76-100)
- **Decay factor**: repeated triggers of the same rule contribute diminishing scores

## Installation

### Pre-built binaries

Download from [GitHub Releases](https://github.com/clawfortify/clawfortify/releases) for Linux, macOS, and Windows.

### From source

```bash
git clone https://github.com/clawfortify/clawfortify.git
cd clawfortify
cargo build --release
```

## Development

```bash
cargo test          # Run all tests (59 tests)
cargo clippy        # Lint
cargo build --release  # Release build
```

## License

MIT
