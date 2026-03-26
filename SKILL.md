---
name: clawfortify
version: 0.1.0
description: AI skill security scanner with 7-pass analysis. Scans SKILL.md files for prompt injection, credential theft, RCE, supply chain attacks, and 71+ threat patterns before installation.
author: clawfortify
license: MIT
homepage: https://github.com/clawfortify/clawfortify
repository: https://github.com/clawfortify/clawfortify
metadata:
  openclaw:
    requires:
      bins:
        - clawfortify
      env: []
    category: security
    tags:
      - security
      - scanner
      - supply-chain
      - audit
      - prompt-injection
---

# ClawFortify

AI skill security scanner. Runs a 7-pass analysis pipeline with 71+ threat detection rules, Markdown region-aware matching, and weighted risk scoring.

## Install

```bash
cargo install clawfortify
```

Or download pre-built binaries from [GitHub Releases](https://github.com/clawfortify/clawfortify/releases) (Linux / macOS / Windows).

## Usage

Scan a local skill:

```bash
clawfortify scan ./skill-folder/
```

JSON output for CI/CD:

```bash
clawfortify scan ./skill-folder/ --format json --fail-on high
```

SARIF output for GitHub Code Scanning:

```bash
clawfortify scan ./skill-folder/ --format sarif -o results.sarif
```

Audit all installed skills:

```bash
clawfortify audit
```

Watch mode — auto-scan on file changes:

```bash
clawfortify watch ./skills/
```

Update threat rules:

```bash
clawfortify update-rules
```

## Analysis Passes

1. **Skill Parser** — Markdown region-aware parsing with YAML frontmatter extraction
2. **Static Analysis** — 71 regex patterns: RCE, credential theft, obfuscation, supply chain, agent attacks
3. **Metadata Validator** — Undeclared binaries/env vars, missing descriptions, semver validation
4. **Dependency Auditor** — Typosquatting, malicious packages, dangerous install patterns
5. **Prompt Injection** — Instruction override, role hijack, hidden channels (zero-width, RTL, HTML comments)
6. **Behavioral Sandbox** — Static behavior inference: sensitive path access, persistence, data flow analysis
7. **Community Intelligence** — Known malicious signatures, community reports

## Risk Grades

| Score | Grade | Action |
|-------|-------|--------|
| 0-10 | A | Safe to install |
| 11-25 | B | Safe to install |
| 26-50 | C | Review before installing |
| 51-75 | D | Review carefully |
| 76-100 | F | Do not install |
