# ClawFortify — 智能安全审计技能设计方案

> AI Agent 技能生态的"杀毒软件" — 安装前扫描、运行时监控、社区信誉体系

---

## 一、竞品分析总结

### 1.1 已分析的 4 个竞品

| 项目 | 语言 | 检测方法 | 核心优势 | 核心缺陷 |
|------|------|----------|----------|----------|
| **skill-vetter-multi** | Bash | 编排器（串联 aguara + cisco scanner + 内建 grep） | 优雅降级、多输入源、AI Agent 友好 | 内建检测极弱（仅 grep）、无测试、无 JSON 输出、仅 Linux/macOS |
| **ClawVet** | TypeScript | 6-Pass 引擎（54 条正则 + LLM 语义分析 + typosquat） | 架构最完善、置信度评分、Web 仪表板、SARIF 输出、CI/CD 集成 | 重量级（需 Postgres+Redis）、LLM 分析收费、JWT 自实现、缓存无 TTL |
| **skill-scanner** | Python | 46 条正则 + URL 一致性检查 | 零依赖、完全离线、可扩展 patterns.json | 逐行匹配、无语义分析、context_sensitive 未实现、无 typosquat |
| **skill-scanner-guard** | Bash | 策略层（依赖 cisco scanner 引擎） | systemd 自动监控、暂存-扫描-安装流水线、自动隔离 | 仅 Linux、Markdown 解析脆弱、解析失败 fail-open（危险） |

### 1.2 所有竞品的共同弱点

1. **无沙箱行为分析** — 全部基于静态分析（正则/AST），无法检测运行时恶意行为
2. **无依赖链审计** — 不检查技能依赖的外部包是否安全
3. **无社区信誉系统** — 缺少作者评分、社区投票、历史安全记录
4. **Windows 支持差** — Bash 脚本为主，Windows 用户群被忽略
5. **误报率高** — 文档中讨论 `.env` 就会触发告警，缺乏上下文理解
6. **无增量/差异扫描** — 技能更新时需要全量重扫
7. **无供应链完整性验证** — 不验证发布包与源码的一致性
8. **缺乏标准化报告** — 各工具报告格式不兼容

---

## 二、ClawFortify 设计目标

### 2.1 核心定位

**一个为 Cursor / OpenClaw 生态设计的"技能杀毒软件"**，覆盖技能生命周期的安全需求：

```
发现技能 → 安装前扫描 → 安装 → 运行时监控 → 更新检测 → 社区反馈
```

### 2.2 差异化优势（vs 竞品）

| 维度 | 竞品现状 | ClawFortify 方案 |
|------|----------|-----------------|
| 检测深度 | 纯静态（正则/AST） | **静态 + 语义 + 轻量沙箱三层防护** |
| 上下文理解 | 无（文档=代码一视同仁） | **Markdown 区域感知引擎**（区分 prose/codeblock/frontmatter） |
| 依赖安全 | 不检查 | **依赖链审计**（检查 bins/env/npm/pip 声明） |
| 平台支持 | Linux/macOS | **跨平台**（Rust 单二进制，Windows/macOS/Linux） |
| 社区协防 | 无 | **社区信誉评分 + 众包威胁情报** |
| 报告标准 | 各自为政 | **统一 JSON Schema + SARIF + Markdown** |
| 集成方式 | 独立 CLI | **Cursor Skill + CLI + GitHub Action 三合一** |
| 安全失败 | fail-open（危险） | **fail-closed 原则**（异常时阻断） |

---

## 三、架构设计

### 3.1 整体架构

```
┌─────────────────────────────────────────────────────────────┐
│                     ClawFortify Skill                          │
│                    (SKILL.md + scripts/)                      │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────────┐   │
│  │  CLI 入口    │   │ Cursor 集成  │   │ GitHub Action   │   │
│  │ clawfortify    │   │ Agent 自动   │   │  CI/CD 管道     │   │
│  │ scan/audit/  │   │ 触发扫描     │   │  PR 检查        │   │
│  │ watch/report │   │              │   │                 │   │
│  └──────┬───────┘   └──────┬───────┘   └───────┬─────────┘   │
│         │                  │                    │             │
│         └──────────┬───────┘────────────────────┘             │
│                    ▼                                          │
│  ┌─────────────────────────────────────────────────────┐     │
│  │              扫描编排引擎 (Orchestrator)               │     │
│  │  输入标准化 → Pass 调度 → 结果聚合 → 评分 → 报告       │     │
│  └───────────────────────┬─────────────────────────────┘     │
│                          ▼                                    │
│  ┌──── 7-Pass 扫描管线 ────────────────────────────────┐     │
│  │                                                      │     │
│  │  Pass 1: Skill Parser                                │     │
│  │  ├── YAML frontmatter 解析                           │     │
│  │  ├── Markdown 区域标注 (prose/code/heading/link)      │     │
│  │  └── 元数据提取 (URLs, IPs, env vars, bins)          │     │
│  │                                                      │     │
│  │  Pass 2: Static Pattern Analysis                     │     │
│  │  ├── 70+ 检测规则 (JSON 可配置)                       │     │
│  │  ├── 区域感知匹配 (代码块权重 > 文档权重)              │     │
│  │  └── 置信度 × 严重性评分                              │     │
│  │                                                      │     │
│  │  Pass 3: Metadata & Integrity Validator              │     │
│  │  ├── frontmatter 完整性检查                           │     │
│  │  ├── 声明 vs 实际使用一致性 (bins/env/permissions)    │     │
│  │  └── 文件结构规范性检查                               │     │
│  │                                                      │     │
│  │  Pass 4: Dependency Chain Auditor                    │     │
│  │  ├── npm/pip/brew 包名 typosquat 检测                │     │
│  │  ├── 已知恶意包数据库比对                              │     │
│  │  ├── 不安全安装模式 (npx -y, curl|bash)              │     │
│  │  └── 权限范围审计 (要求的权限 vs 声称的功能)          │     │
│  │                                                      │     │
│  │  Pass 5: Prompt Injection Detector                   │     │
│  │  ├── 指令覆写检测 (ignore/forget/override)           │     │
│  │  ├── 角色劫持检测 (you are now/act as)               │     │
│  │  ├── 隐蔽通道检测 (零宽字符/RTL覆写/Unicode隐写)     │     │
│  │  └── 多语言 prompt injection (LLM 语义分析)          │     │
│  │                                                      │     │
│  │  Pass 6: Behavioral Sandbox (轻量级)                 │     │
│  │  ├── 脚本静态模拟执行 (Shell AST 分析)               │     │
│  │  ├── 文件系统访问图谱 (读/写/删除目标分析)            │     │
│  │  ├── 网络连接意图分析 (目标域名/IP 分类)              │     │
│  │  └── 环境变量影响面评估                               │     │
│  │                                                      │     │
│  │  Pass 7: Community Intelligence                      │     │
│  │  ├── 作者信誉评分查询                                 │     │
│  │  ├── 已知恶意签名比对 (ClawHavoc 数据库)              │     │
│  │  └── 社区举报/审核状态                                │     │
│  │                                                      │     │
│  └──────────────────────────────────────────────────────┘     │
│                          ▼                                    │
│  ┌─────────────────────────────────────────────────────┐     │
│  │              风险评分引擎 (Risk Scorer)                │     │
│  │                                                      │     │
│  │  score = Σ(severity_weight × confidence × context)   │     │
│  │                                                      │     │
│  │  ┌─────┬─────┬─────┬─────┬─────┐                    │     │
│  │  │  A  │  B  │  C  │  D  │  F  │                    │     │
│  │  │0-10 │11-25│26-50│51-75│76+  │                    │     │
│  │  │安全 │低风险│需审查│高风险│阻断 │                    │     │
│  │  └─────┴─────┴─────┴─────┴─────┘                    │     │
│  └─────────────────────────────────────────────────────┘     │
│                          ▼                                    │
│  ┌─────────────────────────────────────────────────────┐     │
│  │              报告生成器 (Reporter)                     │     │
│  │  ├── Terminal (彩色 ANSI)                             │     │
│  │  ├── JSON (机器可读，含完整 schema)                    │     │
│  │  ├── SARIF (GitHub Code Scanning 兼容)                │     │
│  │  └── Markdown (人类可读报告)                           │     │
│  └─────────────────────────────────────────────────────┘     │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### 3.2 技术选型

| 组件 | 技术 | 理由 |
|------|------|------|
| 核心引擎 | Rust | 单二进制分发、零依赖、启动快（~5-20ms）、正则天然防回溯 |
| CLI 框架 | clap v4 | Rust 生态最成熟的 CLI 框架 |
| Markdown 解析 | pulldown-cmark | 高性能 CommonMark 解析器，完美支持区域标注 |
| YAML 解析 | serde_yaml | 安全的 YAML 反序列化 |
| 正则引擎 | regex crate | 基于 Thompson NFA，天然防灾难性回溯 |
| JSON 序列化 | serde_json | Rust 标准序列化库 |
| 终端美化 | owo-colors + indicatif | 彩色输出 + 进度条 |
| 编辑距离 | strsim | Levenshtein / Jaro-Winkler |
| HTTP 请求 | reqwest | 远程技能获取 |
| 文件监控 | notify | watch 模式 |
| Unicode 安全 | unicode-security | 检测同形字符、零宽字符 |
| 模式配置 | JSON | 可热更新、社区可贡献 |
| 社区数据 | SQLite (rusqlite) | 离线优先、按需同步 |
| Cursor 集成 | SKILL.md + scripts/ | 原生 Cursor Skill 格式 |

### 3.3 目录结构

```
clawfortify/
├── SKILL.md                          # Cursor Skill 定义（入口）
├── README.md                         # 用户文档
├── Cargo.toml                        # Rust 包定义
├── LICENSE                           # MIT
│
├── scripts/
│   ├── install.sh                    # macOS/Linux 一键安装（下载预编译二进制）
│   ├── install.ps1                   # Windows 一键安装
│   └── pre-install-hook.sh           # Agent 预安装钩子
│
├── src/
│   ├── main.rs                       # 入口
│   ├── cli.rs                        # clap 命令定义
│   │
│   ├── core/                         # 核心引擎
│   │   ├── mod.rs
│   │   ├── orchestrator.rs           # 扫描编排
│   │   ├── risk_scorer.rs            # 风险评分
│   │   └── cache.rs                  # SHA-256 内容缓存 + TTL
│   │
│   ├── parsers/                      # 输入解析
│   │   ├── mod.rs
│   │   ├── skill_parser.rs           # SKILL.md 解析 + 区域标注
│   │   ├── yaml_parser.rs            # 安全的 YAML frontmatter 解析
│   │   └── code_extractor.rs         # 代码块提取 + 语言检测
│   │
│   ├── passes/                       # 7 个扫描 Pass
│   │   ├── mod.rs
│   │   ├── static_analysis.rs        # Pass 2: 静态模式匹配
│   │   ├── metadata_validator.rs     # Pass 3: 元数据一致性
│   │   ├── dependency_auditor.rs     # Pass 4: 依赖链审计
│   │   ├── prompt_injection.rs       # Pass 5: Prompt 注入检测
│   │   ├── behavioral_sandbox.rs     # Pass 6: 行为沙箱
│   │   └── community_intel.rs        # Pass 7: 社区情报
│   │
│   ├── rules/                        # 检测规则（可热更新）
│   │   ├── patterns.json             # 静态分析规则 (70+)
│   │   ├── malicious_packages.json   # 已知恶意包名
│   │   ├── suspicious_domains.json   # 可疑域名/IP
│   │   └── clawhavoc_signatures.json # ClawHavoc 恶意签名
│   │
│   ├── reporters/                    # 报告生成
│   │   ├── mod.rs
│   │   ├── terminal.rs               # 终端彩色输出
│   │   ├── json_reporter.rs          # JSON Schema 报告
│   │   ├── sarif_reporter.rs         # SARIF 2.1.0 报告
│   │   └── markdown_reporter.rs      # Markdown 报告
│   │
│   └── utils/                        # 工具函数
│       ├── mod.rs
│       ├── fetcher.rs                # 技能获取 (本地/URL/ClawHub)
│       ├── levenshtein.rs            # strsim 封装
│       └── unicode_detector.rs       # Unicode 隐写检测
│
├── tests/                            # 测试套件
│   ├── fixtures/                     # 测试用 skill 样本
│   │   ├── benign/                   # 安全技能样本 (10+)
│   │   └── malicious/                # 恶意技能样本 (10+, base64 编码)
│   ├── test_passes/                  # 每个 Pass 的单元测试
│   ├── test_integration.rs           # 端到端集成测试
│   ├── test_regex_safety.rs          # 正则灾难性回溯测试
│   └── test_benchmarks.rs            # 准确率基准测试
│
└── .github/
    └── workflows/
        └── ci.yml                    # CI/CD + 交叉编译 + 自动发布
```

---

## 四、核心模块详细设计

### 4.1 Pass 1: Skill Parser — Markdown 区域感知引擎

**这是 ClawFortify 的关键创新点**。所有竞品的最大问题是把 SKILL.md 当作"纯文本"进行正则匹配，导致文档中讨论 `.env` 安全实践的段落也会触发告警。

ClawFortify 的解析器将 SKILL.md 分解为带区域标签的结构：

```rust
enum RegionType {
    Frontmatter,   // YAML 元数据区
    CodeBlock,     // ```...``` 代码块
    InlineCode,    // `...` 行内代码
    Heading,       // # 标题
    Prose,         // 普通文本段落
    Link,          // [text](url) 链接
    HtmlComment,   // <!-- --> 注释（可能隐藏恶意内容）
}

struct Region {
    region_type: RegionType,
    content: String,
    language: Option<String>,  // 代码块的语言标识
    line_start: usize,
    line_end: usize,
}
```

**区域权重矩阵：**

| 区域类型 | 权重 | 理由 |
|----------|------|------|
| CODE_BLOCK (shell/bash) | 1.0 | 直接可执行，最高风险 |
| CODE_BLOCK (python/js/ts) | 0.95 | 可执行代码 |
| FRONTMATTER | 0.85 | 元数据可被 Agent 系统读取 |
| HTML_COMMENT | 0.9 | 隐藏内容高度可疑 |
| INLINE_CODE | 0.7 | 可能被 Agent 执行 |
| LINK | 0.6 | URL 可能指向恶意地址 |
| HEADING | 0.3 | 通常只是标题描述 |
| PROSE | 0.2 | 文档描述，低风险 |

### 4.2 Pass 2: Static Pattern Analysis — 70+ 规则

在竞品 54 条（ClawVet）和 46 条（skill-scanner）的基础上，完整继承并扩展到 70+ 条规则。

**继承自 ClawVet 的 54 条规则（12 类别）：**

| 类别 | 规则数 | 关键检测项 |
|------|--------|-----------|
| remote_code_execution | 8 | curl\|bash, wget exec, eval(), python -c, reverse shell, perl -e, node -e, ruby -e |
| credential_theft | 10 | .env/.aws/.ssh, API keys, OpenClaw dotfiles, session data, SSH keys, browser data, git creds, npm token, kube config, wildcard sensitive files |
| data_exfiltration | 7 | webhooks, tunnel services, malicious IPs, DNS exfil, pastebin, suspicious TLDs, raw sockets |
| obfuscation | 11 | base64 decode, URL shorteners, hex encoding, JS obfuscator, zero-width chars, RTL override, HTML comment injection, string concat, Buffer/atob, fromCharCode, dynamic property access, large base64 |
| social_engineering | 5 | prerequisite install, copy-paste commands, fake dependencies, authority spoofing, urgency manipulation |
| prompt_injection | 5 | ignore instructions, system override, jailbreak (DAN), role hijack, prompt extraction |
| persistence | 2 | cron/systemd, memory/personality files (SOUL.md/AGENTS.md) |
| privilege_escalation | 2 | sudo usage, dangerous chmod |
| file_system | 2 | path traversal, file write |
| container_escape | 1 | Docker socket/exec |
| code_execution | 1 | child_process/exec/spawn |
| network | 1 | fetch/axios/node-fetch |
| environment | 1 | process.env modification |

**ClawFortify 新增规则（5 类别，17 条）：**

| 类别 | 新增规则数 | 关键检测项 |
|------|-----------|-----------|
| Agent 特定攻击 | 5 | MCP 配置篡改（mcp.json/mcp_servers）、CLAUDE.md 注入、.cursorrules 覆写、skill 相互引用链（技能 A 要求安装技能 B）、pre/post-install hook 滥用 |
| 供应链攻击 | 4 | npm/pip registry 劫持（private registry URL）、lock 文件篡改（package-lock.json/yarn.lock 中非官方 resolved URL）、postinstall 脚本检测、dependency confusion（内部包名与公共包名冲突） |
| 数据外泄新通道 | 2 | ICMP 隧道（ping -p / icmpsh）、图片隐写（steghide/outguess/zsteg） |
| 加密货币相关 | 2 | 挖矿脚本检测（xmrig/stratum+tcp/coinhive/cryptonight）、钱包地址替换（BTC/ETH/XMR 地址模式） |
| PowerShell/脚本混淆 | 3 | PowerShell 混淆（-EncodedCommand, IEX, Invoke-Expression, -WindowStyle Hidden）、Python 动态执行（exec(/compile(/\_\_import\_\_）、环境侦察组合（whoami+hostname+uname 组合出现时提升严重性） |
| **合计** | **70+** | 54 继承 + 17 新增 = 71 条静态规则 |

### 4.3 Pass 4: Dependency Chain Auditor — 全新模块

竞品完全缺失此能力。ClawFortify 的依赖审计包括：

```rust
impl DependencyAuditor {
    pub fn audit(&self, parsed_skill: &ParsedSkill) -> Vec<Finding> {
        let mut findings = Vec::new();
        findings.extend(self.check_undeclared_binaries(parsed_skill));
        findings.extend(self.check_undeclared_env_vars(parsed_skill));
        findings.extend(self.check_dangerous_install_patterns(parsed_skill));
        findings.extend(self.check_typosquat_packages(parsed_skill));
        findings.extend(self.check_known_malicious_packages(parsed_skill));
        findings.extend(self.check_permission_scope(parsed_skill));
        findings
    }

    /// 审计权限范围：技能声称的功能是否与请求的权限匹配
    /// 例: 一个 "weather" 技能请求 SSH 密钥读取权限 → 高风险
    fn check_permission_scope(&self, skill: &ParsedSkill) -> Vec<Finding> {
        let declared_purpose = skill.frontmatter.description.as_deref().unwrap_or("");
        let requested_permissions = self.extract_permissions(skill);
        self.score_permission_mismatch(declared_purpose, &requested_permissions)
    }
}
```

### 4.4 Pass 5: Prompt Injection Detector — 多语言支持

ClawFortify 的 prompt injection 检测策略：**正则捕获已知英文模式 + LLM 语义分析覆盖多语言**。

不再为每种语言维护单独的正则规则集。原因：
1. 大语言模型天然理解多语言，用 LLM 做语义判断远比穷举各语言正则更准确
2. 正则无法覆盖攻击者的改写/变体（如"忽略前面的指令"→"把刚才说的都忘了"）
3. 维护成本：每增加一种语言就需要大量正则，且覆盖率永远不够

**正则层（快速过滤，零成本）：** 继承 ClawVet 的 5 条英文 prompt injection 规则，作为快速预筛。

**LLM 语义层（可选，深度分析）：** 对 Pass 1 解析出的所有区域，用 LLM 判断是否包含 prompt injection 意图，不限语言。此层为可选增强，离线模式下跳过。

### 4.5 Pass 6: Behavioral Sandbox — 轻量级行为分析

**不是真正的沙箱执行**（那太重了），而是对脚本进行**静态行为推理**：

```rust
impl BehavioralSandbox {
    /// 轻量级行为分析：不执行代码，而是分析代码的行为意图
    pub fn analyze(&self, code_blocks: &[CodeBlock]) -> Vec<Finding> {
        let mut findings = Vec::new();
        for block in code_blocks {
            match block.language.as_deref() {
                Some("bash" | "sh" | "shell" | "zsh") => {
                    findings.extend(self.analyze_shell_behavior(block));
                }
                Some("python" | "python3") => {
                    findings.extend(self.analyze_python_behavior(block));
                }
                Some("javascript" | "js" | "typescript" | "ts") => {
                    findings.extend(self.analyze_js_behavior(block));
                }
                Some("powershell" | "pwsh" | "ps1") => {
                    findings.extend(self.analyze_powershell_behavior(block));
                }
                _ => {}
            }
        }
        findings
    }

    fn analyze_shell_behavior(&self, block: &CodeBlock) -> Vec<Finding> {
        let mut behavior = ShellBehaviorGraph::new();

        // 构建行为图：命令 → 文件系统影响 → 网络访问 → 环境修改
        for line in block.content.lines() {
            behavior.add_command(line);
        }

        let mut findings = Vec::new();

        // 检查 1: 文件系统访问范围
        let sensitive_paths: Vec<_> = behavior.get_fs_targets()
            .into_iter()
            .filter(|p| self.is_sensitive_path(p))
            .collect();
        if !sensitive_paths.is_empty() {
            findings.push(Finding {
                rule_id: "BHV001".into(),
                severity: Severity::High,
                message: format!("Script accesses sensitive paths: {}", sensitive_paths.join(", ")),
                evidence: block.content.clone(),
                ..Default::default()
            });
        }

        // 检查 2: 网络连接目标分类
        let suspicious_targets: Vec<_> = behavior.get_network_targets()
            .into_iter()
            .filter(|t| self.is_suspicious_target(t))
            .collect();

        // 检查 3: 数据流分析（读取敏感文件 → 发送到网络 = exfiltration）
        let exfil_flows: Vec<_> = behavior.trace_data_flows()
            .into_iter()
            .filter(|f| f.source_is_sensitive && f.sink_is_network)
            .collect();

        findings
    }
}
```

### 4.6 风险评分引擎

改进竞品的评分系统，引入**区域权重**和**衰减因子**：

```rust
fn calculate_score(findings: &[Finding]) -> RiskScore {
    const SEVERITY_WEIGHTS: &[(&str, u32)] = &[
        ("critical", 30),
        ("high", 15),
        ("medium", 7),
        ("low", 3),
        ("info", 0),
    ];

    let mut raw_score: f64 = 0.0;
    for f in findings {
        let weight = severity_weight(f.severity);
        let region_factor = region_weight(f.region_type);  // 区域权重
        let confidence = f.confidence;
        raw_score += weight as f64 * region_factor * confidence;
    }

    // 去重衰减：同一规则多次触发时，后续触发递减
    // 第 1 次: 100%, 第 2 次: 60%, 第 3 次: 30%, 第 4+次: 10%
    const DECAY: [f64; 4] = [1.0, 0.6, 0.3, 0.1];

    let final_score = raw_score.min(100.0) as u32;
    let grade = score_to_grade(final_score);

    RiskScore { score: final_score, grade, findings: findings.to_vec() }
}
```

---

## 五、CLI 设计

### 5.1 命令概览

```bash
# 扫描单个技能（本地目录）
clawfortify scan ./my-skill/

# 扫描 ClawHub 技能（远程）
clawfortify scan --remote steipete/summarize

# 扫描 GitHub 仓库
clawfortify scan https://github.com/user/skill-repo

# 批量扫描已安装的所有技能
clawfortify audit

# 文件监控模式（技能目录变更时自动扫描）
clawfortify watch

# 生成不同格式的报告
clawfortify scan ./skill/ --format json
clawfortify scan ./skill/ --format sarif
clawfortify scan ./skill/ --format markdown --output report.md

# CI/CD 集成（指定失败阈值）
clawfortify scan ./skill/ --fail-on high --format sarif

# 更新规则库
clawfortify update-rules

# 查看技能的社区信誉
clawfortify reputation steipete/summarize
```

### 5.2 终端输出设计

```
╭──────────────────────────────────────────────────────╮
│  ClawFortify v1.0.0 — AI Skill Security Scanner         │
╰──────────────────────────────────────────────────────╯

📂 Scanning: steipete/summarize (v1.0.0)

  Pass 1/7  Parsing SKILL.md ................... ✓ 3 regions
  Pass 2/7  Static Pattern Analysis ............ ✓ 2 findings
  Pass 3/7  Metadata Validation ................ ✓ 1 finding
  Pass 4/7  Dependency Chain Audit ............. ✓ 0 findings
  Pass 5/7  Prompt Injection Detection ......... ✓ 0 findings
  Pass 6/7  Behavioral Analysis ................ ✓ 0 findings
  Pass 7/7  Community Intelligence ............. ✓ reputation: 4.8/5

╭── Risk Score ───────────────────────────────────────╮
│                                                      │
│        Score: 18/100          Grade: ██ B            │
│        ░░░░░░░░░░░░░░░░░░░░                         │
│                                                      │
│  Verdict: LOW RISK — Safe to install with review     │
│                                                      │
╰──────────────────────────────────────────────────────╯

┌── Findings (3) ─────────────────────────────────────┐
│                                                      │
│  ⚠ MEDIUM  ENV_VAR_USAGE                            │
│  Line 12 (code_block, bash)                          │
│  References OPENAI_API_KEY — ensure this is          │
│  proportionate to the skill's purpose                │
│  Confidence: 0.7 | Context: code_block              │
│                                                      │
│  ℹ LOW     NETWORK_REQUEST                           │
│  Line 8 (code_block, bash)                           │
│  Makes HTTP requests via CLI tool                    │
│  Confidence: 0.5 | Context: code_block              │
│                                                      │
│  ℹ INFO    MISSING_VERSION                           │
│  Frontmatter missing semver version field            │
│  Confidence: 1.0 | Context: frontmatter             │
│                                                      │
└──────────────────────────────────────────────────────┘
```

---

## 六、Cursor Skill 集成设计

### 6.1 SKILL.md

```yaml
---
name: clawfortify
description: >-
  AI 技能安全审计扫描器。在安装任何 ClawHub/GitHub 技能前自动扫描安全风险，
  检测 prompt 注入、凭证窃取、恶意代码、供应链攻击和可疑行为模式。
  Use when: (1) 安装新技能前, (2) 用户提到安全/扫描/审计,
  (3) 审查 SKILL.md 文件, (4) 评估技能安全性
---

# ClawFortify — AI 技能安全审计

安装前扫描、运行时监控、社区信誉体系。

## 快速使用

扫描本地技能:
```bash
clawfortify scan <path-to-skill>
```

扫描 ClawHub 技能:
```bash
clawfortify scan --remote <slug>
```

批量扫描已安装技能:
```bash
clawfortify audit
```

## Agent 自动触发

当检测到以下场景时自动执行扫描：
1. 用户要求安装新技能 → 安装前自动扫描
2. 用户要求审查技能安全性 → 执行完整扫描并输出报告
3. 用户提到 "安全" / "扫描" / "审计" → 提供扫描建议

## 判定标准

| 评级 | 分数 | 操作 |
|------|------|------|
| A | 0-10 | 直接安装 |
| B | 11-25 | 安装并提示低风险发现 |
| C | 26-50 | 展示发现，让用户决定 |
| D | 51-75 | 强烈建议不要安装 |
| F | 76+ | 阻断安装，展示详细风险报告 |

## 详细文档

- 完整规则列表见 [references/rules.md](references/rules.md)
- CI/CD 集成指南见 [references/ci-integration.md](references/ci-integration.md)
```

---

## 七、开发路线图

### Phase 1: MVP (2 周)

- [ ] Rust 项目脚手架 + Cargo.toml + CI
- [ ] Pass 1-3 核心引擎（解析 + 静态分析 + 元数据校验）
- [ ] 71 条检测规则（JSON 配置）
- [ ] CLI 基础命令（scan / audit）
- [ ] Terminal + JSON 报告输出
- [ ] SKILL.md 集成
- [ ] 基础测试套件（10 benign + 10 malicious fixtures）
- [ ] 交叉编译（Windows/macOS/Linux）

### Phase 2: 增强 (2 周)

- [ ] Pass 4: 依赖链审计
- [ ] Pass 5: Prompt 注入检测（正则 + 可选 LLM 语义分析）
- [ ] SARIF + Markdown 报告
- [ ] GitHub Action
- [ ] 缓存系统（SHA-256 + TTL）
- [ ] `clawfortify watch` 文件监控

### Phase 3: 高级 (2 周)

- [ ] Pass 6: 轻量行为沙箱
- [ ] Pass 7: 社区情报（本地 SQLite + HTTP API）
- [ ] 规则热更新
- [ ] 正则灾难性回溯安全测试（Rust regex crate 天然安全，此为验证测试）
- [ ] 发布到 GitHub Releases + ClawHub
- [ ] Homebrew / Scoop / cargo install 分发渠道

---

## 八、风险与缓解

| 风险 | 影响 | 缓解策略 |
|------|------|----------|
| 误报率过高导致用户弃用 | 高 | 区域感知引擎 + 置信度加权 + 衰减因子 |
| 扫描器自身被攻击 | 高 | 规则文件 base64 编码存储、CI 签名验证 |
| 正则灾难性回溯 | 低 | Rust regex crate 基于 NFA，天然免疫；仍做验证测试 |
| 社区情报 API 不可用 | 低 | 离线优先设计，Pass 7 可选跳过 |
| 恶意规则注入 | 中 | 规则文件签名验证 + 规则审核流程 |
| Rust 开发速度较慢 | 中 | 优先实现 Pass 1-3 MVP，渐进交付 |
