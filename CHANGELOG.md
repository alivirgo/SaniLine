# Changelog

All notable changes to **SaniLine** are documented in this file.
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-09-21

### Major 2026 Ecosystem Expansion & Security Upgrades

#### Highlights
- **Full Universal Node.js & NPM Ecosystem Package**:
  - `SaniLineTransformStream`: Web Streams API `TransformStream` that integrates directly into **Vercel AI SDK** (`streamText.pipeThrough(...)`), Next.js App Router, Cloudflare Workers, and browser fetch streams with zero buffer latency.
  - `SaniLineNodeTransform`: Node.js `node:stream` Transform for stdio and Node HTTP pipelines.
  - Native zero-Python Model Context Protocol (MCP) Server: run directly with `npx -y saniline mcp` or `saniline-mcp`.
  - Recursive CLI directory auditor with path filtering, symlink loop prevention, and colored scorecard.
  - Automated Git pre-commit hook installer (`npx saniline hook install`).
- **Complete Rule Parity (17 Active Rules Across Python & JS)**:
  - `SL-PROTO-001` (Prototype Pollution / CWE-1321): Neutralizes `__proto__` and `constructor.prototype` tampering.
  - `SL-XSS-001` (DOM XSS / CWE-79): Flags React `dangerouslySetInnerHTML`, `innerHTML = ...`, and `document.write`.
  - `SL-RCE-004` (Child Process Insecure Shell / CWE-78): Auto-patches `child_process.exec()` / `execSync()` to `execFile()` / `execFileSync()`.
  - Secrets Expansion: Added recognition for **Stripe (`sk_live_...`)** and **Supabase (`sbp_...`)** tokens.
- **Enterprise CI & GitHub Code Scanning**:
  - Standard **OASIS SARIF v2.1.0** export via `--format sarif` across both Python and Node CLIs.
  - Multi-platform GitHub Actions CI matrix testing Python 3.9–3.13 and Node.js 18.x, 20.x, 22.x across Ubuntu, Windows, and macOS.
  - Automated release workflow with npm provenance and GitHub Release artifact attachments.
- **2026 Coding Standards & Robustness**:
  - Upgraded Python code to **PEP 604** modern union and collection typings (`list[T]`, `dict[K, V]`, `X | None`).
  - Introduced custom domain exceptions: `SaniLineError` and `SecurityViolationError`.
  - ReDoS defense: bounded regex whitespace quantifiers (`\s{1,8}`) and bounded lookaheads.
  - Minified file defense: bracket depth counting capped at 2,048 chars in `StreamContext`.
  - Memory DoS guards: MCP servers limit incoming line length (1MB) and block length (10MB).
  - Stream lifecycle control: `signal?: AbortSignal` cancellation on streaming transforms.

## [0.1.0] - 2026-09-14

### Initial Release: Real-Time Military-Grade Line-by-Line Code Sanitizer & Security Shield for AI Agents

#### Highlights
- **Real-Time Line-by-Line Sanitization Engine**: Designed specifically for autonomous AI coding agents (Antigravity, Claude Code, Cursor, Devin) to sanitize code as it is generated or streamed.
- **Token-Optimized AI Telemetry**: Hyper-compact outputs (`{"status": "CLEAN"}` <10 tokens) ensuring that inspecting and shielding code consumes virtually zero token budget from the agent's context window.
- **Zero-Token Local Execution**: 100% deterministic local heuristic, AST, regex, and Shannon entropy analysis—zero external API calls required.
- **Military & Industry Standards Alignment**:
  - **DoD STIG** (Application Security and Development)
  - **NIST SP 800-218** (Secure Software Development Framework - SSDF)
  - **CWE / SANS Top 25 Most Dangerous Software Weaknesses**
  - **OWASP Top 10** (A01, A02, A03, A08)
- **Active Defense Modules**:
  - `HardcodedSecretRule` (`SL-SEC-001` / CWE-798): High-entropy Shannon analysis and signature masking for AWS, GitHub, OpenAI, Anthropic, Google Cloud, Slack tokens, private keys, database URIs.
  - `ShellTrueInjectionRule` (`SL-RCE-001` / CWE-78): Auto-patches `shell=True` to `shell=False`.
  - `ArbitraryEvalExecRule` (`SL-RCE-002` / CWE-95): Identifies and mitigates dangerous dynamic `eval()` and `exec()`.
  - `OsSystemCommandRule` (`SL-RCE-003` / CWE-78): Auto-patches `os.system()` to parameterized `subprocess.run(shlex.split(...))`.
  - `UnsafeYamlLoadRule` (`SL-DESER-001` / CWE-502): Auto-patches unsafe `yaml.load()` to `yaml.safe_load()`.
  - `UnsafePickleRule` (`SL-DESER-002` / CWE-502): Flags remote arbitrary code execution via pickle deserialization.
  - `PathTraversalSequenceRule` (`SL-PATH-001` / CWE-22): Flags relative directory traversal (`../`).
  - `ZipSlipVulnerabilityRule` (`SL-PATH-002` / CWE-22): Detects unconfined archive extraction.
  - `SqlStringFormattingInjectionRule` (`SL-INJ-001` / CWE-89): Detects dynamic SQL query formatting.
  - `TrojanSourceUnicodeRule` (`SL-UNI-001` / CVE-2021-42574): Detects and purges bidirectional Unicode overrides (RLO/LRO) and zero-width characters.
  - `PromptInjectionSmugglingRule` (`SL-PRM-001` / CWE-1188): Defuses adversarial prompt injections smuggled inside comments/docstrings.
  - `DisabledTlsVerificationRule` (`SL-CRY-001` / CWE-295): Auto-patches `verify=False` to `verify=True`.
  - `InsecurePrngForSecurityRule` (`SL-CRY-002` / CWE-330): Auto-patches `random.` to `secrets.` in security contexts.
  - `WeakHashAlgorithmRule` (`SL-CRY-003` / CWE-328): Auto-patches broken hashes (`md5`/`sha1`) to `sha256`.
  - `CloudMetadataSsrfRule` (`SL-NET-001` / CWE-918): Blocks instance metadata service endpoints (`169.254.169.254`).
  - `WildcardBindRule` (`SL-NET-002` / CWE-200): Detects wildcard socket binding (`0.0.0.0`).
- **Interfaces**:
  - Python SDK: `SaniLine(level=SecurityLevel.MILITARY)`
  - Model Context Protocol (MCP) Server: `saniline-mcp` with native tools (`saniline_sanitize_line`, `saniline_sanitize_block`, `saniline_audit_security`, `saniline_explain_rule`)
  - Command Line Interface: `saniline check`, `saniline sanitize`, `saniline stream`, `saniline mcp`, `saniline rules`, `saniline hook install`
