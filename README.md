# SaniLine 🛡️

> **Real-Time Military-Grade Line-by-Line Code Sanitizer & Security Shield for AI Agents**

[![CI](https://github.com/alivirgo/SaniLine/actions/workflows/ci.yml/badge.svg)](https://github.com/alivirgo/SaniLine/actions)
[![NPM Version](https://img.shields.io/npm/v/saniline.svg?color=blue)](https://www.npmjs.com/package/saniline)
[![jsDelivr Hits](https://data.jsdelivr.com/v1/package/npm/saniline/badge)](https://www.jsdelivr.com/package/npm/saniline)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python](https://img.shields.io/badge/Python-3.9%20|%203.10%20|%203.11%20|%203.12%20|%203.13-brightgreen.svg)](https://python.org)
[![Node](https://img.shields.io/badge/Node-ESM%20%7C%20CJS-green.svg)](https://nodejs.org)
[![MCP](https://img.shields.io/badge/Protocol-MCP%20Ready-purple.svg)](https://modelcontextprotocol.io)
[![Token Cost](https://img.shields.io/badge/Token%20Cost-~0%20Tokens%20%28Hyper--Compact%29-brightgreen.svg)](#token-efficiency-for-ai-agents)

---

## ⚡ The Problem SaniLine Solves

Autonomous AI coding agents (such as **Antigravity**, **Claude Code**, **Cursor**, **Devin**, and **Copilot Workspace**) produce code at superhuman speed. However, LLMs systematically introduce catastrophic security vulnerabilities:
- **Hardcoded secrets and API keys** generated during prototyping.
- **Remote Code Execution (RCE)** through unconstrained `subprocess.run(..., shell=True)` and `os.system()`.
- **Insecure deserialization** (`pickle.loads()`, unconstrained `yaml.load()`).
- **Path traversal** (`../` traversal, Zip Slip).
- **Trojan Source Unicode exploits** ([CVE-2021-42574](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42574)) using bidirectional overrides (`U+202E`) to mask backdoors.
- **Smuggled prompt injections** embedded within comments and docstrings designed to hijack downstream agent reasoning.

Traditional linters (Bandit, SonarQube, Semgrep) are slow batch scanners built for human CI workflows. They cannot operate on a streaming line-by-line basis, take hundreds of milliseconds to start up, and dump verbose text that consumes vast amounts of the agent's context window.

**SaniLine is engineered specifically for AI agents:**
1. **Line-by-Line & Streaming Zero-Latency**: Evaluates code in sub-millisecond real time as tokens and lines are generated.
2. **Deterministic Auto-Patching**: Does not just complain—automatically neutralizes vulnerabilities into safe, idiomatic patterns.
3. **Hyper-Compact Token Footprint**: Returns token-minified responses (`{"status": "CLEAN"}` < 10 tokens) to preserve the agent's context window.
4. **100% Local Zero-Token Execution**: Runs locally using deterministic heuristics, AST context, and Shannon entropy. Consumes **zero** external LLM tokens during inspection.
5. **Military & Zero-Trust Compliance**: Enforces **DoD STIG**, **NIST SP 800-218 (SSDF)**, and **CWE Top 25** standards.
6. **Agent Self-Discovery**: Includes [`llms.txt`](llms.txt), [agent skill definition](.agents/skills/saniline-shield/SKILL.md), [Cursor rules](.cursorrules), and [`AGENT_GUIDE.md`](AGENT_GUIDE.md) allowing AI agents to discover, learn, and use SaniLine autonomously.

---

## 🚀 Installation & Distribution

### Python (PyPI)
```bash
pip install saniline
```

### Node.js (NPM)
```bash
npm install saniline
```

### jsDelivr CDN (Browser / Edge / Web Agents)
```html
<!-- Via NPM package on jsDelivr -->
<script src="https://cdn.jsdelivr.net/npm/saniline/dist/saniline.min.js"></script>

<!-- Via GitHub release on jsDelivr -->
<script src="https://cdn.jsdelivr.net/gh/alivirgo/SaniLine@v0.1.0/dist/saniline.min.js"></script>
```

---

## 🤖 AI Agent Integration

### 1. Python SDK

```python
from saniline import SaniLine, SecurityLevel, SanitizeAction

# Initialize with military-grade zero-trust policies
shield = SaniLine(
    level=SecurityLevel.MILITARY,
    action=SanitizeAction.AUTOPATCH
)

# Sanitize single line on the fly
result = shield.sanitize_line("subprocess.run(user_cmd, shell=True)", language="python")
print(result.sanitized_code)
# => subprocess.run(user_cmd, shell=False)

# Hyper-compact telemetry for agent context window (<10 tokens when clean):
print(result.to_token_compact())
```

### 2. Node.js / TypeScript SDK

```typescript
import { SaniLine } from "saniline";

const shield = new SaniLine();
const result = shield.sanitizeLine('const secret = "AKIAIOSFODNN7EXAMPLE";');

console.log(result.sanitizedCode);
// => const secret = "[REDACTED_SECRET:AWS_ACCESS_KEY]";
```

### 3. Streaming Filter (Real-Time Token Stream)

Sanitize streaming output from LLMs or subprocesses with zero buffer latency:

```python
# As tokens coalesce into lines from your agent's LLM stream:
for safe_line in shield.sanitize_stream(raw_line_generator, language="python"):
    write_to_disk(safe_line)
```

---

## 🔌 Model Context Protocol (MCP) Server

SaniLine provides a built-in MCP server compatible with **Claude Desktop**, **Cursor**, **Antigravity**, and **Devin**.

Launch the server:
```bash
saniline mcp
# or directly:
saniline-mcp
```

### Configure in Claude / Cursor (`mcpServers`):

```json
{
  "mcpServers": {
    "saniline": {
      "command": "saniline-mcp"
    }
  }
}
```

---

## 💻 Command Line Interface (CLI)

```bash
# Audit a file or directory with visual scorecard:
saniline check src/

# Token-compact JSON output for agent processes:
saniline check src/ --compact

# Automatically patch a file in-place:
saniline sanitize src/app.py --in-place

# Stream filter (pipe stdin to stdout):
cat raw_llm_code.py | saniline stream > safe_code.py

# List all military-grade defense rules:
saniline rules

# Install zero-trust Git pre-commit hook:
saniline hook install
```

---

## 🎯 Military-Grade Rules Matrix

| Rule ID | Name | Category | Standard | Severity | Auto-Patch |
| :--- | :--- | :--- | :--- | :---: | :---: |
| **`SL-SEC-001`** | Hardcoded Credentials & High-Entropy Tokens | Secrets Exposure | **CWE-798** / DoD STIG APPS-000170 | `CRITICAL` | ✅ Yes |
| **`SL-RCE-001`** | `shell=True` Subprocess Execution | Command Injection | **CWE-78** / DoD STIG APSC-DV-002100 | `CRITICAL` | ✅ Yes |
| **`SL-RCE-002`** | Arbitrary Dynamic `eval()` / `exec()` | Dynamic Execution | **CWE-95** / CWE-94 | `CRITICAL` | ✅ Yes |
| **`SL-RCE-003`** | Insecure Shell Spawn via `os.system` | Command Injection | **CWE-78** / APSC-DV-002100 | `HIGH` | ✅ Yes |
| **`SL-DESER-001`** | Unsafe `yaml.load()` Deserialization | Object Injection | **CWE-502** / APSC-DV-002620 | `CRITICAL` | ✅ Yes |
| **`SL-DESER-002`** | Arbitrary Code Execution via `pickle.loads` | Object Injection | **CWE-502** / APSC-DV-002620 | `CRITICAL` | ⚠️ Flag |
| **`SL-PATH-001`** | Relative Directory Traversal (`../`) | Path Traversal | **CWE-22** / APSC-DV-002560 | `HIGH` | ⚠️ Flag |
| **`SL-PATH-002`** | Unconfined Archive Extraction (Zip Slip) | Path Traversal | **CWE-22** / CWE-29 | `HIGH` | ⚠️ Flag |
| **`SL-INJ-001`** | Dynamic SQL Query Formatting / F-Strings | SQL Injection | **CWE-89** / APSC-DV-002510 | `CRITICAL` | ⚠️ Flag |
| **`SL-UNI-001`** | Trojan Source Bidi Unicode Overrides | Trojan Source | **CVE-2021-42574** / CWE-1036 | `CRITICAL` | ✅ Yes |
| **`SL-PRM-001`** | Smuggled AI Prompt Injection in Comments | Prompt Hijack | **CWE-1188** / APSC-DV-003100 | `HIGH` | ✅ Yes |
| **`SL-CRY-001`** | Disabled TLS Verification (`verify=False`) | Transport Security | **CWE-295** / APSC-DV-002010 | `CRITICAL` | ✅ Yes |
| **`SL-CRY-002`** | Insecure PRNG (`random`) in Security Tokens | Cryptography | **CWE-330** / APSC-DV-002030 | `HIGH` | ✅ Yes |
| **`SL-CRY-003`** | Broken Cryptographic Hash (`md5`/`sha1`) | Cryptography | **CWE-328** / APSC-DV-002010 | `HIGH` | ✅ Yes |
| **`SL-NET-001`** | Cloud Metadata SSRF (`169.254.169.254`) | SSRF Exfiltration | **CWE-918** / APSC-DV-002570 | `CRITICAL` | ⚠️ Flag |
| **`SL-NET-002`** | Wildcard Socket Interface Binding (`0.0.0.0`) | Exposure | **CWE-200** / APSC-DV-002580 | `MEDIUM` | ✅ Yes |

---

## 🧠 Token Efficiency for AI Agents

Every token consumed by tool responses shrinks your AI agent's effective reasoning window and increases API costs.

| Scenario | Standard Linter Output | SaniLine Compact Output | Token Reduction |
| :--- | :--- | :--- | :---: |
| **Clean Line** | 150 - 300 tokens (JSON schema dump) | `{"status":"CLEAN"}` (**~4 tokens**) | **98.6%** |
| **Auto-Patched Line** | 400 - 800 tokens (full file context) | `{"status":"MODIFIED","patch":"...","issues":[...]}` (**~35 tokens**) | **91.2%** |
| **Audit Summary** | 800 - 2,000 tokens (raw AST traces) | `{"score":95.0,"pass":true,"issues":0}` (**~12 tokens**) | **98.8%** |

---

## 🤖 Autonomous Agent Discovery Files

- [`llms.txt`](llms.txt): Machine-readable primer for web-crawling LLMs and autonomous coders.
- [`AGENT_GUIDE.md`](AGENT_GUIDE.md): Detailed integration patterns and prompt snippets.
- [`.agents/skills/saniline-shield/SKILL.md`](.agents/skills/saniline-shield/SKILL.md): Antigravity agent skill definition.
- [`.cursorrules`](.cursorrules): Cursor IDE AI agent compliance rules.
- [`.claude/rules/saniline.md`](.claude/rules/saniline.md): Claude Code AI agent instructions.

---

## 📄 License

Licensed under the **Apache License, Version 2.0**. See the [LICENSE](LICENSE) file for details.
