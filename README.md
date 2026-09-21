# SaniLine 🛡️

> **Real-Time Military-Grade Line-by-Line Code Sanitizer & Security Shield for AI Agents**

[![CI](https://github.com/alivirgo/SaniLine/actions/workflows/ci.yml/badge.svg)](https://github.com/alivirgo/SaniLine/actions)
[![NPM Version](https://img.shields.io/npm/v/saniline.svg?color=blue)](https://www.npmjs.com/package/saniline)
[![jsDelivr Hits](https://data.jsdelivr.com/v1/package/npm/saniline/badge)](https://www.jsdelivr.com/package/npm/saniline)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Node](https://img.shields.io/badge/Node-ESM%20%7C%20CJS%20%7C%20Edge-green.svg)](https://nodejs.org)
[![Python](https://img.shields.io/badge/Python-3.9%20|%203.10%20|%203.11%20|%203.12%20|%203.13-brightgreen.svg)](https://python.org)
[![MCP](https://img.shields.io/badge/Protocol-MCP%20Ready-purple.svg)](https://modelcontextprotocol.io)
[![Token Cost](https://img.shields.io/badge/Token%20Cost-~0%20Tokens%20%28Hyper--Compact%29-brightgreen.svg)](#token-efficiency-for-ai-agents)

---

## ⚡ The Problem SaniLine Solves

Autonomous AI coding agents (such as **Antigravity**, **Claude Code**, **Cursor**, **Devin**, **Copilot**, and custom agent runtimes built with **Vercel AI SDK** or **LangChain**) produce code at superhuman speed. However, LLMs systematically introduce catastrophic security vulnerabilities:
- **Hardcoded secrets & tokens**: AWS keys, OpenAI/Anthropic/Gemini keys, Stripe tokens, DB URIs, and high-entropy passwords.
- **Remote Code Execution (RCE)**: Unconstrained `child_process.exec()`, `execSync()`, `subprocess.run(..., shell=True)`, and `eval()`.
- **Prototype Pollution**: Dynamic mutation of `__proto__` and `constructor.prototype` (CWE-1321).
- **DOM XSS & Insecure Rendering**: `dangerouslySetInnerHTML`, `innerHTML = ...`, and `document.write` (CWE-79).
- **Insecure deserialization**: Unsafe `yaml.load()`, `pickle.loads()`, `unserialize()`.
- **Path traversal & Zip Slip**: `../` traversal and unconfined archive extraction (CWE-22).
- **Trojan Source Unicode exploits**: Bidirectional overrides (`U+202E`, `U+2066`) and zero-width spaces disguising backdoors ([CVE-2021-42574](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42574)).
- **Smuggled prompt injections**: Hijack instructions concealed in code comments and docstrings targeting downstream agents (CWE-1188).

Traditional linters (Bandit, ESLint, SonarQube, Semgrep) are slow batch scanners designed for human git-commit workflows. They cannot operate on real-time streaming tokens, fail to run at the edge, and produce verbose output that consumes large portions of an agent's context window.

**SaniLine is engineered specifically for AI agents and modern streaming apps:**
1. **Zero-Latency Streaming & Line-by-Line**: Sanitizes code line-by-line as tokens are generated using Web Streams (`TransformStream`) and Node streams.
2. **Deterministic Auto-Patching**: Fixes vulnerabilities instantly in-place to safe, idiomatic patterns.
3. **Hyper-Compact Token Footprint**: Minified responses (`{"status": "CLEAN"}` < 10 tokens) preserve agent reasoning context.
4. **100% Local & Zero-Token Cost**: Zero network calls, zero external LLM API costs, sub-millisecond execution.
5. **Zero-Dependency Universal JS Runtime**: Pure JavaScript running on Node.js, Vercel Edge, Cloudflare Workers, Next.js, Browser, Bun, and Deno.
6. **Built-in Model Context Protocol (MCP)**: Native stdio MCP server for Cursor, Windsurf, Claude Desktop, and Devin with zero Python setup.
7. **DoD STIG, NIST SP 800-218 (SSDF), & CWE Top 25 Compliance**: Enforces verified defense benchmarks.

---

## 🚀 Installation & Distribution

### Node.js (NPM)
```bash
npm install saniline
```

### Python (PyPI)
```bash
pip install saniline
```

### jsDelivr CDN (Browser / Edge / WebContainers)
```html
<script src="https://cdn.jsdelivr.net/npm/saniline/dist/saniline.min.js"></script>
```

---

## 🤖 JavaScript & TypeScript Integration

### 1. Vercel AI SDK Real-Time Streaming Guard
Stream LLM code safely to clients or files with zero buffer latency using standard Web Streams `TransformStream`:

```typescript
import { streamText } from "ai";
import { openai } from "@ai-sdk/openai";
import { SaniLineTransformStream } from "saniline";

export async function POST(req: Request) {
  const result = streamText({
    model: openai("gpt-4o"),
    prompt: "Generate an Express backend route for user file uploads...",
  });

  // Neutralizes secrets, shell injections, and Trojan Source Unicode in real-time
  const safeStream = result.textStream.pipeThrough(new SaniLineTransformStream());

  return new Response(safeStream);
}
```

### 2. Node.js Programmatic SDK
```typescript
import { SaniLine, SecurityLevel, SanitizeAction } from "saniline";

const shield = new SaniLine({
  level: SecurityLevel.MILITARY,
  action: SanitizeAction.AUTOPATCH,
});

// Single line sanitization
const res = shield.sanitizeLine('const key = "AKIAIOSFODNN7EXAMPLE";');
console.log(res.sanitizedCode);
// => const key = "[REDACTED_SECRET:AWS_ACCESS_KEY]";

// Token-compact telemetry for AI agent context (<10 tokens when clean):
console.log(res.toTokenCompact());
// => { status: "MODIFIED", patch: "...", issues: [...] }
```

### 3. Node.js Stream Pipeline (`SaniLineNodeTransform`)
```typescript
import fs from "node:fs";
import { SaniLineNodeTransform } from "saniline";

fs.createReadStream("agent_generated_code.js")
  .pipe(new SaniLineNodeTransform())
  .pipe(fs.createWriteStream("safe_code.js"));
```

---

## 🐍 Python SDK Integration

```python
from saniline import SaniLine, SecurityLevel, SanitizeAction

shield = SaniLine(level=SecurityLevel.MILITARY, action=SanitizeAction.AUTOPATCH)

# Sanitize line on the fly
result = shield.sanitize_line("subprocess.run(user_cmd, shell=True)", language="python")
print(result.sanitized_code)
# => subprocess.run(user_cmd, shell=False)

# Token-compact response for AI context windows:
print(result.to_token_compact())
```

---

## 🔌 Model Context Protocol (MCP) Server

SaniLine includes a built-in MCP server that runs out of the box with **Claude Desktop**, **Cursor**, **Windsurf**, and **Antigravity**.

### Option A: Using NPM (Zero Python Required)
Add to your IDE's `mcpServers` configuration:

```json
{
  "mcpServers": {
    "saniline": {
      "command": "npx",
      "args": ["-y", "saniline", "mcp"]
    }
  }
}
```

### Option B: Using Python
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

Available via `npx saniline` or installed globally:

```bash
# Audit a file or directory with visual scorecard:
npx saniline check src/

# Token-compact JSON output for autonomous AI agents (<10 tokens when clean):
npx saniline check src/ --compact

# Export standard OASIS SARIF v2.1.0 for GitHub Actions Code Scanning:
npx saniline check src/ --format sarif > results.sarif

# Automatically patch files or directories in-place:
npx saniline sanitize src/ --in-place

# Stream filter (pipe stdin to stdout):
cat raw_llm_code.py | npx saniline stream > safe_code.py

# Display the military-grade defense rules matrix:
npx saniline rules

# Install zero-dependency Git pre-commit security hook:
npx saniline hook install
```

---

## 🎯 Military-Grade Defense Rules Matrix

| Rule ID | Name | Category | Standard | Severity | Auto-Patch |
| :--- | :--- | :--- | :--- | :---: | :---: |
| **`SL-SEC-001`** | Hardcoded Credentials & High-Entropy Tokens | Secrets Exposure | **CWE-798** / DoD STIG APPS-000170 | `CRITICAL` | ✅ Yes |
| **`SL-UNI-001`** | Trojan Source Bidi & Zero-Width Unicode Exploits | Trojan Source | **CVE-2021-42574** / CWE-1036 | `CRITICAL` | ✅ Yes |
| **`SL-PRM-001`** | Smuggled AI Prompt Injection in Comments | Prompt Hijack | **CWE-1188** / APSC-DV-003100 | `HIGH` | ✅ Yes |
| **`SL-RCE-001`** | Insecure Subprocess & Command Injection (`shell=True`) | Command Injection | **CWE-78** / DoD STIG APSC-DV-002100 | `CRITICAL` | ✅ Yes |
| **`SL-RCE-002`** | Arbitrary Dynamic `eval()` / `new Function()` | Dynamic Execution | **CWE-95** / CWE-94 | `CRITICAL` | ⚠️ Flag |
| **`SL-RCE-004`** | Insecure `child_process.exec` / `execSync` Shell Invocations | Command Injection | **CWE-78** / APSC-DV-002100 | `HIGH` | ✅ Yes |
| **`SL-PROTO-001`**| Prototype Pollution Mutation (`__proto__`, `prototype`) | Prototype Pollution | **CWE-1321** | `HIGH` | ✅ Yes |
| **`SL-XSS-001`** | DOM XSS / Insecure `dangerouslySetInnerHTML` | Cross-Site Scripting | **CWE-79** / APSC-DV-002530 | `HIGH` | ⚠️ Flag |
| **`SL-PATH-001`** | Relative Directory Traversal (`../`) | Path Traversal | **CWE-22** / APSC-DV-002560 | `HIGH` | ⚠️ Flag |
| **`SL-PATH-002`** | Unconfined Archive Extraction (Zip Slip) | Path Traversal | **CWE-22** / CWE-29 | `HIGH` | ⚠️ Flag |
| **`SL-INJ-001`** | Dynamic SQL Query Formatting / Template Literals | SQL Injection | **CWE-89** / APSC-DV-002510 | `CRITICAL` | ⚠️ Flag |
| **`SL-DESER-001`**| Unsafe `yaml.load()` / Deserialization | Object Injection | **CWE-502** / APSC-DV-002620 | `CRITICAL` | ✅ Yes |
| **`SL-CRY-001`** | Disabled TLS Verification (`rejectUnauthorized: false`) | Transport Security | **CWE-295** / APSC-DV-002010 | `CRITICAL` | ✅ Yes |
| **`SL-CRY-002`** | Insecure PRNG (`Math.random`) in Security Tokens | Cryptography | **CWE-330** / APSC-DV-002030 | `HIGH` | ⚠️ Flag |
| **`SL-CRY-003`** | Broken Cryptographic Hash (`md5`/`sha1`) | Cryptography | **CWE-328** / APSC-DV-002010 | `HIGH` | ✅ Yes |
| **`SL-NET-001`** | Cloud Metadata SSRF (`169.254.169.254`) | SSRF Exfiltration | **CWE-918** / APSC-DV-002570 | `CRITICAL` | ⚠️ Flag |
| **`SL-NET-002`** | Wildcard Socket Interface Binding (`0.0.0.0`) | Exposure | **CWE-200** / APSC-DV-002580 | `MEDIUM` | ✅ Yes |

---

## 🧠 Token Efficiency for AI Agents

Every token consumed by linter output shrinks an AI agent's effective reasoning window and inflates API costs.

| Scenario | Standard Linter Output | SaniLine Compact Output | Token Reduction |
| :--- | :--- | :--- | :---: |
| **Clean Line** | 150 - 300 tokens (JSON schema dump) | `{"status":"CLEAN"}` (**~4 tokens**) | **98.6%** |
| **Auto-Patched Line** | 400 - 800 tokens (full file context) | `{"status":"MODIFIED","patch":"...","issues":[...]}` (**~35 tokens**) | **91.2%** |
| **Audit Summary** | 800 - 2,000 tokens (raw AST traces) | `{"score":100,"pass":true,"files":12}` (**~12 tokens**) | **98.8%** |

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
