# Autonomous AI Agent Integration Guide for SaniLine 🛡️

This guide explains how autonomous AI agents (**Antigravity**, **Claude Code**, **Cursor**, **Devin**, **Aider**, **Copilot Workspace**, and **AutoGPT**) discover, configure, and invoke **SaniLine** in their coding workflows.

---

## 🌟 Why AI Agents Need SaniLine

When AI agents generate code, they lack runtime awareness and often introduce:
- **Hallucinated or leaked credentials** (AWS, GitHub, OpenAI, Anthropic, Gemini, Stripe, Supabase keys, DB connection strings).
- **Dangerous command injection vectors** (`subprocess.run(..., shell=True)`, `child_process.exec(...)`, `os.system()`).
- **Prototype Pollution exploits** (`__proto__`, `constructor.prototype`).
- **DOM XSS vulnerabilities** (`dangerouslySetInnerHTML`, `innerHTML = ...`, `document.write`).
- **Insecure deserialization** (`yaml.load()`, `pickle.loads()`).
- **Adversarial prompt injection directives** smuggled into comments and docstrings.
- **Deceptive Unicode Trojan Source backdoors** (CVE-2021-42574).

**SaniLine provides an automated, local, zero-overhead safety net that intercepts and repairs code line-by-line.**

---

## 🧠 Preserving the Agent's Token Budget

Traditional linters dump extensive AST warnings and file traces into the conversation, consuming thousands of tokens. SaniLine solves this with **Hyper-Compact Agent Serialization**:

### Clean Code Example (< 5 tokens):
```json
{ "status": "CLEAN" }
```

### Auto-Patched Code Example (< 30 tokens):
```json
{
  "status": "MODIFIED",
  "patch": "subprocess.run(shlex.split(cmd), shell=False)",
  "issues": [
    {
      "line": 4,
      "rule": "SL-RCE-001",
      "cwe": "CWE-78",
      "fix": "Set shell=False and pass command arguments as a validated list."
    }
  ]
}
```

---

## 🛠️ Integration Patterns for AI Agents

### Pattern 1: Tool Invocation via Model Context Protocol (MCP)

If your agent supports MCP (Claude Desktop, Cursor, Antigravity):
1. Start the MCP server: `npx -y saniline mcp` or `saniline-mcp`.
2. Configuration snippet:
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
3. Call `saniline_sanitize_line` with `{"line": "...", "compact": true}`.
4. If `"status": "MODIFIED"`, substitute the line with `"patch"`.

### Pattern 2: Subprocess Filter via CLI

Agents executing shell tools can pipe or check files directly:
```bash
# Verify modified file without polluting output (<10 tokens):
npx saniline check src/app.py --compact

# Export OASIS SARIF v2.1.0 for GitHub Actions Code Scanning:
npx saniline check src/ --format sarif > results.sarif

# Auto-remediate all violations in-place:
npx saniline sanitize src/app.py --in-place
```

### Pattern 3: In-Memory Python / Node.js Shield

When writing scripts or running within Python or Node runtimes:

#### Python:
```python
from saniline import SaniLine, SecurityLevel, SanitizeAction

shield = SaniLine(level=SecurityLevel.MILITARY, action=SanitizeAction.AUTOPATCH)
result = shield.sanitize_line(generated_line)
safe_line = result.sanitized_code
```

#### Node.js & Vercel AI SDK:
```javascript
import { SaniLine, SaniLineTransformStream } from "saniline";

// 1. Line-by-line inspection:
const shield = new SaniLine();
const result = shield.sanitizeLine(generatedLine);
const safeLine = result.sanitizedCode;

// 2. Real-time LLM token stream filtering:
const safeStream = result.textStream.pipeThrough(new SaniLineTransformStream());
```

---

## 🌐 jsDelivr & Browser Agent Environments

For browser-based agents, web playgrounds, or edge workers:

### jsDelivr CDN Links:
```html
<!-- Primary npm release on jsDelivr -->
<script src="https://cdn.jsdelivr.net/npm/saniline/dist/saniline.min.js"></script>

<!-- Direct GitHub release on jsDelivr -->
<script src="https://cdn.jsdelivr.net/gh/alivirgo/SaniLine@v0.2.0/dist/saniline.min.js"></script>
```

```javascript
// Access via global object:
const shield = new window.SaniLine();
const result = shield.sanitizeLine(code);
```

---

## 📋 Standard Agent Configuration Snippet

Add this prompt block to your agent's system instructions (`AGENTS.md`, `.cursorrules`, or custom prompt):

```markdown
### Security Directive: SaniLine Compliance
Before finalizing any file edit or code generation:
1. Verify no plaintext credentials, 'shell=True', Prototype Pollution, or 'yaml.load()' exist.
2. Run 'npx saniline check <file> --compact' or 'npx saniline sanitize <file> --in-place'.
3. Maintain compliance with DoD STIG, NIST SP 800-218, and CWE Top 25 standards.
```
