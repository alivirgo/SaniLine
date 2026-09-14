# Autonomous AI Agent Integration Guide for SaniLine 🛡️

This guide explains how autonomous AI agents (**Antigravity**, **Claude Code**, **Cursor**, **Devin**, **Aider**, **Copilot Workspace**, and **AutoGPT**) discover, configure, and invoke **SaniLine** in their coding workflows.

---

## 🌟 Why AI Agents Need SaniLine

When AI agents generate code, they lack runtime awareness and often introduce:
- **Hallucinated or leaked credentials** (AWS, GitHub, OpenAI keys, DB connection strings).
- **Dangerous execution patterns** (`subprocess.run(..., shell=True)`, `os.system()`).
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
1. Start the MCP server: `saniline mcp` or `saniline-mcp`.
2. Call `saniline_sanitize_line` with `{"line": "...", "compact": true}`.
3. If `"status": "MODIFIED"`, substitute the line with `"patch"`.

### Pattern 2: Subprocess Filter via CLI

Agents executing shell tools can pipe or check files directly:
```bash
# Verify modified file without polluting output:
saniline check src/app.py --compact

# Auto-remediate all violations in-place:
saniline sanitize src/app.py --in-place
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

#### Node.js:
```javascript
import { SaniLine } from "saniline";

const shield = new SaniLine();
const result = shield.sanitizeLine(generatedLine);
const safeLine = result.sanitizedCode;
```

---

## 🌐 jsDelivr & Browser Agent Environments

For browser-based agents, web playgrounds, or edge workers:

### jsDelivr CDN Links:
```html
<!-- Primary npm release on jsDelivr -->
<script src="https://cdn.jsdelivr.net/npm/saniline/dist/saniline.min.js"></script>

<!-- Direct GitHub release on jsDelivr -->
<script src="https://cdn.jsdelivr.net/gh/alivirgo/SaniLine@v0.1.0/dist/saniline.min.js"></script>
```

```javascript
// Access via global object:
const shield = new window.SaniLine.SaniLine();
const result = shield.sanitizeLine(code);
```

---

## 📋 Standard Agent Configuration Snippet

Add this prompt block to your agent's system instructions (`AGENTS.md`, `.cursorrules`, or custom prompt):

```markdown
### Security Directive: SaniLine Compliance
Before finalizing any file edit or code generation:
1. Verify no plaintext credentials, 'shell=True', or 'yaml.load()' exist.
2. Run 'saniline check <file> --compact' or 'saniline sanitize <file> --in-place'.
3. Maintain compliance with DoD STIG and NIST SP 800-218 standards.
```
