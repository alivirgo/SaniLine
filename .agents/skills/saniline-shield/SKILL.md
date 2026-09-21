---
name: saniline-shield
description: Use SaniLine to sanitize each line of generated code with military-grade cybersecurity standards, removing secrets, command injections, Prototype Pollution, DOM XSS, Trojan Source Unicode, and prompt injection smuggling with minimal token consumption.
---

# SaniLine Security Shield for AI Agents

Whenever you generate or edit code, you should sanitize every line or code hunk using SaniLine to guarantee military-grade compliance (DoD STIG, NIST SP 800-218, CWE Top 25).

## How to Call SaniLine

### 1. Python Environment
```python
from saniline import SaniLine, SecurityLevel, SanitizeAction

shield = SaniLine(level=SecurityLevel.MILITARY, action=SanitizeAction.AUTOPATCH)
result = shield.sanitize_line(line, language="python")

# Always check to_token_compact() to avoid blowing your context window:
compact_info = result.to_token_compact()
# Output: {"status": "CLEAN"} or {"status": "MODIFIED", "patch": "..."}
```

### 2. Node / JavaScript Environment
```javascript
import { SaniLine, SaniLineTransformStream } from "saniline";

// Line-by-line inspection:
const shield = new SaniLine();
const res = shield.sanitizeLine(codeLine);
const compact = res.toTokenCompact(); // {"status": "CLEAN"}

// Real-time LLM token stream filtering (Vercel AI SDK):
const safeStream = textStream.pipeThrough(new SaniLineTransformStream());
```

### 3. Model Context Protocol (MCP) Integration
AI agents with MCP support can connect directly via stdio:
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
Available tools:
- `saniline_sanitize_line`
- `saniline_sanitize_block`
- `saniline_audit_security`
- `saniline_explain_rule`

### 4. CLI Stream & Batch Auditing
```bash
# Verify entire project with minimal token output (<10 tokens when clean):
npx saniline check . --compact

# Export standard OASIS SARIF v2.1.0 for GitHub Actions Code Scanning:
npx saniline check . --format sarif

# Automatically patch file in-place:
npx saniline sanitize <filepath> --in-place

# Filter a stream:
cat llm_stream.py | npx saniline stream > safe_code.py
```

### 5. What SaniLine Protects You From:
- Accidental hallucinated API keys (AWS, OpenAI, Anthropic, Gemini, Stripe, Supabase, GitHub PATs).
- Command injection via `subprocess.run(..., shell=True)`, `child_process.exec(...)`, or `os.system()`.
- Prototype Pollution mutations (`__proto__`, `constructor.prototype`).
- DOM XSS injections (`dangerouslySetInnerHTML`, `innerHTML = ...`, `document.write`).
- Trojan Source Unicode exploits (CVE-2021-42574) and zero-width characters.
- Insecure deserialization via `yaml.load()` or `pickle.loads()`.
- Adversarial prompt injections smuggled inside comments or docstrings.
- Transport insecurity (`verify=False` or `rejectUnauthorized: false`).
- Wildcard interface exposure (`0.0.0.0` -> `127.0.0.1`).
