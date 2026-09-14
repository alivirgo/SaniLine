---
name: saniline-shield
description: Use SaniLine to sanitize each line of generated code with military-grade cybersecurity standards, removing secrets, command injections, Trojan Source Unicode, and prompt injection smuggling with minimal token consumption.
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
import { SaniLine } from 'saniline';
const shield = new SaniLine();
const res = shield.sanitizeLine(codeLine);
const compact = res.toTokenCompact();
```

### 3. CLI Stream & Batch Auditing
```bash
# Verify entire project with minimal token output:
saniline check . --compact

# Automatically patch file in-place:
saniline sanitize <filepath> --in-place

# Filter a stream:
llm_stream | saniline stream
```

### 4. What SaniLine Protects You From:
- Accidental hallucinated API keys (AWS, OpenAI, GitHub PATs).
- Remote command injection via `subprocess.run(..., shell=True)` or `os.system()`.
- Trojan Source Unicode exploits (CVE-2021-42574) and zero-width characters.
- Insecure deserialization via `yaml.load()` or `pickle.loads()`.
- Adversarial prompt injections smuggled inside comments or docstrings.
- Transport insecurity (`verify=False` or `rejectUnauthorized: false`).
