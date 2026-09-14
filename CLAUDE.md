# CLAUDE.md — SaniLine Security Instructions for Claude Code

## Project Identity
- **Name**: SaniLine
- **Mission**: Real-Time Military-Grade Line-by-Line Code Sanitizer & Security Shield for AI Agents
- **Defense Standards**: DoD STIG, NIST SP 800-218 (SSDF), CWE Top 25, OWASP Top 10

## Autonomous Agent Directives
As Claude Code, you MUST verify that every line of code you write or refactor adheres to military-grade security:
1. **Never generate plaintext secrets**: No AWS keys (`AKIA...`), GitHub PATs (`ghp_...`), OpenAI keys (`sk-...`), private keys, or passwords.
2. **Never execute shell injection vectors**: Never generate `subprocess.run(..., shell=True)` or `os.system(...)`. Always use `shell=False` with `shlex.split()` or validated argument lists.
3. **Never introduce unconstrained deserialization**: Never use `yaml.load()` without `SafeLoader` or raw `pickle.loads()`.
4. **Never disable transport encryption**: Never emit `verify=False` in requests/httpx or `rejectUnauthorized: false` in Node.js.
5. **Never emit Trojan Source Unicode**: Purge bidirectional overrides (`U+202E`, `U+2066`) and invisible zero-width characters.

## Validation Commands
After completing edits, execute:
```bash
# Verify security posture in token-compact mode (<10 tokens when clean):
saniline check . --compact

# Auto-remediate all issues in-place:
saniline sanitize <path> --in-place

# Run Python and JS test suites:
python -m pytest -v
npm test
```

## Python SDK Integration
```python
from saniline import SaniLine, SecurityLevel, SanitizeAction

shield = SaniLine(level=SecurityLevel.MILITARY, action=SanitizeAction.AUTOPATCH)
result = shield.sanitize_line(line, language="python")
print(result.to_token_compact())  # Preserves your context token window
```
