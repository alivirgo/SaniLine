# Claude Code Security Rule: SaniLine

When generating code or writing tests, sanitize each line with SaniLine:
- Command: `saniline check . --compact`
- In-place remediation: `saniline sanitize <file> --in-place`
- Python SDK: `from saniline import SaniLine; shield = SaniLine()`
- Ensure zero hardcoded credentials, zero command injection vectors, and zero Trojan Source Unicode characters.
