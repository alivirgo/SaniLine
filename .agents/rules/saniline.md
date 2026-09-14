# Antigravity Global Workspace Rule: SaniLine Zero-Trust Security

Whenever generating or editing code in this workspace:
1. Every code line must be vetted against military-grade cybersecurity standards (DoD STIG, NIST SP 800-218, CWE Top 25).
2. Neutralize hardcoded credentials, command injection risks (`subprocess(..., shell=True)`), insecure deserialization (`yaml.load`), and Trojan Source Unicode sequences.
3. Use SaniLine's token-compact outputs (`saniline check . --compact` or `res.to_token_compact()`) to protect the context token budget.
4. Auto-patch files in-place using `saniline sanitize <file> --in-place`.
