# AGENTS.md — Universal Autonomous AI Agent Standard Instructions

## System Identity & Security Standard
- **Project**: SaniLine
- **Core Standard**: DoD STIG, NIST SP 800-218 (SSDF), CWE Top 25 Most Dangerous Weaknesses.
- **Goal**: Zero-trust, line-by-line code sanitization with sub-millisecond local execution and minimal token footprint.

## Mandatory Directives for Autonomous Coders
When any AI agent (Antigravity, Claude Code, Cursor, Devin, ChatGPT, Codex, OpenHands, Aider) performs code operations:
1. **Never Emit Plaintext Secrets**: Detect and mask credentials with `[REDACTED_SECRET:<TYPE>]` or redirect to environment variables.
2. **Never Emit Shell Injection Vectors**: Auto-patch `shell=True` to `shell=False`.
3. **Never Emit Trojan Source Unicode**: Strip bidirectional control characters (`U+202E`, `U+2066`) and zero-width spaces (CVE-2021-42574).
4. **Token Conservation**: Always request compact outputs (`--compact` in CLI or `.to_token_compact()` / `compact: true` in MCP). A clean line consumes `< 10 tokens`.

## Automated Commands
```bash
# Check code in token-minified mode:
saniline check <path> --compact

# Auto-patch files:
saniline sanitize <path> --in-place

# Pipe streams:
cat raw.py | saniline stream > safe.py
```
