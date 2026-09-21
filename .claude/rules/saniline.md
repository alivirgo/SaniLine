# Claude Code Security Rule: SaniLine

When generating code, writing tests, or reviewing code changes, sanitize each line with SaniLine:
- CLI Audit: `saniline check . --compact` or `npx saniline check . --compact`
- In-place remediation: `saniline sanitize <file> --in-place` or `npx saniline sanitize <file> --in-place`
- SARIF export: `saniline check . --format sarif`
- MCP Server: `saniline mcp` or `npx -y saniline mcp`
- Python SDK: `from saniline import SaniLine; shield = SaniLine()`
- Node.js SDK: `import { SaniLine, SaniLineTransformStream } from "saniline"`
- Ensure zero hardcoded credentials (AWS, GitHub, OpenAI, Anthropic, Gemini, Stripe, Supabase), zero command injection vectors (`shell=True`, `child_process.exec`), zero Prototype Pollution, zero DOM XSS, and zero Trojan Source Unicode characters (CVE-2021-42574).
