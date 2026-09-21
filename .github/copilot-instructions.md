# GitHub Copilot Instructions for SaniLine

When generating code suggestions, completions, or pull request diffs:
1. **Zero-Trust Line Sanitization**: Apply military-grade cybersecurity standards on every line (DoD STIG, NIST SP 800-218 SSDF, CWE Top 25).
2. **Never Generate Vulnerable Idioms**:
   - Do NOT emit `subprocess.Popen(..., shell=True)` or insecure `os.system()`.
   - Do NOT emit `child_process.exec()` / `execSync()` with dynamic shell strings (use `execFile()` or `spawn()` with argument arrays).
   - Do NOT emit Prototype Pollution mutations (`__proto__` or `constructor.prototype`).
   - Do NOT emit unescaped DOM HTML sinks (`dangerouslySetInnerHTML`, `innerHTML = ...`, `document.write`).
   - Do NOT emit `yaml.load()` without `SafeLoader` or use `yaml.safe_load()`.
   - Do NOT emit hardcoded credentials (AWS, GitHub, OpenAI, Anthropic, Gemini, Stripe, Supabase tokens, DB connection strings).
   - Do NOT emit broken hashes (`md5` or `sha1` for security operations).
   - Do NOT disable TLS certificate verification (`verify=False` or `rejectUnauthorized: false`).
   - Do NOT emit Trojan Source bidirectional Unicode characters (`U+202E`, `U+2066`) or zero-width spaces (CVE-2021-42574).
   - Do NOT bind server sockets to wildcard interfaces (`0.0.0.0`) by default (use `127.0.0.1`).
3. **Verify Compliance**:
   - Run `npx saniline check <path> --compact` or `saniline check <path> --compact` to audit security posture.
   - Run `npx saniline sanitize <path> --in-place` to auto-remediate vulnerabilities.
   - Run `npx saniline check <path> --format sarif` to generate OASIS SARIF v2.1.0 telemetry for GitHub Code Scanning.
