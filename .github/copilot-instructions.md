# GitHub Copilot Instructions for SaniLine

When generating code suggestions, completions, or pull request diffs:
1. **Zero-Trust Line Sanitization**: Apply military-grade cybersecurity standards on every line.
2. **Never Generate Vulnerable Idioms**:
   - Do NOT emit `subprocess.Popen(..., shell=True)`.
   - Do NOT emit `yaml.load()` without SafeLoader.
   - Do NOT emit hardcoded credentials (AWS, OpenAI, GitHub tokens).
   - Do NOT emit broken hashes (`md5` or `sha1` for security operations).
   - Do NOT disable TLS certificate verification (`verify=False`).
3. **Verify Compliance**:
   Run `saniline check <path> --compact` to audit security compliance.
   Run `saniline sanitize <path> --in-place` to remediate issues automatically.
