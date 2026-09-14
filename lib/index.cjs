/**
 * SaniLine - CommonJS Implementation
 * Version 0.1.0 | Apache-2.0 License
 */

"use strict";

const VERSION = "0.1.0";
const TAGLINE = "Real-Time Military-Grade Line-by-Line Code Sanitizer & Security Shield for AI Agents";

const SecurityLevel = {
  STANDARD: "standard",
  STRICT: "strict",
  MILITARY: "military",
};

const SanitizeAction = {
  AUDIT: "audit",
  REDACT: "redact",
  AUTOPATCH: "autopatch",
  BLOCK: "block",
};

const Severity = {
  LOW: "LOW",
  MEDIUM: "MEDIUM",
  HIGH: "HIGH",
  CRITICAL: "CRITICAL",
};

function calculateShannonEntropy(str) {
  if (!str) return 0;
  const len = str.length;
  const freq = {};
  for (let i = 0; i < len; i++) {
    const ch = str[i];
    freq[ch] = (freq[ch] || 0) + 1;
  }
  let entropy = 0;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

const DANGEROUS_UNICODE_CHARS = {
  "\u202A": "LEFT-TO-RIGHT EMBEDDING [LRE]",
  "\u202B": "RIGHT-TO-LEFT EMBEDDING [RLE]",
  "\u202C": "POP DIRECTIONAL FORMATTING [PDF]",
  "\u202D": "LEFT-TO-RIGHT OVERRIDE [LRO]",
  "\u202E": "RIGHT-TO-LEFT OVERRIDE [RLO]",
  "\u2066": "LEFT-TO-RIGHT ISOLATE [LRI]",
  "\u2067": "RIGHT-TO-LEFT ISOLATE [RLI]",
  "\u2068": "FIRST STRONG ISOLATE [FSI]",
  "\u2069": "POP DIRECTIONAL ISOLATE [PDI]",
  "\u200B": "ZERO-WIDTH SPACE [ZWSP]",
  "\u200C": "ZERO-WIDTH NON-JOINER [ZWNJ]",
  "\u200D": "ZERO-WIDTH JOINER [ZWJ]",
  "\uFEFF": "ZERO-WIDTH NO-BREAK SPACE [BYTE-ORDER-MARK]",
};

class SaniLine {
  constructor(options = {}) {
    this.level = options.level || SecurityLevel.MILITARY;
    this.action = options.action || SanitizeAction.AUTOPATCH;
    this.defaultLanguage = options.defaultLanguage || "generic";
  }

  sanitizeLine(line, lineNumber = 1, language = null) {
    const lang = language || this.defaultLanguage;
    let currentLine = line;
    const violations = [];
    let modified = false;

    // 1. Trojan Source (CVE-2021-42574)
    let hasUnicodeBidi = false;
    for (const ch in DANGEROUS_UNICODE_CHARS) {
      if (currentLine.includes(ch)) {
        hasUnicodeBidi = true;
        break;
      }
    }
    if (hasUnicodeBidi) {
      let cleaned = currentLine;
      for (const ch in DANGEROUS_UNICODE_CHARS) {
        cleaned = cleaned.split(ch).join("");
      }
      violations.push({
        rule_id: "SL-UNI-001",
        title: "Trojan Source Bidi / Zero-Width Unicode Exploit (CVE-2021-42574)",
        cwe_id: "CWE-1036",
        severity: Severity.CRITICAL,
        line_number: lineNumber,
        remediation_advice: "Purge deceptive bidirectional and zero-width characters.",
      });
      if (this.action === SanitizeAction.AUTOPATCH) {
        currentLine = cleaned;
        modified = true;
      }
    }

    // 2. Hardcoded Secrets & High Entropy Tokens (CWE-798)
    const secretPatterns = [
      { regex: /\b(AKIA[0-9A-Z]{16})\b/g, mask: "[REDACTED_SECRET:AWS_ACCESS_KEY]" },
      { regex: /\b(gh[pousr]_[A-Za-z0-9_]{36,255})\b/g, mask: "[REDACTED_SECRET:GITHUB_TOKEN]" },
      { regex: /\b(sk-[a-zA-Z0-9]{20,}|sk-proj-[a-zA-Z0-9_-]{20,})\b/g, mask: "[REDACTED_SECRET:OPENAI_API_KEY]" },
      { regex: /\b(sk-ant-[a-zA-Z0-9_-]{20,})\b/g, mask: "[REDACTED_SECRET:ANTHROPIC_API_KEY]" },
      { regex: /\b(AIza[0-9A-Za-z_-]{35})\b/g, mask: "[REDACTED_SECRET:GOOGLE_API_KEY]" },
      { regex: /\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b/g, mask: "[REDACTED_SECRET:SLACK_TOKEN]" },
      { regex: /-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP)?\s*PRIVATE KEY-----/g, mask: "[REDACTED_SECRET:PRIVATE_KEY]" },
      { regex: /((?:postgres|mysql|mongodb(?:\+srv)?|redis):\/\/[^:\s]+:)([^@\s]+)(@)/g, mask: "$1[REDACTED_SECRET:DB_PASSWORD]$3" },
      { regex: /\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g, mask: "[REDACTED_SECRET:JWT_TOKEN]" },
    ];

    for (const { regex, mask } of secretPatterns) {
      if (regex.test(currentLine)) {
        violations.push({
          rule_id: "SL-SEC-001",
          title: "Hardcoded Credential or API Token Exposure",
          cwe_id: "CWE-798",
          severity: Severity.CRITICAL,
          line_number: lineNumber,
          remediation_advice: "Extract secret into environment variable (e.g. process.env.API_KEY).",
        });
        if (this.action === SanitizeAction.AUTOPATCH || this.action === SanitizeAction.REDACT) {
          currentLine = currentLine.replace(regex, mask);
          modified = true;
        }
      }
    }

    // High-Entropy assignment detection
    const assignMatch = currentLine.match(/\b(password|passwd|secret|api_?key|access_?token|auth_?token|client_?secret|bearer)\s*[:=]\s*(['"])([^'"]{8,})\2/i);
    if (assignMatch) {
      const varName = assignMatch[1];
      const val = assignMatch[3];
      const dummies = ["dummy", "example", "changeme", "test", "fake", "placeholder", "your_api_key"];
      const isDummy = dummies.some(d => val.toLowerCase().includes(d));
      if (!isDummy) {
        const ent = calculateShannonEntropy(val);
        if ((val.length >= 12 && ent >= 3.2) || (val.length >= 8 && ent >= 3.6)) {
          violations.push({
            rule_id: "SL-SEC-001",
            title: `High-Entropy Secret Assigned to '${varName}'`,
            cwe_id: "CWE-798",
            severity: Severity.CRITICAL,
            line_number: lineNumber,
            remediation_advice: `Retrieve '${varName}' from process.env instead of hardcoding.`,
          });
          if (this.action === SanitizeAction.AUTOPATCH || this.action === SanitizeAction.REDACT) {
            const envName = varName.toUpperCase().replace(/-/g, "_");
            const patch = `process.env.${envName} || ""`;
            currentLine = currentLine.replace(assignMatch[0], `${varName} = ${patch}`);
            modified = true;
          }
        }
      }
    }

    // 3. RCE (CWE-78, CWE-95)
    if (/\bshell\s*=\s*True\b/.test(currentLine)) {
      violations.push({
        rule_id: "SL-RCE-001",
        title: "Insecure Subprocess with shell=True",
        cwe_id: "CWE-78",
        severity: Severity.CRITICAL,
        line_number: lineNumber,
        remediation_advice: "Set shell=False and pass arguments as an array.",
      });
      if (this.action === SanitizeAction.AUTOPATCH) {
        currentLine = currentLine.replace(/\bshell\s*=\s*True\b/g, "shell=False");
        modified = true;
      }
    }

    if (/\bchild_process\s*\.\s*exec\s*\(/.test(currentLine)) {
      violations.push({
        rule_id: "SL-RCE-001",
        title: "Insecure child_process.exec() Shell Invocation",
        cwe_id: "CWE-78",
        severity: Severity.HIGH,
        line_number: lineNumber,
        remediation_advice: "Use child_process.execFile() or spawn() with argument arrays.",
      });
      if (this.action === SanitizeAction.AUTOPATCH) {
        currentLine = currentLine.replace(/child_process\s*\.\s*exec\s*\(/g, "child_process.execFile(");
        modified = true;
      }
    }

    if (/\b(eval|new\s+Function)\s*\(/.test(currentLine) && !currentLine.trim().startsWith("//")) {
      violations.push({
        rule_id: "SL-RCE-002",
        title: "Dangerous Dynamic eval() / new Function()",
        cwe_id: "CWE-95",
        severity: Severity.CRITICAL,
        line_number: lineNumber,
        remediation_advice: "Refactor dynamic evaluation to JSON.parse or static lookup dispatch.",
      });
    }

    // 4. Insecure Deserialization (CWE-502)
    if (/\byaml\s*\.\s*load\s*\([^)]*\)/.test(currentLine) && !currentLine.includes("SafeLoader")) {
      violations.push({
        rule_id: "SL-DESER-001",
        title: "Unsafe yaml.load() Deserialization",
        cwe_id: "CWE-502",
        severity: Severity.CRITICAL,
        line_number: lineNumber,
        remediation_advice: "Use yaml.safe_load() to prevent arbitrary code execution.",
      });
      if (this.action === SanitizeAction.AUTOPATCH) {
        currentLine = currentLine.replace(/\byaml\s*\.\s*load\s*\(/g, "yaml.safe_load(");
        modified = true;
      }
    }

    // 5. Prompt Injection Smuggling (CWE-1188)
    const promptHijackRegex = /\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above)\s+instructions\b/i;

    if (promptHijackRegex.test(currentLine)) {
      violations.push({
        rule_id: "SL-PRM-001",
        title: "Smuggled AI Prompt Injection Directive",
        cwe_id: "CWE-1188",
        severity: Severity.HIGH,
        line_number: lineNumber,
        remediation_advice: "Purge prompt injection directives embedded in code or comments.",
      });
      if (this.action === SanitizeAction.AUTOPATCH) {
        currentLine = currentLine.replace(promptHijackRegex, "[SANILINE_DEFUSED_PROMPT_INJECTION]");
        modified = true;
      }
    }

    // 6. Cryptography & Transport (CWE-295, CWE-328)
    if (/\brejectUnauthorized\s*:\s*false\b/.test(currentLine)) {
      violations.push({
        rule_id: "SL-CRY-001",
        title: "Disabled TLS Certificate Validation (rejectUnauthorized: false)",
        cwe_id: "CWE-295",
        severity: Severity.CRITICAL,
        line_number: lineNumber,
        remediation_advice: "Set rejectUnauthorized: true to enforce SSL/TLS verification.",
      });
      if (this.action === SanitizeAction.AUTOPATCH) {
        currentLine = currentLine.replace(/\brejectUnauthorized\s*:\s*false\b/g, "rejectUnauthorized: true");
        modified = true;
      }
    }

    if (/\bverify\s*=\s*False\b/.test(currentLine)) {
      violations.push({
        rule_id: "SL-CRY-001",
        title: "Disabled TLS Certificate Verification (verify=False)",
        cwe_id: "CWE-295",
        severity: Severity.CRITICAL,
        line_number: lineNumber,
        remediation_advice: "Set verify=True to prevent MitM credential interception.",
      });
      if (this.action === SanitizeAction.AUTOPATCH) {
        currentLine = currentLine.replace(/\bverify\s*=\s*False\b/g, "verify=True");
        modified = true;
      }
    }

    // 7. SSRF (CWE-918)
    if (/(?:169\.254\.169\.254|metadata\.google\.internal)/.test(currentLine)) {
      violations.push({
        rule_id: "SL-NET-001",
        title: "Cloud Metadata Endpoint SSRF (169.254.169.254)",
        cwe_id: "CWE-918",
        severity: Severity.CRITICAL,
        line_number: lineNumber,
        remediation_advice: "Do not query instance metadata endpoints directly from application code.",
      });
    }

    return {
      originalCode: line,
      sanitizedCode: currentLine,
      isClean: violations.length === 0,
      wasModified: modified,
      violations,
      toTokenCompact() {
        if (violations.length === 0 && !modified) {
          return { status: "CLEAN" };
        }
        const res = { status: modified ? "MODIFIED" : "VIOLATION" };
        if (modified) res.patch = currentLine;
        res.issues = violations.map(v => ({
          line: v.line_number,
          rule: v.rule_id,
          cwe: v.cwe_id,
          fix: v.remediation_advice,
        }));
        return res;
      },
    };
  }

  sanitizeCode(code, language = null) {
    const lines = code.split("\n");
    const sanitizedLines = [];
    const allViolations = [];
    let modified = false;

    for (let i = 0; i < lines.length; i++) {
      const res = this.sanitizeLine(lines[i], i + 1, language);
      sanitizedLines.push(res.sanitizedCode);
      if (!res.isClean) allViolations.push(...res.violations);
      if (res.wasModified) modified = true;
    }

    return {
      originalCode: code,
      sanitizedCode: sanitizedLines.join("\n"),
      isClean: allViolations.length === 0,
      wasModified: modified,
      violations: allViolations,
      toTokenCompact() {
        if (allViolations.length === 0 && !modified) {
          return { status: "CLEAN" };
        }
        const res = { status: modified ? "MODIFIED" : "VIOLATION" };
        if (modified) res.patch = sanitizedLines.join("\n");
        res.issues = allViolations.map(v => ({
          line: v.line_number,
          rule: v.rule_id,
          cwe: v.cwe_id,
          fix: v.remediation_advice,
        }));
        return res;
      },
    };
  }
}

module.exports = {
  VERSION,
  TAGLINE,
  SecurityLevel,
  SanitizeAction,
  Severity,
  calculateShannonEntropy,
  SaniLine,
  default: SaniLine,
};
