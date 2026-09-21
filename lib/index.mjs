/**
 * SaniLine - Real-Time Military-Grade Line-by-Line Code Sanitizer & Security Shield for AI Agents
 * Version 0.1.0 | Apache-2.0 License
 */

import { Transform } from "node:stream";

export const VERSION = "0.2.0";
export const TAGLINE = "Real-Time Military-Grade Line-by-Line Code Sanitizer & Security Shield for AI Agents";

export const SecurityLevel = {
  STANDARD: "standard",
  STRICT: "strict",
  MILITARY: "military",
};

export const SanitizeAction = {
  AUDIT: "audit",
  REDACT: "redact",
  AUTOPATCH: "autopatch",
  BLOCK: "block",
};

export const Severity = {
  LOW: "LOW",
  MEDIUM: "MEDIUM",
  HIGH: "HIGH",
  CRITICAL: "CRITICAL",
};

export const RULES_CATALOG = [
  {
    rule_id: "SL-SEC-001",
    title: "Hardcoded Credentials & High-Entropy Tokens",
    category: "Secrets Exposure",
    standard: "CWE-798 / DoD STIG APPS-000170",
    severity: Severity.CRITICAL,
    auto_patch: true,
    remediation: "Extract secret into environment variable (process.env.KEY).",
  },
  {
    rule_id: "SL-UNI-001",
    title: "Trojan Source Bidi & Zero-Width Unicode Exploits",
    category: "Trojan Source",
    standard: "CVE-2021-42574 / CWE-1036",
    severity: Severity.CRITICAL,
    auto_patch: true,
    remediation: "Purge deceptive bidirectional overrides and zero-width characters.",
  },
  {
    rule_id: "SL-PRM-001",
    title: "Smuggled AI Prompt Injection Directive",
    category: "Prompt Hijack",
    standard: "CWE-1188 / APSC-DV-003100",
    severity: Severity.HIGH,
    auto_patch: true,
    remediation: "Neutralize prompt injection directives hidden in code or comments.",
  },
  {
    rule_id: "SL-RCE-001",
    title: "Insecure Subprocess & Shell Command Injection",
    category: "Command Injection",
    standard: "CWE-78 / DoD STIG APSC-DV-002100",
    severity: Severity.CRITICAL,
    auto_patch: true,
    remediation: "Use child_process.execFile() or spawn() with argument arrays, or set shell=False.",
  },
  {
    rule_id: "SL-RCE-002",
    title: "Arbitrary Dynamic Code Execution (eval / new Function)",
    category: "Dynamic Execution",
    standard: "CWE-95 / CWE-94",
    severity: Severity.CRITICAL,
    auto_patch: false,
    remediation: "Refactor dynamic evaluation to JSON.parse or static lookup dispatch.",
  },
  {
    rule_id: "SL-RCE-004",
    title: "Insecure child_process shell invocation (exec/execSync)",
    category: "Command Injection",
    standard: "CWE-78 / APSC-DV-002100",
    severity: Severity.HIGH,
    auto_patch: true,
    remediation: "Use child_process.execFile() or spawn() with argument arrays.",
  },
  {
    rule_id: "SL-PROTO-001",
    title: "Prototype Pollution Vulnerability",
    category: "Prototype Pollution",
    standard: "CWE-1321",
    severity: Severity.HIGH,
    auto_patch: true,
    remediation: "Disallow __proto__ and constructor.prototype property mutation.",
  },
  {
    rule_id: "SL-XSS-001",
    title: "DOM XSS / Insecure HTML Injection",
    category: "Cross-Site Scripting",
    standard: "CWE-79 / APSC-DV-002530",
    severity: Severity.HIGH,
    auto_patch: false,
    remediation: "Sanitize user input with DOMPurify or use safe text content binding.",
  },
  {
    rule_id: "SL-PATH-001",
    title: "Directory Traversal Sequence",
    category: "Path Traversal",
    standard: "CWE-22 / APSC-DV-002560",
    severity: Severity.HIGH,
    auto_patch: false,
    remediation: "Normalize and validate paths against an allowed root directory.",
  },
  {
    rule_id: "SL-PATH-002",
    title: "Unconfined Archive Extraction (Zip Slip)",
    category: "Path Traversal",
    standard: "CWE-22 / CWE-29",
    severity: Severity.HIGH,
    auto_patch: false,
    remediation: "Verify archive extraction targets stay confined to the destination folder.",
  },
  {
    rule_id: "SL-INJ-001",
    title: "Dynamic SQL Injection via Interpolation",
    category: "SQL Injection",
    standard: "CWE-89 / APSC-DV-002510",
    severity: Severity.CRITICAL,
    auto_patch: false,
    remediation: "Use parameterized queries or prepared statements instead of string interpolation.",
  },
  {
    rule_id: "SL-DESER-001",
    title: "Unsafe Object Deserialization",
    category: "Insecure Deserialization",
    standard: "CWE-502 / APSC-DV-002620",
    severity: Severity.CRITICAL,
    auto_patch: true,
    remediation: "Use yaml.safe_load() or standard JSON deserialization.",
  },
  {
    rule_id: "SL-CRY-001",
    title: "Disabled TLS Certificate Verification",
    category: "Transport Security",
    standard: "CWE-295 / APSC-DV-002010",
    severity: Severity.CRITICAL,
    auto_patch: true,
    remediation: "Enforce TLS verification (rejectUnauthorized: true, verify=True).",
  },
  {
    rule_id: "SL-CRY-002",
    title: "Insecure PRNG in Security Context",
    category: "Cryptography",
    standard: "CWE-330 / APSC-DV-002030",
    severity: Severity.HIGH,
    auto_patch: false,
    remediation: "Use crypto.randomBytes() or crypto.getRandomValues() for cryptographic tokens.",
  },
  {
    rule_id: "SL-CRY-003",
    title: "Broken Cryptographic Hash (MD5 / SHA-1)",
    category: "Cryptography",
    standard: "CWE-328 / APSC-DV-002010",
    severity: Severity.HIGH,
    auto_patch: true,
    remediation: "Upgrade to SHA-256 (crypto.createHash('sha256')).",
  },
  {
    rule_id: "SL-NET-001",
    title: "Cloud Metadata Endpoint SSRF",
    category: "SSRF Exfiltration",
    standard: "CWE-918 / APSC-DV-002570",
    severity: Severity.CRITICAL,
    auto_patch: false,
    remediation: "Do not query instance metadata endpoints (169.254.169.254) from application code.",
  },
  {
    rule_id: "SL-NET-002",
    title: "Wildcard Socket Interface Binding (0.0.0.0)",
    category: "Exposure",
    standard: "CWE-200 / APSC-DV-002580",
    severity: Severity.MEDIUM,
    auto_patch: true,
    remediation: "Bind to localhost (127.0.0.1) unless external exposure is explicitly required.",
  },
];

export function calculateShannonEntropy(str) {
  if (!str || typeof str !== "string") return 0;
  const len = str.length;
  if (len === 0) return 0;
  const freq = Object.create(null);
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

export class SaniLine {
  constructor(options = {}) {
    this.level = options.level || SecurityLevel.MILITARY;
    this.action = options.action || SanitizeAction.AUTOPATCH;
    this.defaultLanguage = options.defaultLanguage || "generic";
  }

  sanitizeLine(line, lineNumber = 1, language = null) {
    if (typeof line !== "string") {
      line = line == null ? "" : String(line);
    }
    const lang = (language || this.defaultLanguage).toLowerCase();
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
      { regex: /\b(sk-[a-zA-Z0-9]{20,128}|sk-proj-[a-zA-Z0-9_-]{20,128})\b/g, mask: "[REDACTED_SECRET:OPENAI_API_KEY]" },
      { regex: /\b(sk-ant-[a-zA-Z0-9_-]{20,128})\b/g, mask: "[REDACTED_SECRET:ANTHROPIC_API_KEY]" },
      { regex: /\b(AIza[0-9A-Za-z_-]{35})\b/g, mask: "[REDACTED_SECRET:GOOGLE_API_KEY]" },
      { regex: /\b(sk_live_[0-9a-zA-Z]{24,128})\b/g, mask: "[REDACTED_SECRET:STRIPE_SECRET_KEY]" },
      { regex: /\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b/g, mask: "[REDACTED_SECRET:SLACK_TOKEN]" },
      { regex: /\b(sbp_[a-zA-Z0-9]{40,128})\b/g, mask: "[REDACTED_SECRET:SUPABASE_TOKEN]" },
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

    // High-Entropy assignment detection (bounded quantifier for ReDoS safety)
    const assignMatch = currentLine.match(/\b(password|passwd|secret|api_?key|access_?token|auth_?token|client_?secret|bearer)\s*[:=]\s*(['"])([^'"]{8,256})\2/i);
    if (assignMatch) {
      const varName = assignMatch[1];
      const val = assignMatch[3];
      const dummies = ["dummy", "example", "changeme", "test", "fake", "placeholder", "your_api_key", "default"];
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
            remediation_advice: `Retrieve '${varName}' from environment variables (process.env) instead of hardcoding.`,
          });
          if (this.action === SanitizeAction.AUTOPATCH || this.action === SanitizeAction.REDACT) {
            const envName = varName.toUpperCase().replace(/[^A-Z0-9]/g, "_");
            const patch = (lang === "python" || lang.includes("py"))
              ? `os.environ.get("${envName}", "")`
              : `process.env.${envName} || ""`;
            currentLine = currentLine.replace(assignMatch[0], `${varName} = ${patch}`);
            modified = true;
          }
        }
      }
    }

    // 3. Command Injection & RCE (CWE-78, CWE-95)
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

    if (/\bchild_process\s*\.\s*(exec|execSync)\s*\(/.test(currentLine)) {
      violations.push({
        rule_id: "SL-RCE-004",
        title: "Insecure child_process shell invocation (exec/execSync)",
        cwe_id: "CWE-78",
        severity: Severity.HIGH,
        line_number: lineNumber,
        remediation_advice: "Use child_process.execFile() or spawn() with argument arrays.",
      });
      if (this.action === SanitizeAction.AUTOPATCH) {
        currentLine = currentLine.replace(/child_process\s*\.\s*execSync\s*\(/g, "child_process.execFileSync(");
        currentLine = currentLine.replace(/child_process\s*\.\s*exec\s*\(/g, "child_process.execFile(");
        modified = true;
      }
    }

    if (/\bos\s*\.\s*system\s*\(/.test(currentLine)) {
      violations.push({
        rule_id: "SL-RCE-001",
        title: "Insecure os.system Shell Command Invocation",
        cwe_id: "CWE-78",
        severity: Severity.HIGH,
        line_number: lineNumber,
        remediation_advice: "Use subprocess.run([...], check=True) instead of os.system().",
      });
    }

    if (/\b(eval|new\s+Function)\s*\(/.test(currentLine) && !currentLine.trim().startsWith("//")) {
      violations.push({
        rule_id: "SL-RCE-002",
        title: "Dangerous Dynamic Code Execution (eval / new Function)",
        cwe_id: "CWE-95",
        severity: Severity.CRITICAL,
        line_number: lineNumber,
        remediation_advice: "Refactor dynamic evaluation to JSON.parse or static lookup dispatch.",
      });
    }

    // 4. Prototype Pollution (CWE-1321)
    if (/(?:\[\s*['"`]__proto__['"`]\s*\]|\.\s*__proto__\b|constructor\s*(?:\.\s*prototype|\[\s*['"`]prototype['"`]\s*\]))/.test(currentLine)) {
      violations.push({
        rule_id: "SL-PROTO-001",
        title: "Prototype Pollution Vulnerability (__proto__ / constructor.prototype)",
        cwe_id: "CWE-1321",
        severity: Severity.HIGH,
        line_number: lineNumber,
        remediation_advice: "Prevent mutation of Object prototype. Use Object.create(null) or Map.",
      });
    }

    // 5. DOM XSS & Unsafe HTML Injection (CWE-79)
    if (/\bdangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:/i.test(currentLine)) {
      violations.push({
        rule_id: "SL-XSS-001",
        title: "Insecure React dangerouslySetInnerHTML without sanitization",
        cwe_id: "CWE-79",
        severity: Severity.HIGH,
        line_number: lineNumber,
        remediation_advice: "Sanitize HTML using DOMPurify.sanitize() before rendering.",
      });
    } else if (/(?:\.innerHTML|\.outerHTML|\bdocument\s*\.\s*write(?:ln)?)\s*=/i.test(currentLine)) {
      violations.push({
        rule_id: "SL-XSS-001",
        title: "Dangerous DOM Sink Assignment (innerHTML / document.write)",
        cwe_id: "CWE-79",
        severity: Severity.HIGH,
        line_number: lineNumber,
        remediation_advice: "Use textContent or DOMPurify.sanitize() to prevent XSS.",
      });
    }

    // 6. Directory Traversal & Zip Slip (CWE-22)
    if (/(?:(?:path\s*\.\s*join|fs\s*\.\s*read|open)\s*\([^)]*\.\.\/|\b\.\.\/\.\.\/)/.test(currentLine)) {
      violations.push({
        rule_id: "SL-PATH-001",
        title: "Relative Directory Traversal Pattern (../)",
        cwe_id: "CWE-22",
        severity: Severity.HIGH,
        line_number: lineNumber,
        remediation_advice: "Normalize and validate path boundaries using path.resolve and startsWith check.",
      });
    }

    if (/\b(?:extractall|extract)\s*\([^)]*\)/.test(currentLine) && !currentLine.includes("is_safe_path")) {
      if (/zipfile|tarfile|adm-zip|unzipper/i.test(currentLine)) {
        violations.push({
          rule_id: "SL-PATH-002",
          title: "Unconfined Archive Extraction (Zip Slip risk)",
          cwe_id: "CWE-22",
          severity: Severity.HIGH,
          line_number: lineNumber,
          remediation_advice: "Verify extracted member paths stay strictly within the target directory.",
        });
      }
    }

    // 7. Dynamic SQL Injection (CWE-89)
    if (/(?:execute|query|raw)\s*\(\s*`[^`]*(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)[^`]*\$\{/i.test(currentLine) ||
        /(?:execute|query)\s*\(\s*["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)[^"']*["']\s*\+/i.test(currentLine)) {
      violations.push({
        rule_id: "SL-INJ-001",
        title: "Dynamic SQL Query Interpolation / Concatenation",
        cwe_id: "CWE-89",
        severity: Severity.CRITICAL,
        line_number: lineNumber,
        remediation_advice: "Use parameterized queries or prepared statements ($1, ?).",
      });
    }

    // 8. Insecure Deserialization (CWE-502)
    if (/\byaml\s*\.\s*load\s*\([^)]*\)/.test(currentLine) && !currentLine.includes("SafeLoader") && !currentLine.includes("safe_load")) {
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

    if (/\bpickle\s*\.\s*loads\s*\(/.test(currentLine)) {
      violations.push({
        rule_id: "SL-DESER-001",
        title: "Arbitrary Code Execution via pickle.loads()",
        cwe_id: "CWE-502",
        severity: Severity.CRITICAL,
        line_number: lineNumber,
        remediation_advice: "Do not deserialize untrusted data with pickle. Use json or protobuf.",
      });
    }

    // 9. Prompt Injection Smuggling (CWE-1188) (bounded whitespace prevents ReDoS)
    const promptHijackRegex = /\b(?:ignore|disregard|forget)\s{1,8}(?:all\s{1,8})?(?:previous|prior|above)\s{1,8}instructions\b/i;
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

    // 10. Cryptography & Transport (CWE-295, CWE-330, CWE-328)
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

    if (/\bMath\s*\.\s*random\s*\(\s*\)/.test(currentLine)) {
      if (/(?:token|key|secret|password|passwd|salt|nonce|session|auth|otp|id|uuid)/i.test(currentLine)) {
        violations.push({
          rule_id: "SL-CRY-002",
          title: "Insecure PRNG Math.random() in Cryptographic / Token Context",
          cwe_id: "CWE-330",
          severity: Severity.HIGH,
          line_number: lineNumber,
          remediation_advice: "Use crypto.randomBytes() or crypto.getRandomValues() instead of Math.random().",
        });
      }
    }

    if (/(?:crypto\.createHash\s*\(\s*['"](?:md5|sha1)['"]\s*\)|hashlib\.(?:md5|sha1)\s*\()/i.test(currentLine)) {
      violations.push({
        rule_id: "SL-CRY-003",
        title: "Broken Cryptographic Hash Algorithm (MD5 / SHA-1)",
        cwe_id: "CWE-328",
        severity: Severity.HIGH,
        line_number: lineNumber,
        remediation_advice: "Upgrade to collision-resistant SHA-256 (crypto.createHash('sha256')).",
      });
      if (this.action === SanitizeAction.AUTOPATCH) {
        currentLine = currentLine.replace(/createHash\s*\(\s*['"](?:md5|sha1)['"]\s*\)/g, "createHash('sha256')");
        currentLine = currentLine.replace(/hashlib\.(?:md5|sha1)\s*\(/g, "hashlib.sha256(");
        modified = true;
      }
    }

    // 11. SSRF & Wildcard Binding (CWE-918, CWE-200)
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

    if (/(?:['"]0\.0\.0\.0['"]|\bhost\s*:\s*['"]0\.0\.0\.0['"])/.test(currentLine)) {
      violations.push({
        rule_id: "SL-NET-002",
        title: "Wildcard Socket Interface Binding (0.0.0.0)",
        cwe_id: "CWE-200",
        severity: Severity.MEDIUM,
        line_number: lineNumber,
        remediation_advice: "Bind to 127.0.0.1 for local service safety.",
      });
      if (this.action === SanitizeAction.AUTOPATCH) {
        currentLine = currentLine.replace(/0\.0\.0\.0/g, "127.0.0.1");
        modified = true;
      }
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
    if (typeof code !== "string") {
      code = code == null ? "" : String(code);
    }
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

    const sanitizedCode = sanitizedLines.join("\n");

    return {
      originalCode: code,
      sanitizedCode,
      isClean: allViolations.length === 0,
      wasModified: modified,
      violations: allViolations,
      toTokenCompact() {
        if (allViolations.length === 0 && !modified) {
          return { status: "CLEAN" };
        }
        const res = { status: modified ? "MODIFIED" : "VIOLATION" };
        if (modified) res.patch = sanitizedCode;
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

/**
 * Web Streams API TransformStream for real-time LLM token streams.
 * Compatible with Vercel AI SDK (streamText.pipeThrough), Next.js, Cloudflare Workers, and Browser.
 */
export class SaniLineTransformStream {
  constructor(options = {}) {
    const engine = new SaniLine(options);
    let buffer = "";
    let lineIndex = 1;

    if (typeof globalThis.TransformStream !== "undefined") {
      this.stream = new globalThis.TransformStream({
        transform(chunk, controller) {
          if (options.signal && options.signal.aborted) {
            controller.error(new Error("Stream aborted by client"));
            return;
          }
          const text = typeof chunk === "string" ? chunk : new TextDecoder().decode(chunk);
          buffer += text;
          const lines = buffer.split("\n");
          buffer = lines.pop() || "";
          for (const rawLine of lines) {
            const res = engine.sanitizeLine(rawLine, lineIndex++, options.language);
            controller.enqueue(res.sanitizedCode + "\n");
          }
        },
        flush(controller) {
          if (buffer.length > 0) {
            const res = engine.sanitizeLine(buffer, lineIndex++, options.language);
            controller.enqueue(res.sanitizedCode);
          }
        },
      });
      this.readable = this.stream.readable;
      this.writable = this.stream.writable;
    }
  }
}

/**
 * Node.js stream.Transform for piping streams in Node.js applications.
 */
export class SaniLineNodeTransform extends Transform {
  constructor(options = {}) {
    super({ objectMode: false, decodeStrings: false });
    this.engine = new SaniLine(options);
    this.options = options;
    this.buffer = "";
    this.lineIndex = 1;

    if (options.signal) {
      options.signal.addEventListener("abort", () => {
        this.destroy(new Error("Stream aborted by client"));
      }, { once: true });
    }
  }

  _transform(chunk, encoding, callback) {
    const text = typeof chunk === "string" ? chunk : chunk.toString("utf-8");
    this.buffer += text;
    const lines = this.buffer.split("\n");
    this.buffer = lines.pop() || "";
    for (const rawLine of lines) {
      const res = this.engine.sanitizeLine(rawLine, this.lineIndex++, this.options.language);
      this.push(res.sanitizedCode + "\n");
    }
    callback();
  }

  _flush(callback) {
    if (this.buffer.length > 0) {
      const res = this.engine.sanitizeLine(this.buffer, this.lineIndex++, this.options.language);
      this.push(res.sanitizedCode);
    }
    callback();
  }
}

/**
 * Generates an OASIS SARIF v2.1.0 JSON report from SaniLine audit findings.
 */
export function generateSarifReport(target, violations) {
  return {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "SaniLine",
            version: VERSION,
            informationUri: "https://github.com/alivirgo/SaniLine",
            rules: RULES_CATALOG.map(r => ({
              id: r.rule_id,
              name: r.title,
              shortDescription: { text: r.title },
              helpUri: "https://github.com/alivirgo/SaniLine#rules-matrix",
              properties: {
                category: r.category,
                standard: r.standard,
                severity: r.severity,
              },
            })),
          },
        },
        results: violations.map(v => ({
          ruleId: v.rule_id,
          level: v.severity === Severity.CRITICAL || v.severity === Severity.HIGH ? "error" : "warning",
          message: { text: `${v.title} - ${v.remediation_advice}` },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: v.file || target },
                region: { startLine: v.line_number || 1 },
              },
            },
          ],
        })),
      },
    ],
  };
}

export default SaniLine;
