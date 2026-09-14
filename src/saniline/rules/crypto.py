"""
Military-Grade Cryptographic Robustness and Transport Security Defense.

Detects broken cryptographic ciphers, insecure pseudorandom number generators (PRNG)
used in security contexts, and disabled transport layer security (verify=False)
in compliance with CWE-327, CWE-328, CWE-330, and DoD STIG APSC-DV-002010.
"""

from __future__ import annotations

import re
from typing import Optional

from saniline.core.context import StreamContext
from saniline.core.models import (
    RuleCategory,
    SecurityLevel,
    Severity,
    Violation,
)
from saniline.rules.base import BaseRule, RuleRegistry


@RuleRegistry.register
class DisabledTlsVerificationRule(BaseRule):
    rule_id = "SL-CRY-001"
    title = "Disabled TLS Certificate Verification (verify=False)"
    description = (
        "Disabling SSL/TLS certificate verification exposes network communication to "
        "Man-in-the-Middle (MitM) interception and credential theft (CWE-295, DoD STIG APSC-DV-002010)."
    )
    category = RuleCategory.CRYPTO_FAILURE
    severity = Severity.CRITICAL
    cwe_id = "CWE-295"
    stig_id = "APSC-DV-002010"
    nist_control = "SC-8"
    min_security_level = SecurityLevel.STANDARD
    supported_languages = ["python", "javascript", "typescript"]

    PATTERN = re.compile(r"""\bverify\s*=\s*(?:False|0)\b""")
    JS_REJECT_UNAUTHORIZED = re.compile(r"""\brejectUnauthorized\s*:\s*false\b""")

    def inspect_line(
        self, line: str, line_no: int, context: StreamContext
    ) -> Optional[Violation]:
        if context.is_inside_comment_or_docstring():
            return None

        # Check Python requests/httpx verify=False
        match = self.PATTERN.search(line)
        if match:
            patched = self.PATTERN.sub("verify=True", line)
            return self.create_violation(
                line_no=line_no,
                matched_snippet=match.group(0),
                column=match.start(),
                remediation_advice="Set verify=True to enforce strict TLS certificate validation.",
                suggested_patch=patched,
                custom_description="TLS certificate validation explicitly disabled via verify=False.",
            )

        # Check Node.js rejectUnauthorized: false
        js_match = self.JS_REJECT_UNAUTHORIZED.search(line)
        if js_match:
            patched = self.JS_REJECT_UNAUTHORIZED.sub("rejectUnauthorized: true", line)
            return self.create_violation(
                line_no=line_no,
                matched_snippet=js_match.group(0),
                column=js_match.start(),
                remediation_advice="Set rejectUnauthorized: true to enforce valid SSL/TLS certificates.",
                suggested_patch=patched,
                custom_description="Node.js TLS certificate rejection explicitly disabled.",
            )

        return None


@RuleRegistry.register
class InsecurePrngForSecurityRule(BaseRule):
    rule_id = "SL-CRY-002"
    title = "Insecure PRNG in Token/Security Context"
    description = (
        "The standard 'random' module is pseudo-random and predictable. Cryptographic secrets, "
        "session tokens, and nonces require the 'secrets' module (CWE-330, CWE-338)."
    )
    category = RuleCategory.CRYPTO_FAILURE
    severity = Severity.HIGH
    cwe_id = "CWE-330"
    stig_id = "APSC-DV-002030"
    nist_control = "SC-13"
    min_security_level = SecurityLevel.STRICT
    supported_languages = ["python"]

    # Detect random.choice or random.randint when assigning to token, secret, salt, password, or key
    PATTERN = re.compile(
        r"""\b(?:token|secret|salt|key|nonce|auth|otp|password)\w*\s*=\s*.*?\brandom\s*\.\s*(?:choice|choices|randint|randrange|getrandbits)\b""",
        re.IGNORECASE
    )

    def inspect_line(
        self, line: str, line_no: int, context: StreamContext
    ) -> Optional[Violation]:
        if context.is_inside_comment_or_docstring():
            return None

        match = self.PATTERN.search(line)
        if match:
            # Auto-patch: replace random. with secrets.
            patched = line.replace("random.", "secrets.")
            return self.create_violation(
                line_no=line_no,
                matched_snippet=match.group(0),
                column=match.start(),
                remediation_advice="Use Python's CSPRNG 'secrets' module instead of 'random' for security-sensitive tokens.",
                suggested_patch=patched,
                custom_description="Predictable PRNG 'random' used for sensitive credential/token generation.",
            )
        return None


@RuleRegistry.register
class WeakHashAlgorithmRule(BaseRule):
    rule_id = "SL-CRY-003"
    title = "Cryptographically Broken Hash Algorithm (MD5 / SHA-1)"
    description = (
        "MD5 and SHA-1 suffer from practical collision vulnerabilities and are prohibited "
        "for secure signatures or authentication (CWE-328, DoD STIG APSC-DV-002010)."
    )
    category = RuleCategory.CRYPTO_FAILURE
    severity = Severity.HIGH
    cwe_id = "CWE-328"
    stig_id = "APSC-DV-002010"
    nist_control = "SC-13"
    min_security_level = SecurityLevel.STRICT
    supported_languages = ["python", "javascript", "typescript"]

    PY_PATTERN = re.compile(r"""\bhashlib\s*\.\s*(md5|sha1)\s*\(""")
    JS_PATTERN = re.compile(r"""\bcrypto\s*\.\s*createHash\s*\(\s*['"](md5|sha1)['"]\s*\)""", re.IGNORECASE)

    def inspect_line(
        self, line: str, line_no: int, context: StreamContext
    ) -> Optional[Violation]:
        if context.is_inside_comment_or_docstring():
            return None

        py_match = self.PY_PATTERN.search(line)
        if py_match:
            algo = py_match.group(1).upper()
            patched = line.replace(f"hashlib.{py_match.group(1)}(", "hashlib.sha256(")
            return self.create_violation(
                line_no=line_no,
                matched_snippet=py_match.group(0),
                column=py_match.start(),
                remediation_advice=f"Upgrade broken hash {algo} to SHA-256 (hashlib.sha256) or SHA-3.",
                suggested_patch=patched,
                custom_description=f"Broken cryptographic hash algorithm '{algo}' detected.",
            )

        js_match = self.JS_PATTERN.search(line)
        if js_match:
            algo = js_match.group(1).upper()
            patched = line[:js_match.start(1)] + "sha256" + line[js_match.end(1):]
            return self.create_violation(
                line_no=line_no,
                matched_snippet=js_match.group(0),
                column=js_match.start(),
                remediation_advice="Upgrade broken hash algorithm to 'sha256'.",
                suggested_patch=patched,
                custom_description=f"Broken cryptographic hash algorithm '{algo}' detected.",
            )

        return None
