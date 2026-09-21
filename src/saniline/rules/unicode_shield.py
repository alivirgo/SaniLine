"""
Military-Grade Trojan Source and Invisible Unicode Exploit Shield.

Neutralizes bidirectional control characters and invisible payload smuggling
documented in CVE-2021-42574 and CWE-1036 (Homoglyph / Invisible Character Tampering).
"""

from __future__ import annotations

from saniline.core.context import StreamContext
from saniline.core.models import (
    RuleCategory,
    SecurityLevel,
    Severity,
    Violation,
)
from saniline.rules.base import BaseRule, RuleRegistry

# CVE-2021-42574 Trojan Source Bidi Override & Isolates
DANGEROUS_UNICODE_CHARS: dict[str, str] = {
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
}


@RuleRegistry.register
class TrojanSourceUnicodeRule(BaseRule):
    rule_id = "SL-UNI-001"
    title = "Trojan Source Bidi / Zero-Width Unicode Exploit (CVE-2021-42574)"
    description = (
        "Detected invisible or bidirectional Unicode control characters capable of altering "
        "human code perception vs compiler execution logic (Trojan Source CVE-2021-42574, CWE-1036)."
    )
    category = RuleCategory.TROJAN_SOURCE
    severity = Severity.CRITICAL
    cwe_id = "CWE-1036"
    stig_id = "APSC-DV-003000"
    nist_control = "SI-7"
    min_security_level = SecurityLevel.STANDARD
    supported_languages = ["*"]

    def inspect_line(
        self, line: str, line_no: int, context: StreamContext
    ) -> Violation | None:
        detected_chars: list[str] = []
        for ch in line:
            if ch in DANGEROUS_UNICODE_CHARS:
                detected_chars.append(DANGEROUS_UNICODE_CHARS[ch])

        if detected_chars:
            unique_chars = sorted(set(detected_chars))
            cleaned_line = "".join(ch for ch in line if ch not in DANGEROUS_UNICODE_CHARS)
            return self.create_violation(
                line_no=line_no,
                matched_snippet=", ".join(unique_chars),
                column=0,
                remediation_advice="Purge deceptive bidirectional and zero-width characters to prevent visual code spoofing.",
                suggested_patch=cleaned_line,
                custom_description=f"Deceptive Unicode control characters detected: {', '.join(unique_chars)}.",
            )
        return None
