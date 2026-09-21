"""
Prototype Pollution Vulnerability Defense.

Neutralizes dynamic __proto__ and constructor.prototype property tampering in JavaScript and TypeScript
sources as defined in CWE-1321.
"""

from __future__ import annotations

import re

from saniline.core.context import StreamContext
from saniline.core.models import (
    RuleCategory,
    SecurityLevel,
    Severity,
    Violation,
)
from saniline.rules.base import BaseRule, RuleRegistry


@RuleRegistry.register
class PrototypePollutionRule(BaseRule):
    rule_id = "SL-PROTO-001"
    title = "Prototype Pollution Vulnerability"
    description = (
        "Detected direct modification or assignment to __proto__ or constructor.prototype. "
        "Prototype pollution allows attackers to alter application logic or escalate privileges (CWE-1321)."
    )
    category = RuleCategory.PROTOTYPE_POLLUTION
    severity = Severity.HIGH
    cwe_id = "CWE-1321"
    stig_id = "APSC-DV-002590"
    nist_control = "SI-10"
    min_security_level = SecurityLevel.STRICT
    supported_languages = ["javascript", "typescript", "generic", "*"]

    PATTERN = re.compile(
        r"""(?x)
        (?:
            \[\s*['"`]__proto__['"`]\s*\]
            |
            \.\s*__proto__\b
            |
            \bconstructor\s*(?:\.\s*prototype|\[\s*['"`]prototype['"`]\s*\])
        )
        """
    )

    def inspect_line(
        self, line: str, line_no: int, context: StreamContext
    ) -> Violation | None:
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("/*"):
            return None

        match = self.PATTERN.search(line)
        if match:
            return self.create_violation(
                line_no=line_no,
                matched_snippet=match.group(0),
                column=match.start(),
                remediation_advice="Prevent mutation of Object prototype. Use Object.create(null) or Map.",
                suggested_patch=None,
            )
        return None

    def sanitize_line(
        self, line: str, line_no: int, context: StreamContext
    ) -> tuple[str, Violation | None]:
        violation = self.inspect_line(line, line_no, context)
        # We flag without arbitrary replacement because safe refactor requires Object.create(null)
        return line, violation
