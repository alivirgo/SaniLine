"""
Cross-Site Scripting (XSS) & Insecure HTML Injection Defense.

Identifies unescaped React dangerouslySetInnerHTML assignments, innerHTML DOM sinks,
and document.write calls as mandated by CWE-79 and DoD STIG APSC-DV-002530.
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
class DomXssRule(BaseRule):
    rule_id = "SL-XSS-001"
    title = "DOM XSS / Insecure HTML Injection"
    description = (
        "Detected assignment to dangerous DOM sink (innerHTML, outerHTML, document.write) "
        "or React dangerouslySetInnerHTML without sanitization (CWE-79)."
    )
    category = RuleCategory.XSS
    severity = Severity.HIGH
    cwe_id = "CWE-79"
    stig_id = "APSC-DV-002530"
    nist_control = "SI-10"
    min_security_level = SecurityLevel.STRICT
    supported_languages = ["javascript", "typescript", "html", "generic", "*"]

    REACT_DANGEROUS_PATTERN = re.compile(
        r"""dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:""", re.IGNORECASE
    )
    DOM_SINK_PATTERN = re.compile(
        r"""(?:\.innerHTML|\.outerHTML|\bdocument\s*\.\s*write(?:ln)?)\s*=""", re.IGNORECASE
    )

    def inspect_line(
        self, line: str, line_no: int, context: StreamContext
    ) -> Violation | None:
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("/*"):
            return None

        match_react = self.REACT_DANGEROUS_PATTERN.search(line)
        if match_react:
            return self.create_violation(
                line_no=line_no,
                matched_snippet=match_react.group(0),
                column=match_react.start(),
                remediation_advice="Sanitize HTML using DOMPurify.sanitize() before rendering.",
                custom_description="Insecure React dangerouslySetInnerHTML without sanitization.",
            )

        match_dom = self.DOM_SINK_PATTERN.search(line)
        if match_dom:
            return self.create_violation(
                line_no=line_no,
                matched_snippet=match_dom.group(0),
                column=match_dom.start(),
                remediation_advice="Use textContent or DOMPurify.sanitize() to prevent XSS.",
                custom_description="Dangerous DOM Sink Assignment (innerHTML / document.write).",
            )

        return None

    def sanitize_line(
        self, line: str, line_no: int, context: StreamContext
    ) -> tuple[str, Violation | None]:
        violation = self.inspect_line(line, line_no, context)
        return line, violation
