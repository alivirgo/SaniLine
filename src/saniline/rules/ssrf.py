"""
Military-Grade Server-Side Request Forgery (SSRF) & Network Exfiltration Defense.

Blocks dangerous cloud instance metadata endpoints (169.254.169.254) and insecure
wildcard network listeners as mandated by CWE-918 and DoD STIG APSC-DV-002570.
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
class CloudMetadataSsrfRule(BaseRule):
    rule_id = "SL-NET-001"
    title = "Cloud Instance Metadata Service SSRF (169.254.169.254)"
    description = (
        "Accessing link-local metadata addresses (169.254.169.254 / metadata.google.internal) "
        "allows SSRF exfiltration of IAM instance credentials and tokens (CWE-918, DoD STIG APSC-DV-002570)."
    )
    category = RuleCategory.SSRF_NETWORK
    severity = Severity.CRITICAL
    cwe_id = "CWE-918"
    stig_id = "APSC-DV-002570"
    nist_control = "SC-7"
    min_security_level = SecurityLevel.STANDARD
    supported_languages = ["*"]

    METADATA_PATTERN = re.compile(
        r"""(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)"""
    )

    def inspect_line(
        self, line: str, line_no: int, context: StreamContext
    ) -> Optional[Violation]:
        if context.is_inside_comment_or_docstring():
            return None

        match = self.METADATA_PATTERN.search(line)
        if match:
            return self.create_violation(
                line_no=line_no,
                matched_snippet=match.group(0),
                column=match.start(),
                remediation_advice="Never query instance metadata endpoints directly from application code. Use verified IAM SDKs.",
                suggested_patch=None,
                custom_description="Hardcoded cloud instance metadata service endpoint detected. High SSRF risk.",
            )
        return None


@RuleRegistry.register
class WildcardBindRule(BaseRule):
    rule_id = "SL-NET-002"
    title = "Insecure Wildcard Socket Interface Binding (0.0.0.0)"
    description = (
        "Binding internal debug servers or services to '0.0.0.0' exposes them to external network interfaces (CWE-200)."
    )
    category = RuleCategory.SSRF_NETWORK
    severity = Severity.MEDIUM
    cwe_id = "CWE-200"
    stig_id = "APSC-DV-002580"
    nist_control = "SC-7"
    min_security_level = SecurityLevel.STRICT
    supported_languages = ["python", "javascript", "typescript"]

    PATTERN = re.compile(r"""\b(?:host|bind|address)\s*[:=]\s*['"]0\.0\.0\.0['"]""")

    def inspect_line(
        self, line: str, line_no: int, context: StreamContext
    ) -> Optional[Violation]:
        if context.is_inside_comment_or_docstring():
            return None

        match = self.PATTERN.search(line)
        if match:
            patched = line.replace("0.0.0.0", "127.0.0.1")
            return self.create_violation(
                line_no=line_no,
                matched_snippet=match.group(0),
                column=match.start(),
                remediation_advice="Bind explicitly to '127.0.0.1' (localhost) unless public ingress is strictly required and authenticated.",
                suggested_patch=patched,
                custom_description="Socket bound to public wildcard address '0.0.0.0'.",
            )
        return None
