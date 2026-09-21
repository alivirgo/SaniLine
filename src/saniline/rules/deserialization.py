"""
Military-Grade Insecure Deserialization Defense.

Identifies and mitigates unsafe object deserialization flaws in Python and related runtimes
as mandated by CWE-502, OWASP A08:2021, and DoD STIG APSC-DV-002620.
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
class UnsafeYamlLoadRule(BaseRule):
    rule_id = "SL-DESER-001"
    title = "Arbitrary Code Execution via Unsafe yaml.load()"
    description = (
        "Using yaml.load() without SafeLoader allows remote code execution via arbitrary object instantiation (CWE-502)."
    )
    category = RuleCategory.DESERIALIZATION
    severity = Severity.CRITICAL
    cwe_id = "CWE-502"
    stig_id = "APSC-DV-002620"
    nist_control = "SI-10"
    min_security_level = SecurityLevel.STANDARD
    supported_languages = ["python", "javascript", "typescript", "generic", "*"]

    # Match yaml.load(...) that does NOT specify SafeLoader
    PATTERN = re.compile(r"""\byaml\s*\.\s*load\s*\(([^)]{0,256})\)""")

    def inspect_line(
        self, line: str, line_no: int, context: StreamContext
    ) -> Violation | None:
        if context.is_inside_comment_or_docstring():
            return None

        match = self.PATTERN.search(line)
        if match:
            args = match.group(1)
            # If SafeLoader, safe_load, or CSafeLoader is explicitly used, it's safe
            if "SafeLoader" in args or "safe_load" in line:
                return None

            # Generate auto-patch to yaml.safe_load()
            clean_args = re.sub(r",\s*Loader\s*=\s*[a-zA-Z0-9_\.]+", "", args).strip()
            patched = line[:match.start()] + f"yaml.safe_load({clean_args})" + line[match.end():]

            return self.create_violation(
                line_no=line_no,
                matched_snippet=match.group(0),
                column=match.start(),
                remediation_advice="Replace yaml.load() with yaml.safe_load() to disallow arbitrary object creation.",
                suggested_patch=patched,
            )
        return None


@RuleRegistry.register
class UnsafePickleRule(BaseRule):
    rule_id = "SL-DESER-002"
    title = "Insecure Object Deserialization via pickle"
    description = (
        "Deserializing untrusted pickle streams allows instant arbitrary code execution via __reduce__ payloads (CWE-502)."
    )
    category = RuleCategory.DESERIALIZATION
    severity = Severity.CRITICAL
    cwe_id = "CWE-502"
    stig_id = "APSC-DV-002620"
    nist_control = "SI-10"
    min_security_level = SecurityLevel.STANDARD
    supported_languages = ["python"]

    PATTERN = re.compile(r"""\b(?:pickle|_pickle)\s*\.\s*(?:loads?)\s*\((.{1,512}?)\)""")

    def inspect_line(
        self, line: str, line_no: int, context: StreamContext
    ) -> Violation | None:
        if context.is_inside_comment_or_docstring():
            return None

        match = self.PATTERN.search(line)
        if match:
            return self.create_violation(
                line_no=line_no,
                matched_snippet=match.group(0),
                column=match.start(),
                remediation_advice="Use standard non-executable serializers like json.loads() or protobuf with cryptographic integrity checks.",
                suggested_patch=None,
                custom_description=f"Pickle deserialization detected: '{match.group(0)}'. Untrusted input here grants full system takeover.",
            )
        return None
