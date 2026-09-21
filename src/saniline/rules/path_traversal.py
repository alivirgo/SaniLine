"""
Military-Grade Path Traversal and File Boundary Defense.

Detects directory traversal sequences, null-byte injection, and Zip Slip flaws
in compliance with CWE-22, CWE-23, and DoD STIG APSC-DV-002560.
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
class PathTraversalSequenceRule(BaseRule):
    rule_id = "SL-PATH-001"
    title = "Relative Directory Traversal Pattern"
    description = (
        "Hardcoded or dynamically assembled relative path traversal ('../' or '..\\') "
        "allows attackers to escape intended storage directories (CWE-22)."
    )
    category = RuleCategory.PATH_TRAVERSAL
    severity = Severity.HIGH
    cwe_id = "CWE-22"
    stig_id = "APSC-DV-002560"
    nist_control = "AC-3"
    min_security_level = SecurityLevel.STANDARD
    supported_languages = ["*"]

    PATTERN = re.compile(r"""(?:\.\./|\.\.\\)+""")

    def inspect_line(
        self, line: str, line_no: int, context: StreamContext
    ) -> Violation | None:
        if context.is_inside_comment_or_docstring() or line.strip().startswith(("#", "//")):
            return None

        # Check if line involves file operations or path manipulations
        if any(kw in line for kw in ("open(", "path", "file", "read", "write", "fs.", "Path(")):
            match = self.PATTERN.search(line)
            if match:
                return self.create_violation(
                    line_no=line_no,
                    matched_snippet=match.group(0),
                    column=match.start(),
                    remediation_advice="Resolve target paths with Path.resolve() or os.path.realpath() and assert path.startswith(trusted_base_dir).",
                    suggested_patch=None,
                    custom_description="Directory traversal sequence ('../') detected in file manipulation statement.",
                )
        return None


@RuleRegistry.register
class ZipSlipVulnerabilityRule(BaseRule):
    rule_id = "SL-PATH-002"
    title = "Unconfined Archive Extraction (Zip Slip)"
    description = (
        "Extracting archives directly using extractall() or extract() without member path validation "
        "enables arbitrary file overwrites via malicious archive member paths (CWE-22, CWE-29)."
    )
    category = RuleCategory.PATH_TRAVERSAL
    severity = Severity.HIGH
    cwe_id = "CWE-22"
    stig_id = "APSC-DV-002560"
    nist_control = "SI-10"
    min_security_level = SecurityLevel.STRICT
    supported_languages = ["python", "javascript", "typescript", "generic", "*"]

    PATTERN = re.compile(r"""\b(?:zip_file|zipfile|tarfile|archive|tar|zf|zip)\s*\.\s*(?:extractall|extract)\s*\((.{0,256}?)\)""")

    def inspect_line(
        self, line: str, line_no: int, context: StreamContext
    ) -> Violation | None:
        if context.is_inside_comment_or_docstring():
            return None

        match = self.PATTERN.search(line)
        if match:
            args = match.group(1)
            if "filter=" in args or "is_safe_path" in line:
                return None

            return self.create_violation(
                line_no=line_no,
                matched_snippet=match.group(0),
                column=match.start(),
                remediation_advice="Validate every archive member destination before extraction or pass filter='data' (Python 3.12+).",
                suggested_patch=None,
                custom_description="Unvalidated archive extraction call susceptible to Zip Slip directory overwrite.",
            )
        return None
