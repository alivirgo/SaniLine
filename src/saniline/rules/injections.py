"""
Military-Grade SQL and Database Injection Defense.

Identifies dynamic query assembly, unparameterized statements, and formatted strings
in database execution contexts in compliance with CWE-89, CWE-943, and DoD STIG APSC-DV-002510.
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
class SqlStringFormattingInjectionRule(BaseRule):
    rule_id = "SL-INJ-001"
    title = "SQL Injection via Dynamic String Formatting"
    description = (
        "Constructing SQL statements via f-strings, '%', or '+' string concatenation "
        "enables SQL injection and database compromise (CWE-89, DoD STIG APSC-DV-002510)."
    )
    category = RuleCategory.SQL_INJECTION
    severity = Severity.CRITICAL
    cwe_id = "CWE-89"
    stig_id = "APSC-DV-002510"
    nist_control = "SI-10"
    min_security_level = SecurityLevel.STANDARD
    supported_languages = ["python", "javascript", "typescript"]

    # Match execute/query calls with f-strings or concatenation containing SQL keywords
    EXEC_PATTERN = re.compile(
        r"""\b(?:execute|raw|execute_query|query)\s*\(\s*f["'](?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\b""",
        re.IGNORECASE
    )

    CONCAT_PATTERN = re.compile(
        r"""\b(?:execute|query)\s*\(\s*["'](?:SELECT|INSERT|UPDATE|DELETE)\b[^"']*["']\s*\+""",
        re.IGNORECASE
    )

    FORMAT_PATTERN = re.compile(
        r"""\b(?:execute|query)\s*\(\s*["'](?:SELECT|INSERT|UPDATE|DELETE)\b[^"']*["']\s*%\s*""",
        re.IGNORECASE
    )

    def inspect_line(
        self, line: str, line_no: int, context: StreamContext
    ) -> Optional[Violation]:
        if context.is_inside_comment_or_docstring():
            return None

        # Check f-string pattern
        if self.EXEC_PATTERN.search(line):
            return self.create_violation(
                line_no=line_no,
                matched_snippet="execute(f'SQL ...')",
                column=line.find("execute"),
                remediation_advice="Use parameterized query placeholders (?, %s, or :param) and pass query arguments as a separate tuple.",
                suggested_patch=None,
                custom_description="SQL execution with dynamic f-string detected. Direct risk of arbitrary SQL injection.",
            )

        # Check concatenation pattern
        if self.CONCAT_PATTERN.search(line):
            return self.create_violation(
                line_no=line_no,
                matched_snippet="execute('SQL' + var)",
                column=line.find("execute"),
                remediation_advice="Never concatenate untrusted variables into query strings. Use prepared statements.",
                suggested_patch=None,
                custom_description="SQL execution with string concatenation '+' detected.",
            )

        # Check % formatting pattern
        if self.FORMAT_PATTERN.search(line):
            return self.create_violation(
                line_no=line_no,
                matched_snippet="execute('SQL %s' % var)",
                column=line.find("execute"),
                remediation_advice="Pass parameters to execute() as a separate tuple instead of string formatting with %.",
                suggested_patch=None,
                custom_description="SQL query assembled using Python '%' string formatting.",
            )

        return None
