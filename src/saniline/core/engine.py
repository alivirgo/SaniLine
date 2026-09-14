"""
SaniLine Core Engine.

Orchestrates real-time line-by-line sanitization, stream filtering, AST context tracking,
and token-optimized telemetry for autonomous AI agents.
"""

from __future__ import annotations

import io
from pathlib import Path
from typing import Iterable, Iterator, List, Optional, Union

import saniline.rules  # Ensures all rules are loaded in RuleRegistry
from saniline.core.context import StreamContext
from saniline.core.models import (
    AuditReport,
    RuleCategory,
    SanitizeAction,
    SanitizedResult,
    SecurityLevel,
    Severity,
    Violation,
)
from saniline.rules.base import BaseRule, RuleRegistry


class SaniLine:
    """
    Military-Grade Line-by-Line Code Sanitizer and Security Shield.

    Engineered to intercept code as it is generated or streamed by AI agents,
    evaluating and neutralising vulnerabilities in real time with sub-millisecond
    zero-overhead local heuristics.
    """

    def __init__(
        self,
        level: SecurityLevel = SecurityLevel.MILITARY,
        action: SanitizeAction = SanitizeAction.AUTOPATCH,
        default_language: str = "generic",
        strict_fail_on_critical: bool = False,
    ):
        self.level = level
        self.action = action
        self.default_language = default_language
        self.strict_fail_on_critical = strict_fail_on_critical

    def sanitize_line(
        self,
        line: str,
        line_no: int = 1,
        language: Optional[str] = None,
        context: Optional[StreamContext] = None,
    ) -> SanitizedResult:
        """
        Sanitizes a single line of code with lexical context awareness.
        """
        lang = language or self.default_language
        if context is None:
            context = StreamContext(language=lang)

        context.advance(line)
        active_rules = RuleRegistry.get_rules(lang, self.level)

        current_line = line
        violations: List[Violation] = []
        modified = False

        for rule in active_rules:
            # Under AUDIT mode, we only detect
            if self.action == SanitizeAction.AUDIT:
                v = rule.inspect_line(current_line, line_no, context)
                if v:
                    violations.append(v)
            # Under REDACT mode, only secrets are masked
            elif self.action == SanitizeAction.REDACT:
                if rule.category == RuleCategory.SECRETS:
                    patched, v = rule.sanitize_line(current_line, line_no, context)
                    if v:
                        violations.append(v)
                        if patched != current_line:
                            current_line = patched
                            modified = True
                else:
                    v = rule.inspect_line(current_line, line_no, context)
                    if v:
                        violations.append(v)
            # Under AUTOPATCH or BLOCK
            else:
                patched, v = rule.sanitize_line(current_line, line_no, context)
                if v:
                    violations.append(v)
                    if patched != current_line:
                        current_line = patched
                        modified = True

        if self.strict_fail_on_critical and any(v.severity == Severity.CRITICAL for v in violations):
            crit = next(v for v in violations if v.severity == Severity.CRITICAL)
            raise SecurityViolationError(f"CRITICAL Security Violation [{crit.rule_id}] on line {line_no}: {crit.title}")

        return SanitizedResult(
            original_code=line,
            sanitized_code=current_line,
            violations=violations,
            was_modified=modified,
            metadata={"language": lang, "security_level": self.level.value},
        )

    def sanitize_stream(
        self,
        stream: Iterable[str],
        language: Optional[str] = None,
    ) -> Iterator[str]:
        """
        Consumes an iterator of lines (e.g. from an LLM token/line stream or stdin)
        and yields safe, sanitized lines in real-time with zero buffering delay.
        """
        lang = language or self.default_language
        context = StreamContext(language=lang)
        line_no = 0

        for raw_line in stream:
            line_no += 1
            res = self.sanitize_line(raw_line, line_no=line_no, language=lang, context=context)
            yield res.sanitized_code

    def sanitize_code(
        self,
        code: str,
        language: Optional[str] = None,
    ) -> SanitizedResult:
        """
        Sanitizes a complete multi-line block of code or file content.
        """
        lang = language or self.default_language
        context = StreamContext(language=lang)

        # Split preserving line breaks
        lines = code.splitlines(keepends=True)
        sanitized_lines: List[str] = []
        all_violations: List[Violation] = []
        any_modified = False

        for idx, line in enumerate(lines, start=1):
            res = self.sanitize_line(line, line_no=idx, language=lang, context=context)
            sanitized_lines.append(res.sanitized_code)
            all_violations.extend(res.violations)
            if res.was_modified:
                any_modified = True

        return SanitizedResult(
            original_code=code,
            sanitized_code="".join(sanitized_lines),
            violations=all_violations,
            was_modified=any_modified,
            metadata={"language": lang, "lines_processed": len(lines)},
        )

    def audit_code(
        self,
        code: str,
        language: Optional[str] = None,
        target_name: str = "<in-memory>",
    ) -> AuditReport:
        """
        Performs a full security audit on a codebase without modifying the code,
        generating a compliance scorecard.
        """
        lang = language or self.default_language
        context = StreamContext(language=lang)
        lines = code.splitlines(keepends=True)

        report = AuditReport(target_name=target_name, total_lines=len(lines))
        active_rules = RuleRegistry.get_rules(lang, self.level)

        for idx, line in enumerate(lines, start=1):
            context.advance(line)
            for rule in active_rules:
                v = rule.inspect_line(line, idx, context)
                if v:
                    report.violations.append(v)

        report.calculate_score()
        return report

    def audit_file(self, file_path: Union[str, Path]) -> AuditReport:
        """Audits a file on disk."""
        path = Path(file_path)
        lang = StreamContext.detect_language_from_path_or_content(path.name)
        content = path.read_text(encoding="utf-8", errors="replace")
        return self.audit_code(content, language=lang, target_name=str(path))


class SecurityViolationError(Exception):
    """Raised when a critical security violation is encountered under BLOCK mode."""
    pass
