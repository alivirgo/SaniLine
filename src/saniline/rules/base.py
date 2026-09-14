"""
SaniLine Rule Engine Foundation.

Provides the abstract base rule specification and extensible registry for
military-grade security checks, matching, and deterministic auto-patching.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar, Dict, List, Optional, Tuple, Type

from saniline.core.context import StreamContext
from saniline.core.models import (
    RuleCategory,
    SecurityLevel,
    Severity,
    Violation,
)


class BaseRule(ABC):
    """Abstract base class for all SaniLine defense rules."""

    rule_id: ClassVar[str] = "SL-BASE-000"
    title: ClassVar[str] = "Base Security Rule"
    description: ClassVar[str] = "Base security description."
    category: ClassVar[RuleCategory] = RuleCategory.RCE_COMMAND_INJECTION
    severity: ClassVar[Severity] = Severity.HIGH
    cwe_id: ClassVar[str] = "CWE-0"
    stig_id: ClassVar[str] = "APSC-DV-000000"
    nist_control: ClassVar[str] = "SI-10"
    min_security_level: ClassVar[SecurityLevel] = SecurityLevel.STANDARD
    supported_languages: ClassVar[List[str]] = ["*"]

    @classmethod
    def applies_to(cls, language: str, level: SecurityLevel) -> bool:
        """Determines if this rule is enabled for the language and security level."""
        # Level hierarchy: STANDARD <= STRICT <= MILITARY
        level_order = {
            SecurityLevel.STANDARD: 1,
            SecurityLevel.STRICT: 2,
            SecurityLevel.MILITARY: 3,
        }
        if level_order[level] < level_order[cls.min_security_level]:
            return False

        if "*" in cls.supported_languages or language.lower() in ("*", "all", "generic"):
            return True
        return language.lower() in [l.lower() for l in cls.supported_languages]


    @abstractmethod
    def inspect_line(
        self, line: str, line_no: int, context: StreamContext
    ) -> Optional[Violation]:
        """Inspects a line for vulnerabilities. Returns a Violation if identified."""
        pass

    def sanitize_line(
        self, line: str, line_no: int, context: StreamContext
    ) -> Tuple[str, Optional[Violation]]:
        """Inspects and optionally auto-patches the line to neutralize the threat."""
        violation = self.inspect_line(line, line_no, context)
        if violation and violation.suggested_patch is not None:
            return violation.suggested_patch, violation
        return line, violation

    protected_violation_helper = None

    def create_violation(
        self,
        line_no: int,
        matched_snippet: str,
        column: int = 0,
        remediation_advice: str = "",
        suggested_patch: Optional[str] = None,
        custom_description: Optional[str] = None,
    ) -> Violation:
        """Helper to instantiate a standardized Violation object."""
        return Violation(
            rule_id=self.rule_id,
            title=self.title,
            description=custom_description or self.description,
            severity=self.severity,
            category=self.category,
            line_number=line_no,
            column=column,
            cwe_id=self.cwe_id,
            stig_id=self.stig_id,
            nist_control=self.nist_control,
            matched_snippet=matched_snippet,
            remediation_advice=remediation_advice or self.description,
            suggested_patch=suggested_patch,
        )


class RuleRegistry:
    """Registry maintaining active defense rules."""

    _rules: Dict[str, BaseRule] = {}

    @classmethod
    def register(cls, rule_cls: Type[BaseRule]) -> Type[BaseRule]:
        instance = rule_cls()
        cls._rules[rule_cls.rule_id] = instance
        return rule_cls

    @classmethod
    def get_rules(cls, language: str, level: SecurityLevel) -> List[BaseRule]:
        return [
            rule for rule in cls._rules.values()
            if rule.applies_to(language, level)
        ]

    @classmethod
    def all_rules(cls) -> List[BaseRule]:
        return list(cls._rules.values())

    @classmethod
    def get_rule_by_id(cls, rule_id: str) -> Optional[BaseRule]:
        return cls._rules.get(rule_id)

    @classmethod
    def clear(cls) -> None:
        cls._rules.clear()
