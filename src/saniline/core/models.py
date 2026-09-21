"""
SaniLine Core Data Models.

Defines the fundamental security levels, violation structures, audit reports,
and remediation policies conforming to DoD STIG, NIST SP 800-218, and CWE standards.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class SaniLineError(Exception):
    """Base exception for all SaniLine domain errors."""


class SecurityViolationError(SaniLineError):
    """Raised when strict zero-tolerance enforcement encounters a critical violation."""


class SecurityLevel(str, Enum):
    """Military and industrial defense thresholds."""
    STANDARD = "standard"  # Critical exploits and obvious credentials
    STRICT = "strict"      # OWASP Top 10 + High entropy tokens + SSRF
    MILITARY = "military"  # Zero-Trust: DoD STIG, NIST SSDF, Trojan Source, Full Shannon Entropy


class SanitizeAction(str, Enum):
    """Operational action executed when a violation is identified."""
    AUDIT = "audit"          # Detection only, returns audit telemetry
    REDACT = "redact"        # Masks secrets with DoD-compliant tokens
    AUTOPATCH = "autopatch"  # Automatically rewrites dangerous idioms to secure patterns
    BLOCK = "block"          # Raises exception or halts processing on critical violations


class RuleCategory(str, Enum):
    """Taxonomy of security rule families."""
    SECRETS = "secrets_exposure"
    RCE_COMMAND_INJECTION = "rce_command_injection"
    DESERIALIZATION = "insecure_deserialization"
    PATH_TRAVERSAL = "path_traversal"
    SQL_INJECTION = "sql_injection"
    TROJAN_SOURCE = "trojan_source_unicode"
    PROMPT_INJECTION = "prompt_injection_smuggling"
    CRYPTO_FAILURE = "cryptographic_failure"
    SSRF_NETWORK = "ssrf_network_exfiltration"
    SANDBOX_ESCAPE = "sandbox_escape"
    PROTOTYPE_POLLUTION = "prototype_pollution"
    XSS = "cross_site_scripting"


class Severity(str, Enum):
    """Severity ratings mapped directly to CVSS v3.1 base scoring equivalents."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def score_weight(self) -> int:
        return {
            Severity.LOW: 1,
            Severity.MEDIUM: 4,
            Severity.HIGH: 8,
            Severity.CRITICAL: 15,
        }[self]


@dataclass
class Violation:
    """Represents a specific cybersecurity weakness identified on a line or hunk."""
    rule_id: str
    title: str
    description: str
    severity: Severity
    category: RuleCategory
    line_number: int
    column: int = 0
    cwe_id: str | None = None
    stig_id: str | None = None
    nist_control: str | None = None
    matched_snippet: str = ""
    remediation_advice: str = ""
    suggested_patch: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "category": self.category.value,
            "line_number": self.line_number,
            "column": self.column,
            "cwe_id": self.cwe_id,
            "stig_id": self.stig_id,
            "nist_control": self.nist_control,
            "matched_snippet": self.matched_snippet,
            "remediation_advice": self.remediation_advice,
            "suggested_patch": self.suggested_patch,
        }


@dataclass
class SanitizedResult:
    """Outcome of processing a line or code block through SaniLine."""
    original_code: str
    sanitized_code: str
    violations: list[Violation] = field(default_factory=list)
    was_modified: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_clean(self) -> bool:
        return len(self.violations) == 0

    @property
    def has_critical(self) -> bool:
        return any(v.severity == Severity.CRITICAL for v in self.violations)

    def to_dict(self) -> dict[str, Any]:
        return {
            "original_code": self.original_code,
            "sanitized_code": self.sanitized_code,
            "was_modified": self.was_modified,
            "is_clean": self.is_clean,
            "violations_count": len(self.violations),
            "violations": [v.to_dict() for v in self.violations],
            "metadata": self.metadata,
        }

    def to_token_compact(self) -> dict[str, Any]:
        """
        Hyper-compact representation engineered specifically to minimize LLM token consumption
        when returned to autonomous AI agents (saves up to 90% context tokens).
        """
        if self.is_clean and not self.was_modified:
            return {"status": "CLEAN"}

        compact: dict[str, Any] = {
            "status": "MODIFIED" if self.was_modified else "VIOLATION",
        }
        if self.was_modified:
            compact["patch"] = self.sanitized_code

        compact["issues"] = [
            {
                "line": v.line_number,
                "rule": v.rule_id,
                "cwe": v.cwe_id,
                "fix": v.remediation_advice,
            }
            for v in self.violations
        ]
        return compact


@dataclass
class AuditReport:
    """Comprehensive compliance and security evaluation report."""
    target_name: str
    total_lines: int
    violations: list[Violation] = field(default_factory=list)
    security_score: float = 100.0
    passed_military_spec: bool = True

    def calculate_score(self) -> float:
        if self.total_lines <= 0:
            return 100.0
        penalty = sum(v.severity.score_weight for v in self.violations)
        density_factor = max(1.0, self.total_lines / 20.0)
        deduction = (penalty * 10.0) / density_factor
        score = max(0.0, min(100.0, 100.0 - deduction))
        self.security_score = round(score, 1)
        self.passed_military_spec = (
            self.security_score >= 90.0
            and not any(v.severity in (Severity.CRITICAL, Severity.HIGH) for v in self.violations)
        )
        return self.security_score

    def get_counts_by_severity(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for v in self.violations:
            counts[v.severity.value] += 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        self.calculate_score()
        return {
            "target_name": self.target_name,
            "total_lines": self.total_lines,
            "security_score": self.security_score,
            "passed_military_spec": self.passed_military_spec,
            "severity_counts": self.get_counts_by_severity(),
            "violations_count": len(self.violations),
            "violations": [v.to_dict() for v in self.violations],
        }

    def to_token_compact(self) -> dict[str, Any]:
        """Token-minified audit summary for AI agents."""
        self.calculate_score()
        if self.passed_military_spec and not self.violations:
            return {"score": self.security_score, "status": "PASS_MILITARY_SPEC"}

        return {
            "score": self.security_score,
            "pass": self.passed_military_spec,
            "counts": {k: v for k, v in self.get_counts_by_severity().items() if v > 0},
            "findings": [
                f"L{v.line_number} [{v.rule_id} {v.cwe_id}]: {v.remediation_advice}"
                for v in self.violations[:10]  # Cap at top 10 to protect token budget
            ],
        }
