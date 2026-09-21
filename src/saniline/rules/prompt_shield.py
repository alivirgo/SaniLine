"""
Military-Grade AI Prompt Injection and Adversarial Smuggling Defense.

Detects jailbreak directives, system role impersonation, and prompt hijack sequences
smuggled inside code comments, docstrings, or string literals targeting autonomous AI agents.
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
class PromptInjectionSmugglingRule(BaseRule):
    rule_id = "SL-PRM-001"
    title = "Smuggled AI Prompt Injection / Role Hijacking in Code"
    description = (
        "Detected prompt injection directives embedded inside code comments or strings "
        "designed to hijack autonomous AI coding agents or exfiltrate host environment state."
    )
    category = RuleCategory.PROMPT_INJECTION
    severity = Severity.HIGH
    cwe_id = "CWE-1188"
    stig_id = "APSC-DV-003100"
    nist_control = "SI-10"
    min_security_level = SecurityLevel.STRICT
    supported_languages = ["*"]

    # ReDoS-safe bounded patterns preventing catastrophic backtracking
    HIJACK_PATTERNS = [
        re.compile(r"""(?i)\b(?:ignore|disregard|forget)\s{1,8}(?:all\s{1,8})?(?:previous|prior|above)\s{1,8}instructions\b"""),
        re.compile(r"""(?i)(?:<\|im_start\|>|<\|im_end\|>|\[INST\]|\[/INST\]|<system>|<assistant>)"""),
        re.compile(r"""(?i)\b(?:system\s{0,4}prompt|you\s{1,4}are\s{1,4}now\s{1,4}in\s{1,4}developer\s{1,4}mode|jailbreak|DAN\s{1,4}mode)\b"""),
        re.compile(r"""(?i)(?:exfiltrate|send|upload)\s{1,8}(?:all\s{1,8})?(?:secrets|tokens|credentials|env\s{1,4}vars)\s{1,8}to\b"""),
    ]

    def inspect_line(
        self, line: str, line_no: int, context: StreamContext
    ) -> Violation | None:
        stripped = line.strip()
        if not stripped:
            return None

        for pattern in self.HIJACK_PATTERNS:
            match = pattern.search(line)
            if match:
                neutralized = pattern.sub("[SANILINE_DEFUSED_PROMPT_INJECTION]", line)
                return self.create_violation(
                    line_no=line_no,
                    matched_snippet=match.group(0),
                    column=match.start(),
                    remediation_advice="Remove or sanitize adversarial prompt injection sequences targeting AI reasoning engines.",
                    suggested_patch=neutralized,
                    custom_description="Adversarial prompt injection pattern detected within code structure.",
                )
        return None
