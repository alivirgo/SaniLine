"""
Military-Grade AI Prompt Injection and Adversarial Smuggling Defense.

Detects jailbreak directives, system role impersonation, and prompt hijack sequences
smuggled inside code comments, docstrings, or string literals targeting autonomous AI agents.
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

    # Patterns commonly used to hijack LLMs from within source files
    HIJACK_PATTERNS = [
        re.compile(r"""(?i)\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above)\s+instructions\b"""),
        re.compile(r"""(?i)(?:<\|im_start\|>|<\|im_end\|>|\[INST\]|\[/INST\]|<system>|<assistant>)"""),
        re.compile(r"""(?i)\b(?:system\s*prompt|you\s+are\s+now\s+in\s+developer\s+mode|jailbreak|DAN\s+mode)\b"""),
        re.compile(r"""(?i)(?:exfiltrate|send|upload)\s+(?:all\s+)?(?:secrets|tokens|credentials|env\s+vars)\s+to\b"""),
    ]

    def inspect_line(
        self, line: str, line_no: int, context: StreamContext
    ) -> Optional[Violation]:
        stripped = line.strip()
        if not stripped:
            return None

        for pattern in self.HIJACK_PATTERNS:
            match = pattern.search(line)
            if match:
                # Neutralize the smuggled payload by neutralizing directive words
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
