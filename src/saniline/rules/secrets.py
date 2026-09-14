"""
Military-Grade Secret and Credential Exposure Defense.

Combines deterministic signature regex matching with Shannon Entropy analysis
to detect, isolate, and redact hardcoded API keys, private keys, database credentials,
and high-entropy tokens as mandated by DoD STIG APPS-000170 and CWE-798.
"""

from __future__ import annotations

import math
import re
from typing import List, Optional, Tuple

from saniline.core.context import StreamContext
from saniline.core.models import (
    RuleCategory,
    SecurityLevel,
    Severity,
    Violation,
)
from saniline.rules.base import BaseRule, RuleRegistry


def calculate_shannon_entropy(data: str) -> float:
    """Calculates Shannon Entropy in bits per character."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    frequencies = {}
    for char in data:
        frequencies[char] = frequencies.get(char, 0) + 1
    for count in frequencies.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


@RuleRegistry.register
class HardcodedSecretRule(BaseRule):
    rule_id = "SL-SEC-001"
    title = "Hardcoded Credential or API Token Exposure"
    description = (
        "Detected plaintext credential, private key, or high-entropy token in code. "
        "Hardcoding secrets violates DoD STIG APPS-000170 and CWE-798."
    )
    category = RuleCategory.SECRETS
    severity = Severity.CRITICAL
    cwe_id = "CWE-798"
    stig_id = "APSC-DV-000170"
    nist_control = "IA-5"
    min_security_level = SecurityLevel.STANDARD
    supported_languages = ["*"]

    # Explicit high-confidence signatures
    SIGNATURES = [
        ("AWS Access Key", re.compile(r"\b(AKIA[0-9A-Z]{16})\b"), "[REDACTED_SECRET:AWS_ACCESS_KEY]"),
        ("GitHub Token", re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{36,255})\b"), "[REDACTED_SECRET:GITHUB_TOKEN]"),
        ("OpenAI Key", re.compile(r"\b(sk-[a-zA-Z0-9]{20,}|sk-proj-[a-zA-Z0-9_-]{20,})\b"), "[REDACTED_SECRET:OPENAI_API_KEY]"),
        ("Anthropic Key", re.compile(r"\b(sk-ant-[a-zA-Z0-9_-]{20,})\b"), "[REDACTED_SECRET:ANTHROPIC_API_KEY]"),
        ("Google Cloud Key", re.compile(r"\b(AIza[0-9A-Za-z_-]{35})\b"), "[REDACTED_SECRET:GOOGLE_API_KEY]"),
        ("Slack Token", re.compile(r"\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b"), "[REDACTED_SECRET:SLACK_TOKEN]"),
        ("Private Key Header", re.compile(r"-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH|PGP)?\s*PRIVATE\s+KEY-----"), "[REDACTED_SECRET:PRIVATE_KEY]"),
        ("Database URI Password", re.compile(r"((?:postgres|mysql|mongodb(?:\+srv)?|redis)://[^:\s]+:)([^@\s]+)(@)"), r"\1[REDACTED_SECRET:DB_PASSWORD]\3"),
        ("Generic JWT", re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"), "[REDACTED_SECRET:JWT_TOKEN]"),
    ]

    # Assignment patterns indicative of sensitive credentials
    ASSIGNMENT_PATTERN = re.compile(
        r"""(?i)\b(password|passwd|secret|api_?key|access_?token|auth_?token|client_?secret|bearer)\s*[:=]\s*(['"])([^'"]{8,})\2"""
    )

    def inspect_line(
        self, line: str, line_no: int, context: StreamContext
    ) -> Optional[Violation]:
        # Skip pure comments if they are not carrying secrets
        stripped = line.strip()
        if not stripped:
            return None

        # 1. Check explicit signatures
        for label, pattern, _ in self.SIGNATURES:
            match = pattern.search(line)
            if match:
                snippet = match.group(0)
                col = match.start()
                return self.create_violation(
                    line_no=line_no,
                    matched_snippet=snippet,
                    column=col,
                    remediation_advice=f"Extract {label} into a secure environment variable or KMS vault (e.g. os.environ.get('...')).",
                    suggested_patch=self._generate_patch(line, match, snippet),
                    custom_description=f"Hardcoded {label} detected in source code.",
                )

        # 2. Check sensitive assignments with Shannon Entropy
        assign_match = self.ASSIGNMENT_PATTERN.search(line)
        if assign_match:
            var_name = assign_match.group(1)
            quote = assign_match.group(2)
            value = assign_match.group(3)
            # Exclude obvious mock or dummy tokens
            if self._is_mock_value(value):
                return None

            entropy = calculate_shannon_entropy(value)
            # High entropy thresholds: >= 3.2 for length >= 12 or >= 3.6 for shorter
            if (len(value) >= 12 and entropy >= 3.2) or (len(value) >= 8 and entropy >= 3.6):
                env_name = var_name.upper().replace("-", "_")
                if context.language == "python":
                    patch_val = f'os.environ.get("{env_name}", "")'
                    # Replace variable assignment
                    patched_line = line[:assign_match.start(2)] + patch_val + line[assign_match.end(3) + 1:]
                elif context.language in ("javascript", "typescript"):
                    patch_val = f'process.env.{env_name} || ""'
                    patched_line = line[:assign_match.start(2)] + patch_val + line[assign_match.end(3) + 1:]
                else:
                    patched_line = line[:assign_match.start(3)] + f"[REDACTED_{env_name}]" + line[assign_match.end(3):]

                return self.create_violation(
                    line_no=line_no,
                    matched_snippet=assign_match.group(0),
                    column=assign_match.start(),
                    remediation_advice=f"Replace hardcoded credential with secure environment retrieval: {env_name}.",
                    suggested_patch=patched_line,
                    custom_description=f"High-entropy secret assignment detected for '{var_name}' (Entropy: {entropy:.2f} bits).",
                )

        return None

    def _generate_patch(self, line: str, match: re.Match, snippet: str) -> str:
        for label, pattern, replacement in self.SIGNATURES:
            if pattern.search(snippet):
                if label == "Database URI Password":
                    return pattern.sub(replacement, line)
                return line[:match.start()] + replacement + line[match.end():]
        return line.replace(snippet, "[REDACTED_SECRET]")

    @staticmethod
    def _is_mock_value(val: str) -> bool:
        lower = val.lower()
        dummies = [
            "dummy", "example", "changeme", "test", "fake", "placeholder",
            "none", "null", "undefined", "your_api_key", "xxx", "123456",
            "password123", "secret123"
        ]
        return any(d in lower for d in dummies)
