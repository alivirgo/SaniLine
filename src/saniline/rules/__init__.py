"""
SaniLine Rule Matrix Initialization.

Auto-registers all military-grade and industry-standard defense rules into RuleRegistry.
"""

from __future__ import annotations

from saniline.rules.base import BaseRule, RuleRegistry
from saniline.rules.crypto import (
    DisabledTlsVerificationRule,
    InsecurePrngForSecurityRule,
    WeakHashAlgorithmRule,
)
from saniline.rules.deserialization import UnsafePickleRule, UnsafeYamlLoadRule
from saniline.rules.injections import SqlStringFormattingInjectionRule
from saniline.rules.path_traversal import PathTraversalSequenceRule, ZipSlipVulnerabilityRule
from saniline.rules.prompt_shield import PromptInjectionSmugglingRule
from saniline.rules.prototype_pollution import PrototypePollutionRule
from saniline.rules.rce import (
    ArbitraryEvalExecRule,
    NodeChildProcessExecRule,
    OsSystemCommandRule,
    ShellTrueInjectionRule,
)
from saniline.rules.secrets import HardcodedSecretRule
from saniline.rules.ssrf import CloudMetadataSsrfRule, WildcardBindRule
from saniline.rules.unicode_shield import TrojanSourceUnicodeRule
from saniline.rules.xss import DomXssRule

__all__ = [
    "BaseRule",
    "RuleRegistry",
    "HardcodedSecretRule",
    "ShellTrueInjectionRule",
    "NodeChildProcessExecRule",
    "ArbitraryEvalExecRule",
    "OsSystemCommandRule",
    "UnsafeYamlLoadRule",
    "UnsafePickleRule",
    "PathTraversalSequenceRule",
    "ZipSlipVulnerabilityRule",
    "SqlStringFormattingInjectionRule",
    "TrojanSourceUnicodeRule",
    "PromptInjectionSmugglingRule",
    "DisabledTlsVerificationRule",
    "InsecurePrngForSecurityRule",
    "WeakHashAlgorithmRule",
    "CloudMetadataSsrfRule",
    "WildcardBindRule",
    "PrototypePollutionRule",
    "DomXssRule",
]
