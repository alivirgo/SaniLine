"""
SaniLine Rule Matrix Initialization.

Auto-registers all military-grade and industry-standard defense rules into RuleRegistry.
"""

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
from saniline.rules.rce import (
    ArbitraryEvalExecRule,
    OsSystemCommandRule,
    ShellTrueInjectionRule,
)
from saniline.rules.secrets import HardcodedSecretRule
from saniline.rules.ssrf import CloudMetadataSsrfRule, WildcardBindRule
from saniline.rules.unicode_shield import TrojanSourceUnicodeRule

__all__ = [
    "BaseRule",
    "RuleRegistry",
    "HardcodedSecretRule",
    "ShellTrueInjectionRule",
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
]
