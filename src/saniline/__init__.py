"""
SaniLine.

Military-Grade Line-by-Line Code Sanitizer & Security Shield for AI Agents.
"""

from saniline.core.context import StreamContext
from saniline.core.engine import SaniLine, SecurityViolationError
from saniline.core.models import (
    AuditReport,
    RuleCategory,
    SanitizeAction,
    SanitizedResult,
    SecurityLevel,
    Severity,
    Violation,
)

__version__ = "0.1.0"
__tagline__ = "Real-Time Military-Grade Line-by-Line Code Sanitizer & Security Shield for AI Agents"

__all__ = [
    "SaniLine",
    "SecurityLevel",
    "SanitizeAction",
    "RuleCategory",
    "Severity",
    "Violation",
    "SanitizedResult",
    "AuditReport",
    "StreamContext",
    "SecurityViolationError",
    "__version__",
    "__tagline__",
]
