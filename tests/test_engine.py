"""
SaniLine Core Engine Tests.

Validates streaming filters, block sanitization, compliance scoring,
and hyper-compact token serialization.
"""

import pytest
from saniline.core.context import StreamContext
from saniline.core.engine import SaniLine, SecurityViolationError
from saniline.core.models import SanitizeAction, SecurityLevel


def test_sanitize_clean_line():
    engine = SaniLine(level=SecurityLevel.MILITARY)
    res = engine.sanitize_line("def add(a: int, b: int) -> int:\n")
    assert res.is_clean
    assert not res.was_modified
    assert res.to_token_compact() == {"status": "CLEAN"}


def test_sanitize_stream():
    engine = SaniLine(level=SecurityLevel.MILITARY, action=SanitizeAction.AUTOPATCH)
    stream = [
        "import os\n",
        "import subprocess\n",
        "subprocess.run('ls', shell=True)\n",
        "return True\n",
    ]
    output = list(engine.sanitize_stream(stream, language="python"))
    assert len(output) == 4
    assert "shell=False" in output[2]


def test_sanitize_code_block():
    engine = SaniLine(level=SecurityLevel.MILITARY, action=SanitizeAction.AUTOPATCH)
    code = """import yaml
import requests

def load_config(path):
    data = requests.get(path, verify=False).text
    return yaml.load(data)
"""
    res = engine.sanitize_code(code, language="python")
    assert res.was_modified
    assert len(res.violations) == 2
    assert "verify=True" in res.sanitized_code
    assert "yaml.safe_load(data)" in res.sanitized_code


def test_strict_fail_on_critical():
    engine = SaniLine(
        level=SecurityLevel.MILITARY,
        action=SanitizeAction.BLOCK,
        strict_fail_on_critical=True,
    )
    with pytest.raises(SecurityViolationError):
        engine.sanitize_line("subprocess.run('malicious', shell=True)", language="python")


def test_audit_code_and_scoring():
    engine = SaniLine(level=SecurityLevel.MILITARY)
    vuln_code = """
import os
os.system(user_input)
key = "AKIAIOSFODNN7EXAMPLE"
"""
    report = engine.audit_code(vuln_code, language="python", target_name="test.py")
    assert not report.passed_military_spec
    assert report.security_score < 80.0
    compact = report.to_token_compact()
    assert "score" in compact
    assert compact["pass"] is False


def test_token_compact_efficiency():
    engine = SaniLine(level=SecurityLevel.MILITARY, action=SanitizeAction.AUTOPATCH)
    res = engine.sanitize_line("subprocess.run(c, shell=True)", language="python")
    compact = res.to_token_compact()
    # Ensure compact representation does not contain bloated AST or excessive keys
    assert "patch" in compact
    assert "issues" in compact
    assert "status" in compact
    assert compact["status"] == "MODIFIED"
    assert "original_code" not in compact  # Excluded to save tokens
