"""
Military-Grade Remote Code Execution (RCE) and Command Injection Defense.

Neutralizes dangerous OS shell spawning, eval/exec execution, and child process
misconfigurations as specified in CWE-78, CWE-95, and DoD STIG APSC-DV-002100.
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
class ShellTrueInjectionRule(BaseRule):
    rule_id = "SL-RCE-001"
    title = "Insecure Subprocess Execution with shell=True"
    description = (
        "Invoking subprocess functions with shell=True allows arbitrary command execution "
        "and bypasses OS argument boundaries (CWE-78, DoD STIG APSC-DV-002100)."
    )
    category = RuleCategory.RCE_COMMAND_INJECTION
    severity = Severity.CRITICAL
    cwe_id = "CWE-78"
    stig_id = "APSC-DV-002100"
    nist_control = "SI-10"
    min_security_level = SecurityLevel.STANDARD
    supported_languages = ["python"]

    PATTERN = re.compile(
        r"""\b(?:subprocess\s*\.\s*(?:run|Popen|call|check_call|check_output))\s*\([^)]*?\bshell\s*=\s*True""",
        re.DOTALL
    )

    def inspect_line(
        self, line: str, line_no: int, context: StreamContext
    ) -> Optional[Violation]:
        if context.is_inside_comment_or_docstring():
            return None

        if "shell=True" in line or "shell = True" in line:
            if any(call in line for call in ("subprocess.", "Popen(", "run(", "call(")):
                patched = re.sub(r"\bshell\s*=\s*True\b", "shell=False", line)
                return self.create_violation(
                    line_no=line_no,
                    matched_snippet="shell=True",
                    column=line.find("shell"),
                    remediation_advice="Set shell=False and pass command arguments as a validated list, using shlex.split() where necessary.",
                    suggested_patch=patched,
                )
        return None


@RuleRegistry.register
class ArbitraryEvalExecRule(BaseRule):
    rule_id = "SL-RCE-002"
    title = "Dangerous Dynamic Code Execution via eval()/exec()"
    description = (
        "Dynamic evaluation of untrusted strings via eval() or exec() directly enables "
        "arbitrary code execution (CWE-95, CWE-94)."
    )
    category = RuleCategory.RCE_COMMAND_INJECTION
    severity = Severity.CRITICAL
    cwe_id = "CWE-95"
    stig_id = "APSC-DV-002110"
    nist_control = "SC-18"
    min_security_level = SecurityLevel.STANDARD
    supported_languages = ["python", "javascript", "typescript"]

    # Match eval(...) or exec(...) not preceded by safe wrappers
    PY_PATTERN = re.compile(r"""\b(eval|exec)\s*\((.+?)\)""")
    JS_PATTERN = re.compile(r"""\b(eval|new\s+Function)\s*\((.+?)\)""")

    def inspect_line(
        self, line: str, line_no: int, context: StreamContext
    ) -> Optional[Violation]:
        if context.is_inside_comment_or_docstring():
            return None

        # Check Python
        if context.language in ("python", "generic"):
            match = self.PY_PATTERN.search(line)
            if match:
                fn_name = match.group(1)
                arg = match.group(2).strip()
                # Don't flag trivial literals like eval("1+1") or ast.literal_eval
                if not (line.strip().startswith("#") or "literal_eval" in line):
                    suggested = None
                    if fn_name == "eval" and context.language == "python":
                        suggested = line.replace("eval(", "ast.literal_eval(")
                    return self.create_violation(
                        line_no=line_no,
                        matched_snippet=match.group(0),
                        column=match.start(),
                        remediation_advice=f"Replace '{fn_name}()' with safe data deserialization (ast.literal_eval, json.loads) or explicit dispatch mapping.",
                        suggested_patch=suggested,
                        custom_description=f"Direct invocation of '{fn_name}()' introduces arbitrary code execution hazards.",
                    )

        # Check JS/TS
        if context.language in ("javascript", "typescript"):
            match = self.JS_PATTERN.search(line)
            if match:
                return self.create_violation(
                    line_no=line_no,
                    matched_snippet=match.group(0),
                    column=match.start(),
                    remediation_advice="Refactor dynamic evaluation to JSON.parse or structured lookup tables.",
                    suggested_patch=None,
                )

        return None


@RuleRegistry.register
class OsSystemCommandRule(BaseRule):
    rule_id = "SL-RCE-003"
    title = "Insecure System Command Invocation via os.system"
    description = (
        "os.system executes shell commands without argument containment, allowing command injection (CWE-78)."
    )
    category = RuleCategory.RCE_COMMAND_INJECTION
    severity = Severity.HIGH
    cwe_id = "CWE-78"
    stig_id = "APSC-DV-002100"
    nist_control = "SI-10"
    min_security_level = SecurityLevel.STANDARD
    supported_languages = ["python"]

    PATTERN = re.compile(r"""\bos\.system\s*\((.+?)\)""")

    def inspect_line(
        self, line: str, line_no: int, context: StreamContext
    ) -> Optional[Violation]:
        if context.is_inside_comment_or_docstring():
            return None

        match = self.PATTERN.search(line)
        if match:
            arg = match.group(1).strip()
            patch = line[:match.start()] + f"subprocess.run(shlex.split({arg}), check=True)" + line[match.end():]
            return self.create_violation(
                line_no=line_no,
                matched_snippet=match.group(0),
                column=match.start(),
                remediation_advice="Replace os.system with subprocess.run(shlex.split(...), check=True) to eliminate shell injection.",
                suggested_patch=patch,
            )
        return None
