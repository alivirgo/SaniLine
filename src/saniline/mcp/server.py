"""
SaniLine Model Context Protocol (MCP) Server.

Standard JSON-RPC 2.0 interface enabling autonomous AI coding agents (Antigravity,
Claude Code, Cursor, Devin) to invoke real-time line sanitization and security audits
with hyper-compact, token-optimized responses.
"""

from __future__ import annotations

import json
import sys
from typing import Any

from saniline import __version__
from saniline.core.engine import SaniLine
from saniline.core.models import SanitizeAction, SecurityLevel
from saniline.rules.base import RuleRegistry

MCP_PROTOCOL_VERSION = "2024-11-05"
MAX_LINE_LENGTH = 1_000_000       # 1MB limit on single line
MAX_BLOCK_LENGTH = 10_000_000     # 10MB limit on code block

TOOLS = [
    {
        "name": "saniline_sanitize_line",
        "description": (
            "Military-grade line-by-line code sanitizer. Sanitizes a single line of code "
            "as it is being generated or streamed. Returns token-compact response (<10 tokens when clean)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "line": {"type": "string", "description": "The single line of code to inspect."},
                "language": {"type": "string", "description": "Programming language (python, js, ts, bash, generic)."},
                "compact": {"type": "boolean", "default": True, "description": "Whether to return minimal token-efficient output."},
            },
            "required": ["line"],
        },
    },
    {
        "name": "saniline_sanitize_block",
        "description": (
            "Audits and automatically neutralizes vulnerabilities (RCE, hardcoded secrets, "
            "Trojan Source Unicode, Insecure Deserialization, SSRF, SQL Injection, Prototype Pollution, XSS) in a code block."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "code": {"type": "string", "description": "Full source code block to sanitize."},
                "language": {"type": "string", "description": "Language (python, js, ts, bash)."},
                "action": {
                    "type": "string",
                    "enum": ["autopatch", "audit", "redact"],
                    "default": "autopatch",
                    "description": "Remediation policy.",
                },
                "compact": {"type": "boolean", "default": True, "description": "Token-optimized representation."},
            },
            "required": ["code"],
        },
    },
    {
        "name": "saniline_audit_security",
        "description": "Performs a zero-token local compliance audit returning DoD STIG & NIST SSDF compliance score.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "code": {"type": "string", "description": "Code to audit."},
                "language": {"type": "string", "description": "Programming language."},
            },
            "required": ["code"],
        },
    },
    {
        "name": "saniline_explain_rule",
        "description": "Provides military-grade remediation guidance for a specific SaniLine rule or CWE.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "rule_id": {"type": "string", "description": "Rule ID (e.g. SL-SEC-001, SL-RCE-001, SL-PROTO-001)."},
            },
            "required": ["rule_id"],
        },
    },
]


class McpServer:
    def __init__(self) -> None:
        self.engine = SaniLine(
            level=SecurityLevel.MILITARY,
            action=SanitizeAction.AUTOPATCH,
        )

    def handle_request(self, request: dict[str, Any]) -> dict[str, Any] | None:
        if not isinstance(request, dict):
            return {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32600, "message": "Invalid Request: root must be an object."},
            }

        msg_id = request.get("id")
        method = request.get("method")
        params = request.get("params", {})
        if not isinstance(params, dict):
            params = {}

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "serverInfo": {
                        "name": "saniline-mcp",
                        "version": __version__,
                        "tagline": "Military-Grade Line-by-Line Code Sanitizer for AI Agents",
                    },
                    "capabilities": {
                        "tools": {"listChanged": False},
                    },
                },
            }

        elif method == "notifications/initialized":
            return None

        elif method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {"tools": TOOLS},
            }

        elif method == "tools/call":
            tool_name = params.get("name")
            args = params.get("arguments", {})
            try:
                content = self.dispatch_tool(tool_name, args)
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "content": [
                            {"type": "text", "text": json.dumps(content, separators=(",", ":"))}
                        ]
                    },
                }
            except Exception as exc:
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {"code": -32000, "message": str(exc)},
                }

        elif method == "ping":
            return {"jsonrpc": "2.0", "id": msg_id, "result": {}}

        else:
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32601, "message": f"Method not found: {method}"},
            }

    def dispatch_tool(self, name: str, args: dict[str, Any]) -> Any:
        compact = args.get("compact", True)

        if name == "saniline_sanitize_line":
            line = args.get("line", "")
            if len(line) > MAX_LINE_LENGTH:
                raise ValueError(f"Line exceeds maximum permitted size of {MAX_LINE_LENGTH} characters.")
            lang = args.get("language")
            res = self.engine.sanitize_line(line, language=lang)
            return res.to_token_compact() if compact else res.to_dict()

        elif name == "saniline_sanitize_block":
            code = args.get("code", "")
            if len(code) > MAX_BLOCK_LENGTH:
                raise ValueError(f"Code block exceeds maximum permitted size of {MAX_BLOCK_LENGTH} characters.")
            lang = args.get("language")
            action_str = args.get("action", "autopatch")
            action = SanitizeAction(action_str)
            engine = SaniLine(level=SecurityLevel.MILITARY, action=action)
            res = engine.sanitize_code(code, language=lang)
            return res.to_token_compact() if compact else res.to_dict()

        elif name == "saniline_audit_security":
            code = args.get("code", "")
            if len(code) > MAX_BLOCK_LENGTH:
                raise ValueError(f"Code block exceeds maximum permitted size of {MAX_BLOCK_LENGTH} characters.")
            lang = args.get("language")
            report = self.engine.audit_code(code, language=lang)
            return report.to_token_compact() if compact else report.to_dict()

        elif name == "saniline_explain_rule":
            rule_id = args.get("rule_id", "")
            rule = RuleRegistry.get_rule_by_id(rule_id)
            if not rule:
                return {"error": f"Rule '{rule_id}' not recognized."}
            return {
                "rule_id": rule.rule_id,
                "title": rule.title,
                "description": rule.description,
                "cwe": rule.cwe_id,
                "stig": rule.stig_id,
                "nist": rule.nist_control,
                "severity": rule.severity.value,
            }

        else:
            raise ValueError(f"Unknown tool: {name}")


def main() -> None:
    """Runs the MCP server over standard I/O."""
    server = McpServer()
    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            resp = server.handle_request(req)
            if resp is not None:
                sys.stdout.write(json.dumps(resp, separators=(",", ":")) + "\n")
                sys.stdout.flush()
        except Exception as exc:
            err_resp = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": f"Parse error: {str(exc)}"},
            }
            sys.stdout.write(json.dumps(err_resp, separators=(",", ":")) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
