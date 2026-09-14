"""
SaniLine MCP Server Protocol Tests.

Validates JSON-RPC 2.0 tool discovery, tool invocation, and token-saving schemas
for autonomous AI agents.
"""

import json
from saniline.mcp.server import McpServer


def test_mcp_initialize():
    server = McpServer()
    req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    }
    resp = server.handle_request(req)
    assert resp["id"] == 1
    assert "serverInfo" in resp["result"]
    assert resp["result"]["serverInfo"]["name"] == "saniline-mcp"


def test_mcp_tools_list():
    server = McpServer()
    req = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    }
    resp = server.handle_request(req)
    tools = resp["result"]["tools"]
    tool_names = [t["name"] for t in tools]
    assert "saniline_sanitize_line" in tool_names
    assert "saniline_sanitize_block" in tool_names
    assert "saniline_audit_security" in tool_names
    assert "saniline_explain_rule" in tool_names


def test_mcp_sanitize_line_clean_compact():
    server = McpServer()
    req = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "saniline_sanitize_line",
            "arguments": {
                "line": "x = 42 + y",
                "compact": True
            }
        }
    }
    resp = server.handle_request(req)
    content_text = resp["result"]["content"][0]["text"]
    parsed = json.loads(content_text)
    # Minimal token footprint for clean code
    assert parsed == {"status": "CLEAN"}


def test_mcp_sanitize_line_violation_autopatched():
    server = McpServer()
    req = {
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "saniline_sanitize_line",
            "arguments": {
                "line": "subprocess.Popen(cmd, shell=True)",
                "compact": True
            }
        }
    }
    resp = server.handle_request(req)
    content_text = resp["result"]["content"][0]["text"]
    parsed = json.loads(content_text)
    assert parsed["status"] == "MODIFIED"
    assert "shell=False" in parsed["patch"]
    assert len(parsed["issues"]) > 0


def test_mcp_explain_rule():
    server = McpServer()
    req = {
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {
            "name": "saniline_explain_rule",
            "arguments": {
                "rule_id": "SL-RCE-001"
            }
        }
    }
    resp = server.handle_request(req)
    content_text = resp["result"]["content"][0]["text"]
    parsed = json.loads(content_text)
    assert parsed["cwe"] == "CWE-78"
    assert parsed["stig"] == "APSC-DV-002100"
