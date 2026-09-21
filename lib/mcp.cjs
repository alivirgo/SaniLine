/**
 * SaniLine Model Context Protocol (MCP) Server for Node.js
 * Enables autonomous AI coding agents (Cursor, Windsurf, Claude Desktop, Antigravity)
 * to perform real-time code sanitization and security audits over stdio.
 */

"use strict";

const readline = require("node:readline");
const { SaniLine, SecurityLevel, SanitizeAction, RULES_CATALOG, VERSION, TAGLINE } = require("./index.cjs");

const MCP_PROTOCOL_VERSION = "2024-11-05";

// Maximum allowable input sizes to protect against memory exhaustion / resource exhaustion DoS
const MAX_LINE_LENGTH = 1024 * 1024; // 1 MB
const MAX_BLOCK_LENGTH = 10 * 1024 * 1024; // 10 MB

const TOOLS = [
  {
    name: "saniline_sanitize_line",
    description: "Military-grade line-by-line code sanitizer. Sanitizes a single line of code as it is generated or streamed. Returns token-compact response (<10 tokens when clean).",
    inputSchema: {
      type: "object",
      properties: {
        line: { type: "string", description: "The single line of code to inspect." },
        language: { type: "string", description: "Programming language (python, js, ts, bash, generic)." },
        compact: { type: "boolean", default: true, description: "Whether to return minimal token-efficient output." },
      },
      required: ["line"],
    },
  },
  {
    name: "saniline_sanitize_block",
    description: "Audits and automatically neutralizes vulnerabilities (RCE, hardcoded secrets, Trojan Source Unicode, Prototype Pollution, XSS, SSRF, SQL Injection) in a code block.",
    inputSchema: {
      type: "object",
      properties: {
        code: { type: "string", description: "Full source code block to sanitize." },
        language: { type: "string", description: "Language (python, js, ts, bash)." },
        action: {
          type: "string",
          enum: ["autopatch", "audit", "redact"],
          default: "autopatch",
          description: "Remediation policy.",
        },
        compact: { type: "boolean", default: true, description: "Token-optimized representation." },
      },
      required: ["code"],
    },
  },
  {
    name: "saniline_audit_security",
    description: "Performs a zero-token local compliance audit returning DoD STIG & NIST SSDF compliance score.",
    inputSchema: {
      type: "object",
      properties: {
        code: { type: "string", description: "Code to audit." },
        language: { type: "string", description: "Programming language." },
      },
      required: ["code"],
    },
  },
  {
    name: "saniline_explain_rule",
    description: "Provides military-grade remediation guidance for a specific SaniLine rule or CWE.",
    inputSchema: {
      type: "object",
      properties: {
        rule_id: { type: "string", description: "Rule ID (e.g. SL-SEC-001, SL-RCE-001, SL-PROTO-001, SL-RCE-004)." },
      },
      required: ["rule_id"],
    },
  },
];

class NodeMcpServer {
  constructor() {
    this.engine = new SaniLine({
      level: SecurityLevel.MILITARY,
      action: SanitizeAction.AUTOPATCH,
    });
  }

  handleRequest(request) {
    if (!request || typeof request !== "object" || Array.isArray(request)) {
      return {
        jsonrpc: "2.0",
        id: null,
        error: { code: -32600, message: "Invalid Request: expected a JSON-RPC 2.0 object" },
      };
    }

    const msgId = request.id !== undefined ? request.id : null;
    const method = request.method;
    const params = request.params || {};

    if (typeof method !== "string") {
      return {
        jsonrpc: "2.0",
        id: msgId,
        error: { code: -32600, message: "Invalid Request: 'method' must be a string" },
      };
    }

    if (method === "initialize") {
      return {
        jsonrpc: "2.0",
        id: msgId,
        result: {
          protocolVersion: MCP_PROTOCOL_VERSION,
          serverInfo: {
            name: "saniline-mcp",
            version: VERSION,
            tagline: TAGLINE,
          },
          capabilities: {
            tools: { listChanged: false },
          },
        },
      };
    }

    if (method === "notifications/initialized") {
      return null;
    }

    if (method === "tools/list") {
      return {
        jsonrpc: "2.0",
        id: msgId,
        result: { tools: TOOLS },
      };
    }

    if (method === "tools/call") {
      const toolName = params.name;
      const args = params.arguments || {};
      try {
        const content = this.dispatchTool(toolName, args);
        return {
          jsonrpc: "2.0",
          id: msgId,
          result: {
            content: [{ type: "text", text: JSON.stringify(content) }],
          },
        };
      } catch (exc) {
        return {
          jsonrpc: "2.0",
          id: msgId,
          error: { code: -32000, message: exc.message || String(exc) },
        };
      }
    }

    if (method === "ping") {
      return { jsonrpc: "2.0", id: msgId, result: {} };
    }

    return {
      jsonrpc: "2.0",
      id: msgId,
      error: { code: -32601, message: `Method not found: ${method}` },
    };
  }

  dispatchTool(name, args) {
    const compact = args.compact !== false;

    if (name === "saniline_sanitize_line") {
      let line = args.line;
      if (typeof line !== "string") {
        line = line == null ? "" : String(line);
      }
      if (line.length > MAX_LINE_LENGTH) {
        throw new Error(`Line length (${line.length}) exceeds maximum allowable size (${MAX_LINE_LENGTH} bytes).`);
      }
      const lang = args.language || null;
      const res = this.engine.sanitizeLine(line, 1, lang);
      if (compact) return res.toTokenCompact();
      return {
        isClean: res.isClean,
        wasModified: res.wasModified,
        sanitizedCode: res.sanitizedCode,
        violations: res.violations,
      };
    }

    if (name === "saniline_sanitize_block") {
      let code = args.code;
      if (typeof code !== "string") {
        code = code == null ? "" : String(code);
      }
      if (code.length > MAX_BLOCK_LENGTH) {
        throw new Error(`Code block length (${code.length}) exceeds maximum allowable size (${MAX_BLOCK_LENGTH} bytes).`);
      }
      const lang = args.language || null;
      const action = args.action || "autopatch";
      const blockEngine = new SaniLine({
        level: SecurityLevel.MILITARY,
        action: action,
      });
      const res = blockEngine.sanitizeCode(code, lang);
      if (compact) return res.toTokenCompact();
      return {
        isClean: res.isClean,
        wasModified: res.wasModified,
        sanitizedCode: res.sanitizedCode,
        violations: res.violations,
      };
    }

    if (name === "saniline_audit_security") {
      let code = args.code;
      if (typeof code !== "string") {
        code = code == null ? "" : String(code);
      }
      if (code.length > MAX_BLOCK_LENGTH) {
        throw new Error(`Code block length (${code.length}) exceeds maximum allowable size (${MAX_BLOCK_LENGTH} bytes).`);
      }
      const lang = args.language || null;
      const auditEngine = new SaniLine({
        level: SecurityLevel.MILITARY,
        action: SanitizeAction.AUDIT,
      });
      const res = auditEngine.sanitizeCode(code, lang);
      const totalLines = code.split("\n").length;
      const score = Math.max(0, 100 - res.violations.length * 10);
      return {
        score,
        passed: res.violations.length === 0,
        total_lines: totalLines,
        violations_count: res.violations.length,
        violations: res.violations,
      };
    }

    if (name === "saniline_explain_rule") {
      const ruleId = (args.rule_id || "").toUpperCase().trim();
      const rule = RULES_CATALOG.find(r => r.rule_id === ruleId);
      if (!rule) {
        return { error: `Rule '${ruleId}' not found in SaniLine defense catalog.` };
      }
      return rule;
    }

    throw new Error(`Unknown tool: ${name}`);
  }

  start() {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
      terminal: false,
    });

    rl.on("line", (rawLine) => {
      const line = rawLine.trim();
      if (!line) return;
      try {
        const req = JSON.parse(line);
        const resp = this.handleRequest(req);
        if (resp !== null) {
          process.stdout.write(JSON.stringify(resp) + "\n");
        }
      } catch (err) {
        const errResp = {
          jsonrpc: "2.0",
          id: null,
          error: { code: -32700, message: `Parse error: ${err.message}` },
        };
        process.stdout.write(JSON.stringify(errResp) + "\n");
      }
    });
  }
}

module.exports = {
  NodeMcpServer,
  TOOLS,
  MAX_LINE_LENGTH,
  MAX_BLOCK_LENGTH,
  main() {
    const server = new NodeMcpServer();
    server.start();
  },
};

if (require.main === module) {
  module.exports.main();
}
