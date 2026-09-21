#!/usr/bin/env node
/**
 * SaniLine CLI for Node.js
 * Military-Grade Line-by-Line Code Sanitizer & Security Shield for AI Agents
 */

"use strict";

const fs = require("node:fs");
const path = require("node:path");
const readline = require("node:readline");
const { SaniLine, SecurityLevel, SanitizeAction, Severity, RULES_CATALOG, generateSarifReport, VERSION, TAGLINE } = require("../lib/index.cjs");

// Direct MCP execution if invoked as saniline-mcp
if (path.basename(process.argv[1] || "").startsWith("saniline-mcp")) {
  require("../lib/mcp.cjs").main();
  process.exit(0);
}

const args = process.argv.slice(2);

const HELP_TEXT = `
\x1b[1;36mSaniLine\x1b[0m v${VERSION} - \x1b[2m${TAGLINE}\x1b[0m

\x1b[1mUSAGE:\x1b[0m
  saniline check <path> [options]      Audit a file or directory for security posture
  saniline sanitize <path> [options]   Auto-patch security vulnerabilities
  saniline stream                      Filter & sanitize code lines from stdin in real-time
  saniline rules                       Display the military-grade defense rules matrix
  saniline hook install                Install zero-dependency Git pre-commit security hook
  saniline mcp                         Launch stdio Model Context Protocol (MCP) server
  saniline --version                   Show version information

\x1b[1mOPTIONS:\x1b[0m
  -c, --compact       Token-minified output (<10 tokens) for AI agent context efficiency
  -i, --in-place      Overwrite target files with sanitized, auto-patched code
  --format sarif      Output OASIS SARIF v2.1.0 JSON for GitHub Actions Code Scanning
  --json              Output complete audit telemetry JSON
  -l, --level <lvl>   Security policy level: standard | strict | military (default: military)
  -h, --help          Show this help screen
`;

if (args.length === 0 || args.includes("--help") || args.includes("-h")) {
  console.log(HELP_TEXT);
  process.exit(0);
}

if (args.includes("--version") || args.includes("-v")) {
  console.log(`saniline v${VERSION}`);
  process.exit(0);
}

const command = args[0];

const IGNORED_DIRS = new Set([
  "node_modules",
  ".git",
  "dist",
  "build",
  ".next",
  ".turbo",
  ".cache",
  "coverage",
  "__pycache__",
  ".venv",
  "venv",
  ".gemini",
]);

const ALLOWED_EXTENSIONS = new Set([
  ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx",
  ".py", ".sh", ".bash", ".sql", ".json", ".yaml", ".yml",
  ".go", ".c", ".cpp", ".html",
]);

function collectFiles(targetPath) {
  let stat;
  try {
    stat = fs.statSync(targetPath);
  } catch {
    return [];
  }
  if (stat.isFile()) return [targetPath];

  const files = [];
  const visitedDirs = new Set();

  function walk(dir) {
    let realDir;
    try {
      realDir = fs.realpathSync(dir);
    } catch {
      return;
    }
    if (visitedDirs.has(realDir)) return;
    visitedDirs.add(realDir);

    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (entry.isDirectory()) {
        if (!IGNORED_DIRS.has(entry.name)) {
          walk(path.join(dir, entry.name));
        }
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (ALLOWED_EXTENSIONS.has(ext)) {
          files.push(path.join(dir, entry.name));
        }
      }
    }
  }
  walk(targetPath);
  return files;
}

if (command === "check") {
  const target = args[1] || ".";
  if (!fs.existsSync(target)) {
    console.error(`\x1b[31mError:\x1b[0m Target not found: ${target}`);
    process.exit(1);
  }

  const compact = args.includes("--compact") || args.includes("-c");
  const jsonOut = args.includes("--json");
  const sarifOut = args.includes("--format") && args[args.indexOf("--format") + 1] === "sarif";

  const levelIdx = args.indexOf("--level") !== -1 ? args.indexOf("--level") : args.indexOf("-l");
  const level = levelIdx !== -1 && args[levelIdx + 1] ? args[levelIdx + 1] : SecurityLevel.MILITARY;

  const engine = new SaniLine({ level, action: SanitizeAction.AUDIT });
  const files = collectFiles(target);

  if (files.length === 0) {
    if (compact) {
      console.log(JSON.stringify({ status: "NO_SOURCE_FILES" }));
    } else if (jsonOut) {
      console.log(JSON.stringify({ target, total_files: 0, violations: [] }));
    } else {
      console.log(`\x1b[33mNo source files found in ${target}\x1b[0m`);
    }
    process.exit(0);
  }

  let totalLines = 0;
  const allViolations = [];

  for (const file of files) {
    try {
      const content = fs.readFileSync(file, "utf-8");
      const ext = path.extname(file).replace(".", "");
      const res = engine.sanitizeCode(content, ext);
      totalLines += content.split("\n").length;
      for (const v of res.violations) {
        allViolations.push({ ...v, file: path.relative(process.cwd(), file) });
      }
    } catch {
      // ignore read errors
    }
  }

  const passed = allViolations.length === 0;
  const score = Math.max(0, 100 - allViolations.length * 10);

  if (sarifOut) {
    console.log(JSON.stringify(generateSarifReport(target, allViolations), null, 2));
    process.exit(passed ? 0 : 1);
  }

  if (compact) {
    if (passed) {
      console.log(JSON.stringify({ status: "CLEAN", score, files_scanned: files.length }));
    } else {
      console.log(JSON.stringify({
        status: "VIOLATION",
        score,
        issues_count: allViolations.length,
        issues: allViolations.slice(0, 15).map(v => ({
          file: v.file,
          line: v.line_number,
          rule: v.rule_id,
          cwe: v.cwe_id,
          fix: v.remediation_advice,
        })),
      }));
    }
    process.exit(passed ? 0 : 1);
  }

  if (jsonOut) {
    console.log(JSON.stringify({
      target,
      total_files: files.length,
      total_lines: totalLines,
      score,
      passed,
      violations: allViolations,
    }, null, 2));
    process.exit(passed ? 0 : 1);
  }

  // Pretty terminal output
  console.log(`\n\x1b[1;36m🛡️  SaniLine Security Audit Report\x1b[0m`);
  console.log(`\x1b[2mTarget: ${target} | Policy: ${level.toUpperCase()}\x1b[0m\n`);

  if (passed) {
    console.log(`\x1b[1;32m✔ 100% CLEAN - No security threats detected!\x1b[0m`);
    console.log(`\x1b[2mScanned ${files.length} files (${totalLines} lines) with zero violations.\x1b[0m\n`);
  } else {
    console.log(`\x1b[1;31m✖ ${allViolations.length} Security Threat(s) Neutralization Required:\x1b[0m\n`);
    for (const v of allViolations) {
      const color = v.severity === Severity.CRITICAL ? "\x1b[1;31m" : "\x1b[1;33m";
      console.log(`  ${color}[${v.severity}]\x1b[0m \x1b[1m${v.file}:${v.line_number}\x1b[0m`);
      console.log(`    \x1b[36m${v.rule_id}\x1b[0m (${v.cwe_id}): ${v.title}`);
      console.log(`    \x1b[2mFix: ${v.remediation_advice}\x1b[0m\n`);
    }
    console.log(`\x1b[1mCompliance Score:\x1b[0m \x1b[31m${score}/100\x1b[0m (DoD STIG / NIST SSDF Non-Compliant)`);
    console.log(`\x1b[2mTip: Run 'saniline sanitize ${target} --in-place' to auto-patch.\x1b[0m\n`);
  }

  process.exit(passed ? 0 : 1);

} else if (command === "sanitize") {
  const target = args[1];
  if (!target || !fs.existsSync(target)) {
    console.error(`\x1b[31mError:\x1b[0m File or directory not found: ${target}`);
    process.exit(1);
  }

  const inPlace = args.includes("--in-place") || args.includes("-i");
  const engine = new SaniLine({ action: SanitizeAction.AUTOPATCH });
  const files = collectFiles(target);

  if (!inPlace && files.length === 1) {
    const content = fs.readFileSync(files[0], "utf-8");
    const res = engine.sanitizeCode(content);
    process.stdout.write(res.sanitizedCode);
    process.exit(0);
  }

  let totalPatched = 0;
  for (const file of files) {
    const content = fs.readFileSync(file, "utf-8");
    const ext = path.extname(file).replace(".", "");
    const res = engine.sanitizeCode(content, ext);
    if (res.wasModified) {
      if (inPlace) {
        fs.writeFileSync(file, res.sanitizedCode, "utf-8");
      }
      totalPatched += res.violations.length;
      console.log(`\x1b[32m✔ Auto-patched:\x1b[0m ${file} (${res.violations.length} threat(s) neutralized)`);
    }
  }

  console.log(`\n\x1b[1;32m✔ Sanitization Complete!\x1b[0m ${totalPatched} threat(s) auto-patched across ${files.length} files.`);
  process.exit(0);

} else if (command === "stream") {
  const engine = new SaniLine({ action: SanitizeAction.AUTOPATCH });
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    terminal: false,
  });

  let lineNo = 1;
  rl.on("line", (line) => {
    const res = engine.sanitizeLine(line, lineNo++);
    console.log(res.sanitizedCode);
  });

} else if (command === "rules") {
  console.log(`\n\x1b[1;36m🛡️  SaniLine Military-Grade Defense Rules Matrix\x1b[0m\n`);
  console.log("┌──────────────┬─────────────────────────────────────────────────┬──────────┬────────────┐");
  console.log("│ Rule ID      │ Rule Title / Standard                           │ Severity │ Auto-Patch │");
  console.log("├──────────────┼─────────────────────────────────────────────────┼──────────┼────────────┤");
  for (const r of RULES_CATALOG) {
    const sevColor = r.severity === Severity.CRITICAL ? "\x1b[31mCRITICAL\x1b[0m" : (r.severity === Severity.HIGH ? "\x1b[33mHIGH    \x1b[0m" : "\x1b[36mMEDIUM  \x1b[0m");
    const patch = r.auto_patch ? "\x1b[32m  Yes   \x1b[0m" : "\x1b[2m  Flag  \x1b[0m";
    const rulePad = r.rule_id.padEnd(12);
    const titleTrunc = r.title.length > 47 ? r.title.slice(0, 44) + "..." : r.title.padEnd(47);
    console.log(`│ ${rulePad} │ ${titleTrunc} │ ${sevColor} │ ${patch} │`);
  }
  console.log("└──────────────┴─────────────────────────────────────────────────┴──────────┴────────────┘\n");
  process.exit(0);

} else if (command === "hook") {
  const sub = args[1];
  if (sub === "install") {
    const gitDir = path.join(process.cwd(), ".git");
    if (!fs.existsSync(gitDir)) {
      console.error(`\x1b[31mError:\x1b[0m No .git repository found in ${process.cwd()}`);
      process.exit(1);
    }
    const hooksDir = path.join(gitDir, "hooks");
    if (!fs.existsSync(hooksDir)) fs.mkdirSync(hooksDir, { recursive: true });
    const hookPath = path.join(hooksDir, "pre-commit");
    const script = `#!/bin/sh
# SaniLine Pre-Commit Security Shield
npx saniline check . --compact
EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ]; then
  echo "❌ SaniLine: Commit blocked due to security violations."
  echo "💡 Run 'npx saniline sanitize . --in-place' to fix."
  exit 1
fi
exit 0
`;
    fs.writeFileSync(hookPath, script, { mode: 0o755 });
    console.log(`\x1b[32m✔ Git pre-commit hook installed successfully at:\x1b[0m ${hookPath}`);
    process.exit(0);
  } else {
    console.error(`Unknown hook command: ${sub}. Usage: saniline hook install`);
    process.exit(1);
  }

} else if (command === "mcp") {
  require("../lib/mcp.cjs").main();

} else {
  console.error(`\x1b[31mUnknown command:\x1b[0m ${command}`);
  console.log(`Run \x1b[1msaniline --help\x1b[0m for available commands.`);
  process.exit(1);
}
