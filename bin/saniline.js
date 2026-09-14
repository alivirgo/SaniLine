#!/usr/bin/env node
/**
 * SaniLine CLI for Node.js
 */

const fs = require("fs");
const path = require("path");
const readline = require("readline");
const { SaniLine, VERSION, TAGLINE } = require("../lib/index.cjs");

const args = process.argv.slice(2);

if (args.length === 0 || args.includes("--help") || args.includes("-h")) {
  console.log(`\x1b[1;36mSaniLine\x1b[0m v${VERSION} - \x1b[2m${TAGLINE}\x1b[0m\n`);
  console.log("Usage:");
  console.log("  saniline check <path> [--compact]");
  console.log("  saniline sanitize <file> [--in-place]");
  console.log("  saniline stream");
  console.log("  saniline --version\n");
  process.exit(0);
}

if (args.includes("--version") || args.includes("-v")) {
  console.log(`saniline v${VERSION}`);
  process.exit(0);
}

const command = args[0];

if (command === "check") {
  const target = args[1];
  if (!target || !fs.existsSync(target)) {
    console.error(`Error: File or directory not found: ${target}`);
    process.exit(1);
  }
  const compact = args.includes("--compact") || args.includes("-c");
  const content = fs.readFileSync(target, "utf-8");
  const engine = new SaniLine();
  const res = engine.sanitizeCode(content);

  if (compact) {
    console.log(JSON.stringify(res.toTokenCompact()));
  } else {
    console.log(`\x1b[1;36mSaniLine Security Audit:\x1b[0m ${target}`);
    console.log(`Violations Found: ${res.violations.length}`);
    for (const v of res.violations) {
      console.log(`  Line ${v.line_number} [${v.rule_id} ${v.cwe_id}]: ${v.title}`);
    }
  }
  process.exit(res.isClean ? 0 : 1);
} else if (command === "sanitize") {
  const target = args[1];
  if (!target || !fs.existsSync(target)) {
    console.error(`Error: File not found: ${target}`);
    process.exit(1);
  }
  const inPlace = args.includes("--in-place") || args.includes("-i");
  const content = fs.readFileSync(target, "utf-8");
  const engine = new SaniLine();
  const res = engine.sanitizeCode(content);

  if (inPlace) {
    fs.writeFileSync(target, res.sanitizedCode, "utf-8");
    console.log(`✓ Sanitized in-place: ${target} (${res.violations.length} threats neutralized)`);
  } else {
    process.stdout.write(res.sanitizedCode);
  }
  process.exit(0);
} else if (command === "stream") {
  const engine = new SaniLine();
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
} else {
  console.error(`Unknown command: ${command}`);
  process.exit(1);
}
