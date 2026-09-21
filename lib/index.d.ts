/**
 * SaniLine TypeScript Definitions
 * Military-Grade Line-by-Line Code Sanitizer & Security Shield for AI Agents
 */

import type { Transform } from "node:stream";

export const VERSION: string;
export const TAGLINE: string;

export enum SecurityLevel {
  STANDARD = "standard",
  STRICT = "strict",
  MILITARY = "military",
}

export enum SanitizeAction {
  AUDIT = "audit",
  REDACT = "redact",
  AUTOPATCH = "autopatch",
  BLOCK = "block",
}

export enum Severity {
  LOW = "LOW",
  MEDIUM = "MEDIUM",
  HIGH = "HIGH",
  CRITICAL = "CRITICAL",
}

export interface RuleDefinition {
  rule_id: string;
  title: string;
  category: string;
  standard: string;
  severity: Severity;
  auto_patch: boolean;
  remediation: string;
}

export const RULES_CATALOG: RuleDefinition[];

export interface Violation {
  rule_id: string;
  title: string;
  cwe_id: string;
  severity: Severity;
  line_number: number;
  remediation_advice: string;
  file?: string;
}

export interface CompactIssue {
  line: number;
  rule: string;
  cwe: string;
  fix: string;
}

export interface TokenCompactResult {
  status: "CLEAN" | "MODIFIED" | "VIOLATION";
  patch?: string;
  issues?: CompactIssue[];
}

export interface SanitizedLineResult {
  originalCode: string;
  sanitizedCode: string;
  isClean: boolean;
  wasModified: boolean;
  violations: Violation[];
  toTokenCompact(): TokenCompactResult;
}

export interface SanitizedBlockResult {
  originalCode: string;
  sanitizedCode: string;
  isClean: boolean;
  wasModified: boolean;
  violations: Violation[];
  toTokenCompact(): TokenCompactResult;
}

export interface SaniLineOptions {
  level?: SecurityLevel;
  action?: SanitizeAction;
  defaultLanguage?: string;
  language?: string;
  signal?: AbortSignal;
}

export class SaniLine {
  level: SecurityLevel;
  action: SanitizeAction;
  defaultLanguage: string;

  constructor(options?: SaniLineOptions);
  sanitizeLine(line: string, lineNumber?: number, language?: string | null): SanitizedLineResult;
  sanitizeCode(code: string, language?: string | null): SanitizedBlockResult;
}

/**
 * Web Streams API TransformStream for real-time LLM token streams.
 * Compatible with Vercel AI SDK (streamText.pipeThrough), Next.js, Cloudflare Workers, and Browser.
 */
export class SaniLineTransformStream {
  readonly readable: ReadableStream<string>;
  readonly writable: WritableStream<string | Uint8Array>;
  constructor(options?: SaniLineOptions);
}

/**
 * Node.js stream.Transform for piping streams in Node.js applications.
 */
export class SaniLineNodeTransform extends Transform {
  constructor(options?: SaniLineOptions);
}

export function calculateShannonEntropy(str: string): number;

export function generateSarifReport(target: string, violations: Violation[]): Record<string, any>;

export default SaniLine;
