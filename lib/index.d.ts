/**
 * SaniLine TypeScript Definitions
 */

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

export interface Violation {
  rule_id: string;
  title: string;
  cwe_id: string;
  severity: Severity;
  line_number: number;
  remediation_advice: string;
}

export interface SanitizedLineResult {
  originalCode: string;
  sanitizedCode: string;
  isClean: boolean;
  wasModified: boolean;
  violations: Violation[];
  toTokenCompact(): Record<string, any>;
}

export interface SanitizedBlockResult {
  originalCode: string;
  sanitizedCode: string;
  isClean: boolean;
  wasModified: boolean;
  violations: Violation[];
  toTokenCompact(): Record<string, any>;
}

export interface SaniLineOptions {
  level?: SecurityLevel;
  action?: SanitizeAction;
  defaultLanguage?: string;
}

export class SaniLine {
  level: SecurityLevel;
  action: SanitizeAction;
  defaultLanguage: string;

  constructor(options?: SaniLineOptions);
  sanitizeLine(line: string, lineNumber?: number, language?: string | null): SanitizedLineResult;
  sanitizeCode(code: string, language?: string | null): SanitizedBlockResult;
}

export function calculateShannonEntropy(str: string): number;

export default SaniLine;
