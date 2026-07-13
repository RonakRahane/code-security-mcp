// ─── Severity & Category Types ───────────────────────────────────────────────

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type Category =
  | "injection"
  | "xss"
  | "secrets"
  | "ai"
  | "iac"
  | "supply-chain"
  | "auth"
  | "crypto"
  | "dangerous-functions"
  | "path-traversal"
  | "prototype-pollution"
  | "miscellaneous";

// ─── Security Pattern Definition ─────────────────────────────────────────────

export interface SecurityPattern {
  /** Unique rule identifier, e.g., "SQL_INJECTION_CONCAT" */
  id: string;
  /** Regex pattern to match against each line of code */
  regex: RegExp;
  /** Severity level of this finding */
  severity: Severity;
  /** Category grouping */
  category: Category;
  /** CWE identifier, e.g., "CWE-89" */
  cweId: string;
  /** Human-readable description of the issue */
  message: string;
  /** Suggested fix */
  remediation: string;
  /** Languages this pattern applies to. Use "*" for all languages */
  languages: string[];
}

// ─── Scan Finding (result of a pattern match) ────────────────────────────────

export interface Finding {
  /** Rule that triggered this finding */
  ruleId: string;
  /** Severity */
  severity: Severity;
  /** Category */
  category: Category;
  /** CWE identifier */
  cweId: string;
  /** Description */
  message: string;
  /** File where the finding was detected */
  filePath: string;
  /** Line number (1-indexed) */
  line: number;
  /** Content of the matching line (trimmed) */
  lineContent: string;
  /** Suggested remediation */
  remediation: string;
  /** Confidence level based on contextual indicators */
  confidence?: "high" | "medium" | "low";
  /** Scanner that produced this result. Kept optional for backwards compatibility. */
  source?: "semgrep" | "compatibility" | "secret-detector" | "iac-detector";
  /** Stable, non-secret identifier used by baseline mode and deduplication. */
  fingerprint?: string;
  /** Optional framework/rule metadata supplied by the underlying engine. */
  metadata?: Record<string, string | number | boolean>;
}

// ─── Scan Result (aggregate for a file) ──────────────────────────────────────

export interface ScanResult {
  filePath: string;
  language: string;
  totalFindings: number;
  findings: Finding[];
  summary: SeveritySummary;
}

export interface SeveritySummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

// ─── Dependency Vulnerability ────────────────────────────────────────────────

export interface DependencyVulnerability {
  package: string;
  ecosystem?: string;
  /** Advisory identifier when supplied by OSV (for example GHSA-xxxx or CVE-xxxx). */
  advisoryId?: string;
  severity: Severity;
  title: string;
  url: string;
  installedVersion: string;
  patchedVersion: string;
  path: string;
  /** Manifest or lockfile from which the dependency was resolved. */
  manifestPath?: string;
  /** Whether a direct import/reference was found in the project source. */
  reachability?: "reachable" | "unreachable" | "unknown";
  /** Stable, non-secret identifier used by baseline mode and deduplication. */
  fingerprint?: string;
}

export type ScanEngine = "semgrep" | "compatibility";

export interface ScanEngineStatus {
  engine: ScanEngine;
  available: boolean;
  used: boolean;
  message?: string;
}

export interface ProjectScanSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface ProjectSecurityScan {
  rootPath: string;
  generatedAt: string;
  filesScanned: number;
  filesSkipped: number;
  findings: Finding[];
  dependencyVulnerabilities: DependencyVulnerability[];
  summary: ProjectScanSummary;
  engine: ScanEngineStatus;
  warnings: string[];
  baseline?: {
    applied: boolean;
    path?: string;
    suppressedFindings: number;
    suppressedDependencies: number;
  };
}

// ─── Secret Finding (extends Finding with entropy) ───────────────────────────

export interface SecretFinding extends Finding {
  /** Shannon entropy score of the detected value */
  entropyScore: number;
  /** The type of secret detected */
  secretType: string;
}

export interface HistorySecretFinding extends SecretFinding {
  /** Commit hash that introduced or contained the secret */
  commitHash: string;
  /** ISO-8601 commit timestamp when available */
  commitDate?: string;
}

// ─── Sentinel Config ────────────────────────────────────────────────────────

export interface SentinelConfig {
  /** Relative file or directory paths to skip */
  ignorePaths?: string[];
  /** Rule IDs to suppress from results */
  ignoreRules?: string[];
  /** Only include findings at or above this severity */
  minimumSeverity?: Severity;
  /** CI should fail when findings at or above this severity exist */
  failOnSeverity?: Severity;
}

// ─── GitHub PR Types ─────────────────────────────────────────────────────────

export interface PrInfo {
  number: number;
  title: string;
  author: string;
  createdAt: string;
  changedFiles: number;
  additions: number;
  deletions: number;
}

export interface PrDiffFile {
  filename: string;
  status: string;
  additions: number;
  deletions: number;
  patch?: string;
}

export interface SecurityReviewComment {
  path: string;
  line: number;
  body: string;
  severity: Severity;
}

// ─── CWE Knowledge Base ──────────────────────────────────────────────────────

export interface CweEntry {
  id: string;
  name: string;
  description: string;
  impact: string;
  examples: string[];
  remediation: string[];
  references: string[];
}
