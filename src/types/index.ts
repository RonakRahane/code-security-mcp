// Severity & Category Types

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

// Security Pattern Definition

export interface SecurityPattern {
  /** Unique rule identifier, for example "SQL_INJECTION_CONCAT". */
  id: string;
  /** Matched against each line of code. */
  regex: RegExp;
  severity: Severity;
  category: Category;
  /** CWE identifier, for example "CWE-89". */
  cweId: string;
  message: string;
  remediation: string;
  /** Languages this pattern applies to. "*" matches every language. */
  languages: string[];
  /**
   * Which view of a source line the pattern is matched against.
   *
   * - `"masked"` (default): string and comment contents are blanked first, so
   *   the rule fires only on executable code. Keeps a code sample in a
   *   docstring from being reported as a vulnerability.
   * - `"literal"`: only comments are blanked. Needed by rules whose evidence
   *   lives inside a literal, such as the algorithm name in `createHash("md5")`
   *   or the `"*"` in `ALLOWED_HOSTS = ["*"]`, which masking would erase.
   */
  matchScope?: "masked" | "literal";
}

// Scan Finding (result of a pattern match)

export interface Finding {
  ruleId: string;
  severity: Severity;
  category: Category;
  cweId: string;
  message: string;
  filePath: string;
  /** 1-indexed. */
  line: number;
  /** Matching line, trimmed and redacted where the rule matched a secret. */
  lineContent: string;
  remediation: string;
  /** Derived from contextual indicators on the matched line. */
  confidence?: "high" | "medium" | "low";
  /** Engine that produced this result. Optional for backwards compatibility. */
  source?: "semgrep" | "compatibility" | "secret-detector" | "iac-detector";
  /**
   * Set once the file-context downgrade has been applied, so a finding is
   * never graded twice. Three engines produce findings and each used to decide
   * this for itself: the pattern engine downgraded a fixture, Semgrep and the
   * secret detector did not, and the same fake credential in the same file was
   * reported at both critical and low. Grading now happens at one choke point
   * and this marker keeps it idempotent.
   */
  contextGraded?: boolean;
  /** Stable, non-secret identifier used by baseline mode and deduplication. */
  fingerprint?: string;
  /** Optional framework/rule metadata supplied by the underlying engine. */
  metadata?: Record<string, string | number | boolean>;
}

// Scan Result (aggregate for a file)

export interface ScanResult {
  filePath: string;
  language: string;
  totalFindings: number;
  findings: Finding[];
  summary: SeveritySummary;
  /**
   * False when no rules applied to the file, so zero findings means "not
   * examined" rather than "clean". Callers aggregate this into coverage.
   */
  analyzed: boolean;
}

export interface SeveritySummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

// Dependency Vulnerability

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

export type ScanEngine = "semgrep" | "compatibility" | "hybrid";

export interface ScanEngineStatus {
  engine: ScanEngine;
  available: boolean;
  used: boolean;
  /**
   * True when Semgrep was switched off deliberately, rather than being
   * missing. A pattern-only scan is a gap either way, but only one of the two
   * is a decision the operator made, and the CLI verdict distinguishes them.
   */
  disabled?: boolean;
  message?: string;
  /**
   * Files Semgrep analysed, per its own reporting. It applies built-in ignore
   * rules and skips files it cannot parse, so this differs from the number of
   * files it was asked to scan.
   */
  filesAnalyzedBySemgrep?: number;
  /** Files the built-in pattern engine covered, including Semgrep's gaps. */
  filesAnalyzedByPatternEngine?: number;
}

export interface ProjectScanSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface ScanCoverage {
  /** Files read and analysed. */
  filesScanned: number;
  /** Files deliberately excluded (ignore rules, binaries, size caps). */
  filesSkipped: number;
  /** Files that could not be read. Non-zero means results are incomplete. */
  filesUnreadable: number;
  /** True when the file cap was reached before the tree was fully enumerated. */
  truncated: boolean;
  /** Wall-clock duration of the scan. */
  durationMs: number;
  /** Files that received no static-analysis pass. Anything above zero is a coverage hole. */
  filesWithoutStaticAnalysis?: number;
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
  /** Explicit statement of what the scan did and did not cover. */
  coverage: ScanCoverage;
  baseline?: {
    applied: boolean;
    path?: string;
    suppressedFindings: number;
    suppressedDependencies: number;
  };
}

// Secret Finding (extends Finding with entropy)

export interface SecretFinding extends Finding {
  /** Shannon entropy of the detected value. */
  entropyScore: number;
  secretType: string;
}

export interface HistorySecretFinding extends SecretFinding {
  /** Commit that introduced or contained the secret. */
  commitHash: string;
  /** ISO-8601 commit timestamp, when available. */
  commitDate?: string;
}

// Sentinel Config

export interface SentinelConfig {
  /** Relative paths, basenames, or globs to skip. */
  ignorePaths?: string[];
  /** Rule IDs to suppress from results. */
  ignoreRules?: string[];
  /** Only report findings at or above this severity. */
  minimumSeverity?: Severity;
  /** CI fails when findings at or above this severity exist. */
  failOnSeverity?: Severity;
  /** Upper bound on files visited in one scan. */
  maxFiles?: number;
  /** Parallel file reads, bounded to protect file-descriptor limits. */
  concurrency?: number;
  /** Disable every outbound network call: advisory lookups and registry rules. */
  offline?: boolean;
  semgrep?: {
    /** Set false to force the built-in pattern engine. */
    enabled?: boolean;
    timeoutMs?: number;
    /**
     * Registry rule packs, for example "p/javascript". Empty by default:
     * packs are downloaded at scan time and float between versions, so opting
     * in is what keeps a scan reproducible.
     */
    registryRulesets?: string[];
  };
}

// GitHub PR Types

export interface PrInfo {
  number: number;
  title: string;
  author: string;
  createdAt: string;
  /**
   * Size of the change, when the endpoint that produced this record reported
   * it. The pull-request list endpoint does not, so these are undefined there;
   * only fetching a single pull request fills them in. Undefined means unknown,
   * which a zero would misrepresent as an empty change.
   */
  changedFiles?: number;
  additions?: number;
  deletions?: number;
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

export interface CweEntry {
  id: string;
  name: string;
  description: string;
  impact: string;
  examples: string[];
  remediation: string[];
  references: string[];
}
