/**
 * Markdown renderer for security reports.
 *
 * No filesystem, process, scanner, or network dependencies. Callers collect
 * findings with whichever engines are available, then pass normalized metadata
 * here to render the same report for MCP, CI, and a .md artifact.
 */

export type ReportSeverity = "critical" | "high" | "medium" | "low" | "info";

export type ReportFindingSource =
  | "sast"
  | "secrets"
  | "ai"
  | "iac"
  | "semgrep"
  | "native"
  | string;

/**
 * The subset of a code finding the renderer needs. Structurally compatible with
 * Finding. `lineContent` is excluded on purpose: a report must not echo source
 * snippets, least of all where the finding identifies a secret.
 */
export interface MarkdownReportFinding {
  severity: ReportSeverity | string;
  ruleId?: string;
  id?: string;
  title?: string;
  message?: string;
  /** How to fix it. Rendered in the detail section. */
  remediation?: string;
  cweId?: string;
  category?: string;
  source?: ReportFindingSource;
  engine?: string;
  filePath?: string;
  file?: string;
  path?: string;
  line?: number;
}

/**
 * Dependency-vulnerability metadata. Structurally compatible with
 * DependencyVulnerability, and accepts the common aliases OSV adapters emit.
 */
export interface MarkdownReportDependency {
  severity: ReportSeverity | string;
  package?: string;
  name?: string;
  title?: string;
  message?: string;
  ecosystem?: string;
  installedVersion?: string;
  currentVersion?: string;
  patchedVersion?: string;
  fixedVersion?: string;
}

export interface MarkdownReportInput {
  /** Display name only; filesystem paths should be supplied via projectRoot. */
  projectName?: string;
  /** Passed in by the caller to keep rendering deterministic and testable. */
  generatedAt?: string | Date;
  /** Used solely to turn finding locations into relative paths. */
  projectRoot?: string;
  filesScanned?: number;
  filesWithFindings?: number;
  riskLevel?: string;
  findings?: readonly MarkdownReportFinding[];
  dependencies?: readonly MarkdownReportDependency[];
  /** Which analysis engine produced the results. */
  engine?: {
    engine?: string;
    available?: boolean;
    used?: boolean;
    message?: string;
  };
  /**
   * What the scan covered. Rendered prominently, so a reader does not read
   * "no findings" as "secure" when the scan had blind spots.
   */
  coverage?: {
    filesScanned?: number;
    filesSkipped?: number;
    filesUnreadable?: number;
    truncated?: boolean;
    durationMs?: number;
  };
  /** Non-fatal problems encountered during the scan. */
  warnings?: readonly string[];
}

export interface MarkdownReportOptions {
  /** Maximum number of rows rendered in each findings section. Default: 50. */
  maxRowsPerSection?: number;
  /** Include a clearly labelled empty table for sections without findings. */
  includeEmptySections?: boolean;
  /** Render dependency upgrade recommendations when a fixed version is known. */
  includeRecommendedUpgrades?: boolean;
  /** Use false when a calling UI supplies its own follow-up prompt. */
  closingPrompt?: string | false;
  /**
   * Appends a per-finding section carrying the full message, the rule and CWE
   * identifiers, and the remediation. The summary tables truncate to stay
   * readable in a terminal, so without this the report says what is wrong but
   * never what to do about it. Defaults to true.
   */
  includeFindingDetail?: boolean;
}

type ReportSection = "secrets" | "sast" | "ai" | "iac";

interface NormalizedFinding {
  issue: string;
  location: string;
  /** Location without the line suffix, so distinct files can be counted. */
  file: string;
  severity: ReportSeverity;
  section: ReportSection;
  ruleId: string;
  cweId: string;
  remediation: string;
  isSecret: boolean;
}

interface NormalizedDependency {
  issue: string;
  library: string;
  packageName: string;
  ecosystem: string;
  installedVersion: string;
  patchedVersion: string;
  severity: ReportSeverity;
}

const SEVERITY_ORDER: Record<ReportSeverity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

const SECTION_DEFINITIONS: ReadonlyArray<{ key: ReportSection; title: string }> = [
  { key: "secrets", title: "Secrets" },
  { key: "sast", title: "SAST" },
  { key: "ai", title: "AI / LLM Security" },
  { key: "iac", title: "Infrastructure as Code" },
];

const DEFAULT_MAX_ROWS_PER_SECTION = 50;
const DEFAULT_CLOSING_PROMPT =
  "Would you like me to help prioritize remediation or walk through these findings individually?";

const ANSI_OSC_SEQUENCE = /\u001B\][\s\S]*?(?:\u0007|\u001B\\)/g;
const ANSI_CSI_SEQUENCE = /(?:\u001B\[|\u009B)[0-?]*[ -/]*[@-~]/g;
const CONTROL_CHARACTERS = /[\u0000-\u001F\u007F-\u009F]/g;

/**
 * Renders a complete Markdown report. The result is safe for a
 * terminal-oriented Markdown client and can be written unchanged to a .md file.
 */
export function renderMarkdownReport(
  input: MarkdownReportInput,
  options: MarkdownReportOptions = {}
): string {
  const findings = (input.findings ?? []).map((finding) => normalizeFinding(finding, input.projectRoot));
  const dependencies = (input.dependencies ?? []).map(normalizeDependency);
  const maxRows = clampMaxRows(options.maxRowsPerSection);
  const includeEmptySections = options.includeEmptySections ?? false;
  const includeRecommendedUpgrades = options.includeRecommendedUpgrades ?? true;

  const reportTitle = escapeMarkdownInline(
    sanitizeCellValue(input.projectName || "Security Scan", 120)
  );
  const allSeverities = [
    ...findings.map((finding) => finding.severity),
    ...dependencies.map((dependency) => dependency.severity),
  ];
  const severitySummary = summarizeSeverities(allSeverities);
  const totalFindings = findings.length + dependencies.length;
  // Counted per file. Counting locations instead made one file holding three
  // findings report as three files with findings.
  const derivedFilesWithFindings = new Set(
    findings.map((finding) => finding.file).filter((file) => file !== "Unknown location")
  ).size;
  const riskLevel = normalizeRiskLevel(input.riskLevel, severitySummary);

  const lines: string[] = [`# Sentinel Security Report: ${reportTitle}`, ""];

  const generatedAt = formatGeneratedAt(input.generatedAt);
  if (generatedAt) {
    lines.push(`_Generated: ${escapeMarkdownInline(generatedAt)}_`, "");
  }

  lines.push("## Summary", "");
  lines.push(renderTextBlock(renderSummaryTable({
    filesScanned: input.filesScanned,
    filesWithFindings: input.filesWithFindings ?? derivedFilesWithFindings,
    totalFindings,
    riskLevel,
    severitySummary,
  })), "");

  appendCoverageSection(lines, input);

  for (const definition of SECTION_DEFINITIONS) {
    const sectionFindings = findings
      .filter((finding) => finding.section === definition.key)
      .sort(compareFindings);

    if (sectionFindings.length === 0 && !includeEmptySections) continue;

    lines.push(`## ${definition.title} (${pluralize(sectionFindings.length, "finding")})`, "");
    if (sectionFindings.length === 0) {
      lines.push("No findings in this category.", "");
      continue;
    }

    const displayedRows = sectionFindings
      .slice(0, maxRows)
      .map((finding) => [
        sanitizeIssue(finding.issue, definition.key === "secrets", 76),
        sanitizeCellValue(finding.location, 48),
        finding.severity.toUpperCase(),
      ]);

    lines.push(
      renderTextBlock(renderAsciiTable(["Issue", "File", "Severity"], displayedRows)),
      ""
    );
    appendOmissionNotice(lines, sectionFindings.length, displayedRows.length);
  }

  const sortedDependencies = [...dependencies].sort(compareDependencies);
  if (sortedDependencies.length > 0 || includeEmptySections) {
    lines.push(`## SCA: Dependency Vulnerabilities (${pluralize(sortedDependencies.length, "finding")})`, "");
    if (sortedDependencies.length === 0) {
      lines.push("No vulnerable dependencies were reported.", "");
    } else {
      const displayedRows = sortedDependencies
        .slice(0, maxRows)
        .map((dependency) => [
          sanitizeCellValue(dependency.issue, 76),
          sanitizeCellValue(dependency.library, 40),
          dependency.severity.toUpperCase(),
        ]);
      lines.push(
        renderTextBlock(renderAsciiTable(["Issue", "Library", "Severity"], displayedRows)),
        ""
      );
      appendOmissionNotice(lines, sortedDependencies.length, displayedRows.length);
    }
  }

  if (includeRecommendedUpgrades) {
    const upgrades = collectRecommendedUpgrades(dependencies);
    if (upgrades.length > 0) {
      lines.push("## Recommended Upgrades", "");
      const displayedRows = upgrades
        .slice(0, maxRows)
        .map((upgrade) => [
          sanitizeCellValue(upgrade.library, 40),
          sanitizeCellValue(upgrade.currentVersion, 24),
          sanitizeCellValue(upgrade.upgradeTo, 24),
        ]);
      lines.push(
        renderTextBlock(renderAsciiTable(["Library", "Current", "Upgrade To"], displayedRows)),
        ""
      );
      appendOmissionNotice(lines, upgrades.length, displayedRows.length);
    }
  }

  if (options.includeFindingDetail !== false && findings.length > 0) {
    appendFindingDetail(lines, findings);
  }

  const closingPrompt = options.closingPrompt === undefined
    ? DEFAULT_CLOSING_PROMPT
    : options.closingPrompt;
  if (closingPrompt !== false) {
    lines.push(escapeMarkdownInline(sanitizeCellValue(closingPrompt, 300)));
  }

  return lines.join("\n").trimEnd() + "\n";
}


/** Renders a fixed-width ASCII table. Exported so callers and tests share the same table semantics. */
function renderAsciiTable(
  headers: readonly string[],
  rows: readonly (readonly string[])[]
): string {
  if (headers.length === 0) return "";

  const normalizedHeaders = headers.map((header) => sanitizeCellValue(header, 120));
  const normalizedRows = rows.map((row) =>
    normalizedHeaders.map((_, index) => sanitizeCellValue(row[index] ?? "", 120))
  );
  const widths = normalizedHeaders.map((header, index) => Math.max(
    displayWidth(header),
    ...normalizedRows.map((row) => displayWidth(row[index]))
  ));

  const border = `+${widths.map((width) => "-".repeat(width + 2)).join("+")}+`;
  const renderRow = (cells: readonly string[]) =>
    `|${cells.map((cell, index) => ` ${cell}${" ".repeat(widths[index] - displayWidth(cell) + 1)}`).join("|")}|`;

  return [
    border,
    renderRow(normalizedHeaders),
    border,
    ...normalizedRows.flatMap((row) => [renderRow(row), border]),
  ].join("\n");
}

/**
 * Per-finding detail, grouped by file.
 *
 * The summary tables truncate every column to keep the ASCII layout readable in
 * a terminal, which loses the end of most messages and shows no remediation at
 * all. This section carries the full text, so the report is something a
 * developer can work from rather than only a count of what is wrong.
 *
 * Files are ordered by their worst finding, and findings within a file by
 * severity, so the first thing in the section is the thing to fix first.
 */
function appendFindingDetail(lines: string[], findings: readonly NormalizedFinding[]): void {
  const byFile = new Map<string, NormalizedFinding[]>();
  for (const finding of findings) {
    const group = byFile.get(finding.file);
    if (group) group.push(finding);
    else byFile.set(finding.file, [finding]);
  }

  const worstRank = (group: readonly NormalizedFinding[]) =>
    Math.min(...group.map((finding) => SEVERITY_ORDER[finding.severity]));

  const files = [...byFile.entries()].sort((left, right) =>
    worstRank(left[1]) - worstRank(right[1]) ||
    right[1].length - left[1].length ||
    compareText(left[0], right[0])
  );

  lines.push("## Findings in Detail", "");

  for (const [file, group] of files) {
    group.sort(compareFindings);
    lines.push(`### ${escapeMarkdownInline(sanitizeCellValue(file, 200))}`, "");

    for (const finding of group) {
      const heading = [finding.severity.toUpperCase(), finding.ruleId]
        .filter(Boolean)
        .join(" — ");
      lines.push(`#### ${escapeMarkdownInline(sanitizeCellValue(heading, 120))}`, "");

      const facts: string[] = [
        `- **Location:** \`${escapeMarkdownInline(sanitizeCellValue(finding.location, 200))}\``,
      ];
      if (finding.cweId) {
        facts.push(`- **CWE:** ${escapeMarkdownInline(sanitizeCellValue(finding.cweId, 40))}`);
      }
      // Full text, not the truncated table cell. Secret findings still go
      // through the redactor in case the message quotes what it matched.
      facts.push(
        `- **Issue:** ${escapeMarkdownInline(sanitizeIssue(finding.issue, finding.isSecret, 2000))}`
      );
      if (finding.remediation) {
        facts.push(
          `- **Fix:** ${escapeMarkdownInline(sanitizeIssue(finding.remediation, finding.isSecret, 2000))}`
        );
      }

      lines.push(...facts, "");
    }
  }

  lines.push(
    "Source lines are deliberately not reproduced here: a report is often committed or " +
    "shared, and a finding that identifies a secret would carry it along. Open the file " +
    "at the location above to see the code.",
    ""
  );
}

function normalizeFinding(finding: MarkdownReportFinding, projectRoot?: string): NormalizedFinding {
  const section = inferSection(finding);
  const rawIssue = firstText(
    finding.title,
    finding.message,
    humanizeIdentifier(firstText(finding.ruleId, finding.id)),
    "Security finding"
  );

  return {
    issue: rawIssue,
    location: formatLocation(finding, projectRoot),
    file: formatFile(finding, projectRoot),
    severity: normalizeSeverity(finding.severity),
    section,
    ruleId: firstText(finding.ruleId, finding.id),
    cweId: firstText(finding.cweId),
    remediation: firstText(finding.remediation),
    isSecret: section === "secrets",
  };
}

function normalizeDependency(dependency: MarkdownReportDependency): NormalizedDependency {
  const packageName = firstText(dependency.package, dependency.name, "Unknown package");
  const installedVersion = firstText(dependency.installedVersion, dependency.currentVersion, "unknown");
  const patchedVersion = firstText(dependency.patchedVersion, dependency.fixedVersion);
  const ecosystem = firstText(dependency.ecosystem).toLowerCase();
  const library = installedVersion === "unknown" ? packageName : `${packageName}@${installedVersion}`;

  return {
    issue: firstText(
      dependency.title,
      dependency.message,
      `Known vulnerability in ${packageName}`
    ),
    library,
    packageName,
    ecosystem,
    installedVersion,
    patchedVersion,
    severity: normalizeSeverity(dependency.severity),
  };
}

function inferSection(finding: MarkdownReportFinding): ReportSection {
  const category = firstText(finding.category).toLowerCase();
  const source = firstText(finding.source, finding.engine).toLowerCase();

  if (category === "secrets" || source.includes("secret")) return "secrets";
  if (category === "ai" || source.includes("llm") || source.includes("ai")) return "ai";
  if (category === "iac" || source.includes("iac") || source.includes("terraform")) return "iac";
  return "sast";
}

/** The file a finding belongs to, with no line number attached. */
function formatFile(finding: MarkdownReportFinding, projectRoot?: string): string {
  const rawPath = firstText(finding.filePath, finding.file, finding.path);
  if (!rawPath) return "Unknown location";

  return relativizePath(rawPath, projectRoot);
}

function formatLocation(finding: MarkdownReportFinding, projectRoot?: string): string {
  const rawPath = firstText(finding.filePath, finding.file, finding.path);
  if (!rawPath) return "Unknown location";

  const relativePath = relativizePath(rawPath, projectRoot);
  const line = Number.isInteger(finding.line) && (finding.line as number) > 0
    ? `:${finding.line}`
    : "";
  return `${relativePath}${line}`;
}

function relativizePath(filePath: string, projectRoot?: string): string {
  const normalizedFilePath = filePath.replace(/\\/g, "/").replace(/^\.\//, "");
  if (!projectRoot) return normalizedFilePath;

  const normalizedRoot = projectRoot
    .replace(/\\/g, "/")
    .replace(/\/+$/, "")
    .replace(/^\.\//, "");

  if (normalizedFilePath === normalizedRoot) return ".";
  if (normalizedRoot && normalizedFilePath.startsWith(`${normalizedRoot}/`)) {
    return normalizedFilePath.slice(normalizedRoot.length + 1);
  }

  return normalizedFilePath;
}

function renderSummaryTable(input: {
  filesScanned?: number;
  filesWithFindings: number;
  totalFindings: number;
  riskLevel: string;
  severitySummary: Record<ReportSeverity, number>;
}): string {
  const rows: string[][] = [
    ["Risk level", input.riskLevel],
    ["Total findings", String(input.totalFindings)],
    ["Critical", String(input.severitySummary.critical)],
    ["High", String(input.severitySummary.high)],
    ["Medium", String(input.severitySummary.medium)],
    ["Low / Info", String(input.severitySummary.low + input.severitySummary.info)],
    ["Files with findings", String(input.filesWithFindings)],
  ];

  if (isNonNegativeFiniteNumber(input.filesScanned)) {
    rows.splice(1, 0, ["Files scanned", String(Math.floor(input.filesScanned))]);
  }

  return renderAsciiTable(["Metric", "Value"], rows);
}

function collectRecommendedUpgrades(dependencies: readonly NormalizedDependency[]): Array<{
  library: string;
  currentVersion: string;
  upgradeTo: string;
  severity: ReportSeverity;
}> {
  const upgrades = new Map<string, {
    library: string;
    currentVersion: string;
    upgradeTo: string;
    severity: ReportSeverity;
  }>();

  for (const dependency of dependencies) {
    if (!isActionableUpgrade(dependency)) continue;

    const key = [dependency.ecosystem, dependency.packageName, dependency.installedVersion].join("\u0000");
    const existing = upgrades.get(key);
    if (!existing || SEVERITY_ORDER[dependency.severity] < SEVERITY_ORDER[existing.severity]) {
      upgrades.set(key, {
        library: dependency.library,
        currentVersion: dependency.installedVersion,
        upgradeTo: dependency.patchedVersion,
        severity: dependency.severity,
      });
    }
  }

  return [...upgrades.values()].sort((left, right) =>
    compareSeverity(left.severity, right.severity) ||
    compareText(left.library, right.library) ||
    compareText(left.upgradeTo, right.upgradeTo)
  );
}

function isActionableUpgrade(dependency: NormalizedDependency): boolean {
  const fixedVersion = dependency.patchedVersion.trim();
  if (!fixedVersion || fixedVersion === dependency.installedVersion) return false;

  return !/^(?:no fix(?: available)?|check(?: the)? (?:advisory|latest|latest safe version)|unknown|n\/?a|none|-)$/i
    .test(fixedVersion);
}

function summarizeSeverities(severities: readonly ReportSeverity[]): Record<ReportSeverity, number> {
  const summary: Record<ReportSeverity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };

  for (const severity of severities) summary[severity]++;
  return summary;
}

function normalizeRiskLevel(
  requestedRiskLevel: string | undefined,
  summary: Record<ReportSeverity, number>
): string {
  // sanitizeCellValue substitutes "-" for an empty value, which is right for a
  // table cell and wrong here: treating it as a caller-supplied level skipped
  // the fallback below, so every report that did not pass one explicitly (the
  // CLI included) showed "-" as its risk level however many findings it held.
  const requested = (requestedRiskLevel ?? "").trim();
  if (requested) {
    const provided = sanitizeCellValue(requested, 20).toUpperCase();
    if (provided && provided !== "-") return provided;
  }
  if (summary.critical > 0) return "CRITICAL";
  if (summary.high > 0) return "HIGH";
  if (summary.medium > 0) return "MEDIUM";
  if (summary.low > 0) return "LOW";
  if (summary.info > 0) return "INFO";
  return "CLEAN";
}

function normalizeSeverity(value: string): ReportSeverity {
  switch (value.toLowerCase()) {
    case "critical": return "critical";
    case "high": return "high";
    case "medium":
    case "moderate": return "medium";
    case "low": return "low";
    case "info":
    case "informational": return "info";
    default: return "info";
  }
}

function compareFindings(left: NormalizedFinding, right: NormalizedFinding): number {
  return compareSeverity(left.severity, right.severity) ||
    compareText(left.location, right.location) ||
    compareText(left.issue, right.issue);
}

function compareDependencies(left: NormalizedDependency, right: NormalizedDependency): number {
  return compareSeverity(left.severity, right.severity) ||
    compareText(left.library, right.library) ||
    compareText(left.issue, right.issue);
}

function compareSeverity(left: ReportSeverity, right: ReportSeverity): number {
  return SEVERITY_ORDER[left] - SEVERITY_ORDER[right];
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function appendOmissionNotice(lines: string[], totalRows: number, displayedRows: number): void {
  const omitted = totalRows - displayedRows;
  if (omitted > 0) {
    lines.push(`… ${pluralize(omitted, "additional finding")} omitted.`, "");
  }
}

/**
 * Names which analysis ran, and says when the deeper one was unavailable. The
 * built-in engine is line-local and cannot follow a value across statements,
 * so the distinction changes how the result should be read.
 */
function describeEngine(engine: NonNullable<MarkdownReportInput["engine"]>): string {
  if (engine.used) return "Semgrep (AST and taint analysis) + built-in pattern engine";
  return "Built-in pattern engine only (Semgrep not available, no cross-file taint analysis)";
}

/**
 * Renders what the scan covered, which engine produced it, and every warning,
 * so "nothing was found" is distinguishable from "little was looked at".
 */
function appendCoverageSection(lines: string[], input: MarkdownReportInput): void {
  const coverage = input.coverage;
  const engine = input.engine;
  const warnings = (input.warnings ?? []).filter((warning) => typeof warning === "string" && warning.trim());

  if (!coverage && !engine && warnings.length === 0) return;

  lines.push("## Scan Coverage", "");

  const rows: string[][] = [];

  if (engine?.engine) {
    rows.push(["Analysis engine", sanitizeCellValue(describeEngine(engine), 70)]);
  }
  if (coverage?.filesScanned !== undefined) {
    rows.push(["Files analysed", String(coverage.filesScanned)]);
  }
  if (coverage?.filesSkipped !== undefined) {
    rows.push(["Files excluded", String(coverage.filesSkipped)]);
  }
  if (coverage?.filesUnreadable) {
    rows.push(["Files unreadable", String(coverage.filesUnreadable)]);
  }
  if (coverage?.durationMs !== undefined) {
    rows.push(["Duration", `${(coverage.durationMs / 1000).toFixed(2)}s`]);
  }

  if (rows.length > 0) {
    lines.push(renderTextBlock(renderAsciiTable(["Metric", "Value"], rows)), "");
  }

  if (coverage?.truncated) {
    lines.push(
      "> **Incomplete scan.** The file limit was reached before the whole project was examined. " +
      "Findings below cover only the portion that was analysed.",
      ""
    );
  }

  if (coverage?.filesUnreadable) {
    lines.push(
      `> **Coverage gap.** ${pluralize(coverage.filesUnreadable, "file")} could not be read. ` +
      "Vulnerabilities in those files would not appear in this report.",
      ""
    );
  }

  if (warnings.length > 0) {
    lines.push("### Warnings", "");
    for (const warning of warnings.slice(0, 25)) {
      lines.push(`- ${escapeMarkdownInline(sanitizeCellValue(warning, 300))}`);
    }
    if (warnings.length > 25) {
      lines.push(`- … ${pluralize(warnings.length - 25, "further warning")} omitted.`);
    }
    lines.push("");
  }
}

function pluralize(count: number, singular: string): string {
  return `${count} ${singular}${count === 1 ? "" : "s"}`;
}

function clampMaxRows(value: number | undefined): number {
  if (!Number.isFinite(value)) return DEFAULT_MAX_ROWS_PER_SECTION;
  return Math.min(Math.max(Math.floor(value as number), 1), 1_000);
}

function formatGeneratedAt(value: string | Date | undefined): string {
  if (!value) return "";
  if (value instanceof Date) {
    return Number.isNaN(value.getTime()) ? "" : value.toISOString();
  }
  return sanitizeCellValue(value, 80);
}

function sanitizeIssue(value: string, redact: boolean, maxWidth: number): string {
  const safeValue = redact ? redactLikelySecret(value) : value;
  return sanitizeCellValue(safeValue, maxWidth);
}

/**
 * Keeps report cells single-line, terminal-safe, and unable to break out of the
 * table. Conservative on purpose: cell text comes from source code and
 * third-party advisory prose.
 */
function sanitizeCellValue(value: unknown, maxWidth: number): string {
  const text = typeof value === "string" || typeof value === "number" || typeof value === "boolean"
    ? String(value)
    : "";
  const sanitized = text
    .replace(ANSI_OSC_SEQUENCE, "")
    .replace(ANSI_CSI_SEQUENCE, "")
    .replace(CONTROL_CHARACTERS, " ")
    .replace(/\|/g, "/")
    .replace(/\s+/g, " ")
    .trim();

  return truncateDisplayWidth(sanitized || "-", maxWidth);
}

function redactLikelySecret(value: string): string {
  return value
    .replace(/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, "[REDACTED]")
    .replace(/\bgh[pousr]_[A-Za-z0-9_]{20,}\b/g, "[REDACTED]")
    .replace(/\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b/g, "[REDACTED]")
    .replace(/\b(?:xox[bporas]-)[A-Za-z0-9-]{10,}\b/g, "[REDACTED]")
    .replace(
      /\b((?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\s*[:=]\s*["']?)[^\s"']{8,}/gi,
      "$1[REDACTED]"
    );
}

function truncateDisplayWidth(value: string, maxWidth: number): string {
  if (maxWidth <= 0 || displayWidth(value) <= maxWidth) return value;
  if (maxWidth <= 3) return ".".repeat(maxWidth);

  let result = "";
  let width = 0;
  for (const character of value) {
    const characterWidth = displayWidth(character);
    if (width + characterWidth > maxWidth - 3) break;
    result += character;
    width += characterWidth;
  }
  return `${result.trimEnd()}...`;
}

function displayWidth(value: string): number {
  let width = 0;
  for (const character of value) {
    const codePoint = character.codePointAt(0) ?? 0;
    if (isZeroWidthCharacter(character, codePoint)) continue;
    width += isWideCodePoint(codePoint) ? 2 : 1;
  }
  return width;
}

function isZeroWidthCharacter(character: string, codePoint: number): boolean {
  return codePoint === 0x200d ||
    codePoint === 0xfe0f ||
    /^\p{Mark}$/u.test(character);
}

function isWideCodePoint(codePoint: number): boolean {
  return codePoint >= 0x1100 && (
    codePoint <= 0x115f ||
    codePoint === 0x2329 ||
    codePoint === 0x232a ||
    (codePoint >= 0x2e80 && codePoint <= 0xa4cf && codePoint !== 0x303f) ||
    (codePoint >= 0xac00 && codePoint <= 0xd7a3) ||
    (codePoint >= 0xf900 && codePoint <= 0xfaff) ||
    (codePoint >= 0xfe10 && codePoint <= 0xfe19) ||
    (codePoint >= 0xfe30 && codePoint <= 0xfe6f) ||
    (codePoint >= 0xff00 && codePoint <= 0xff60) ||
    (codePoint >= 0xffe0 && codePoint <= 0xffe6) ||
    (codePoint >= 0x1f300 && codePoint <= 0x1faff) ||
    (codePoint >= 0x20000 && codePoint <= 0x3fffd)
  );
}

function firstText(...values: unknown[]): string {
  for (const value of values) {
    if (typeof value === "string" && value.trim()) return value.trim();
  }
  return "";
}

function humanizeIdentifier(value: string): string {
  return value ? value.replace(/[_-]+/g, " ").replace(/\s+/g, " ").trim() : "";
}

/**
 * Escapes every character markdown can treat as markup.
 *
 * Deliberately broad. Trimming it to only the characters that matter in this
 * position reads better - "finding(s)" rather than "finding\\(s\\)" - but a
 * report renders on GitHub and carries attacker-influenced text such as file
 * paths, so the conservative set stays.
 */
function escapeMarkdownInline(value: string): string {
  return value.replace(/([\\`*_[\]{}()<>#+!])/g, "\\$1");
}

function renderTextBlock(value: string): string {
  return `\`\`\`text\n${value}\n\`\`\``;
}

function isNonNegativeFiniteNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0;
}
