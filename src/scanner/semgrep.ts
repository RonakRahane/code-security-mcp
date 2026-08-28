import { execFile } from "child_process";
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";
import { promisify } from "util";
import { ensureSemgrep } from "../core/semgrep-install.js";
import { Category, Finding, ScanEngineStatus, Severity } from "../types/index.js";

const execFileAsync = promisify(execFile);
const DEFAULT_TIMEOUT_MS = 120_000;
const MAX_BUFFER_BYTES = 32 * 1024 * 1024;

interface SemgrepRawResult {
  check_id?: string;
  path?: string;
  start?: { line?: number };
  extra?: {
    message?: string;
    severity?: string;
    lines?: string;
    metadata?: Record<string, unknown>;
  };
}

interface SemgrepRawOutput {
  results?: SemgrepRawResult[];
  errors?: Array<{ message?: string; level?: string }>;
  /**
   * Files Semgrep reports as analysed. Treated as authoritative: anything
   * absent was not covered, whatever the caller asked for.
   */
  paths?: {
    scanned?: string[];
    skipped?: Array<{ path?: string; reason?: string }>;
  };
}

export interface SemgrepScanOptions {
  binary?: string;
  timeoutMs?: number;
  excludePatterns?: string[];
  /**
   * Registry packs (for example "p/javascript") added on top of the
   * repository-owned rules. Empty by default; see resolveRegistryRulesets().
   */
  registryRulesets?: string[];
  /** When true, no registry packs are used regardless of other settings. */
  offline?: boolean;
  /**
   * Explicit absolute file targets. When supplied, Semgrep analyses exactly
   * these paths and nothing else.
   *
   * Pointed at a directory, Semgrep applies its own ignore list, which excludes
   * `test/`, `tests/` and others outright. Naming targets explicitly keeps the
   * scope decision with Sentinel instead of a hidden engine default.
   */
  targets?: string[];
}

export interface SemgrepScanResult {
  findings: Finding[];
  status: ScanEngineStatus;
  warnings: string[];
  /**
   * Paths Semgrep analysed, from its own `paths.scanned` output rather than
   * from what it was asked to scan. Callers run the pattern engine over the rest.
   */
  analyzedFiles: string[];
}

/**
 * Target-list batching limits. A single argv cannot exceed ARG_MAX (~256 KB on
 * macOS, ~2 MB on Linux), so long file lists are split across invocations.
 */
const MAX_TARGET_ARG_BYTES = 100_000;
const MAX_TARGETS_PER_BATCH = 800;

/**
 * Runs the repository-owned Semgrep rule packs. Arguments go through execFile
 * rather than a shell, so paths and ignore patterns cannot become commands.
 */
export async function scanWithSemgrep(
  rootPath: string,
  options: SemgrepScanOptions = {}
): Promise<SemgrepScanResult> {
  const root = path.resolve(rootPath);
  const warnings: string[] = [];

  if (!fs.existsSync(root)) {
    return unavailable(`Semgrep target does not exist: ${root}`);
  }

  const isFile = fs.statSync(root).isFile();
  const cwd = isFile ? path.dirname(root) : root;

  const ruleFiles = getRuleFiles();
  if (ruleFiles.length === 0) {
    return unavailable("Sentinel Semgrep rule packs were not found. Reinstall Sentinel with its rules directory.");
  }

  // An explicitly supplied binary is taken as given - tests point this at a
  // stub, and an operator who names a path has already made the decision.
  // Otherwise Semgrep is located, and installed if it is missing: running
  // without it silently reports "no findings" for every class of bug that
  // needs data flow to see.
  let binary = options.binary;
  if (!binary) {
    const readiness = await ensureSemgrep();
    if (readiness.status === "unavailable") return unavailable(readiness.message);
    binary = readiness.binary;
  }
  const baseArgs = ["scan", "--json", "--quiet", "--metrics=off", "--timeout", "30", "--disable-version-check"];
  for (const ruleFile of ruleFiles) {
    baseArgs.push("--config", ruleFile);
  }

  const registryRulesets = resolveRegistryRulesets(options);
  for (const ruleset of registryRulesets) {
    baseArgs.push("--config", ruleset);
  }
  if (registryRulesets.length > 0) {
    warnings.push(
      `Semgrep registry packs are enabled (${registryRulesets.join(", ")}). These are downloaded at scan time, ` +
      `so results depend on network access and on the registry's current rule contents. ` +
      `Unset SENTINEL_SEMGREP_REGISTRY for fully reproducible, offline-capable scans.`
    );
  }

  for (const pattern of options.excludePatterns || []) {
    const trimmed = pattern.trim();
    // A leading dash would be consumed as the next flag rather than as this
    // option's value.
    if (trimmed && !trimmed.startsWith("-")) baseArgs.push("--exclude", trimmed);
  }

  const batches = resolveTargetBatches(cwd, root, isFile, options.targets);
  if (batches.length === 0) {
    return {
      findings: [],
      analyzedFiles: [],
      status: {
        engine: "semgrep",
        available: true,
        used: false,
        message: "No files were in scope for Semgrep; the built-in pattern engine covered the scan.",
      },
      warnings,
    };
  }

  const findings: Finding[] = [];
  const analyzedFiles = new Set<string>();
  let completedBatches = 0;
  let firstFailure: string | undefined;

  for (const batch of batches) {
    // "--" ends option parsing. Without it a scanned file called
    // "--config=evil.yml" is read by Semgrep as a flag rather than a target,
    // which lets a hostile repository load its own rules, redirect output over
    // an arbitrary file, or switch the engine off. This tool exists to scan
    // untrusted code, so that path has to be closed at the argv boundary.
    const outcome = await runSemgrepBatch(
      binary,
      [...baseArgs, "--", ...batch],
      cwd,
      options.timeoutMs
    );

    if (outcome.kind === "missing") return unavailable(outcome.message);

    if (outcome.kind === "failed") {
      firstFailure ??= outcome.message;
      // A failed batch is a coverage gap, not a zero. The count lets the
      // caller re-analyse those files with the pattern engine.
      warnings.push(
        `Semgrep did not complete for ${batch.length} file(s): ${outcome.message}. ` +
        `Those files were analysed by the built-in pattern engine instead.`
      );
      continue;
    }

    completedBatches++;
    collectBatch(outcome.parsed, cwd, outcome.stderr, warnings, findings, analyzedFiles);
  }

  if (completedBatches === 0) {
    const detail = firstFailure || "Semgrep produced no parseable output.";
    return {
      findings: [],
      analyzedFiles: [],
      status: { engine: "semgrep", available: true, used: false, message: detail },
      warnings: [`Semgrep did not complete: ${detail}`],
    };
  }

  return {
    findings,
    analyzedFiles: [...analyzedFiles],
    status: { engine: "semgrep", available: true, used: true },
    warnings,
  };
}

type BatchOutcome =
  | { kind: "ok"; parsed: SemgrepRawOutput; stderr: string }
  | { kind: "failed"; message: string }
  | { kind: "missing"; message: string };

async function runSemgrepBatch(
  binary: string,
  args: string[],
  cwd: string,
  timeoutMs: number | undefined
): Promise<BatchOutcome> {
  let stdout = "";
  let stderr = "";

  try {
    const completed = await execFileAsync(binary, args, {
      cwd,
      encoding: "utf-8",
      timeout: timeoutMs ?? DEFAULT_TIMEOUT_MS,
      maxBuffer: MAX_BUFFER_BYTES,
      windowsHide: true,
      // The default timeout sends SIGTERM and then waits for `close` forever,
      // which is a request rather than a deadline: a child that ignores or
      // traps SIGTERM held the scan open indefinitely. SIGKILL cannot be
      // trapped.
      killSignal: "SIGKILL",
    });
    stdout = completed.stdout;
    stderr = completed.stderr;
  } catch (error: unknown) {
    const processError = error as NodeJS.ErrnoException & {
      stdout?: string;
      stderr?: string;
      killed?: boolean;
    };
    stdout = processError.stdout || "";
    stderr = processError.stderr || "";

    // Semgrep may use a non-zero code when it finds matches. Its JSON output is
    // still authoritative, so parse it before treating this as a scan failure.
    const parsed = parseSemgrepOutput(stdout);
    if (parsed) return { kind: "ok", parsed, stderr };

    if (processError.code === "ENOENT") {
      return {
        kind: "missing",
        message: "Semgrep is not installed or is not on PATH. Install it to enable cross-file taint and IaC analysis.",
      };
    }

    return {
      kind: "failed",
      message: processError.killed
        ? "Semgrep timed out before it completed."
        : sanitizeProcessError(stderr || processError.message || "unknown Semgrep failure"),
    };
  }

  const parsed = parseSemgrepOutput(stdout);
  if (!parsed) {
    return { kind: "failed", message: sanitizeProcessError(stderr || "Semgrep returned no parseable JSON output.") };
  }

  return { kind: "ok", parsed, stderr };
}

function collectBatch(
  parsed: SemgrepRawOutput,
  root: string,
  stderr: string,
  warnings: string[],
  findings: Finding[],
  analyzedFiles: Set<string>
): void {
  if (stderr.trim()) warnings.push(`Semgrep: ${sanitizeProcessError(stderr)}`);
  for (const error of parsed.errors || []) {
    const message = error.message?.trim();
    if (message) warnings.push(`Semgrep ${error.level || "warning"}: ${message}`);
  }

  for (const result of parsed.results || []) {
    const finding = mapSemgrepFinding(result, root);
    if (finding) findings.push(finding);
  }

  for (const scanned of parsed.paths?.scanned || []) {
    if (typeof scanned !== "string" || !scanned) continue;
    analyzedFiles.add(path.resolve(root, scanned));
  }
}

/**
 * Splits explicit targets into argv-sized batches, relative to `cwd` to keep
 * the command line short. With no explicit targets the caller gets the
 * single-target form, used only when scanning one file.
 */
export function resolveTargetBatches(
  cwd: string,
  root: string,
  isFile: boolean,
  targets: readonly string[] | undefined
): string[][] {
  if (!targets) return [[isFile ? path.basename(root) : "."]];
  if (targets.length === 0) return [];

  const batches: string[][] = [];
  let current: string[] = [];
  let bytes = 0;

  for (const target of targets) {
    const relative = path.relative(cwd, path.resolve(target));
    // A target outside the scan root would widen coverage past what the
    // caller authorised, so drop it.
    if (relative.startsWith("..") || path.isAbsolute(relative)) continue;

    // Defence in depth alongside the "--" separator: a "./" prefix means the
    // path can never be read as a flag even if the separator is ever dropped
    // or an argv is assembled somewhere else.
    const entry = relative ? (relative.startsWith("-") ? `.${path.sep}${relative}` : relative) : ".";
    const size = Buffer.byteLength(entry) + 1;

    if (current.length > 0 && (bytes + size > MAX_TARGET_ARG_BYTES || current.length >= MAX_TARGETS_PER_BATCH)) {
      batches.push(current);
      current = [];
      bytes = 0;
    }

    current.push(entry);
    bytes += size;
  }

  if (current.length > 0) batches.push(current);
  return batches;
}

/**
 * Semgrep prefixes a rule id with the path of the config file that defined it,
 * so a rule loaded from `/Users/someone/project/rules/sentinel-core.yml` arrives
 * as `Users.someone.project.rules.sentinel.core...`. That puts the scanning
 * machine's directory layout, and usually a username, into every report and
 * SARIF upload. The rule's own id starts at the last `sentinel.` segment.
 */
export function normalizeSemgrepRuleId(checkId: string): string {
  const marker = checkId.lastIndexOf("sentinel.");
  if (marker > 0) return checkId.slice(marker);

  // A registry pack id ("javascript.lang.security.audit...") carries no path
  // prefix, so it is already what it should be.
  return checkId;
}

function mapSemgrepFinding(result: SemgrepRawResult, root: string): Finding | null {
  if (!result.check_id || !result.path) return null;

  const filePath = path.resolve(root, result.path);
  if (!isWithin(root, filePath)) return null;

  const metadata = result.extra?.metadata || {};
  const flattenedMetadata = flattenMetadata(metadata);
  // Sentinel's own namespace is consulted first. Semgrep convention puts
  // "category: security" on every rule, which is not one of Sentinel's
  // categories, so reading it first sent every Semgrep finding to
  // "miscellaneous" and the sentinel block was never reached.
  const category = toCategory(
    stringMetadata(metadata, "sentinel.category") ||
    stringMetadata(metadata, "category") ||
    (isIacPath(filePath) ? "iac" : "miscellaneous")
  );

  const ruleId = normalizeSemgrepRuleId(result.check_id);

  return {
    ruleId,
    severity: toSeverity(
      stringMetadata(metadata, "sentinel.severity") ||
      stringMetadata(metadata, "severity") ||
      result.extra?.severity
    ),
    category,
    cweId: stringMetadata(metadata, "cwe") || stringMetadata(metadata, "cwe-id") || "CWE-0",
    message: sanitizeText(result.extra?.message || ruleId, 500),
    filePath,
    line: Math.max(1, result.start?.line || 1),
    lineContent: sanitizeText(result.extra?.lines || "", 200),
    remediation: stringMetadata(metadata, "remediation") || "Review the finding and apply the rule's recommended secure pattern.",
    confidence: toConfidence(
      stringMetadata(metadata, "sentinel.confidence") ||
      stringMetadata(metadata, "confidence")
    ),
    source: "semgrep",
    metadata: flattenedMetadata,
  };
}

function getRuleFiles(): string[] {
  const moduleDirectory = path.dirname(fileURLToPath(import.meta.url));
  const rulesDirectory = path.resolve(moduleDirectory, "../../rules");
  const expected = ["sentinel-core.yml", "sentinel-ai.yml", "sentinel-iac.yml"];
  return expected
    .map((name) => path.join(rulesDirectory, name))
    .filter((file) => fs.existsSync(file));
}

/** Registry pack identifier, e.g. "p/javascript" or "r/python.lang.security". */
const REGISTRY_RULESET = /^[pr]\/[A-Za-z0-9._-]+(?:\.[A-Za-z0-9._-]+)*$/;

/**
 * Resolves which Semgrep registry packs to use. They are off by default.
 *
 * Registry packs are fetched from semgrep.dev at scan time: scans then need
 * network access, results move when the registry moves, and a compromised
 * registry would run attacker-chosen rules over the user's source. Enabling
 * them is a per-project choice made through `semgrep.registryRulesets` in
 * sentinel.config.json or the SENTINEL_SEMGREP_REGISTRY variable.
 *
 * The packs in `rules/` are always applied and need no network.
 */
export function resolveRegistryRulesets(options: SemgrepScanOptions = {}): string[] {
  if (options.offline) return [];

  const configured = options.registryRulesets?.length
    ? options.registryRulesets
    : (process.env.SENTINEL_SEMGREP_REGISTRY || "")
        .split(",")
        .map((entry) => entry.trim())
        .filter(Boolean);

  // Only well-formed registry identifiers are accepted, so configuration
  // cannot redirect rule loading to a URL or a local path.
  return configured.filter((entry) => REGISTRY_RULESET.test(entry));
}

export function parseSemgrepOutput(stdout: string): SemgrepRawOutput | null {
  const trimmed = stdout.trim();
  if (!trimmed) return null;

  try {
    const parsed = JSON.parse(trimmed) as SemgrepRawOutput;
    return Array.isArray(parsed.results) ? parsed : null;
  } catch {
    // Some Semgrep versions prepend a non-JSON diagnostic line despite --json.
    const objectStart = trimmed.indexOf("{");
    if (objectStart < 0) return null;
    try {
      const parsed = JSON.parse(trimmed.slice(objectStart)) as SemgrepRawOutput;
      return Array.isArray(parsed.results) ? parsed : null;
    } catch {
      return null;
    }
  }
}

function unavailable(message: string): SemgrepScanResult {
  return {
    findings: [],
    analyzedFiles: [],
    status: { engine: "semgrep", available: false, used: false, message },
    warnings: [message],
  };
}

function toSeverity(value: string | undefined): Severity {
  switch (value?.toLowerCase()) {
    case "critical": return "critical";
    case "error":
    case "high": return "high";
    case "warning":
    case "medium": return "medium";
    case "low": return "low";
    case "info": return "info";
    default: return "medium";
  }
}

function toCategory(value: string): Category {
  const valid = new Set<Category>([
    "injection", "xss", "secrets", "ai", "iac", "supply-chain", "auth", "crypto",
    "dangerous-functions", "path-traversal", "prototype-pollution", "miscellaneous",
  ]);
  return valid.has(value as Category) ? value as Category : "miscellaneous";
}

function toConfidence(value: string | undefined): "high" | "medium" | "low" | undefined {
  const normalized = value?.toLowerCase();
  return normalized === "high" || normalized === "medium" || normalized === "low" ? normalized : undefined;
}

/**
 * Reads a metadata value, following a dotted path into nested blocks.
 *
 * Sentinel's rules carry their category, severity and confidence under a
 * `sentinel:` block. A flat `metadata["sentinel.category"]` lookup never
 * matches that, so every lookup fell through to its default: Semgrep's own
 * `category: security` (not a Sentinel category, so "miscellaneous") and
 * Semgrep's coarse ERROR/WARNING severity. The whole block was inert.
 */
export function readStringMetadataForTest(metadata: Record<string, unknown>, key: string): string | undefined {
  return stringMetadata(metadata, key);
}

function stringMetadata(metadata: Record<string, unknown>, key: string): string | undefined {
  let current: unknown = metadata;

  for (const segment of key.split(".")) {
    if (typeof current !== "object" || current === null) return undefined;
    current = (current as Record<string, unknown>)[segment];
  }

  return typeof current === "string" ? current : undefined;
}

function flattenMetadata(metadata: Record<string, unknown>): Record<string, string | number | boolean> {
  const flattened: Record<string, string | number | boolean> = {};
  for (const [key, value] of Object.entries(metadata)) {
    if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
      flattened[key] = value;
    }
  }
  return flattened;
}

function isIacPath(filePath: string): boolean {
  const normalized = filePath.replace(/\\/g, "/").toLowerCase();
  return normalized.endsWith("dockerfile") || normalized.endsWith(".tf") ||
    normalized.includes("/.github/workflows/") || normalized.endsWith(".yaml") || normalized.endsWith(".yml");
}

function isWithin(root: string, candidate: string): boolean {
  const relative = path.relative(root, candidate);
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

function sanitizeProcessError(value: string): string {
  return sanitizeText(value.replace(/\s+/g, " "), 500);
}

function sanitizeText(value: string, maxLength: number): string {
  return value.replace(/[\u0000-\u001F\u007F]/g, " ").replace(/\s+/g, " ").trim().slice(0, maxLength);
}
