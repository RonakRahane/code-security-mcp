import { createHash, randomBytes } from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { DependencyVulnerability, Finding } from "../types/index.js";

/**
 * The on-disk baseline holds fingerprints only. It never persists source
 * snippets, which can contain credentials, and still identifies known findings.
 */
/**
 * Raised whenever the fingerprint changes. An older baseline holds hashes this
 * build cannot reproduce, so accepting it would suppress nothing while
 * appearing to work; parseBaseline refuses it with a message instead.
 */
export const BASELINE_SCHEMA_VERSION = 2 as const;

const SHA_256_HEX = /^[a-f0-9]{64}$/;
const MAX_BASELINE_BYTES = 10 * 1024 * 1024;

export interface SentinelBaseline {
  version: typeof BASELINE_SCHEMA_VERSION;
  generatedAt: string;
  scannerVersion?: string;
  findingFingerprints: string[];
  dependencyFingerprints: string[];
}

export interface CreateBaselineOptions {
  /**
   * Project root used to make finding paths portable inside a repository.
   * Pass the same root when filtering a future scan.
   */
  rootPath?: string;
  /** Supplied by callers that want a reproducible baseline in tests. */
  generatedAt?: string;
  scannerVersion?: string;
}

/** Conventional baseline location for a project. */
export function getBaselinePath(projectRoot: string): string {
  return path.join(path.resolve(projectRoot), ".sentinel-baseline.json");
}

/**
 * Deterministic SHA-256 identity for a code finding.
 *
 * Severity and remediation are excluded so rule metadata can change without
 * turning a known finding into a new CI failure. Path, rule, location, and
 * matched code are included, so a changed or duplicated finding stays visible.
 */
export function fingerprintFinding(finding: Finding, rootPath?: string): string {
  return sha256([
    "sentinel:finding:v2",
    // The CWE rather than the rule id. Which engine reports a finding decides
    // its rule id, and deduplication prefers Semgrep where it is installed, so
    // a baseline written on a developer machine suppressed nothing in a CI
    // runner without Semgrep - the day-one wall of findings the baseline
    // exists to prevent.
    normalizeText(finding.cweId),
    normalizeFilePath(finding.filePath, rootPath),
    // The line number is deliberately absent. lineContent already identifies
    // the code, and including the position meant one comment inserted above a
    // finding turned every accepted finding below it into a new CI failure.
    normalizeText(finding.lineContent),
  ]);
}

/**
 * Deterministic SHA-256 identity for an advisory against a resolved dependency.
 * Patch recommendations and severity are omitted, since advisory metadata moves
 * without a new vulnerability appearing.
 */
export function fingerprintDependency(vulnerability: DependencyVulnerability): string {
  const ecosystem = normalizeText(vulnerability.ecosystem || "unknown").toLowerCase();

  return sha256([
    "sentinel:dependency:v1",
    ecosystem,
    normalizePackageName(vulnerability.package, ecosystem),
    normalizeText(vulnerability.installedVersion),
    normalizeAdvisoryIdentity(vulnerability.url, vulnerability.title),
  ]);
}

/** Produces a compact, sorted baseline suitable for committing to a repository. */
export function createBaseline(
  findings: readonly Finding[],
  dependencies: readonly DependencyVulnerability[] = [],
  options: CreateBaselineOptions = {}
): SentinelBaseline {
  const generatedAt = options.generatedAt || new Date().toISOString();

  return {
    version: BASELINE_SCHEMA_VERSION,
    generatedAt,
    ...(options.scannerVersion ? { scannerVersion: options.scannerVersion } : {}),
    findingFingerprints: sortAndDedupe(
      findings.map((finding) => fingerprintFinding(finding, options.rootPath))
    ),
    dependencyFingerprints: sortAndDedupe(
      dependencies.map((vulnerability) => fingerprintDependency(vulnerability))
    ),
  };
}

/**
 * Reads and validates a baseline. Missing files are normal and return null;
 * malformed baselines throw so CI cannot silently run with a broken policy.
 */
export function loadBaseline(filePath: string): SentinelBaseline | null {
  const resolvedPath = path.resolve(filePath);

  if (!fs.existsSync(resolvedPath)) {
    return null;
  }

  const stat = fs.statSync(resolvedPath);
  if (!stat.isFile()) {
    throw new Error(`Baseline path is not a file: ${resolvedPath}`);
  }
  if (stat.size > MAX_BASELINE_BYTES) {
    throw new Error(`Baseline file is too large (maximum ${MAX_BASELINE_BYTES} bytes): ${resolvedPath}`);
  }

  let parsed: unknown;
  try {
    // A leading BOM is written by default by several editors and by
    // PowerShell, and JSON.parse rejects it, so the whole baseline was
    // discarded and every accepted finding resurfaced.
    parsed = JSON.parse(fs.readFileSync(resolvedPath, "utf-8").replace(/^\uFEFF/, ""));
  } catch (error) {
    const detail = error instanceof Error ? error.message : "unknown JSON error";
    throw new Error(`Unable to parse Sentinel baseline at ${resolvedPath}: ${detail}`);
  }

  return parseBaseline(parsed);
}

/** Validates untrusted JSON before it is used to suppress scan findings. */
export function parseBaseline(value: unknown): SentinelBaseline {
  if (!isRecord(value)) {
    throw new Error("Invalid Sentinel baseline: expected an object.");
  }
  if (value.version !== BASELINE_SCHEMA_VERSION) {
    throw new Error(
      `Unsupported Sentinel baseline version: ${String(value.version)}. Expected ${BASELINE_SCHEMA_VERSION}.`
    );
  }
  if (typeof value.generatedAt !== "string" || value.generatedAt.trim().length === 0) {
    throw new Error("Invalid Sentinel baseline: generatedAt must be a non-empty string.");
  }
  if (value.scannerVersion !== undefined && typeof value.scannerVersion !== "string") {
    throw new Error("Invalid Sentinel baseline: scannerVersion must be a string when present.");
  }

  return {
    version: BASELINE_SCHEMA_VERSION,
    generatedAt: value.generatedAt,
    ...(typeof value.scannerVersion === "string" && value.scannerVersion.trim()
      ? { scannerVersion: value.scannerVersion }
      : {}),
    findingFingerprints: parseFingerprintList(value.findingFingerprints, "findingFingerprints"),
    dependencyFingerprints: parseFingerprintList(value.dependencyFingerprints, "dependencyFingerprints"),
  };
}

/**
 * Atomically persists a validated baseline. The temporary file is created in
 * the destination directory so rename remains atomic on normal filesystems.
 */
export function writeBaseline(filePath: string, baseline: SentinelBaseline): void {
  const validated = parseBaseline(baseline);
  const resolvedPath = path.resolve(filePath);
  const directory = path.dirname(resolvedPath);
  const temporaryPath = path.join(
    directory,
    `.${path.basename(resolvedPath)}.${process.pid}.${randomBytes(8).toString("hex")}.tmp`
  );

  fs.mkdirSync(directory, { recursive: true });

  try {
    fs.writeFileSync(
      temporaryPath,
      `${JSON.stringify(validated, null, 2)}\n`,
      { encoding: "utf-8", mode: 0o600, flag: "wx" }
    );
    fs.renameSync(temporaryPath, resolvedPath);
  } finally {
    // A failed write/rename must not leave a policy-looking partial baseline.
    try {
      fs.unlinkSync(temporaryPath);
    } catch (error: unknown) {
      if (!isMissingFileError(error)) throw error;
    }
  }
}

/** Returns findings absent from the baseline. A missing baseline leaves results intact. */
export function filterFindingsAgainstBaseline<T extends Finding>(
  findings: readonly T[],
  baseline: SentinelBaseline | null | undefined,
  rootPath?: string
): T[] {
  if (!baseline) return [...findings];

  const known = new Set(baseline.findingFingerprints);
  return findings.filter((finding) => !known.has(fingerprintFinding(finding, rootPath)));
}

/** Returns dependency vulnerabilities absent from the baseline. See fingerprintDependency() for identity. */
export function filterDependenciesAgainstBaseline<T extends DependencyVulnerability>(
  vulnerabilities: readonly T[],
  baseline: SentinelBaseline | null | undefined
): T[] {
  if (!baseline) return [...vulnerabilities];

  const known = new Set(baseline.dependencyFingerprints);
  return vulnerabilities.filter((vulnerability) => !known.has(fingerprintDependency(vulnerability)));
}

function sha256(parts: string[]): string {
  return createHash("sha256").update(parts.join("\u0000"), "utf8").digest("hex");
}

function normalizeFilePath(filePath: string, rootPath?: string): string {
  const input = normalizeText(filePath).replace(/\\/g, "/");
  if (!input) return "<unknown-path>";

  if (rootPath && path.isAbsolute(filePath)) {
    return normalizeText(path.relative(path.resolve(rootPath), path.resolve(filePath)))
      .replace(/\\/g, "/")
      .replace(/^\.\//, "") || ".";
  }

  return input.replace(/^\.\//, "");
}


function normalizeText(value: unknown): string {
  return typeof value === "string"
    ? value.replace(/\r\n?/g, "\n").trim().replace(/[\t \n]+/g, " ")
    : "";
}

function normalizePackageName(packageName: string, ecosystem: string): string {
  const normalized = normalizeText(packageName);
  if (ecosystem === "pypi") {
    // PyPI canonicalization is defined by PEP 503.
    return normalized.toLowerCase().replace(/[-_.]+/g, "-");
  }
  return ecosystem === "npm" ? normalized.toLowerCase() : normalized;
}

function normalizeAdvisoryIdentity(url: string, title: string): string {
  const urlIdentity = normalizeText(url).replace(/\/$/, "").toLowerCase();
  if (urlIdentity) return urlIdentity;
  return normalizeText(title).toLowerCase();
}

function parseFingerprintList(value: unknown, fieldName: string): string[] {
  if (!Array.isArray(value)) {
    throw new Error(`Invalid Sentinel baseline: ${fieldName} must be an array.`);
  }

  const fingerprints = value.map((fingerprint) => {
    if (typeof fingerprint !== "string" || !SHA_256_HEX.test(fingerprint)) {
      throw new Error(`Invalid Sentinel baseline: ${fieldName} contains an invalid SHA-256 fingerprint.`);
    }
    return fingerprint;
  });

  return sortAndDedupe(fingerprints);
}

function sortAndDedupe(values: readonly string[]): string[] {
  return [...new Set(values)].sort();
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isMissingFileError(error: unknown): boolean {
  return typeof error === "object" && error !== null &&
    "code" in error && (error as NodeJS.ErrnoException).code === "ENOENT";
}
