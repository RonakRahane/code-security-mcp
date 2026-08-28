import * as fs from "node:fs";
import * as path from "node:path";
import { DependencyVulnerability, Finding, SecretFinding, SentinelConfig, Severity } from "../types/index.js";
import { Diagnostics } from "../core/diagnostics.js";
import { errorMessage } from "../core/logger.js";
import { isSeverity, isSeverityAtOrAbove, severityRank } from "../core/severity.js";

const CONFIG_FILENAMES = ["sentinel.config.json", ".sentinelrc.json"];

/** Configuration files are policy, not data; anything larger is not a config. */
const MAX_CONFIG_BYTES = 1024 * 1024;

/** Bound on how far the config search walks up the tree. */
const MAX_CONFIG_SEARCH_DEPTH = 64;

export { severityRank, isSeverityAtOrAbove };

export function findConfigPath(startPath: string): string | null {
  return findFilePath(startPath, CONFIG_FILENAMES);
}

function findIgnorePath(startPath: string): string | null {
  return findFilePath(startPath, [".sentinelignore"]);
}

function findFilePath(startPath: string, filenames: string[]): string | null {
  let current: string;
  try {
    current = fs.statSync(startPath).isDirectory()
      ? path.resolve(startPath)
      : path.dirname(path.resolve(startPath));
  } catch {
    // A missing start path is not an error: the caller gets no config and the
    // scan proceeds with defaults.
    current = path.dirname(path.resolve(startPath));
  }

  for (let depth = 0; depth < MAX_CONFIG_SEARCH_DEPTH; depth++) {
    for (const filename of filenames) {
      const candidate = path.join(current, filename);
      if (fs.existsSync(candidate)) return candidate;
    }

    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }

  return null;
}

/**
 * Loads `sentinel.config.json` and `.sentinelignore`. Parse failures are
 * reported through `diagnostics` rather than swallowed, because a config that
 * fails to load leaves the user with a policy they think is active but is not.
 */
export function loadSentinelConfig(startPath: string, diagnostics?: Diagnostics): SentinelConfig {
  const config: SentinelConfig = { ignorePaths: [], ignoreRules: [] };

  const configPath = findConfigPath(startPath);
  if (configPath) {
    try {
      const parsed = readJsonFile(configPath);
      applyParsedConfig(config, parsed, configPath, diagnostics);
    } catch (error) {
      diagnostics?.add(`Sentinel config at ${configPath} could not be loaded: ${errorMessage(error)}. Default policy is in effect.`);
    }
  }

  const ignorePath = findIgnorePath(startPath);
  if (ignorePath) {
    try {
      const stats = fs.statSync(ignorePath);
      if (stats.size > MAX_CONFIG_BYTES) {
        diagnostics?.add(`.sentinelignore at ${ignorePath} is too large (limit ${MAX_CONFIG_BYTES} bytes) and was not applied.`);
      } else {
        for (const line of fs.readFileSync(ignorePath, "utf-8").split(/\r?\n/)) {
          const trimmed = line.trim();
          if (trimmed && !trimmed.startsWith("#")) config.ignorePaths!.push(trimmed);
        }
      }
    } catch (error) {
      diagnostics?.add(`.sentinelignore at ${ignorePath} could not be read: ${errorMessage(error)}. Its exclusions are not applied.`);
    }
  }

  return config;
}

function readJsonFile(filePath: string): unknown {
  const stats = fs.statSync(filePath);
  if (stats.size > MAX_CONFIG_BYTES) {
    throw new Error(`file exceeds the ${MAX_CONFIG_BYTES} byte limit`);
  }
  // A leading BOM is what several editors and PowerShell write by default, and
  // JSON.parse rejects it, which discarded the whole policy.
  return JSON.parse(fs.readFileSync(filePath, "utf-8").replace(/^\uFEFF/, ""));
}

/**
 * Validates each field independently, so one bad key does not discard an
 * otherwise valid policy. Every rejected key is reported.
 */
function applyParsedConfig(
  config: SentinelConfig,
  parsed: unknown,
  configPath: string,
  diagnostics?: Diagnostics
): void {
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    diagnostics?.add(`Sentinel config at ${configPath} must contain a JSON object. Default policy is in effect.`);
    return;
  }

  const raw = parsed as Record<string, unknown>;

  config.ignorePaths!.push(...stringArray(raw.ignorePaths, "ignorePaths", configPath, diagnostics));
  config.ignoreRules!.push(...stringArray(raw.ignoreRules, "ignoreRules", configPath, diagnostics));

  if (raw.minimumSeverity !== undefined) {
    if (isSeverity(raw.minimumSeverity)) config.minimumSeverity = raw.minimumSeverity;
    else diagnostics?.add(`Ignored invalid "minimumSeverity" in ${configPath}: expected one of critical|high|medium|low|info.`);
  }

  if (raw.failOnSeverity !== undefined) {
    if (isSeverity(raw.failOnSeverity)) config.failOnSeverity = raw.failOnSeverity;
    else diagnostics?.add(`Ignored invalid "failOnSeverity" in ${configPath}: expected one of critical|high|medium|low|info.`);
  }

  const maxFiles = positiveInteger(raw.maxFiles);
  if (raw.maxFiles !== undefined) {
    // Clamped like concurrency. Configuration travels with the scanned tree,
    // and an unbounded value here means the file cap never trips.
    if (maxFiles) config.maxFiles = Math.min(maxFiles, 1_000_000);
    else diagnostics?.add(`Ignored invalid "maxFiles" in ${configPath}: expected a positive integer.`);
  }

  const concurrency = positiveInteger(raw.concurrency);
  if (raw.concurrency !== undefined) {
    if (concurrency) config.concurrency = Math.min(concurrency, 64);
    else diagnostics?.add(`Ignored invalid "concurrency" in ${configPath}: expected a positive integer.`);
  }

  if (raw.offline !== undefined) {
    if (typeof raw.offline === "boolean") config.offline = raw.offline;
    else diagnostics?.add(`Ignored invalid "offline" in ${configPath}: expected a boolean.`);
  }

  if (raw.semgrep !== undefined) {
    if (typeof raw.semgrep === "object" && raw.semgrep !== null && !Array.isArray(raw.semgrep)) {
      const semgrep = raw.semgrep as Record<string, unknown>;
      config.semgrep = {};
      if (typeof semgrep.enabled === "boolean") config.semgrep.enabled = semgrep.enabled;
      const timeoutMs = positiveInteger(semgrep.timeoutMs);
      // Passed straight to execFile's timeout. Unclamped, a repository could
      // set it to years and remove the only deadline on the analyzer.
      if (timeoutMs) config.semgrep.timeoutMs = Math.min(timeoutMs, 30 * 60_000);
      const rulesets = stringArray(semgrep.registryRulesets, "semgrep.registryRulesets", configPath, diagnostics);
      if (rulesets.length > 0) config.semgrep.registryRulesets = rulesets;
    } else {
      diagnostics?.add(`Ignored invalid "semgrep" in ${configPath}: expected an object.`);
    }
  }
}

function stringArray(
  value: unknown,
  field: string,
  configPath: string,
  diagnostics?: Diagnostics
): string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) {
    diagnostics?.add(`Ignored invalid "${field}" in ${configPath}: expected an array of strings.`);
    return [];
  }

  const strings = value.filter((entry): entry is string => typeof entry === "string" && entry.trim().length > 0);
  if (strings.length !== value.length) {
    diagnostics?.add(`Some entries in "${field}" (${configPath}) were ignored because they are not non-empty strings.`);
  }
  return strings.map((entry) => entry.trim());
}

function positiveInteger(value: unknown): number | null {
  return typeof value === "number" && Number.isInteger(value) && value > 0 ? value : null;
}

// Ignore matching

/**
 * Matches a path against the configured exclusions. Supports plain paths
 * (`src/generated`), basenames (`secrets.json`), and glob wildcards. Compiled
 * matchers are cached per config object; recompiling per file was measurable.
 */
export function isPathIgnored(filePath: string, rootPath: string, config: SentinelConfig): boolean {
  const matchers = getMatchers(config);
  if (matchers.length === 0) return false;

  const cleanFile = filePath.replace(/\\/g, "/");
  const cleanRoot = rootPath.replace(/\\/g, "/");

  const absolute = normalizePath(path.resolve(cleanFile));
  const relative = normalizePath(path.relative(path.resolve(cleanRoot), path.resolve(cleanFile)));
  const basename = path.basename(absolute);

  // A path outside the root cannot be expressed by a relative pattern; fall back
  // to absolute and basename comparisons only.
  const candidates = relative.startsWith("../") ? [absolute, basename] : [relative, absolute, basename];

  return matchers.some((matcher) => candidates.some((candidate) => matcher(candidate, relative)));
}

type Matcher = (candidate: string, relative: string) => boolean;

const matcherCache = new WeakMap<SentinelConfig, Matcher[]>();

function getMatchers(config: SentinelConfig): Matcher[] {
  const cached = matcherCache.get(config);
  if (cached) return cached;

  const matchers = (config.ignorePaths || [])
    .map((entry) => normalizePath(entry.trim()))
    .filter(Boolean)
    .map(buildMatcher);

  matcherCache.set(config, matchers);
  return matchers;
}

function buildMatcher(pattern: string): Matcher {
  if (pattern.includes("*") || pattern.includes("?")) {
    const regex = globToRegExp(pattern);
    return (candidate) => regex.test(candidate);
  }

  return (candidate, relative) =>
    candidate === pattern ||
    candidate.startsWith(`${pattern}/`) ||
    relative.startsWith(`${pattern}/`) ||
    candidate.endsWith(`/${pattern}`);
}

/**
 * Converts a glob to an anchored regex. Every non-glob character is escaped, so
 * a pattern from an untrusted repository cannot inject regex syntax or become a
 * catastrophic-backtracking expression.
 */
function globToRegExp(pattern: string): RegExp {
  let source = "";
  for (let i = 0; i < pattern.length; i++) {
    const char = pattern[i];
    if (char === "*") {
      if (pattern[i + 1] === "*") {
        source += ".*";
        i++;
        if (pattern[i + 1] === "/") i++;
      } else {
        source += "[^/]*";
      }
    } else if (char === "?") {
      source += "[^/]";
    } else {
      source += char.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    }
  }
  // Anchored, with an optional trailing segment so a directory pattern also
  // matches everything beneath it.
  return new RegExp(`^${source}(?:/.*)?$`);
}

function normalizePath(value: string): string {
  return value.replace(/\\/g, "/").replace(/^\.\/+/, "").replace(/\/+$/, "");
}

export function filterIgnoredFindings<T extends Finding | SecretFinding>(
  findings: readonly T[],
  config: SentinelConfig,
  rootPath?: string
): T[] {
  const ignoreRules = new Set((config.ignoreRules || []).map((rule) => rule.trim()).filter(Boolean));

  return findings.filter((finding) => {
    if (ignoreRules.has(finding.ruleId)) return false;
    if (rootPath && finding.filePath && isPathIgnored(finding.filePath, rootPath, config)) return false;
    return true;
  });
}

export function filterByMinimumSeverity<T extends { severity: Severity }>(
  findings: readonly T[],
  config: SentinelConfig
): T[] {
  if (!config.minimumSeverity) return [...findings];
  return findings.filter((finding) => isSeverityAtOrAbove(finding.severity, config.minimumSeverity!));
}

export function filterDependencyVulnerabilitiesByThreshold(
  vulnerabilities: readonly DependencyVulnerability[],
  config: SentinelConfig
): DependencyVulnerability[] {
  return filterByMinimumSeverity(vulnerabilities, config);
}

/**
 * True when Sentinel must not make network calls. Air-gapped and
 * privacy-sensitive deployments need a hard switch for this.
 */
export function isOfflineMode(config?: SentinelConfig): boolean {
  if (config?.offline) return true;
  const flag = (process.env.SENTINEL_OFFLINE || "").toLowerCase();
  return flag === "1" || flag === "true" || flag === "yes";
}
