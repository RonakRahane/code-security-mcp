import { statSync } from "node:fs";
import * as path from "node:path";
import { DependencyVulnerability, Finding, ProjectSecurityScan, SentinelConfig } from "../types/index.js";
import { DEPENDENCY_MANIFESTS, MANIFEST_SUPERSEDED_BY, MAX_FILE_BYTES } from "../core/constants.js";
import { Diagnostics } from "../core/diagnostics.js";
import { dedupeFindings } from "../core/findings.js";
import { mapWithConcurrency, readTextFile, resolveConcurrency, walkDirectory } from "../core/fs-walk.js";
import { errorMessage, logger } from "../core/logger.js";
import { safeRealpath } from "../core/paths.js";
import { computeSeveritySummary, sortBySeverity } from "../core/severity.js";
import { scanWithSemgrep } from "./semgrep.js";
import { scanCode, shouldSkipFile } from "./pattern-engine.js";
import { detectSecrets } from "./secret-detector.js";
import { auditDependencies } from "./dependency-auditor.js";
import {
  filterByMinimumSeverity,
  filterIgnoredFindings,
  isOfflineMode,
  isPathIgnored,
  loadSentinelConfig,
} from "./config.js";
import {
  filterDependenciesAgainstBaseline,
  filterFindingsAgainstBaseline,
  getBaselinePath,
  loadBaseline,
} from "./baseline.js";

export interface UnifiedScanOptions {
  projectName?: string;
  maxFiles?: number;
  concurrency?: number;
  /** Overrides config/env detection. Used by tests and air-gapped callers. */
  offline?: boolean;
  /**
   * Forces the Semgrep stage on or off, overriding configuration. The benchmark
   * harness uses it to measure each engine configuration separately.
   */
  semgrep?: boolean;
  /**
   * Skips baseline suppression, so the scan reports everything it found rather
   * than only what is new. Writing a baseline needs the complete set: building
   * one from suppressed results would drop every previously recorded finding
   * and resurface it on the next scan.
   */
  ignoreBaseline?: boolean;
}

/**
 * Runs the full scanning pipeline over a project: SAST, secrets, and SCA.
 *
 * Coverage gaps are reported as prominently as findings, so "0 findings" is
 * never confused with "half the repository could not be read".
 */
export async function runUnifiedScan(
  dirPath: string,
  options: UnifiedScanOptions = {}
): Promise<ProjectSecurityScan> {
  const startedAt = Date.now();
  // Resolve symlinks up front so the root matches the paths the walker yields.
  // Otherwise relative ignore patterns stop matching wherever the real path
  // differs from the supplied one, such as a symlinked checkout on macOS.
  const root = safeRealpath(path.resolve(dirPath));
  const diagnostics = new Diagnostics();
  const config = loadSentinelConfig(root, diagnostics);

  const offline = options.offline ?? isOfflineMode(config);
  const concurrency = resolveConcurrency(options.concurrency ?? config.concurrency);
  const maxFiles = options.maxFiles ?? config.maxFiles;

  logger.info("scan started", { root, offline, concurrency });

  const allFindings: Finding[] = [];
  const allDependencies: DependencyVulnerability[] = [];

  // 1. Decide the file list once. Every engine is held to this same list.
  // Left to itself, Semgrep picks its own targets and drops whole subtrees via
  // its built-in ignore list, while the scan still counts them as covered.
  const inventory = await collectFiles(root, config, diagnostics, maxFiles);

  if (inventory.truncated) {
    diagnostics.add(
      `Scan stopped after reaching the file limit; the remainder of the tree was not analysed. ` +
      `Raise "maxFiles" in sentinel.config.json to scan the whole project.`
    );
  }

  // 2. Static analysis
  const semgrepEnabled = options.semgrep ?? config.semgrep?.enabled !== false;
  const semgrepResult = semgrepEnabled
    ? await scanWithSemgrep(root, {
        timeoutMs: config.semgrep?.timeoutMs ?? 120_000,
        registryRulesets: config.semgrep?.registryRulesets,
        offline,
        targets: inventory.files,
      })
    : null;

  const semgrepUsed = Boolean(semgrepResult?.status.used);
  const semgrepAvailable = Boolean(semgrepResult?.status.available);
  const semgrepAnalyzed = new Set(semgrepUsed ? semgrepResult!.analyzedFiles : []);

  if (semgrepResult && semgrepUsed) {
    for (const item of semgrepResult.findings) allFindings.push(item);
    diagnostics.addAll(semgrepResult.warnings);
  } else if (semgrepResult?.status.message) {
    diagnostics.add(`Semgrep unavailable, using the built-in pattern engine: ${semgrepResult.status.message}`);
  } else if (!semgrepEnabled) {
    diagnostics.add("Semgrep is disabled by configuration; the built-in pattern engine was used.");
  }

  // Both engines run over every file. Semgrep follows dataflow across
  // statements; the pattern registry carries rules its packs do not express
  // (weak hashes, hardcoded token arguments, unsafe template rendering).
  // Overlapping reports are collapsed downstream by dedupeFindings.
  // A single file is a valid scan root, but it is the wrong root for path
  // classification: path.relative(file, file) is "", which falls back to the
  // absolute path and lets a directory above the project decide the verdict.
  // A file under ~/test/proj/src was graded as test code for that reason.
  const pathRoot = isRegularFile(root) ? path.dirname(root) : root;

  const sweep = await sweepFiles(inventory.files, diagnostics, {
    semgrepAnalyzed,
    semgrepUsed,
    concurrency,
    root: pathRoot,
  });
  for (const item of sweep.findings) allFindings.push(item);

  if (semgrepUsed && sweep.filesSemgrepCovered < sweep.filesScanned) {
    const uncovered = sweep.filesScanned - sweep.filesSemgrepCovered;
    diagnostics.add(
      `Semgrep analysed ${sweep.filesSemgrepCovered} of ${sweep.filesScanned} scanned file(s); ` +
      `${uncovered} received line-local pattern analysis only, so no cross-function dataflow was ` +
      `evaluated there. Semgrep declines paths matching its built-in ignore rules (notably test ` +
      `directories) and files it cannot parse.`
    );
  }

  // 3. Dependency audit
  const manifests = await findDependencyManifests(root, config, diagnostics, maxFiles);

  if (offline && manifests.length > 0) {
    diagnostics.add(
      `Offline mode: ${manifests.length} dependency manifest(s) were parsed without querying the OSV advisory database. ` +
      `Known-vulnerable dependencies will not be reported.`
    );
  }

  const auditResults = await mapWithConcurrency(
    manifests,
    async (manifest) => {
      try {
        return await auditDependencies(manifest, { offline, diagnostics });
      } catch (error) {
        diagnostics.add(`Dependency audit failed for ${path.relative(root, manifest) || manifest}: ${errorMessage(error)}`);
        return null;
      }
    },
    Math.min(concurrency, 4) // OSV is a shared public service; stay a polite client.
  );

  for (const result of auditResults) {
    if (result) for (const item of result.vulnerabilities) allDependencies.push(item);
  }

  // 4. Policy filtering
  const dedupedFindings = dedupeFindings(allFindings);
  const afterIgnoreRules = filterIgnoredFindings(dedupedFindings, config, root);
  const filteredFindings = filterByMinimumSeverity(afterIgnoreRules, config);
  const filteredDependencies = filterByMinimumSeverity(allDependencies, config);

  // Say what policy removed. Configuration is read from inside the scanned
  // tree, so a pull request can raise minimumSeverity or name its own findings
  // in ignoreRules and turn a failing scan into a quiet one. Suppression is a
  // legitimate feature; suppression nobody is told about is a bypass.
  const suppressedByRules = dedupedFindings.length - afterIgnoreRules.length;
  const suppressedBySeverity = afterIgnoreRules.length - filteredFindings.length;

  if (suppressedByRules > 0) {
    diagnostics.add(
      `${suppressedByRules} finding(s) were hidden by "ignoreRules" in the Sentinel configuration.`
    );
  }
  if (suppressedBySeverity > 0) {
    diagnostics.add(
      `${suppressedBySeverity} finding(s) below "minimumSeverity" (${config.minimumSeverity}) ` +
      `were hidden and are not counted in the summary or the failure threshold.`
    );
  }

  // 5. Baseline suppression
  const baselinePath = getBaselinePath(root);
  let baseline = null;
  if (!options.ignoreBaseline) {
    try {
      baseline = loadBaseline(baselinePath);
    } catch (error) {
      // A corrupt baseline must not silently suppress nothing *or* everything.
      diagnostics.add(`Baseline at ${baselinePath} was ignored: ${errorMessage(error)}`);
    }
  }

  const hasBaseline = baseline !== null;
  const finalFindings = hasBaseline
    ? filterFindingsAgainstBaseline(filteredFindings, baseline, pathRoot)
    : filteredFindings;
  const finalDependencies = hasBaseline
    ? filterDependenciesAgainstBaseline(filteredDependencies, baseline)
    : filteredDependencies;

  sortBySeverity(finalFindings);
  sortBySeverity(finalDependencies);

  const durationMs = Date.now() - startedAt;
  logger.info("scan finished", {
    root,
    findings: finalFindings.length,
    dependencies: finalDependencies.length,
    filesScanned: sweep.filesScanned,
    durationMs,
  });

  return {
    rootPath: root,
    generatedAt: new Date().toISOString(),
    filesScanned: sweep.filesScanned,
    filesSkipped: sweep.filesSkipped,
    findings: finalFindings,
    dependencyVulnerabilities: finalDependencies,
    summary: computeSeveritySummary(finalFindings, finalDependencies),
    engine: {
      // "hybrid" whenever Semgrep contributed, since the pattern registry
      // always runs alongside it.
      engine: semgrepUsed ? "hybrid" : "compatibility",
      available: semgrepAvailable,
      used: semgrepUsed,
      disabled: !semgrepEnabled,
      message: semgrepResult?.status.message,
      filesAnalyzedBySemgrep: semgrepUsed ? sweep.filesSemgrepCovered : 0,
      filesAnalyzedByPatternEngine: sweep.filesPatternScanned,
    },
    warnings: diagnostics.toWarnings(),
    coverage: {
      filesScanned: sweep.filesScanned,
      filesSkipped: inventory.filesSkipped + sweep.filesSkipped,
      filesUnreadable: diagnostics.skippedCount,
      truncated: inventory.truncated,
      durationMs,
      filesWithoutStaticAnalysis: sweep.filesWithoutStaticAnalysis,
    },
    baseline: {
      applied: hasBaseline,
      path: hasBaseline ? baselinePath : undefined,
      suppressedFindings: filteredFindings.length - finalFindings.length,
      suppressedDependencies: filteredDependencies.length - finalDependencies.length,
    },
  };
}

interface FileInventory {
  files: string[];
  filesSkipped: number;
  truncated: boolean;
}

/**
 * Enumerates the files in scope, applying Sentinel's ignore policy. This list
 * is the single definition of what the scan covers.
 */
async function collectFiles(
  root: string,
  config: SentinelConfig,
  diagnostics: Diagnostics,
  maxFiles?: number
): Promise<FileInventory> {
  // A single file is a valid scan root; the directory walker would report it
  // as an ENOTDIR coverage gap.
  if (isRegularFile(root)) {
    const included = !shouldSkipFile(root, path.dirname(root));
    return { files: included ? [root] : [], filesSkipped: included ? 0 : 1, truncated: false };
  }

  let filesSkipped = 0;

  const { files, truncated } = await walkDirectory(root, {
    diagnostics,
    maxFiles,
    shouldEnterDirectory: (fullPath) => {
      if (isPathIgnored(fullPath, root, config)) return false;
      return !shouldSkipFile(fullPath, root);
    },
    shouldReadFile: (fullPath) => {
      if (shouldSkipFile(fullPath, root) || isPathIgnored(fullPath, root, config)) {
        filesSkipped++;
        return false;
      }
      return true;
    },
  });

  return { files, filesSkipped, truncated };
}

function isRegularFile(candidate: string): boolean {
  try {
    return statSync(candidate).isFile();
  } catch {
    // Non-existent or unreadable roots are handled by the walker, which records
    // the failure as a coverage gap rather than guessing.
    return false;
  }
}

interface SweepResult {
  findings: Finding[];
  filesScanned: number;
  filesSkipped: number;
  /** Files given a Semgrep pass, counted after the fact from its own output. */
  filesSemgrepCovered: number;
  /** Files given a pattern-engine pass, including Semgrep's coverage gaps. */
  filesPatternScanned: number;
  /** Files that received no static-analysis pass at all. Must be zero. */
  filesWithoutStaticAnalysis: number;
}

/**
 * Reads every candidate file once and runs every analysis over it.
 *
 * A file counts as unanalysed only when no engine examined it: Semgrep did not
 * report it as scanned and the pattern registry has no rules for its language.
 * Semgrep declines whole categories of file (built-in ignores, unparseable
 * sources, timed-out batches), so those gaps have to reach the coverage counts.
 */
async function sweepFiles(
  files: readonly string[],
  diagnostics: Diagnostics,
  options: {
    semgrepAnalyzed: ReadonlySet<string>;
    semgrepUsed: boolean;
    concurrency: number;
    root: string;
  }
): Promise<SweepResult> {
  const findings: Finding[] = [];
  let filesScanned = 0;
  let filesSkipped = 0;
  let filesSemgrepCovered = 0;
  let filesPatternScanned = 0;
  let filesWithoutStaticAnalysis = 0;

  await mapWithConcurrency(
    files,
    async (filePath) => {
      const code = await readTextFile(filePath, { maxBytes: MAX_FILE_BYTES, diagnostics });
      if (code === null) {
        // Oversized, binary, or unreadable. readTextFile has already recorded
        // unreadable files against the diagnostics collector.
        filesSkipped++;
        return;
      }

      filesScanned++;

      const coveredBySemgrep = options.semgrepUsed && options.semgrepAnalyzed.has(filePath);
      if (coveredBySemgrep) filesSemgrepCovered++;

      const scan = scanCode(code, filePath, undefined, options.root);
      // push(...array) passes every element as an argument, so a file with tens
      // of thousands of findings overflows the call stack. The throw was then
      // swallowed and the file reported as clean.
      for (const finding of scan.findings) findings.push(finding);
      if (scan.analyzed) filesPatternScanned++;
      else if (!coveredBySemgrep && !isDependencyManifest(filePath)) {
        // A dependency manifest holds no code to analyse statically; it is
        // covered by the dependency audit instead. Counting it as a gap made
        // the coverage figure permanently short by the number of manifests in
        // the project, and kept the benchmark's coverage gate red.
        filesWithoutStaticAnalysis++;
      }

      for (const finding of detectSecrets(code, filePath)) findings.push(finding);
    },
    options.concurrency,
    (filePath, _index, error) => {
      // Counted as scanned a moment ago, so undo that and say what happened.
      filesScanned--;
      filesWithoutStaticAnalysis++;
      diagnostics.add(
        `${filePath} could not be analysed and was not scanned: ${errorMessage(error)}`
      );
    }
  );

  return {
    findings,
    filesScanned,
    filesSkipped,
    filesSemgrepCovered,
    filesPatternScanned,
    filesWithoutStaticAnalysis,
  };
}

/** True for a file the dependency auditor handles rather than the static engines. */
function isDependencyManifest(filePath: string): boolean {
  const name = path.basename(filePath).toLowerCase();
  return DEPENDENCY_MANIFESTS.includes(name) || name.startsWith("requirements");
}

/** Locates dependency manifests, honouring the same exclusions as the file sweep. */
async function findDependencyManifests(
  root: string,
  config: SentinelConfig,
  diagnostics: Diagnostics,
  maxFiles?: number
): Promise<string[]> {
  // Scanning one file has no dependency tree to audit, and walking it would
  // fail with ENOTDIR and surface as a spurious coverage gap.
  if (isRegularFile(root)) return [];

  const { files } = await walkDirectory(root, {
    diagnostics,
    maxFiles,
    shouldEnterDirectory: (fullPath) => !isPathIgnored(fullPath, root, config),
    shouldReadFile: (fullPath, name) => {
      const lower = name.toLowerCase();
      const isManifest = DEPENDENCY_MANIFESTS.includes(lower) || lower.startsWith("requirements");
      return isManifest && !isPathIgnored(fullPath, root, config);
    },
  });

  return preferLockfiles(files);
}

/**
 * Drops a loose manifest when a lockfile for the same ecosystem sits in the
 * same directory. The loose manifest carries version ranges, and auditing the
 * floor of a range reports advisories against a version that is not installed.
 */
function preferLockfiles(manifests: readonly string[]): string[] {
  const byDirectory = new Map<string, Set<string>>();
  for (const manifest of manifests) {
    const directory = path.dirname(manifest);
    const names = byDirectory.get(directory);
    if (names) names.add(path.basename(manifest).toLowerCase());
    else byDirectory.set(directory, new Set([path.basename(manifest).toLowerCase()]));
  }

  return manifests.filter((manifest) => {
    const supersedes = MANIFEST_SUPERSEDED_BY[path.basename(manifest).toLowerCase()];
    if (!supersedes) return true;

    const siblings = byDirectory.get(path.dirname(manifest));
    return !supersedes.some((lockfile) => siblings?.has(lockfile));
  });
}
