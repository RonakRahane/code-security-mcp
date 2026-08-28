/**
 * Detection-quality regression harness.
 *
 * This is a regression gate over a small, hand-labelled corpus. It answers
 * "did a rule change break detections that used to work?", not "how accurate
 * is the scanner?". The corpus is small and its labels were written alongside
 * the rules, so the numbers carry no statistical confidence and are not
 * independent. Validated precision and recall need an external corpus such as
 * the OWASP Benchmark, the Juliet Test Suite, or CVE-fixing commits.
 *
 * True negatives are not counted: a clean line is not a well-defined
 * opportunity to alert, so specificity, NPV, MCC and the AUC metrics are not
 * computable here and are not reported. Files listed under `clean` do give an
 * unambiguous false-positive signal, since any alert in them is wrong.
 *
 * Both engine configurations are measured, because which one runs depends on
 * whether Semgrep is installed. `--require-semgrep` turns a missing Semgrep
 * into a failure, so a CI image without it cannot report green while testing
 * only the fallback engine.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { performance } from "node:perf_hooks";
import { runUnifiedScan } from "../scanner/unified-scanner.js";

interface GroundTruthV2 {
  version?: number;
  description?: string;
  /** Files expected to contain findings, mapped to the vulnerable line numbers. */
  vulnerable: Record<string, number[]>;
  /** Files expected to produce no findings at all. Any alert here is a false positive. */
  clean?: string[];
  /**
   * Lines within this distance of a label still count as a detection.
   * Multi-line constructs anchor a finding a line or two from the label, and
   * counting that as both a miss and a false alarm penalises it twice.
   */
  lineTolerance?: number;
}

interface Metrics {
  truePositives: number;
  falseNegatives: number;
  falsePositivesInCleanFiles: number;
  /** Info-level alerts on clean files. Reported, not gated. See matchFindings. */
  informationalAlertsInCleanFiles: number;
  unlabelledAlertsInVulnerableFiles: number;
  labelledLines: number;
}

const DEFAULT_LINE_TOLERANCE = 2;

/**
 * Regression floors, not quality claims: they say "must not fall below what
 * this build already does".
 *
 * The two configurations get different floors because they have genuinely
 * different reach. The pattern engine matches one line at a time, so a
 * vulnerability spread across an assignment and a later use is beyond it by
 * construction; Semgrep follows the value. Holding both to one number meant
 * that adding a taint-only test case lowered the shared floor's headroom
 * without anything having regressed, which is a tripwire rather than a gate.
 */
const MIN_RECALL_BY_MODE: Readonly<Record<string, number>> = {
  pattern: 0.85,
  semgrep: 0.95,
};
const MAX_CLEAN_FILE_ALERTS = 0;

interface EngineMode {
  key: string;
  label: string;
  /** Passed through to runUnifiedScan; undefined means "whatever is installed". */
  semgrep: boolean;
}

const ENGINE_MODES: readonly EngineMode[] = [
  {
    key: "pattern",
    label: "Pattern engine only (Semgrep disabled)",
    semgrep: false,
  },
  {
    key: "semgrep",
    label: "Semgrep + pattern engine (default when Semgrep is installed)",
    semgrep: true,
  },
];

function parseGroundTruth(raw: unknown): GroundTruthV2 {
  if (typeof raw !== "object" || raw === null) {
    throw new Error("Ground truth must be a JSON object.");
  }

  const record = raw as Record<string, unknown>;

  // v2 format.
  if (record.vulnerable && typeof record.vulnerable === "object") {
    return {
      version: 2,
      description: typeof record.description === "string" ? record.description : undefined,
      vulnerable: record.vulnerable as Record<string, number[]>,
      clean: Array.isArray(record.clean) ? record.clean.filter((v): v is string => typeof v === "string") : [],
      lineTolerance: typeof record.lineTolerance === "number" ? record.lineTolerance : DEFAULT_LINE_TOLERANCE,
    };
  }

  // v1 format: a flat map of filename to vulnerable line numbers.
  const vulnerable: Record<string, number[]> = {};
  for (const [key, value] of Object.entries(record)) {
    if (Array.isArray(value)) vulnerable[key] = value.filter((v): v is number => typeof v === "number");
  }

  return { version: 1, vulnerable, clean: [], lineTolerance: DEFAULT_LINE_TOLERANCE };
}

function renderTable(headers: string[], rows: string[][]): string {
  const widths = headers.map((header, i) => Math.max(header.length, ...rows.map((row) => row[i]?.length || 0)));
  const separator = `+${widths.map((w) => "-".repeat(w + 2)).join("+")}+`;
  const line = (cells: string[]) => `|${cells.map((cell, i) => ` ${cell.padEnd(widths[i])} `).join("|")}|`;
  return [separator, line(headers), separator, ...rows.map(line), separator].join("\n");
}

function percent(value: number): string {
  return `${(value * 100).toFixed(2)}%`;
}

async function runBenchmark(): Promise<number> {
  const argv = process.argv.slice(2);
  const requireSemgrep = argv.includes("--require-semgrep") || process.env.SENTINEL_REQUIRE_SEMGREP === "1";
  const [targetDir, groundTruthPath] = argv.filter((arg) => !arg.startsWith("--"));

  if (!targetDir || !groundTruthPath) {
    console.error(
      "Usage: node dist/reporting/benchmark-runner.js <scan-dir> <ground-truth-json> [--require-semgrep]"
    );
    return 2;
  }

  const resolvedDir = path.resolve(targetDir);
  const resolvedGroundTruth = path.resolve(groundTruthPath);

  if (!fs.existsSync(resolvedDir)) {
    console.error(`Error: directory not found: ${resolvedDir}`);
    return 2;
  }
  if (!fs.existsSync(resolvedGroundTruth)) {
    console.error(`Error: ground truth file not found: ${resolvedGroundTruth}`);
    return 2;
  }

  const groundTruth = parseGroundTruth(JSON.parse(fs.readFileSync(resolvedGroundTruth, "utf-8")));
  const tolerance = groundTruth.lineTolerance ?? DEFAULT_LINE_TOLERANCE;

  console.log("=================================================================");
  console.log("Sentinel detection-quality regression harness");
  console.log("=================================================================");
  console.log(`Scan target   : ${resolvedDir}`);
  console.log(`Ground truth  : ${resolvedGroundTruth}`);
  console.log(`Corpus        : ${Object.keys(groundTruth.vulnerable).length} vulnerable file(s), ` +
    `${groundTruth.clean?.length ?? 0} clean file(s)`);
  console.log(`Line tolerance: ±${tolerance}`);
  console.log("");

  const outcomes: ModeOutcome[] = [];

  for (const mode of ENGINE_MODES) {
    outcomes.push(await measureMode(mode, resolvedDir, groundTruth, tolerance));
  }

  console.log("Not computable from this corpus: specificity, NPV, MCC, balanced accuracy,");
  console.log("ROC-AUC, PR-AUC. True negatives are undefined at line granularity, and the");
  console.log("scanner emits binary alerts rather than calibrated probabilities.");
  console.log("These figures are internal regression results over a small hand-labelled");
  console.log("corpus. They are not validated accuracy metrics and must not be published");
  console.log("as such without an independent benchmark such as the OWASP Benchmark or");
  console.log("the Juliet Test Suite.");
  console.log("");

  console.log("--- Engine comparison ---");
  console.log(renderTable(
    ["Configuration", "Semgrep ran", "Recall", "Precision", "F1", "Files w/o analysis"],
    outcomes.map((outcome) => [
      outcome.mode.label,
      outcome.semgrepUsed ? "yes" : "no",
      percent(outcome.recall),
      outcome.precisionDenominator > 0 ? percent(outcome.precision) : "n/a",
      outcome.precisionDenominator > 0 ? percent(outcome.f1) : "n/a",
      String(outcome.filesWithoutStaticAnalysis),
    ])
  ));
  console.log("");

  // A configuration that was requested but did not run is reported as untested
  // rather than folded into the pass.
  const semgrepMode = outcomes.find((outcome) => outcome.mode.key === "semgrep");
  const semgrepUntested = Boolean(semgrepMode && !semgrepMode.semgrepUsed);

  console.log("--- Regression gate ---");
  let passed = true;

  for (const outcome of outcomes) {
    const floor = MIN_RECALL_BY_MODE[outcome.mode.key] ?? 0.85;
    const recallOk = outcome.recall >= floor;
    const cleanOk = outcome.falsePositivesInCleanFiles <= MAX_CLEAN_FILE_ALERTS;
    const analysisOk = outcome.filesWithoutStaticAnalysis === 0;
    passed &&= recallOk && cleanOk && analysisOk;

    console.log(`  [${outcome.mode.key}] Recall ≥ ${percent(floor)}: ` +
      `${recallOk ? "PASS" : "FAIL"} (${percent(outcome.recall)})`);
    console.log(`  [${outcome.mode.key}] Actionable alerts in clean files ≤ ${MAX_CLEAN_FILE_ALERTS}: ` +
      `${cleanOk ? "PASS" : "FAIL"} (${outcome.falsePositivesInCleanFiles})` +
      (outcome.informationalAlertsInCleanFiles > 0
        ? `, plus ${outcome.informationalAlertsInCleanFiles} informational (not gated)`
        : ""));
    console.log(`  [${outcome.mode.key}] Files scanned without any analysis = 0: ` +
      `${analysisOk ? "PASS" : "FAIL"} (${outcome.filesWithoutStaticAnalysis})`);
  }

  if (semgrepUntested) {
    const verdict = requireSemgrep ? "FAIL" : "WARN";
    passed &&= !requireSemgrep;
    console.log(`  [semgrep] Semgrep available on this machine: ${verdict}`);
    console.log("           Semgrep is not installed, so the engine most users run was not");
    console.log(requireSemgrep
      ? "           measured. Install Semgrep on this runner before gating on it."
      : "           measured. Install Semgrep, or pass --require-semgrep to make this a\n" +
        "           failure instead of a quietly narrower run.");
  }

  console.log("=================================================================");

  return passed ? 0 : 1;
}

interface ModeOutcome {
  mode: EngineMode;
  semgrepUsed: boolean;
  recall: number;
  precision: number;
  f1: number;
  precisionDenominator: number;
  falsePositivesInCleanFiles: number;
  informationalAlertsInCleanFiles: number;
  filesWithoutStaticAnalysis: number;
}

async function measureMode(
  mode: EngineMode,
  resolvedDir: string,
  groundTruth: GroundTruthV2,
  tolerance: number
): Promise<ModeOutcome> {
  console.log("=================================================================");
  console.log(`Configuration: ${mode.label}`);
  console.log("=================================================================");

  const startCpu = process.cpuUsage();
  const startMemory = process.memoryUsage().heapUsed;
  const startTime = performance.now();

  // Offline, so the measurement reflects the scanner rather than network
  // latency or a registry rule pack that moved since the last run.
  const scanResult = await runUnifiedScan(resolvedDir, { offline: true, semgrep: mode.semgrep });

  const durationMs = performance.now() - startTime;
  const cpuUsage = process.cpuUsage(startCpu);
  const memoryDeltaMb = (process.memoryUsage().heapUsed - startMemory) / 1024 / 1024;

  const metrics = matchFindings(scanResult.findings, groundTruth, tolerance);

  // Precision counts only unambiguous false positives, meaning alerts in files
  // labelled clean. Unlabelled alerts inside vulnerable files are reported
  // separately, since a fixture written for one flaw often contains others.
  const precisionDenominator = metrics.truePositives + metrics.falsePositivesInCleanFiles;
  const precision = precisionDenominator > 0 ? metrics.truePositives / precisionDenominator : 0;
  const recallDenominator = metrics.truePositives + metrics.falseNegatives;
  const recall = recallDenominator > 0 ? metrics.truePositives / recallDenominator : 0;
  const f1 = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;

  console.log("--- Detection counts ---");
  console.log(renderTable(["Metric", "Count", "Meaning"], [
    ["True positives", String(metrics.truePositives), "Labelled vulnerable lines that were detected"],
    ["False negatives", String(metrics.falseNegatives), "Labelled vulnerable lines that were missed"],
    ["False positives", String(metrics.falsePositivesInCleanFiles), "Alerts raised in files labelled clean"],
    ["Unlabelled alerts", String(metrics.unlabelledAlertsInVulnerableFiles), "Alerts in vulnerable files on unlabelled lines"],
    ["Labelled lines", String(metrics.labelledLines), "Total ground-truth positives in the corpus"],
  ]));
  console.log("");

  console.log("--- Derived rates (this corpus only) ---");
  console.log(renderTable(["Metric", "Value"], [
    ["Recall", percent(recall)],
    ["Precision", precisionDenominator > 0 ? percent(precision) : "n/a (no clean-file corpus)"],
    ["F1", precisionDenominator > 0 ? percent(f1) : "n/a"],
  ]));
  console.log("");

  console.log("--- Coverage and performance ---");
  console.log(renderTable(["Resource", "Value"], [
    ["Wall-clock duration", `${durationMs.toFixed(2)} ms`],
    ["CPU time", `${((cpuUsage.user + cpuUsage.system) / 1000).toFixed(2)} ms`],
    ["Heap delta", `${memoryDeltaMb.toFixed(2)} MB`],
    ["Files scanned", String(scanResult.filesScanned)],
    ["Analysed by Semgrep", String(scanResult.engine.filesAnalyzedBySemgrep ?? 0)],
    ["Analysed by pattern engine", String(scanResult.engine.filesAnalyzedByPatternEngine ?? 0)],
    ["Scanned with no analysis", String(scanResult.coverage.filesWithoutStaticAnalysis ?? 0)],
    ["Throughput", `${(scanResult.filesScanned / (durationMs / 1000)).toFixed(2)} files/sec`],
  ]));
  console.log("");

  if (scanResult.warnings.length > 0) {
    console.log("--- Scan warnings ---");
    for (const warning of scanResult.warnings) console.log(`  - ${warning}`);
    console.log("");
  }

  reportMisses(metrics.missesByFile);

  return {
    mode,
    semgrepUsed: scanResult.engine.used,
    recall,
    precision,
    f1,
    precisionDenominator,
    falsePositivesInCleanFiles: metrics.falsePositivesInCleanFiles,
    informationalAlertsInCleanFiles: metrics.informationalAlertsInCleanFiles,
    filesWithoutStaticAnalysis: scanResult.coverage.filesWithoutStaticAnalysis ?? 0,
  };
}

interface MatchResult extends Metrics {
  missesByFile: Array<{ filename: string; lines: number[] }>;
}

/**
 * Matches findings to labelled lines one-to-one inside the tolerance window.
 *
 * One-to-one matters in both directions: crediting every nearby label to one
 * alert inflates recall where labels are consecutive, and letting one finding
 * claim the first label it sits near deflates it. Closest pairs match first,
 * and each finding and label is consumed at most once.
 */
function matchFindings(
  findings: readonly { filePath: string; line: number; severity?: string }[],
  groundTruth: GroundTruthV2,
  tolerance: number
): MatchResult {
  const cleanFiles = new Set(groundTruth.clean || []);

  let falsePositivesInCleanFiles = 0;
  let informationalAlertsInCleanFiles = 0;
  let unlabelledAlertsInVulnerableFiles = 0;
  let truePositives = 0;
  let labelledLines = 0;
  const missesByFile: Array<{ filename: string; lines: number[] }> = [];

  const findingsByFile = new Map<string, number[]>();
  for (const finding of findings) {
    const filename = path.basename(finding.filePath);
    if (cleanFiles.has(filename)) {
      // "info" is not an assertion that the code is vulnerable; it marks
      // something worth a glance, such as MD5 used as a cache key. Counting it
      // as a false positive would push the rules towards dropping that signal
      // instead of grading it, so it is reported separately rather than gated.
      if (finding.severity === "info") informationalAlertsInCleanFiles++;
      else falsePositivesInCleanFiles++;
      continue;
    }
    const lines = findingsByFile.get(filename);
    if (lines) lines.push(finding.line);
    else findingsByFile.set(filename, [finding.line]);
  }

  for (const [filename, labels] of Object.entries(groundTruth.vulnerable)) {
    labelledLines += labels.length;

    const alertLines = findingsByFile.get(filename) ?? [];
    const claimedAlerts = new Set<number>();
    const matchedLabels = new Set<number>();

    const pairs: Array<{ label: number; alertIndex: number; distance: number }> = [];
    for (const label of labels) {
      alertLines.forEach((alertLine, alertIndex) => {
        const distance = Math.abs(alertLine - label);
        if (distance <= tolerance) pairs.push({ label, alertIndex, distance });
      });
    }

    // Closest first; ties resolved by line number so the result is deterministic.
    pairs.sort((a, b) => a.distance - b.distance || a.label - b.label || a.alertIndex - b.alertIndex);

    for (const pair of pairs) {
      if (matchedLabels.has(pair.label) || claimedAlerts.has(pair.alertIndex)) continue;
      matchedLabels.add(pair.label);
      claimedAlerts.add(pair.alertIndex);
    }

    truePositives += matchedLabels.size;
    unlabelledAlertsInVulnerableFiles += alertLines.length - claimedAlerts.size;

    const missed = labels.filter((label) => !matchedLabels.has(label));
    if (missed.length > 0) missesByFile.push({ filename, lines: missed });
  }

  // Alerts in files carrying no labels at all are outside the corpus: they are
  // neither credited as detections nor penalised as false positives.

  return {
    truePositives,
    falseNegatives: labelledLines - truePositives,
    falsePositivesInCleanFiles,
    informationalAlertsInCleanFiles,
    unlabelledAlertsInVulnerableFiles,
    labelledLines,
    missesByFile,
  };
}

function reportMisses(missesByFile: MatchResult["missesByFile"]): void {
  if (missesByFile.length === 0) return;

  console.log("--- Missed detections ---");
  for (const miss of missesByFile) {
    console.log(`  ${miss.filename}: lines ${miss.lines.join(", ")}`);
  }
  console.log("");
}

runBenchmark()
  .then((code) => { process.exitCode = code; })
  .catch((error: unknown) => {
    console.error("Benchmark failed:", error instanceof Error ? error.message : error);
    process.exitCode = 2;
  });
