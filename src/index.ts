#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { ensureSemgrep } from "./core/semgrep-install.js";
import * as fs from "node:fs";
import * as fsp from "node:fs/promises";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { Severity } from "./types/index.js";
import { errorMessage, logger, setLogLevel } from "./core/logger.js";
import { PathValidationError, validatePath } from "./core/paths.js";
import { computeSeveritySummary, countAtOrAbove } from "./core/severity.js";
import { runUnifiedScan } from "./scanner/unified-scanner.js";
import { loadSentinelConfig } from "./scanner/config.js";
import { detectLanguage } from "./scanner/pattern-engine.js";
import { writeFileNoFollow } from "./core/safe-write.js";
import { generateSarif } from "./scanner/sarif.js";
import { createBaseline, getBaselinePath, writeBaseline } from "./scanner/baseline.js";
import { renderMarkdownReport } from "./reporting/markdown-report.js";

// Tool registrations

import { registerScanFile } from "./tools/scan-file.js";
import { registerScanDirectory } from "./tools/scan-directory.js";
import { registerDetectSecrets } from "./tools/detect-secrets.js";
import { registerCheckDependencies } from "./tools/check-dependencies.js";
import { registerScanGitHistory } from "./tools/scan-git-history.js";
import { registerScanPrDiff } from "./tools/scan-pr-diff.js";
import { registerPostSecurityReview } from "./tools/post-security-review.js";
import { registerExplainVulnerability } from "./tools/explain-vulnerability.js";
import { registerSecurityReport } from "./tools/security-report.js";
import { registerAutoFix } from "./tools/auto-fix.js";
import { registerExportSarif } from "./tools/export-sarif.js";
import { registerListRules } from "./tools/list-rules.js";
import { registerListOpenPrs } from "./tools/list-open-prs.js";
import { registerGetPrDiff } from "./tools/get-pr-diff.js";
import { registerVerifyFix } from "./tools/verify-fix.js";
import { registerCreateBaseline } from "./tools/create-baseline.js";

import { SERVER_VERSION } from "./version.js";

export { SERVER_VERSION };

/**
 * Exit codes are part of the CLI contract. CI has to tell "the scan ran and
 * found blocking issues" apart from "the scan could not run".
 */
const EXIT_OK = 0;
const EXIT_FINDINGS = 1;
const EXIT_ERROR = 2;

// CLI mode

export interface CliScanOptions {
  /** Write a SARIF 2.1.0 report to this path, for CI code-scanning upload. */
  sarifPath?: string;
  /** Suppress writing sentinel-report.md into the scanned project. */
  noReportFile?: boolean;
  /**
   * Records every current finding in .sentinel-baseline.json and exits without
   * failing. Adopting a scanner on an existing project otherwise means a red
   * build on day one; a baseline makes later scans report only what is new.
   */
  writeBaseline?: boolean;
}

async function runCliScan(targetDir: string, options: CliScanOptions = {}): Promise<number> {
  let resolvedPath: string;
  try {
    resolvedPath = validatePath(targetDir, { kind: "directory", label: "scan target" }).absolutePath;
  } catch (error) {
    const message = error instanceof PathValidationError ? error.message : errorMessage(error);
    process.stderr.write(`Error: ${message}\n`);
    return EXIT_ERROR;
  }

  process.stderr.write(`Sentinel scanning: ${resolvedPath}\n`);

  // Resolved up front rather than inside the scan so a first-run install,
  // which takes minutes, explains itself instead of looking like a hang.
  const semgrep = await ensureSemgrep();
  if (semgrep.status === "ready") {
    process.stderr.write(
      `Semgrep ${semgrep.version}${semgrep.installed ? " (installed just now)" : ""}\n`
    );
  } else {
    process.stderr.write(`Warning: ${semgrep.message}\n`);
  }

  // Writing a baseline needs the full picture, not what an existing baseline
  // has already suppressed.
  const scanResult = await runUnifiedScan(resolvedPath, {
    ignoreBaseline: options.writeBaseline,
  });

  if (options.writeBaseline) {
    const baselinePath = getBaselinePath(resolvedPath);
    try {
      writeBaseline(baselinePath, createBaseline(
        scanResult.findings,
        scanResult.dependencyVulnerabilities,
        { rootPath: resolvedPath, scannerVersion: SERVER_VERSION }
      ));
    } catch (error) {
      process.stderr.write(`Error: baseline could not be written: ${errorMessage(error)}\n`);
      return EXIT_ERROR;
    }

    process.stderr.write(
      `Baseline written to ${baselinePath}\n` +
      `  ${scanResult.findings.length} finding(s) and ` +
      `${scanResult.dependencyVulnerabilities.length} dependency vulnerability(ies) recorded.\n` +
      `  Future scans report only what is new. Commit this file.\n`
    );
    // Recording findings is an administrative step, not a gate. Failing on the
    // very findings just accepted would make the flag unusable in CI.
    return EXIT_OK;
  }

  const markdownReport = renderMarkdownReport({
    projectName: path.basename(resolvedPath),
    generatedAt: scanResult.generatedAt,
    projectRoot: resolvedPath,
    filesScanned: scanResult.filesScanned,
    findings: scanResult.findings,
    dependencies: scanResult.dependencyVulnerabilities,
    coverage: scanResult.coverage,
    engine: scanResult.engine,
    warnings: scanResult.warnings,
  }, {
    // The prompt suits a conversation with an agent, not a file that gets
    // committed or a terminal that has already returned to the shell.
    closingPrompt: false,
  });

  process.stdout.write(`${markdownReport}\n`);

  if (!options.noReportFile) {
    const reportPath = path.join(resolvedPath, "sentinel-report.md");
    try {
      await writeFileNoFollow(reportPath, markdownReport);
      process.stderr.write(`Report saved to: ${reportPath}\n`);
    } catch (error) {
      process.stderr.write(`Warning: report file could not be written: ${errorMessage(error)}\n`);
    }
  }

  if (options.sarifPath) {
    try {
      await writeFileNoFollow(path.resolve(options.sarifPath), buildSarif(scanResult, path.basename(resolvedPath)));
      process.stderr.write(`SARIF report saved to: ${path.resolve(options.sarifPath)}\n`);
    } catch (error) {
      // CI uploads the SARIF file; failing to write it must not be silent.
      process.stderr.write(`Error: SARIF report could not be written: ${errorMessage(error)}\n`);
      return EXIT_ERROR;
    }
  }

  for (const warning of scanResult.warnings) {
    process.stderr.write(`Warning: ${warning}\n`);
  }

  const config = loadSentinelConfig(resolvedPath);
  const failThreshold: Severity = config.failOnSeverity ?? "high";
  const blockingCount = countAtOrAbove(scanResult.summary, failThreshold);

  if (blockingCount > 0) {
    process.stderr.write(
      `\nFailed: ${blockingCount} finding(s) at or above '${failThreshold}' severity.\n`
    );
    return EXIT_FINDINGS;
  }

  // Semgrep carries every rule that needs data flow: an HTTP parameter
  // assigned to a variable and then reaching a sink is invisible to the
  // line-local pattern engine. Printing "Passed" for a scan that lost that
  // engine reports a clean result for analysis that never ran, and in CI the
  // exit code is all anyone reads. A deliberate opt-out is a different case -
  // the operator chose the trade - so only an unintended loss fails here.
  if (!scanResult.engine.used && !scanResult.engine.disabled) {
    process.stderr.write(
      `\nIncomplete: Semgrep did not run, so only the line-local pattern engine covered this scan. ` +
      `Findings that need data flow to see were not checked, and this result is not a pass.\n` +
      `  Reason: ${scanResult.engine.message ?? "unknown"}\n` +
      `  Install Semgrep, or set {"semgrep": {"enabled": false}} in sentinel.config.json to accept ` +
      `pattern-only scanning deliberately.\n`
    );
    return EXIT_ERROR;
  }

  // An incomplete scan is not a pass, so say so rather than exiting clean.
  if (scanResult.coverage.truncated || scanResult.coverage.filesUnreadable > 0) {
    process.stderr.write(
      `\nPassed with gaps: no blocking findings, but the scan did not cover the whole project ` +
      `(${scanResult.coverage.filesUnreadable} unreadable file(s)` +
      `${scanResult.coverage.truncated ? ", file limit reached" : ""}). Review the warnings above.\n`
    );
    return EXIT_OK;
  }

  // Zero files analysed is not a pass. Configuration inside the scanned tree
  // can exclude everything - `{"ignorePaths": ["**"]}` in a pull request did
  // exactly that - and rendering it as "Passed" turned a security gate into a
  // formality the author being reviewed could switch off.
  if (scanResult.filesScanned === 0) {
    process.stderr.write(
      `\nFailed: no files were analysed. Every file was excluded by configuration, ` +
      `ignore rules, or the file-type filters, so nothing was checked.\n`
    );
    return EXIT_ERROR;
  }

  process.stderr.write(`\nPassed: no findings at or above '${failThreshold}' severity.\n`);
  return EXIT_OK;
}

// MCP server mode

export function createServer(): McpServer {
  const server = new McpServer({ name: "sentinel-mcp", version: SERVER_VERSION });

  // Core scanning
  registerScanFile(server);
  registerScanDirectory(server);
  registerDetectSecrets(server);
  registerScanGitHistory(server);
  registerCheckDependencies(server);

  // GitHub PR integration
  registerScanPrDiff(server);
  registerPostSecurityReview(server);

  // Intelligence and reporting
  registerExplainVulnerability(server);
  registerSecurityReport(server);
  registerAutoFix(server);
  registerExportSarif(server);
  registerListRules(server);
  registerListOpenPrs(server);
  registerGetPrDiff(server);
  registerVerifyFix(server);
  registerCreateBaseline(server);

  return server;
}

async function startMcpServer(): Promise<void> {
  const server = createServer();

  // Start resolving Semgrep now, but do not await it: a first install takes
  // minutes, and the client is waiting on the stdio handshake. Scans await the
  // same memoised promise, so by the time one arrives this is usually done.
  // A rejection here is impossible - ensureSemgrep reports failure in its
  // return value - but an unhandled rejection would take the server down.
  void ensureSemgrep().catch((error) => {
    logger.warn("semgrep readiness check failed", { error: errorMessage(error) });
  });

  const transport = new StdioServerTransport();
  await server.connect(transport);

  logger.info("sentinel-mcp ready", { version: SERVER_VERSION, transport: "stdio" });

  // Close the transport before exiting so an in-flight response is not cut off
  // mid-frame, which a client would surface as a protocol error.
  let shuttingDown = false;
  const shutdown = async (signal: string) => {
    if (shuttingDown) return;
    shuttingDown = true;
    logger.info("shutting down", { signal });
    try {
      await server.close();
    } catch (error) {
      logger.warn("shutdown error", { error: errorMessage(error) });
    }
    process.exit(EXIT_OK);
  };

  process.on("SIGINT", () => void shutdown("SIGINT"));
  process.on("SIGTERM", () => void shutdown("SIGTERM"));
}

export interface CliArgs {
  scanTarget?: string;
  logLevel?: string;
  sarifPath?: string;
  noReportFile?: boolean;
  writeBaseline?: boolean;
}

export function parseArgs(argv: readonly string[]): CliArgs {
  const result: CliArgs = {};

  const valueOf = (flag: string): string | undefined => {
    const index = argv.indexOf(flag);
    return index !== -1 && index + 1 < argv.length ? argv[index + 1] : undefined;
  };

  result.scanTarget = valueOf("--scan");
  result.logLevel = valueOf("--log-level");
  result.sarifPath = valueOf("--sarif");
  result.noReportFile = argv.includes("--no-report-file");
  result.writeBaseline = argv.includes("--write-baseline");

  return result;
}

/** Renders a scan as SARIF 2.1.0, grouped per file as the schema expects. */
function buildSarif(scan: Awaited<ReturnType<typeof runUnifiedScan>>, projectName: string): string {
  const byFile = new Map<string, typeof scan.findings>();
  for (const finding of scan.findings) {
    const group = byFile.get(finding.filePath);
    if (group) group.push(finding);
    else byFile.set(finding.filePath, [finding]);
  }

  const results = [...byFile.entries()].map(([filePath, findings]) => ({
    filePath,
    language: detectLanguage(filePath),
    totalFindings: findings.length,
    findings,
    summary: computeSeveritySummary(findings),
    analyzed: true,
  }));

  return generateSarif(results, projectName, scan.rootPath);
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));

  if (args.logLevel) {
    const level = args.logLevel.toLowerCase();
    if (["debug", "info", "warn", "error", "silent"].includes(level)) {
      setLogLevel(level as "debug" | "info" | "warn" | "error" | "silent");
    }
  }

  if (args.scanTarget !== undefined) {
    // CLI mode writes human output; raise verbosity unless overridden.
    if (!process.env.SENTINEL_LOG_LEVEL && !args.logLevel) setLogLevel("info");
    process.exitCode = await runCliScan(args.scanTarget, {
      sarifPath: args.sarifPath,
      noReportFile: args.noReportFile,
      writeBaseline: args.writeBaseline,
    });
    return;
  }

  await startMcpServer();
}

/** True when this module was run directly. Without it, importing createServer() in a test starts a stdio server. */
/**
 * Whether this module was launched as the command, rather than imported.
 *
 * Both sides go through realpath. npm installs a `bin` as a symlink on macOS
 * and Linux, so argv[1] is `node_modules/.bin/sentinel-mcp` while
 * import.meta.url is `node_modules/sentinel-mcp/dist/index.js`. Comparing the
 * two with path.resolve alone, which does not follow symlinks, was never true
 * there: the installed command produced no output and exited 0, and an MCP
 * client saw the server exit immediately. On Windows npm writes a shim rather
 * than a symlink, so the comparison happened to hold and the fault was
 * invisible on the one platform CI exercised this way.
 */
function isEntryPoint(): boolean {
  const entry = process.argv[1];
  if (!entry) return false;

  const real = (candidate: string): string => {
    try {
      return fs.realpathSync.native(candidate);
    } catch {
      return path.resolve(candidate);
    }
  };

  return real(entry) === real(fileURLToPath(import.meta.url));
}

if (isEntryPoint()) {
  // Unhandled failures must produce a diagnosable message on stderr, never a
  // silent exit or a partial write to the stdout protocol stream.
  process.on("unhandledRejection", (reason) => {
    logger.error("unhandled rejection", { error: errorMessage(reason) });
    process.exitCode = EXIT_ERROR;
  });

  main().catch((error) => {
    logger.error("fatal error", { error: errorMessage(error) });
    process.stderr.write(`Fatal error: ${errorMessage(error)}\n`);
    process.exit(EXIT_ERROR);
  });
}

export { runCliScan };
