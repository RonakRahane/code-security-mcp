import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import * as path from "node:path";
import { Finding } from "../types/index.js";
import { MAX_FILE_BYTES } from "../core/constants.js";
import { Diagnostics } from "../core/diagnostics.js";
import { dedupeFindings } from "../core/findings.js";
import { readTextFile } from "../core/fs-walk.js";
import { errorMessage } from "../core/logger.js";
import { computeSeveritySummary, sortBySeverity } from "../core/severity.js";
import { scanWithSemgrep } from "../scanner/semgrep.js";
import { detectLanguage, scanCode } from "../scanner/pattern-engine.js";
import { detectSecrets } from "../scanner/secret-detector.js";
import {
  filterByMinimumSeverity,
  filterIgnoredFindings,
  findConfigPath,
  isOfflineMode,
  isPathIgnored,
  loadSentinelConfig,
} from "../scanner/config.js";
import { filterFindingsAgainstBaseline, getBaselinePath, loadBaseline } from "../scanner/baseline.js";
import { errorResponse, jsonResponse, pathArgument, requirePath, runTool } from "./shared.js";

export function registerScanFile(server: McpServer): void {
  server.tool(
    "scan_file",
    "Scan a single file for security vulnerabilities and secrets. Uses Semgrep for deep analysis when available, falling back to the built-in pattern engine. Respects sentinel config and baseline suppression.",
    {
      filePath: pathArgument("Absolute path to the file to scan"),
    },
    async ({ filePath }) => runTool("scan_file", async () => {
      const target = requirePath(filePath, "file", "filePath");
      const resolvedPath = target.absolutePath;

      const diagnostics = new Diagnostics();
      const config = loadSentinelConfig(resolvedPath, diagnostics);
      const configPath = findConfigPath(resolvedPath);
      const configRoot = configPath ? path.dirname(configPath) : path.dirname(resolvedPath);

      if (isPathIgnored(resolvedPath, configRoot, config)) {
        return jsonResponse({
          filePath: resolvedPath,
          skipped: true,
          reason: "File is excluded by Sentinel configuration.",
        });
      }

      const code = await readTextFile(resolvedPath, { maxBytes: MAX_FILE_BYTES, diagnostics });
      if (code === null) {
        return errorResponse(
          `File could not be scanned: it is binary, empty of text, larger than ${MAX_FILE_BYTES} bytes, or unreadable.`
        );
      }

      const findings: Finding[] = [];

      // 1. Static analysis. Both engines run over the file, as scan_directory
      // does: Semgrep follows dataflow across statements, and the pattern
      // registry carries rules its packs do not express. Running the registry
      // only as a fallback meant the same file reported different findings
      // depending on whether Semgrep happened to be installed. Overlapping
      // reports are collapsed by dedupeFindings below.
      // Honour semgrep.enabled, which only the unified scanner used to check:
  // the same file otherwise reported different rule ids depending on
  // which tool asked, which then fed baseline and dedupe identity.
  const semgrepResult = config.semgrep?.enabled === false
    ? null
    : await scanWithSemgrep(resolvedPath, {
        timeoutMs: config.semgrep?.timeoutMs ?? 30_000,
        registryRulesets: config.semgrep?.registryRulesets,
        offline: isOfflineMode(config),
      });

      const semgrepUsed = semgrepResult?.status.used ?? false;
      if (semgrepUsed) {
        for (const item of semgrepResult!.findings) findings.push(item);
        diagnostics.addAll(semgrepResult!.warnings);
      } else if (semgrepResult?.status.message) {
        diagnostics.add(`Semgrep unavailable, using the built-in pattern engine: ${semgrepResult.status.message}`);
      }

      findings.push(...scanCode(code, resolvedPath, undefined, configRoot).findings);

      // 2. Secret detection always runs: Semgrep does no entropy analysis.
      findings.push(...detectSecrets(code, resolvedPath));

      // 3. Policy filtering.
      const filtered = filterByMinimumSeverity(filterIgnoredFindings(dedupeFindings(findings), config), config);

      // 4. Baseline suppression.
      let baseline = null;
      try {
        baseline = loadBaseline(getBaselinePath(configRoot));
      } catch (error) {
        diagnostics.add(`Baseline was ignored: ${errorMessage(error)}`);
      }

      const finalFindings = baseline
        ? filterFindingsAgainstBaseline(filtered, baseline, configRoot)
        : filtered;
      sortBySeverity(finalFindings);

      return jsonResponse({
        filePath: resolvedPath,
        language: detectLanguage(resolvedPath),
        totalFindings: finalFindings.length,
        findings: finalFindings,
        summary: computeSeveritySummary(finalFindings),
        engine: {
          engine: semgrepUsed ? "hybrid" : "compatibility",
          available: semgrepResult?.status.available ?? false,
          used: semgrepUsed,
          message: semgrepResult?.status.message,
        },
        warnings: diagnostics.toWarnings(),
        baseline: {
          applied: baseline !== null,
          suppressedFindings: filtered.length - finalFindings.length,
        },
      });
    })
  );
}
