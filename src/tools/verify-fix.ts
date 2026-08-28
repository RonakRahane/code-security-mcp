/**
 * Confirms whether a finding is actually gone.
 *
 * Without this an agent that edits a file has no way to know its change worked.
 * Re-running scan_directory returns the whole project and leaves the agent to
 * diff two lists; re-running scan_file answers "what is here now" rather than
 * "did the thing I was fixing go away". Both invite the agent to assume success.
 *
 * It also reports findings the edit introduced, because a fix that trades one
 * vulnerability for another is not a fix.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import * as path from "node:path";
import { z } from "zod";
import { Finding } from "../types/index.js";
import { MAX_FILE_BYTES } from "../core/constants.js";
import { Diagnostics } from "../core/diagnostics.js";
import { dedupeFindings } from "../core/findings.js";
import { readTextFile } from "../core/fs-walk.js";
import { computeSeveritySummary, sortBySeverity } from "../core/severity.js";
import { scanWithSemgrep } from "../scanner/semgrep.js";
import { scanCode } from "../scanner/pattern-engine.js";
import { detectSecrets } from "../scanner/secret-detector.js";
import {
  filterByMinimumSeverity,
  filterIgnoredFindings,
  findConfigPath,
  isOfflineMode,
  loadSentinelConfig,
} from "../scanner/config.js";
import { jsonResponse, pathArgument, requirePath, runTool } from "./shared.js";

/** Same pipeline scan_file uses, so a verdict here matches what a scan reports. */
async function scanOneFile(resolvedPath: string, diagnostics: Diagnostics): Promise<Finding[]> {
  const config = loadSentinelConfig(resolvedPath, diagnostics);
  const configPath = findConfigPath(resolvedPath);
  const configRoot = configPath ? path.dirname(configPath) : path.dirname(resolvedPath);

  const code = await readTextFile(resolvedPath, { maxBytes: MAX_FILE_BYTES, diagnostics });
  if (code === null) return [];

  const findings: Finding[] = [];
  // Honour semgrep.enabled, which only the unified scanner used to check:
  // the same file otherwise reported different rule ids depending on
  // which tool asked, which then fed baseline and dedupe identity.
  const semgrep = config.semgrep?.enabled === false
    ? null
    : await scanWithSemgrep(resolvedPath, {
    timeoutMs: config.semgrep?.timeoutMs ?? 30_000,
    registryRulesets: config.semgrep?.registryRulesets,
    offline: isOfflineMode(config),
  });
  if (semgrep?.status.used) for (const item of semgrep.findings) findings.push(item);

  findings.push(...scanCode(code, resolvedPath, undefined, configRoot).findings);
  findings.push(...detectSecrets(code, resolvedPath));

  // The same policy scan_file applies. Without it this reported "the edit did
  // not remove it" for a finding the project has chosen to ignore, so a fix
  // could never be confirmed for any suppressed rule.
  return filterByMinimumSeverity(
    filterIgnoredFindings(dedupeFindings(findings), config, configRoot),
    config
  );
}

export function registerVerifyFix(server: McpServer): void {
  server.tool(
    "verify_fix",
    "Re-scan a file after editing it and report whether a specific finding is gone, plus anything the edit introduced. Use after auto_fix or your own edit, instead of assuming the change worked.",
    {
      filePath: pathArgument("Absolute path to the file that was edited"),
      ruleId: z.string().min(1).max(200).optional()
        .describe("The rule whose finding should be gone, for example 'SQL_INJECTION_CONCAT'. Omit to check the whole file."),
      line: z.number().int().positive().max(10_000_000).optional()
        .describe("Line the finding was reported on, before the edit. Matching allows a small drift, since a fix often changes line numbers."),
      lineTolerance: z.number().int().min(0).max(200).optional()
        .describe("How far the finding may have moved. Defaults to 10."),
    },
    async ({ filePath, ruleId, line, lineTolerance }) => runTool("verify_fix", async () => {
      const target = requirePath(filePath, "file", "filePath");
      const diagnostics = new Diagnostics();
      const findings = await scanOneFile(target.absolutePath, diagnostics);
      sortBySeverity(findings);

      const tolerance = lineTolerance ?? 10;
      // Anywhere in the file, not only near the line the caller remembered. A
      // fix that moves code rather than changing it is not a fix, and matching
      // on the line alone reported "resolved" for a credential that had simply
      // drifted past the tolerance.
      const sameRule = ruleId ? findings.filter((f) => f.ruleId === ruleId) : findings;

      const stillPresent = ruleId && line !== undefined
        ? sameRule.filter((f) => Math.abs(f.line - line) <= tolerance)
        : sameRule;

      // Reported separately so the caller can see the difference between "gone"
      // and "moved".
      const movedElsewhere = sameRule.filter((f) => !stillPresent.includes(f));
      const resolved = sameRule.length === 0;

      return jsonResponse({
        filePath: target.absolutePath,
        checked: ruleId ? { ruleId, line: line ?? null, lineTolerance: tolerance } : "whole file",
        resolved,
        verdict: resolved
          ? (ruleId
            ? `${ruleId} is no longer reported anywhere in this file.`
            : "No findings remain in this file.")
          : movedElsewhere.length > 0 && stillPresent.length === 0
            ? `${ruleId} moved but is still present, now at line ${movedElsewhere[0].line}.`
            : `${ruleId ?? "Findings"} still reported. The edit did not remove it.`,
        stillPresent,
        ...(movedElsewhere.length > 0
          ? {
              movedElsewhere,
              movedNote: `${ruleId ?? "The finding"} no longer appears at the line given, but is still reported elsewhere in this file. Moving code does not remove the finding.`,
            }
          : {}),
        // A fix that introduces a different vulnerability is not a fix, and an
        // agent checking only its own rule would never see it.
        // Everything not already listed above. Excluding by rule id meant a
        // finding of the same rule that had drifted past lineTolerance fell
        // out of both lists: it was not "still present" at the given line and
        // not "other", so the response reported resolved with the credential
        // still in the file.
        otherFindingsInFile: findings.filter((f) => !stillPresent.includes(f)),
        summary: computeSeveritySummary(findings),
        warnings: diagnostics.toWarnings(),
      });
    })
  );
}
