/**
 * Records the findings that already exist, so later scans report only what is
 * new.
 *
 * Adopting a scanner on an existing project otherwise means a wall of findings
 * on day one, which is how a check ends up disabled. The CLI has had
 * `--write-baseline` for this; without the same thing here an agent could read
 * a baseline but never create one, so it could not adopt Sentinel on a
 * codebase that was not already clean.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { runUnifiedScan } from "../scanner/unified-scanner.js";
import { createBaseline, getBaselinePath, loadBaseline, writeBaseline } from "../scanner/baseline.js";
import { SERVER_VERSION } from "../version.js";
import { jsonResponse, pathArgument, requirePath, runTool } from "./shared.js";

export function registerCreateBaseline(server: McpServer): void {
  server.tool(
    "create_baseline",
    "Record the project's current findings in .sentinel-baseline.json so later scans report only new ones. Use when adopting Sentinel on an existing codebase that would otherwise report a wall of pre-existing issues. Commit the file.",
    {
      dirPath: pathArgument("Absolute path to the project root"),
      overwrite: z.boolean().optional()
        .describe("Replace an existing baseline. Defaults to false, which refuses rather than silently widening what is suppressed."),
    },
    async ({ dirPath, overwrite }) => runTool("create_baseline", async () => {
      const target = requirePath(dirPath, "directory", "dirPath");
      const baselinePath = getBaselinePath(target.absolutePath);

      const existing = (() => {
        try {
          return loadBaseline(baselinePath);
        } catch {
          return null;
        }
      })();

      if (existing && !overwrite) {
        return jsonResponse({
          baselinePath,
          written: false,
          reason: "A baseline already exists. Pass overwrite: true to replace it.",
          existingFindings: existing.findingFingerprints.length,
          existingDependencies: existing.dependencyFingerprints.length,
          generatedAt: existing.generatedAt,
        });
      }

      // Baseline suppression is bypassed on purpose. Building a baseline from
      // an already-suppressed scan would record only the new findings and drop
      // every previously accepted one, resurfacing them all on the next scan.
      const scan = await runUnifiedScan(target.absolutePath, { ignoreBaseline: true });

      const baseline = createBaseline(scan.findings, scan.dependencyVulnerabilities, {
        rootPath: target.absolutePath,
        scannerVersion: SERVER_VERSION,
      });
      writeBaseline(baselinePath, baseline);

      return jsonResponse({
        baselinePath,
        written: true,
        replacedExisting: Boolean(existing),
        findingsRecorded: baseline.findingFingerprints.length,
        dependenciesRecorded: baseline.dependencyFingerprints.length,
        filesScanned: scan.filesScanned,
        summary: scan.summary,
        note: "Commit .sentinel-baseline.json. Later scans report only findings absent from it. Re-run this tool to refresh the baseline; it always records the complete current set.",
        warnings: scan.warnings,
      });
    })
  );
}
