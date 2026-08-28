import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import * as path from "node:path";
import { Finding, ScanResult } from "../types/index.js";
import { computeSeveritySummary } from "../core/severity.js";
import { detectLanguage } from "../scanner/pattern-engine.js";
import { runUnifiedScan } from "../scanner/unified-scanner.js";
import { generateSarif } from "../scanner/sarif.js";
import { pathArgument, requirePath, runTool, textResponse } from "./shared.js";

export function registerExportSarif(server: McpServer): void {
  server.tool(
    "export_sarif",
    "Generate a SARIF v2.1.0 report for a directory, suitable for upload to GitHub Code Scanning or any SARIF-consuming CI tool.",
    {
      dirPath: pathArgument("Absolute path to the project root directory to scan"),
      projectName: z.string().min(1).max(200).optional().describe("Project name for the report header"),
    },
    async ({ dirPath, projectName }) => runTool("export_sarif", async () => {
      const target = requirePath(dirPath, "directory", "dirPath");

      // Reuse the unified pipeline so SARIF export applies the same exclusions
      // and file cap as scan_directory.
      const scan = await runUnifiedScan(target.absolutePath, { projectName });

      const byFile = new Map<string, Finding[]>();
      for (const finding of scan.findings) {
        const group = byFile.get(finding.filePath);
        if (group) group.push(finding);
        else byFile.set(finding.filePath, [finding]);
      }

      const results: ScanResult[] = [...byFile.entries()].map(([filePath, findings]) => ({
        filePath,
        language: detectLanguage(filePath),
        totalFindings: findings.length,
        findings,
        summary: computeSeveritySummary(findings),
        // These groups are built from findings a scan already produced, so the
        // file was analysed by definition.
        analyzed: true,
      }));

      const name = projectName || path.basename(target.absolutePath);
      return textResponse(generateSarif(results, name, scan.rootPath));
    })
  );
}
