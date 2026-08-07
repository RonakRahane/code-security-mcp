import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { Finding } from "../types/index.js";
import { computeSeveritySummary } from "../core/severity.js";
import { detectLanguage } from "../scanner/pattern-engine.js";
import { runUnifiedScan } from "../scanner/unified-scanner.js";
import { jsonResponse, pathArgument, requirePath, runTool } from "./shared.js";

export function registerScanDirectory(server: McpServer): void {
  server.tool(
    "scan_directory",
    "Recursively scan a directory for security vulnerabilities and secrets. Uses Semgrep when available, falling back to the built-in pattern engine. Reports scan coverage so incomplete results are visible.",
    {
      dirPath: pathArgument("Absolute path to the directory to scan"),
      maxFiles: z.number().int().positive().max(200_000).optional()
        .describe("Maximum number of files to scan. Defaults to the configured limit."),
    },
    async ({ dirPath, maxFiles }) => runTool("scan_directory", async () => {
      const target = requirePath(dirPath, "directory", "dirPath");
      const scanResult = await runUnifiedScan(target.absolutePath, { maxFiles });

      // Group findings by file so a client can render per-file sections.
      const byFile = new Map<string, Finding[]>();
      for (const finding of scanResult.findings) {
        const group = byFile.get(finding.filePath);
        if (group) group.push(finding);
        else byFile.set(finding.filePath, [finding]);
      }

      const files = [...byFile.entries()]
        .map(([filePath, findings]) => ({
          filePath,
          language: detectLanguage(filePath),
          totalFindings: findings.length,
          findings,
          summary: computeSeveritySummary(findings),
        }))
        .sort((a, b) => {
          if (a.summary.critical !== b.summary.critical) return b.summary.critical - a.summary.critical;
          if (a.summary.high !== b.summary.high) return b.summary.high - a.summary.high;
          return b.totalFindings - a.totalFindings;
        });

      return jsonResponse({
        directory: scanResult.rootPath,
        filesScanned: scanResult.filesScanned,
        filesSkipped: scanResult.filesSkipped,
        filesWithFindings: files.length,
        totalFindings: scanResult.findings.length,
        summary: computeSeveritySummary(scanResult.findings),
        dependencyVulnerabilities: scanResult.dependencyVulnerabilities,
        files,
        engine: scanResult.engine,
        coverage: scanResult.coverage,
        warnings: scanResult.warnings,
        baseline: scanResult.baseline,
      });
    })
  );
}
