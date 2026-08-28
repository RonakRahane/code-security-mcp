import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import * as fsp from "node:fs/promises";
import * as path from "node:path";
import { z } from "zod";
import { errorMessage, logger } from "../core/logger.js";
import { runUnifiedScan } from "../scanner/unified-scanner.js";
import { renderMarkdownReport } from "../reporting/markdown-report.js";
import { pathArgument, requirePath, runTool, textResponse } from "./shared.js";
import { writeFileNoFollow } from "../core/safe-write.js";

export function registerSecurityReport(server: McpServer): void {
  server.tool(
    "security_report",
    "Generate a full security report for a codebase: static analysis, secret detection, and dependency advisories with reachability. Writes sentinel-report.md to the project root and returns the report.",
    {
      dirPath: pathArgument("Absolute path to the project root directory"),
      projectName: z.string().min(1).max(200).optional().describe("Project name for the report header"),
      writeReportFile: z.boolean().optional()
        .describe("Write sentinel-report.md into the project root. Default true."),
    },
    async ({ dirPath, projectName, writeReportFile }) => runTool("security_report", async () => {
      const target = requirePath(dirPath, "directory", "dirPath");
      const resolvedPath = target.absolutePath;
      const name = projectName || path.basename(resolvedPath);

      const scanResult = await runUnifiedScan(resolvedPath, { projectName: name });

      const markdownReport = renderMarkdownReport({
        projectName: name,
        generatedAt: scanResult.generatedAt,
        projectRoot: resolvedPath,
        filesScanned: scanResult.filesScanned,
        findings: scanResult.findings,
        dependencies: scanResult.dependencyVulnerabilities,
        coverage: scanResult.coverage,
        engine: scanResult.engine,
        warnings: scanResult.warnings,
      });

      if (writeReportFile !== false) {
        const reportFilePath = path.join(resolvedPath, "sentinel-report.md");
        try {
          await writeFileNoFollow(reportFilePath, markdownReport);
        } catch (error) {
          // A read-only checkout is a normal CI configuration; the report is
          // still returned to the caller, so this must not fail the tool.
          logger.warn("report file not written", { path: reportFilePath, error: errorMessage(error) });
        }
      }

      return textResponse(markdownReport);
    })
  );
}
