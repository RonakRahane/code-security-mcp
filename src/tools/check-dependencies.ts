import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Diagnostics } from "../core/diagnostics.js";
import { auditDependencies } from "../scanner/dependency-auditor.js";
import {
  filterDependencyVulnerabilitiesByThreshold,
  isOfflineMode,
  loadSentinelConfig,
} from "../scanner/config.js";
import { errorResponse, jsonResponse, pathArgument, requirePath, runTool } from "./shared.js";

export function registerCheckDependencies(server: McpServer): void {
  server.tool(
    "check_dependencies",
    "Audit project dependencies against the OSV vulnerability database. Supports npm, PyPI, Go, crates.io, Maven, RubyGems, and Packagist manifests and lockfiles.",
    {
      manifestPath: pathArgument(
        "Absolute path to a dependency manifest such as package.json, package-lock.json, requirements.txt, poetry.lock, go.mod, or Cargo.lock."
      ).optional(),
      packageJsonPath: pathArgument("Deprecated alias for manifestPath.").optional(),
    },
    async ({ manifestPath, packageJsonPath }) => runTool("check_dependencies", async () => {
      const requested = manifestPath || packageJsonPath;
      if (!requested) {
        return errorResponse("manifestPath is required.", "Pass the absolute path to a dependency manifest or lockfile.");
      }

      const target = requirePath(requested, "file", "manifestPath");
      const diagnostics = new Diagnostics();
      const config = loadSentinelConfig(target.absolutePath, diagnostics);
      const offline = isOfflineMode(config);

      const result = await auditDependencies(target.absolutePath, { offline, diagnostics });
      const vulnerabilities = filterDependencyVulnerabilitiesByThreshold(result.vulnerabilities, config);

      return jsonResponse({
        ecosystem: result.ecosystem,
        scannedManifest: result.scannedManifest,
        offline,
        totalVulnerabilities: vulnerabilities.length,
        vulnerabilities,
        summary: vulnerabilities.reduce<Record<string, number>>(
          (acc, vuln) => {
            acc[vuln.severity] = (acc[vuln.severity] || 0) + 1;
            return acc;
          },
          { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
        ),
        warnings: result.warnings,
      });
    })
  );
}
