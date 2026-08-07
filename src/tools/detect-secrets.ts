import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import * as path from "node:path";
import { MAX_FILE_BYTES } from "../core/constants.js";
import { Diagnostics } from "../core/diagnostics.js";
import { readTextFile } from "../core/fs-walk.js";
import { detectSecrets, detectSecretsInDirectory } from "../scanner/secret-detector.js";
import {
  filterByMinimumSeverity,
  filterIgnoredFindings,
  findConfigPath,
  isPathIgnored,
  loadSentinelConfig,
} from "../scanner/config.js";
import { errorResponse, jsonResponse, pathArgument, requirePath, runTool } from "./shared.js";

export function registerDetectSecrets(server: McpServer): void {
  server.tool(
    "detect_secrets",
    "Scan for hardcoded secrets, API keys, tokens, passwords, and private keys using pattern matching and Shannon entropy analysis. Detected secret values are redacted in the output.",
    {
      path: pathArgument("Absolute path to a file or directory to scan for secrets"),
    },
    async ({ path: targetPath }) => runTool("detect_secrets", async () => {
      const target = requirePath(targetPath, "any", "path");
      const resolvedPath = target.absolutePath;

      const diagnostics = new Diagnostics();
      const config = loadSentinelConfig(resolvedPath, diagnostics);
      const configPath = findConfigPath(resolvedPath);
      const configRoot = configPath
        ? path.dirname(configPath)
        : (target.isDirectory ? resolvedPath : path.dirname(resolvedPath));

      if (target.isFile) {
        if (isPathIgnored(resolvedPath, configRoot, config)) {
          return jsonResponse({
            path: resolvedPath,
            skipped: true,
            reason: "File is excluded by Sentinel configuration.",
          });
        }

        const code = await readTextFile(resolvedPath, { maxBytes: MAX_FILE_BYTES, diagnostics });
        if (code === null) {
          return errorResponse("File could not be scanned: it is binary, oversized, or unreadable.");
        }

        const findings = filterByMinimumSeverity(
          filterIgnoredFindings(detectSecrets(code, resolvedPath), config),
          config
        );

        return jsonResponse({
          path: resolvedPath,
          type: "file",
          totalSecrets: findings.length,
          findings,
          warnings: diagnostics.toWarnings(),
        });
      }

      const scan = await detectSecretsInDirectory(resolvedPath, {
        diagnostics,
        maxFiles: config.maxFiles,
        concurrency: config.concurrency,
      });

      const files = scan.results
        .filter((result) => !isPathIgnored(result.filePath, configRoot, config))
        .map((result) => ({
          ...result,
          findings: filterByMinimumSeverity(filterIgnoredFindings(result.findings, config), config),
        }))
        .filter((result) => result.findings.length > 0);

      return jsonResponse({
        path: resolvedPath,
        type: "directory",
        filesScanned: scan.filesScanned,
        filesWithSecrets: files.length,
        totalSecrets: files.reduce((sum, file) => sum + file.findings.length, 0),
        files,
        warnings: scan.warnings,
      });
    })
  );
}
