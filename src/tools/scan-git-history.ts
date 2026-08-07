import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { scanGitHistoryForSecrets } from "../scanner/git-history-secret-scanner.js";
import { jsonResponse, pathArgument, requirePath, runTool } from "./shared.js";

export function registerScanGitHistory(server: McpServer): void {
  server.tool(
    "scan_git_history",
    "Scan git commit history for secrets that were committed and later removed. Finds leaked credentials that no longer exist in the working tree but remain recoverable from history. Secret values are redacted in the output.",
    {
      repoPath: pathArgument("Absolute path to the git repository root"),
      maxCommits: z.number().int().positive().max(5000).optional()
        .describe("Maximum number of commits to scan, newest first. Default: 100"),
    },
    async ({ repoPath, maxCommits }) => runTool("scan_git_history", async () => {
      const target = requirePath(repoPath, "directory", "repoPath");
      const result = await scanGitHistoryForSecrets(target.absolutePath, maxCommits ?? 100);
      return jsonResponse(result);
    })
  );
}
