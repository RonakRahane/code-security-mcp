/**
 * Pull-request discovery.
 *
 * scan_pr_diff and post_security_review both need a pull-request number. Without
 * a way to list them, an agent can only review a pull request someone has
 * already named, which breaks the obvious workflow of finding what is open and
 * reviewing it.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { listOpenPrs } from "../github/client.js";
import { jsonResponse, runTool } from "./shared.js";

/** GitHub owner and repository name grammar. Validated before use in API paths. */
const GITHUB_NAME = /^[A-Za-z0-9._-]+$/;

export function registerListOpenPrs(server: McpServer): void {
  server.tool(
    "list_open_prs",
    "List open pull requests for a GitHub repository, most recently updated first. Use to find a pull request to review, then pass its number to scan_pr_diff. Requires GITHUB_TOKEN.",
    {
      owner: z.string().min(1).max(100).regex(GITHUB_NAME).describe("GitHub repository owner (user or org)"),
      repo: z.string().min(1).max(100).regex(GITHUB_NAME).describe("GitHub repository name"),
      limit: z.number().int().positive().max(30).optional()
        .describe("Maximum pull requests to return. Defaults to 30, which is the page size."),
    },
    async ({ owner, repo, limit }) => runTool("list_open_prs", async () => {
      const pullRequests = await listOpenPrs(owner, repo);
      const selected = limit ? pullRequests.slice(0, limit) : pullRequests;

      return jsonResponse({
        repository: `${owner}/${repo}`,
        totalReturned: selected.length,
        pullRequests: selected,
        // The list endpoint omits per-pull-request change sizes, so those
        // fields are absent rather than zero. Saying so keeps an agent from
        // reading a missing value as "this pull request changes nothing".
        note: "changedFiles, additions and deletions are not returned by the pull-request list endpoint and are omitted here. Use scan_pr_diff to see what a pull request actually changes.",
      });
    })
  );
}
