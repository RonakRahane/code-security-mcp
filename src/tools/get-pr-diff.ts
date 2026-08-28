/**
 * Raw pull-request diff.
 *
 * scan_pr_diff reports what Sentinel's rules match. This returns the diff
 * itself, so a reviewer can judge what no rule encodes: logic errors, missing
 * authorisation checks, a migration without a rollback. The two are meant to be
 * used together, with post_security_review carrying the conclusions back.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { getPrDiff } from "../github/client.js";
import { jsonResponse, runTool } from "./shared.js";

/** GitHub owner and repository name grammar. Validated before use in API paths. */
const GITHUB_NAME = /^[A-Za-z0-9._-]+$/;

/**
 * Upper bound on the returned diff. A large pull request can run to megabytes,
 * which would swamp a model's context and crowd out the review itself.
 */
const MAX_DIFF_CHARACTERS = 200_000;

export function registerGetPrDiff(server: McpServer): void {
  server.tool(
    "get_pr_diff",
    "Fetch the raw unified diff of a GitHub pull request, for review judgement that pattern rules cannot express. Use scan_pr_diff for rule-based findings; use this to read the change itself. Requires GITHUB_TOKEN.",
    {
      owner: z.string().min(1).max(100).regex(GITHUB_NAME).describe("GitHub repository owner (user or org)"),
      repo: z.string().min(1).max(100).regex(GITHUB_NAME).describe("GitHub repository name"),
      pull_number: z.number().int().positive().max(1_000_000).describe("Pull request number"),
      maxCharacters: z.number().int().positive().max(MAX_DIFF_CHARACTERS).optional()
        .describe(`Truncate the diff to this many characters. Defaults to ${MAX_DIFF_CHARACTERS}.`),
    },
    async ({ owner, repo, pull_number, maxCharacters }) => runTool("get_pr_diff", async () => {
      const diff = await getPrDiff(owner, repo, pull_number);
      const limit = maxCharacters ?? MAX_DIFF_CHARACTERS;
      const truncated = diff.length > limit;

      return jsonResponse({
        pr: `${owner}/${repo}#${pull_number}`,
        characters: truncated ? limit : diff.length,
        // Silent truncation would have a reviewer approve a change whose tail
        // they never saw.
        truncated,
        ...(truncated
          ? { truncationNotice: `Diff truncated at ${limit} of ${diff.length} characters. Use scan_pr_diff for full-file coverage, or raise maxCharacters.` }
          : {}),
        diff: truncated ? diff.slice(0, limit) : diff,
      });
    })
  );
}
