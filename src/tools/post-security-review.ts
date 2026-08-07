import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { errorMessage } from "../core/logger.js";
import { postReview, postReviewComment } from "../github/client.js";
import { jsonResponse, runTool } from "./shared.js";

const GITHUB_NAME = /^[A-Za-z0-9._-]+$/;

interface ActionResult {
  type: "inline_comment" | "review";
  status: "posted" | "failed";
  path?: string;
  line?: number;
  action?: string;
  url?: string;
  error?: string;
}

export function registerPostSecurityReview(server: McpServer): void {
  server.tool(
    "post_security_review",
    "Post security review comments on a GitHub pull request, either inline on specific lines or as a summary review. Use after scan_pr_diff. Requires GITHUB_TOKEN.",
    {
      owner: z.string().min(1).max(100).regex(GITHUB_NAME).describe("GitHub repository owner"),
      repo: z.string().min(1).max(100).regex(GITHUB_NAME).describe("GitHub repository name"),
      pull_number: z.number().int().positive().max(1_000_000).describe("Pull request number"),
      comments: z.array(z.object({
        path: z.string().min(1).max(4096).describe("File path in the PR"),
        line: z.number().int().positive().describe("Line number to comment on"),
        body: z.string().min(1).max(65_536).describe("Comment body (markdown supported)"),
      })).max(50).optional().describe("Inline comments to post. At most 50 per call."),
      summary: z.string().min(1).max(65_536).optional().describe("Overall review summary comment"),
      action: z.enum(["COMMENT", "APPROVE", "REQUEST_CHANGES"]).optional()
        .describe("Review action: COMMENT (default), APPROVE, or REQUEST_CHANGES"),
    },
    async ({ owner, repo, pull_number, comments, summary, action }) => runTool("post_security_review", async () => {
      if (!comments?.length && !summary) {
        return jsonResponse({
          pr: `${owner}/${repo}#${pull_number}`,
          totalActions: 0,
          results: [],
          note: "Nothing was posted: provide comments, a summary, or both.",
        });
      }

      const results: ActionResult[] = [];

      // Each comment is posted independently. A single rejected line (for
      // example one outside the diff) must not discard the rest of the review.
      for (const comment of comments || []) {
        try {
          const result = await postReviewComment(owner, repo, pull_number, comment.body, comment.path, comment.line);
          results.push({
            type: "inline_comment",
            path: comment.path,
            line: comment.line,
            status: "posted",
            url: result.url,
          });
        } catch (error) {
          results.push({
            type: "inline_comment",
            path: comment.path,
            line: comment.line,
            status: "failed",
            error: errorMessage(error),
          });
        }
      }

      if (summary) {
        const reviewAction = action || "COMMENT";
        try {
          const result = await postReview(owner, repo, pull_number, summary, reviewAction);
          results.push({ type: "review", action: reviewAction, status: "posted", url: result.url });
        } catch (error) {
          results.push({ type: "review", action: reviewAction, status: "failed", error: errorMessage(error) });
        }
      }

      const failed = results.filter((result) => result.status === "failed").length;

      return jsonResponse({
        pr: `${owner}/${repo}#${pull_number}`,
        totalActions: results.length,
        posted: results.length - failed,
        failed,
        results,
      });
    })
  );
}
