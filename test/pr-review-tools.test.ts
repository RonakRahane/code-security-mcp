import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { semgrepAvailable } from "./helpers/semgrep-available.js";

/**
 * End-to-end cover for the two pull-request tools.
 *
 * These are the only handlers that act on something outside the machine they
 * run on: scan_pr_diff reads a pull request, and post_security_review writes
 * comments onto it. The GitHub client is stubbed, so what is under test is the
 * handler logic: which lines get scanned, how findings map back to real file
 * line numbers, and what happens when a write is rejected.
 */

const getPrFiles = vi.fn();
const postReviewComment = vi.fn();
const postReview = vi.fn();

const getPrHeadSha = vi.fn();
const getFileAtRef = vi.fn();

vi.mock("../src/github/client.js", () => ({
  getPrFiles: (...args: unknown[]) => getPrFiles(...args),
  postReviewComment: (...args: unknown[]) => postReviewComment(...args),
  postReview: (...args: unknown[]) => postReview(...args),
  getPrHeadSha: (...args: unknown[]) => getPrHeadSha(...args),
  getFileAtRef: (...args: unknown[]) => getFileAtRef(...args),
  getPrDiff: vi.fn(),
  listOpenPrs: vi.fn(),
}));

interface CapturedTool {
  handler: (args: Record<string, unknown>) => Promise<{
    content: Array<{ type: string; text: string }>;
    isError?: boolean;
  }>;
}

function createHarness() {
  const tools = new Map<string, CapturedTool>();
  const server = {
    tool(name: string, _description: string, _schema: unknown, handler: CapturedTool["handler"]) {
      tools.set(name, { handler });
    },
  } as unknown as McpServer;

  return {
    server,
    async payload(name: string, args: Record<string, unknown> = {}) {
      const tool = tools.get(name);
      if (!tool) throw new Error(`tool not registered: ${name}`);
      const response = await tool.handler(args);
      return JSON.parse(response.content[0].text);
    },
    async call(name: string, args: Record<string, unknown> = {}) {
      const tool = tools.get(name);
      if (!tool) throw new Error(`tool not registered: ${name}`);
      return tool.handler(args);
    },
  };
}

let harness: ReturnType<typeof createHarness>;

beforeEach(async () => {
  vi.resetModules();
  getPrFiles.mockReset();
  postReviewComment.mockReset();
  postReview.mockReset();
  getPrHeadSha.mockReset();
  getFileAtRef.mockReset();
  getPrHeadSha.mockResolvedValue("headsha");
  // Default: the file at the head is exactly the added lines, which matches the
  // simple fixtures below.
  getFileAtRef.mockImplementation(async () => defaultFileContents);

  harness = createHarness();
  const { registerScanPrDiff } = await import("../src/tools/scan-pr-diff.js");
  const { registerPostSecurityReview } = await import("../src/tools/post-security-review.js");
  registerScanPrDiff(harness.server);
  registerPostSecurityReview(harness.server);
});

afterEach(() => {
  vi.restoreAllMocks();
});

let defaultFileContents = "const a = 1;\neval(req.body.code);\nconst b = 2;\n";

const prFile = (overrides: Record<string, unknown> = {}) => ({
  filename: "src/app.js",
  status: "modified",
  additions: 1,
  deletions: 0,
  patch: "@@ -1,2 +1,3 @@\n const a = 1;\n+eval(req.body.code);\n const b = 2;",
  ...overrides,
});

describe("scan_pr_diff", () => {
  /**
   * The file at the pull-request head is scanned in full and the findings are
   * then narrowed to lines the pull request added. Scanning a buffer of added
   * lines alone could not see a value assigned on one line and used on the
   * next, and Semgrep cannot parse such a buffer at all.
   */
  const atHead = (contents: string) => getFileAtRef.mockResolvedValue(contents);

  it("reports a vulnerability introduced by the pull request", async () => {
    getPrFiles.mockResolvedValue([prFile()]);
    atHead("const a = 1;\neval(req.body.code);\nconst b = 2;\n");

    const payload = await harness.payload("scan_pr_diff", {
      owner: "owner", repo: "repo", pull_number: 7,
    });

    expect(payload.pr).toBe("owner/repo#7");
    expect(payload.totalFindings).toBeGreaterThan(0);
    expect(payload.files[0].file).toBe("src/app.js");
  });

  it("reports the line number in the real file", async () => {
    getPrFiles.mockResolvedValue([prFile({
      patch: [
        "@@ -1,4 +1,5 @@",
        " const a = 1;",
        " const b = 2;",
        " const c = 3;",
        " const d = 4;",
        "+eval(req.body.code);",
      ].join("\n"),
    })]);
    atHead("const a = 1;\nconst b = 2;\nconst c = 3;\nconst d = 4;\neval(req.body.code);\n");

    const payload = await harness.payload("scan_pr_diff", {
      owner: "owner", repo: "repo", pull_number: 7,
    });

    expect(payload.files[0].findings[0].line).toBe(5);
  });

  it("reports nothing for a problem the pull request did not introduce", async () => {
    // The eval was already there. Blaming this author for it is noise.
    getPrFiles.mockResolvedValue([prFile({
      patch: "@@ -1,2 +1,3 @@\n eval(req.body.code);\n const safe = 1;\n+const alsoSafe = 2;",
    })]);
    atHead("eval(req.body.code);\nconst safe = 1;\nconst alsoSafe = 2;\n");

    const payload = await harness.payload("scan_pr_diff", {
      owner: "owner", repo: "repo", pull_number: 7,
    });

    expect(payload.totalFindings).toBe(0);
  });

  // Needs Semgrep: the flow crosses statements, which the line-local pattern
  // engine cannot follow. CI's fast matrix does not install Semgrep, so this
  // skips there and is covered by the detection-regression job instead.
  it.skipIf(!semgrepAvailable)("finds a vulnerability spread across two lines", async () => {
    // The reason for scanning the real file. A buffer of added lines cannot be
    // parsed, so this went unreported while scan_file caught it.
    const source = [
      "function findUser(req, res) {",
      "  const q = \"SELECT * FROM users WHERE email = '\" + req.query.email + \"'\";",
      "  return db.query(q);",
      "}",
    ].join("\n");

    getPrFiles.mockResolvedValue([prFile({
      patch: [
        "@@ -0,0 +1,4 @@",
        "+function findUser(req, res) {",
        "+  const q = \"SELECT ...\" + req.query.email;",
        "+  return db.query(q);",
        "+}",
      ].join("\n"),
    })]);
    atHead(source);

    const payload = await harness.payload("scan_pr_diff", {
      owner: "owner", repo: "repo", pull_number: 7,
    });

    expect(payload.totalFindings).toBeGreaterThan(0);
  });

  it("detects a secret added by the pull request", async () => {
    getPrFiles.mockResolvedValue([prFile({
      filename: "config.js",
      patch: '@@ -1 +1,2 @@\n const a = 1;\n+const key = "AKIAIOSFODNN7EXAMPLE";',
    })]);
    atHead('const a = 1;\nconst key = "AKIAIOSFODNN7EXAMPLE";\n');

    const payload = await harness.payload("scan_pr_diff", {
      owner: "owner", repo: "repo", pull_number: 7,
    });

    expect(payload.totalFindings).toBeGreaterThan(0);
  });

  it("never echoes the secret it found back into the response", async () => {
    const secret = "AKIAIOSFODNN7EXAMPLE";
    getPrFiles.mockResolvedValue([prFile({
      filename: "config.js",
      patch: `@@ -1 +1,2 @@\n const a = 1;\n+const key = "${secret}";`,
    })]);
    atHead(`const a = 1;\nconst key = "${secret}";\n`);

    const response = await harness.call("scan_pr_diff", {
      owner: "owner", repo: "repo", pull_number: 7,
    });

    expect(response.content[0].text).not.toContain(secret);
  });

  it("skips a file that carries no patch", async () => {
    getPrFiles.mockResolvedValue([prFile({ patch: undefined })]);

    const payload = await harness.payload("scan_pr_diff", {
      owner: "owner", repo: "repo", pull_number: 7,
    });

    expect(payload.filesInPr).toBe(1);
    expect(payload.totalFindings).toBe(0);
  });

  it("says which files it could not read rather than passing over them", async () => {
    // A deleted path or an oversized file returns nothing. Silence about it
    // would let a partial scan read as a clean one.
    getPrFiles.mockResolvedValue([prFile()]);
    getFileAtRef.mockResolvedValue(null);

    const payload = await harness.payload("scan_pr_diff", {
      owner: "owner", repo: "repo", pull_number: 7,
    });

    expect(payload.coverage.filesNotFetched).toContain("src/app.js");
    expect(payload.filesAnalyzed).toBe(0);
  });

  it("returns a clean result for a pull request that introduces nothing", async () => {
    getPrFiles.mockResolvedValue([prFile({
      patch: "@@ -1 +1,2 @@\n const a = 1;\n+const b = 2;",
    })]);
    atHead("const a = 1;\nconst b = 2;\n");

    const payload = await harness.payload("scan_pr_diff", {
      owner: "owner", repo: "repo", pull_number: 7,
    });

    expect(payload.totalFindings).toBe(0);
    expect(payload.files).toEqual([]);
  });

  it("refuses a filename that would escape the scan directory", async () => {
    // The name is whatever a pull-request author committed. A backslash is an
    // ordinary character in a POSIX tree but a separator on Windows, so this
    // wrote attacker content to an arbitrary path there.
    getPrFiles.mockResolvedValue([prFile({ filename: "a\\..\\..\\..\\evil.bat" })]);
    getFileAtRef.mockResolvedValue("const a = 1;\n");

    const payload = await harness.payload("scan_pr_diff", {
      owner: "owner", repo: "repo", pull_number: 7,
    });

    // Refused rather than written, and named rather than passed over silently.
    expect(payload.totalFindings).toBe(0);
    expect(payload.filesAnalyzed).toBe(0);
  });

  it("refuses a traversing filename on any platform", async () => {
    getPrFiles.mockResolvedValue([prFile({ filename: "../../evil.js" })]);
    getFileAtRef.mockResolvedValue("eval(req.body.code);\n");

    const payload = await harness.payload("scan_pr_diff", {
      owner: "owner", repo: "repo", pull_number: 7,
    });

    expect(payload.filesAnalyzed).toBe(0);
  });

  it("surfaces an API failure as an error rather than a clean pull request", async () => {
    getPrFiles.mockRejectedValue(new Error("Not Found"));

    const response = await harness.call("scan_pr_diff", {
      owner: "owner", repo: "repo", pull_number: 7,
    });

    expect(response.isError).toBe(true);
    expect(response.content[0].text).toMatch(/Not Found/);
  });

  it("handles a pull request with no files at all", async () => {
    getPrFiles.mockResolvedValue([]);

    const payload = await harness.payload("scan_pr_diff", {
      owner: "owner", repo: "repo", pull_number: 7,
    });

    expect(payload.filesInPr).toBe(0);
    expect(payload.totalFindings).toBe(0);
  });
});

describe("post_security_review", () => {
  const posted = (id: number) => ({ id, url: `https://github.com/o/r/pull/7#c${id}` });

  it("posts an inline comment and reports where it landed", async () => {
    postReviewComment.mockResolvedValue(posted(1));

    const payload = await harness.payload("post_security_review", {
      owner: "owner", repo: "repo", pull_number: 7,
      comments: [{ path: "src/app.js", line: 12, body: "SQL injection here." }],
    });

    expect(postReviewComment).toHaveBeenCalledWith(
      "owner", "repo", 7, "SQL injection here.", "src/app.js", 12
    );
    expect(payload.posted).toBe(1);
    expect(payload.failed).toBe(0);
    expect(payload.results[0].status).toBe("posted");
  });

  it("posts a summary review with the requested action", async () => {
    postReview.mockResolvedValue(posted(2));

    const payload = await harness.payload("post_security_review", {
      owner: "owner", repo: "repo", pull_number: 7,
      summary: "Two critical issues.",
      action: "REQUEST_CHANGES",
    });

    expect(postReview).toHaveBeenCalledWith(
      "owner", "repo", 7, "Two critical issues.", "REQUEST_CHANGES"
    );
    expect(payload.results[0].action).toBe("REQUEST_CHANGES");
  });

  it("defaults the review action to COMMENT", async () => {
    postReview.mockResolvedValue(posted(3));

    await harness.payload("post_security_review", {
      owner: "owner", repo: "repo", pull_number: 7, summary: "Notes.",
    });

    expect(postReview).toHaveBeenCalledWith("owner", "repo", 7, "Notes.", "COMMENT");
  });

  it("keeps posting after one comment is rejected", async () => {
    // GitHub rejects a comment on a line outside the diff. Losing the rest of
    // the review because of one bad line would drop real findings.
    postReviewComment
      .mockRejectedValueOnce(new Error("line must be part of the diff"))
      .mockResolvedValueOnce(posted(4));

    const payload = await harness.payload("post_security_review", {
      owner: "owner", repo: "repo", pull_number: 7,
      comments: [
        { path: "src/a.js", line: 9999, body: "out of range" },
        { path: "src/b.js", line: 3, body: "real finding" },
      ],
    });

    expect(payload.totalActions).toBe(2);
    expect(payload.posted).toBe(1);
    expect(payload.failed).toBe(1);
    expect(payload.results[0].status).toBe("failed");
    expect(payload.results[0].error).toMatch(/part of the diff/);
    expect(payload.results[1].status).toBe("posted");
  });

  it("reports a failed summary rather than claiming it posted", async () => {
    postReview.mockRejectedValue(new Error("Unprocessable Entity"));

    const payload = await harness.payload("post_security_review", {
      owner: "owner", repo: "repo", pull_number: 7, summary: "Notes.",
    });

    expect(payload.posted).toBe(0);
    expect(payload.failed).toBe(1);
    expect(payload.results[0].status).toBe("failed");
  });

  it("posts nothing and says so when given neither comments nor a summary", async () => {
    const payload = await harness.payload("post_security_review", {
      owner: "owner", repo: "repo", pull_number: 7,
    });

    expect(payload.totalActions).toBe(0);
    expect(payload.note).toMatch(/nothing was posted/i);
    expect(postReviewComment).not.toHaveBeenCalled();
    expect(postReview).not.toHaveBeenCalled();
  });

  it("posts comments and the summary together, in that order", async () => {
    postReviewComment.mockResolvedValue(posted(5));
    postReview.mockResolvedValue(posted(6));

    const payload = await harness.payload("post_security_review", {
      owner: "owner", repo: "repo", pull_number: 7,
      comments: [{ path: "src/a.js", line: 1, body: "inline" }],
      summary: "summary",
    });

    expect(payload.totalActions).toBe(2);
    expect(payload.posted).toBe(2);
    expect(payload.results[0].type).toBe("inline_comment");
    expect(payload.results[1].type).toBe("review");
  });
});
