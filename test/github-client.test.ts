import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

/**
 * The GitHub client is the only code here that writes to somewhere other than
 * the local disk: it posts comments and reviews onto other people's pull
 * requests. Every call is exercised against a stubbed Octokit so the request
 * shape, the pagination behaviour and the returned values are pinned.
 */

const pullsGet = vi.fn();
const pullsList = vi.fn();
const listFiles = vi.fn();
const createReviewComment = vi.fn();
const createReview = vi.fn();
const paginate = vi.fn();

vi.mock("@octokit/rest", () => ({
  Octokit: class {
    pulls = {
      get: pullsGet,
      list: pullsList,
      listFiles,
      createReviewComment,
      createReview,
    };
    paginate = paginate;
  },
}));

const file = (n: number) => ({
  filename: `src/file-${n}.ts`,
  status: "modified",
  additions: 1,
  deletions: 0,
  patch: "@@ -1 +1 @@\n+const a = 1;",
});

const loadClient = () => import("../src/github/client.js");

beforeEach(() => {
  vi.resetModules();
  for (const stub of [pullsGet, pullsList, listFiles, createReviewComment, createReview, paginate]) {
    stub.mockReset();
  }
  process.env.GITHUB_TOKEN = "test-token";
});

afterEach(() => {
  delete process.env.GITHUB_TOKEN;
});

describe("getPrFiles", () => {
  it("returns every file in a pull request larger than one page", async () => {
    paginate.mockResolvedValue(Array.from({ length: 150 }, (_, i) => file(i)));

    const { getPrFiles } = await loadClient();
    const files = await getPrFiles("owner", "repo", 7);

    expect(files).toHaveLength(150);
    expect(files[149].filename).toBe("src/file-149.ts");
  });

  it("pages through the endpoint rather than reading a single response", async () => {
    paginate.mockResolvedValue([file(0)]);

    const { getPrFiles } = await loadClient();
    await getPrFiles("owner", "repo", 7);

    expect(paginate).toHaveBeenCalledTimes(1);
    expect(paginate).toHaveBeenCalledWith(
      listFiles,
      expect.objectContaining({ owner: "owner", repo: "repo", pull_number: 7 })
    );
  });

  it("maps each entry to the fields the diff scanner reads", async () => {
    paginate.mockResolvedValue([file(0)]);

    const { getPrFiles } = await loadClient();
    const [entry] = await getPrFiles("owner", "repo", 7);

    expect(entry).toEqual({
      filename: "src/file-0.ts",
      status: "modified",
      additions: 1,
      deletions: 0,
      patch: "@@ -1 +1 @@\n+const a = 1;",
    });
  });

  it("returns an empty list for a pull request that changes nothing", async () => {
    paginate.mockResolvedValue([]);

    const { getPrFiles } = await loadClient();
    expect(await getPrFiles("owner", "repo", 7)).toEqual([]);
  });

  it("carries a file with no patch through rather than dropping it", async () => {
    // A binary or too-large file arrives with patch undefined. The scanner
    // decides what to do with it; the client must not silently discard it.
    paginate.mockResolvedValue([{ ...file(0), patch: undefined }]);

    const { getPrFiles } = await loadClient();
    const [entry] = await getPrFiles("owner", "repo", 7);

    expect(entry.filename).toBe("src/file-0.ts");
    expect(entry.patch).toBeUndefined();
  });
});

describe("getPrDiff", () => {
  it("requests the diff media type and returns the raw diff", async () => {
    const diff = "diff --git a/a.ts b/a.ts\n@@ -1 +1 @@\n+const a = 1;";
    pullsGet.mockResolvedValue({ data: diff });

    const { getPrDiff } = await loadClient();
    const result = await getPrDiff("owner", "repo", 7);

    expect(result).toBe(diff);
    expect(pullsGet).toHaveBeenCalledWith({
      owner: "owner",
      repo: "repo",
      pull_number: 7,
      mediaType: { format: "diff" },
    });
  });

  it("propagates an API failure instead of returning an empty diff", async () => {
    pullsGet.mockRejectedValue(new Error("Not Found"));

    const { getPrDiff } = await loadClient();
    await expect(getPrDiff("owner", "repo", 7)).rejects.toThrow(/Not Found/);
  });
});

describe("listOpenPrs", () => {
  it("returns open pull requests with the fields the caller needs", async () => {
    paginate.mockResolvedValue([{
      number: 12,
      title: "Add auth",
      user: { login: "alice" },
      created_at: "2026-01-01T00:00:00Z",
      changed_files: 3,
      additions: 40,
      deletions: 2,
    }]);

    const { listOpenPrs } = await loadClient();
    const [pr] = await listOpenPrs("owner", "repo");

    expect(pr).toEqual({
      number: 12,
      title: "Add auth",
      author: "alice",
      createdAt: "2026-01-01T00:00:00Z",
      changedFiles: 3,
      additions: 40,
      deletions: 2,
    });
  });

  it("asks only for open pull requests", async () => {
    paginate.mockResolvedValue([]);

    const { listOpenPrs } = await loadClient();
    await listOpenPrs("owner", "repo");

    // Paginated, not a single page: reading one page returned the first 30 and
    // presented them as the complete list.
    expect(paginate).toHaveBeenCalledWith(
      pullsList,
      expect.objectContaining({ state: "open" })
    );
  });

  it("leaves the change size undefined when the endpoint omits it", async () => {
    // The list endpoint does not return changed_files, additions or deletions.
    // Defaulting them to 0 reported every open pull request as an empty change,
    // which is indistinguishable from a real one that changed nothing.
    paginate.mockResolvedValue([
      { number: 3, title: "t", user: { login: "a" }, created_at: "2026-01-01T00:00:00Z" },
    ]);

    const { listOpenPrs } = await loadClient();
    const [pr] = await listOpenPrs("owner", "repo");

    expect(pr.changedFiles).toBeUndefined();
    expect(pr.additions).toBeUndefined();
    expect(pr.deletions).toBeUndefined();
  });

  it("substitutes a placeholder for a deleted author account", async () => {
    // GitHub returns user: null when the account is gone. Reading .login off
    // it directly would throw and lose the whole listing.
    paginate.mockResolvedValue([
      { number: 1, title: "x", user: null, created_at: "2026-01-01T00:00:00Z" },
    ]);

    const { listOpenPrs } = await loadClient();
    const [pr] = await listOpenPrs("owner", "repo");

    expect(pr.author).toBe("unknown");
  });
});

describe("postReviewComment", () => {
  it("anchors the comment to the head commit of the pull request", async () => {
    // A review comment without the right commit_id is rejected by GitHub, so
    // the client reads head.sha first rather than letting the caller guess.
    pullsGet.mockResolvedValue({ data: { head: { sha: "abc123" } } });
    createReviewComment.mockResolvedValue({
      data: { id: 55, html_url: "https://github.com/owner/repo/pull/7#discussion_r55" },
    });

    const { postReviewComment } = await loadClient();
    const result = await postReviewComment("owner", "repo", 7, "body text", "src/a.ts", 42);

    expect(createReviewComment).toHaveBeenCalledWith({
      owner: "owner",
      repo: "repo",
      pull_number: 7,
      body: "body text",
      path: "src/a.ts",
      line: 42,
      commit_id: "abc123",
    });
    expect(result).toEqual({
      id: 55,
      url: "https://github.com/owner/repo/pull/7#discussion_r55",
    });
  });

  it("propagates a rejected line instead of reporting a comment that was never posted", async () => {
    pullsGet.mockResolvedValue({ data: { head: { sha: "abc123" } } });
    createReviewComment.mockRejectedValue(new Error("line must be part of the diff"));

    const { postReviewComment } = await loadClient();
    await expect(
      postReviewComment("owner", "repo", 7, "body", "src/a.ts", 9999)
    ).rejects.toThrow(/part of the diff/);
  });

  it("does not post when the head commit cannot be read", async () => {
    pullsGet.mockRejectedValue(new Error("Not Found"));

    const { postReviewComment } = await loadClient();
    await expect(postReviewComment("owner", "repo", 7, "b", "a.ts", 1)).rejects.toThrow();
    expect(createReviewComment).not.toHaveBeenCalled();
  });
});

describe("postReview", () => {
  it("posts the summary with the requested action", async () => {
    createReview.mockResolvedValue({
      data: { id: 77, html_url: "https://github.com/owner/repo/pull/7#pullrequestreview-77" },
    });

    const { postReview } = await loadClient();
    const result = await postReview("owner", "repo", 7, "summary text", "REQUEST_CHANGES");

    expect(createReview).toHaveBeenCalledWith({
      owner: "owner",
      repo: "repo",
      pull_number: 7,
      body: "summary text",
      event: "REQUEST_CHANGES",
    });
    expect(result).toEqual({
      id: 77,
      url: "https://github.com/owner/repo/pull/7#pullrequestreview-77",
    });
  });

  it("propagates a failed review rather than reporting success", async () => {
    createReview.mockRejectedValue(new Error("Unprocessable Entity"));

    const { postReview } = await loadClient();
    await expect(postReview("owner", "repo", 7, "s", "APPROVE")).rejects.toThrow(/Unprocessable/);
  });
});

describe("authentication", () => {
  it("fails loudly when no token is configured", async () => {
    delete process.env.GITHUB_TOKEN;

    const { getPrFiles } = await loadClient();
    await expect(getPrFiles("owner", "repo", 7)).rejects.toThrow(/GITHUB_TOKEN/);
  });

  it("never puts the token into the thrown message", async () => {
    process.env.GITHUB_TOKEN = "ghp_supersecrettokenvalue1234567890";
    pullsGet.mockRejectedValue(new Error("Bad credentials"));

    const { getPrDiff } = await loadClient();
    const error = await getPrDiff("owner", "repo", 7).catch((e: Error) => e);

    expect(String(error)).not.toContain("ghp_supersecrettokenvalue1234567890");
  });
});
