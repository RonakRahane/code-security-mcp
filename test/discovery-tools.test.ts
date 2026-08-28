import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { registerListRules } from "../src/tools/list-rules.js";
import { getAllPatterns } from "../src/patterns/index.js";

/**
 * Discovery tools let an agent find out what Sentinel can do before it runs
 * anything: which rules exist, and which pull requests are open. A count that
 * drifts from the real catalogue, or a filter that silently matches nothing,
 * would have an agent report coverage the scanner does not have.
 */

const listOpenPrs = vi.fn();
const getPrDiff = vi.fn();
vi.mock("../src/github/client.js", () => ({
  listOpenPrs: (...args: unknown[]) => listOpenPrs(...args),
  getPrDiff: (...args: unknown[]) => getPrDiff(...args),
}));

interface CapturedTool {
  description: string;
  handler: (args: Record<string, unknown>) => Promise<{
    content: Array<{ type: string; text: string }>;
    isError?: boolean;
  }>;
}

function createHarness() {
  const tools = new Map<string, CapturedTool>();
  const server = {
    tool(name: string, description: string, _schema: unknown, handler: CapturedTool["handler"]) {
      tools.set(name, { description, handler });
    },
  } as unknown as McpServer;

  return {
    server,
    tools,
    async payload(name: string, args: Record<string, unknown> = {}) {
      const tool = tools.get(name);
      if (!tool) throw new Error(`tool not registered: ${name}`);
      return JSON.parse((await tool.handler(args)).content[0].text);
    },
    async call(name: string, args: Record<string, unknown> = {}) {
      return tools.get(name)!.handler(args);
    },
  };
}

describe("list_rules", () => {
  let harness: ReturnType<typeof createHarness>;

  beforeEach(() => {
    harness = createHarness();
    registerListRules(harness.server);
  });

  it("reports the whole catalogue when unfiltered", async () => {
    const payload = await harness.payload("list_rules");

    expect(payload.totalRules).toBe(getAllPatterns().length);
    expect(payload.matchingRules).toBe(payload.totalRules);
    expect(payload.rules).toHaveLength(payload.totalRules);
  });

  it("returns identifiers only until details are asked for", async () => {
    const brief = await harness.payload("list_rules");
    expect(typeof brief.rules[0]).toBe("string");

    const full = await harness.payload("list_rules", { includeRuleDetails: true });
    expect(full.rules[0]).toMatchObject({
      id: expect.any(String),
      severity: expect.any(String),
      cweId: expect.any(String),
    });
  });

  it("never exposes the raw regex, which is an implementation detail", async () => {
    const response = await harness.call("list_rules", { includeRuleDetails: true });
    const full = JSON.parse(response.content[0].text);

    for (const rule of full.rules) expect(rule).not.toHaveProperty("regex");
  });

  it("filters by category", async () => {
    const payload = await harness.payload("list_rules", { category: "injection" });

    expect(payload.matchingRules).toBeGreaterThan(0);
    expect(payload.matchingRules).toBeLessThan(payload.totalRules);
    expect(Object.keys(payload.byCategory)).toEqual(["injection"]);
  });

  it("filters by language", async () => {
    const payload = await harness.payload("list_rules", { language: "python", includeRuleDetails: true });

    expect(payload.matchingRules).toBeGreaterThan(0);
    for (const rule of payload.rules) {
      expect(rule.languages.includes("python") || rule.languages.includes("*")).toBe(true);
    }
  });

  it("composes the two filters instead of letting one replace the other", async () => {
    const injection = await harness.payload("list_rules", { category: "injection" });
    const both = await harness.payload("list_rules", { category: "injection", language: "python" });

    expect(both.matchingRules).toBeGreaterThan(0);
    expect(both.matchingRules).toBeLessThanOrEqual(injection.matchingRules);
    expect(both.filters).toEqual({ category: "injection", language: "python" });
  });

  it("returns an empty match rather than everything for an unknown category", async () => {
    // Falling back to the full catalogue would tell an agent the category is
    // covered when no rule for it exists.
    const payload = await harness.payload("list_rules", { category: "no-such-category" });

    expect(payload.matchingRules).toBe(0);
    expect(payload.rules).toEqual([]);
    expect(payload.totalRules).toBeGreaterThan(0);
  });

  it("says what it does not cover", async () => {
    const payload = await harness.payload("list_rules");
    expect(payload.note).toMatch(/semgrep/i);
    expect(payload.note).toMatch(/entropy/i);
  });
});

describe("list_open_prs", () => {
  let harness: ReturnType<typeof createHarness>;

  beforeEach(async () => {
    vi.resetModules();
    listOpenPrs.mockReset();
    harness = createHarness();
    const { registerListOpenPrs } = await import("../src/tools/list-open-prs.js");
    registerListOpenPrs(harness.server);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  const pr = (n: number) => ({
    number: n, title: `PR ${n}`, author: "alice", createdAt: "2026-01-01T00:00:00Z",
  });

  it("returns the open pull requests", async () => {
    listOpenPrs.mockResolvedValue([pr(1), pr(2)]);

    const payload = await harness.payload("list_open_prs", { owner: "o", repo: "r" });

    expect(payload.repository).toBe("o/r");
    expect(payload.totalReturned).toBe(2);
    expect(payload.pullRequests[0].number).toBe(1);
  });

  it("applies the limit", async () => {
    listOpenPrs.mockResolvedValue([pr(1), pr(2), pr(3), pr(4)]);

    const payload = await harness.payload("list_open_prs", { owner: "o", repo: "r", limit: 2 });

    expect(payload.totalReturned).toBe(2);
  });

  it("handles a repository with nothing open", async () => {
    listOpenPrs.mockResolvedValue([]);

    const payload = await harness.payload("list_open_prs", { owner: "o", repo: "r" });

    expect(payload.totalReturned).toBe(0);
    expect(payload.pullRequests).toEqual([]);
  });

  it("warns that change sizes are absent rather than zero", async () => {
    // The list endpoint omits them. An agent reading a missing value as zero
    // would report a real pull request as changing nothing.
    listOpenPrs.mockResolvedValue([pr(1)]);

    const payload = await harness.payload("list_open_prs", { owner: "o", repo: "r" });

    expect(payload.note).toMatch(/changedFiles/);
    expect(payload.note).toMatch(/scan_pr_diff/);
  });

  it("surfaces an API failure as an error", async () => {
    listOpenPrs.mockRejectedValue(new Error("Not Found"));

    const response = await harness.call("list_open_prs", { owner: "o", repo: "r" });

    expect(response.isError).toBe(true);
    expect(response.content[0].text).toMatch(/Not Found/);
  });
});

describe("get_pr_diff", () => {
  let harness: ReturnType<typeof createHarness>;

  beforeEach(async () => {
    vi.resetModules();
    getPrDiff.mockReset();
    harness = createHarness();
    const { registerGetPrDiff } = await import("../src/tools/get-pr-diff.js");
    registerGetPrDiff(harness.server);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  const diff = "diff --git a/a.ts b/a.ts\n@@ -1 +1 @@\n+const a = 1;";

  it("returns the raw diff", async () => {
    getPrDiff.mockResolvedValue(diff);

    const payload = await harness.payload("get_pr_diff", {
      owner: "o", repo: "r", pull_number: 7,
    });

    expect(payload.pr).toBe("o/r#7");
    expect(payload.diff).toBe(diff);
    expect(payload.truncated).toBe(false);
    expect(payload.characters).toBe(diff.length);
  });

  it("truncates a diff past the limit and says so", async () => {
    // Silent truncation would have a reviewer approve a change whose tail they
    // never saw.
    getPrDiff.mockResolvedValue("x".repeat(500));

    const payload = await harness.payload("get_pr_diff", {
      owner: "o", repo: "r", pull_number: 7, maxCharacters: 100,
    });

    expect(payload.truncated).toBe(true);
    expect(payload.diff).toHaveLength(100);
    expect(payload.truncationNotice).toMatch(/100 of 500/);
  });

  it("omits the truncation notice when nothing was cut", async () => {
    getPrDiff.mockResolvedValue(diff);

    const payload = await harness.payload("get_pr_diff", {
      owner: "o", repo: "r", pull_number: 7,
    });

    expect(payload.truncationNotice).toBeUndefined();
  });

  it("handles an empty diff", async () => {
    getPrDiff.mockResolvedValue("");

    const payload = await harness.payload("get_pr_diff", {
      owner: "o", repo: "r", pull_number: 7,
    });

    expect(payload.diff).toBe("");
    expect(payload.truncated).toBe(false);
  });

  it("surfaces an API failure as an error", async () => {
    getPrDiff.mockRejectedValue(new Error("Not Found"));

    const response = await harness.call("get_pr_diff", {
      owner: "o", repo: "r", pull_number: 7,
    });

    expect(response.isError).toBe(true);
    expect(response.content[0].text).toMatch(/Not Found/);
  });
});
