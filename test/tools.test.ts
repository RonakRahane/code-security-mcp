import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { errorResponse, jsonResponse, pathArgument, requirePath, runTool, textResponse } from "../src/tools/shared.js";
import { extractAddedLines } from "../src/tools/scan-pr-diff.js";
import { PathValidationError } from "../src/core/paths.js";
import { parseSemgrepOutput, resolveRegistryRulesets } from "../src/scanner/semgrep.js";

let root: string;

beforeEach(() => {
  root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "sentinel-tools-")));
});

afterEach(() => {
  fs.rmSync(root, { recursive: true, force: true });
  delete process.env.SENTINEL_SEMGREP_REGISTRY;
});

describe("tool responses", () => {
  it("wraps a payload as pretty JSON text content", () => {
    const response = jsonResponse({ a: 1 });
    expect(response.content[0].type).toBe("text");
    expect(JSON.parse(response.content[0].text)).toEqual({ a: 1 });
    expect(response.isError).toBeUndefined();
  });

  it("passes plain text through unchanged", () => {
    expect(textResponse("# Report").content[0].text).toBe("# Report");
  });

  it("marks errors with isError so a client can tell a failure from a clean scan", () => {
    // The difference matters: "no findings" and "I could not look" are not the
    // same answer, and a model acting on the result must be able to tell them apart.
    const response = errorResponse("boom", "try again");
    expect(response.isError).toBe(true);
    const payload = JSON.parse(response.content[0].text);
    expect(payload.error).toBe("boom");
    expect(payload.hint).toBe("try again");
  });
});

describe("runTool", () => {
  it("returns the handler result on success", async () => {
    const response = await runTool("t", async () => jsonResponse({ ok: true }));
    expect(JSON.parse(response.content[0].text).ok).toBe(true);
  });

  it("converts a path validation failure into a clean client error", async () => {
    const response = await runTool("t", async () => {
      throw new PathValidationError("bad path");
    });
    expect(response.isError).toBe(true);
    expect(JSON.parse(response.content[0].text).error).toBe("bad path");
  });

  it("catches an unexpected throw instead of failing the protocol call", async () => {
    const response = await runTool("scan_file", async () => {
      throw new Error("kaboom");
    });
    expect(response.isError).toBe(true);
    expect(JSON.parse(response.content[0].text).error).toMatch(/scan_file failed: kaboom/);
  });

  it("does not leak a stack trace to the client", async () => {
    const response = await runTool("t", async () => {
      throw new Error("kaboom");
    });
    expect(response.content[0].text).not.toMatch(/\bat .+:\d+:\d+/);
  });
});

describe("requirePath", () => {
  it("resolves a valid file", () => {
    const file = path.join(root, "a.js");
    fs.writeFileSync(file, "x");
    expect(requirePath(file, "file", "filePath").isFile).toBe(true);
  });

  it("throws PathValidationError for a missing file", () => {
    expect(() => requirePath(path.join(root, "missing.js"), "file", "filePath")).toThrow(PathValidationError);
  });
});

describe("pathArgument", () => {
  it("rejects an empty string", () => {
    expect(pathArgument("d").safeParse("").success).toBe(false);
  });

  it("rejects a path beyond the length limit", () => {
    expect(pathArgument("d").safeParse("a".repeat(5000)).success).toBe(false);
  });

  it("accepts a normal path", () => {
    expect(pathArgument("d").safeParse("/tmp/a.js").success).toBe(true);
  });
});

describe("extractAddedLines", () => {
  it("returns nothing for an empty patch", () => {
    expect(extractAddedLines("")).toEqual([]);
  });

  it("maps added lines to their post-merge line numbers", () => {
    const patch = ["@@ -1,2 +1,3 @@", " context", "+added one", "+added two", " trailing"].join("\n");
    expect(extractAddedLines(patch)).toEqual([
      { lineNumber: 2, content: "added one" },
      { lineNumber: 3, content: "added two" },
    ]);
  });

  it("does not advance the counter on removed lines", () => {
    const patch = ["@@ -1,3 +1,2 @@", " keep", "-removed", "+added"].join("\n");
    expect(extractAddedLines(patch)).toEqual([{ lineNumber: 2, content: "added" }]);
  });

  it("handles multiple hunks", () => {
    const patch = [
      "@@ -1,1 +1,2 @@", " a", "+first",
      "@@ -10,1 +20,2 @@", " b", "+second",
    ].join("\n");
    expect(extractAddedLines(patch)).toEqual([
      { lineNumber: 2, content: "first" },
      { lineNumber: 21, content: "second" },
    ]);
  });

  it("ignores the file header and the no-newline marker", () => {
    const patch = ["--- a/x", "+++ b/x", "@@ -1,1 +1,1 @@", "+added", "\\ No newline at end of file"].join("\n");
    expect(extractAddedLines(patch)).toEqual([{ lineNumber: 1, content: "added" }]);
  });
});

describe("parseSemgrepOutput", () => {
  it("returns null for empty output", () => {
    expect(parseSemgrepOutput("")).toBeNull();
    expect(parseSemgrepOutput("   ")).toBeNull();
  });

  it("parses well-formed JSON", () => {
    expect(parseSemgrepOutput('{"results":[]}')).toEqual({ results: [] });
  });

  it("recovers when a diagnostic line precedes the JSON", () => {
    // Some Semgrep versions print a notice before the payload despite --json.
    expect(parseSemgrepOutput('Scanning...\n{"results":[]}')).toEqual({ results: [] });
  });

  it("returns null when results is absent or not an array", () => {
    expect(parseSemgrepOutput('{"errors":[]}')).toBeNull();
    expect(parseSemgrepOutput('{"results":"nope"}')).toBeNull();
  });

  it("returns null for unparseable output", () => {
    expect(parseSemgrepOutput("not json at all")).toBeNull();
  });
});

describe("resolveRegistryRulesets", () => {
  it("returns nothing by default, keeping scans reproducible and offline-capable", () => {
    expect(resolveRegistryRulesets({})).toEqual([]);
  });

  it("uses explicitly configured packs", () => {
    expect(resolveRegistryRulesets({ registryRulesets: ["p/javascript"] })).toEqual(["p/javascript"]);
  });

  it("reads the environment variable", () => {
    process.env.SENTINEL_SEMGREP_REGISTRY = "p/javascript, p/python";
    expect(resolveRegistryRulesets({})).toEqual(["p/javascript", "p/python"]);
  });

  it("returns nothing in offline mode even when packs are configured", () => {
    expect(resolveRegistryRulesets({ registryRulesets: ["p/javascript"], offline: true })).toEqual([]);
  });

  it("rejects values that are not registry identifiers", () => {
    // Configuration must not be able to redirect rule loading at a URL or a
    // local path.
    const resolved = resolveRegistryRulesets({
      registryRulesets: ["https://evil.example/rules.yml", "../../etc/passwd", "p/javascript", "; rm -rf /"],
    });
    expect(resolved).toEqual(["p/javascript"]);
  });
});
