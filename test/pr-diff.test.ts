import { describe, expect, it } from "vitest";
import { extractAddedLines } from "../src/tools/scan-pr-diff.js";

/**
 * Line mapping for PR review comments.
 *
 * `scan_pr_diff` scans the added lines as a synthetic buffer, so every finding
 * carries an index into that buffer rather than a real file position. If the
 * mapping back is wrong, `post_security_review` leaves a security comment on
 * whatever line happens to sit at that offset in someone's pull request. Being
 * off by one here is a public, wrong claim about their code.
 */

describe("extractAddedLines", () => {
  it("returns nothing for an empty patch", () => {
    expect(extractAddedLines("")).toEqual([]);
  });

  it("numbers added lines from the hunk header", () => {
    const patch = [
      "@@ -1,3 +1,4 @@",
      " const a = 1;",
      "+const b = 2;",
      " const c = 3;",
    ].join("\n");

    expect(extractAddedLines(patch)).toEqual([{ lineNumber: 2, content: "const b = 2;" }]);
  });

  it("does not let removed lines advance the new-file counter", () => {
    const patch = [
      "@@ -1,4 +1,3 @@",
      " keep();",
      "-removed();",
      "-alsoRemoved();",
      "+added();",
    ].join("\n");

    expect(extractAddedLines(patch)).toEqual([{ lineNumber: 2, content: "added();" }]);
  });

  it("tracks line numbers across multiple hunks", () => {
    const patch = [
      "@@ -1,2 +1,3 @@",
      " first();",
      "+second();",
      " third();",
      "@@ -40,2 +41,3 @@",
      " fortieth();",
      "+fortyFirst();",
    ].join("\n");

    expect(extractAddedLines(patch)).toEqual([
      { lineNumber: 2, content: "second();" },
      { lineNumber: 42, content: "fortyFirst();" },
    ]);
  });

  it("handles a hunk header without a line count", () => {
    const patch = ["@@ -1 +1 @@", "-old();", "+new();"].join("\n");
    expect(extractAddedLines(patch)).toEqual([{ lineNumber: 1, content: "new();" }]);
  });

  it("ignores the no-newline marker rather than counting it as content", () => {
    const patch = [
      "@@ -1,2 +1,2 @@",
      " first();",
      "-second();",
      "\\ No newline at end of file",
      "+second();",
    ].join("\n");

    expect(extractAddedLines(patch)).toEqual([{ lineNumber: 2, content: "second();" }]);
  });

  it("does not treat file headers as added content", () => {
    const patch = [
      "--- a/app.js",
      "+++ b/app.js",
      "@@ -1,1 +1,2 @@",
      " existing();",
      "+eval(userInput);",
    ].join("\n");

    const added = extractAddedLines(patch);
    expect(added).toHaveLength(1);
    expect(added[0].content).toBe("eval(userInput);");
  });

  it("preserves an added empty line so later offsets stay correct", () => {
    const patch = ["@@ -1,1 +1,3 @@", " first();", "+", "+third();"].join("\n");

    expect(extractAddedLines(patch)).toEqual([
      { lineNumber: 2, content: "" },
      { lineNumber: 3, content: "third();" },
    ]);
  });
});
