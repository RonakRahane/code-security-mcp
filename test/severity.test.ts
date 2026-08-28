import { describe, expect, it } from "vitest";
import {
  computeSeveritySummary,
  countAtOrAbove,
  emptySeveritySummary,
  isSeverity,
  isSeverityAtOrAbove,
  severityRank,
  sortBySeverity,
} from "../src/core/severity.js";
import { Severity } from "../src/types/index.js";

const finding = (severity: Severity, filePath = "a.ts", line = 1) => ({ severity, filePath, line });

describe("severityRank", () => {
  it("orders critical as the most severe", () => {
    expect(severityRank("critical")).toBeLessThan(severityRank("high"));
    expect(severityRank("high")).toBeLessThan(severityRank("medium"));
    expect(severityRank("medium")).toBeLessThan(severityRank("low"));
    expect(severityRank("low")).toBeLessThan(severityRank("info"));
  });
});

describe("isSeverityAtOrAbove", () => {
  it("includes the threshold itself", () => {
    expect(isSeverityAtOrAbove("high", "high")).toBe(true);
  });

  it("includes more severe values", () => {
    expect(isSeverityAtOrAbove("critical", "high")).toBe(true);
  });

  it("excludes less severe values", () => {
    expect(isSeverityAtOrAbove("medium", "high")).toBe(false);
    expect(isSeverityAtOrAbove("info", "low")).toBe(false);
  });
});

describe("isSeverity", () => {
  it("accepts every valid level", () => {
    for (const level of ["critical", "high", "medium", "low", "info"]) {
      expect(isSeverity(level)).toBe(true);
    }
  });

  it("rejects anything else", () => {
    expect(isSeverity("CRITICAL")).toBe(false);
    expect(isSeverity("severe")).toBe(false);
    expect(isSeverity(undefined)).toBe(false);
    expect(isSeverity(3)).toBe(false);
  });
});

describe("computeSeveritySummary", () => {
  it("counts an empty input as all zeroes", () => {
    expect(computeSeveritySummary([])).toEqual(emptySeveritySummary());
  });

  it("counts each severity", () => {
    const summary = computeSeveritySummary([
      finding("critical"), finding("critical"), finding("high"), finding("info"),
    ]);
    expect(summary).toEqual({ critical: 2, high: 1, medium: 0, low: 0, info: 1 });
  });

  it("merges multiple groups, as findings plus dependencies", () => {
    const summary = computeSeveritySummary([finding("high")], [finding("high"), finding("low")]);
    expect(summary.high).toBe(2);
    expect(summary.low).toBe(1);
  });
});

describe("sortBySeverity", () => {
  it("puts the most severe first", () => {
    const items = [finding("low"), finding("critical"), finding("medium")];
    expect(sortBySeverity(items).map((item) => item.severity)).toEqual(["critical", "medium", "low"]);
  });

  it("breaks ties deterministically by path then line", () => {
    const items = [
      finding("high", "b.ts", 1),
      finding("high", "a.ts", 9),
      finding("high", "a.ts", 2),
    ];
    expect(sortBySeverity(items).map((item) => `${item.filePath}:${item.line}`))
      .toEqual(["a.ts:2", "a.ts:9", "b.ts:1"]);
  });

  it("produces identical ordering across repeated runs", () => {
    const build = () => [
      finding("high", "z.ts", 5), finding("critical", "y.ts", 3),
      finding("high", "a.ts", 5), finding("low", "b.ts", 1),
    ];
    const first = sortBySeverity(build()).map((item) => `${item.severity}:${item.filePath}:${item.line}`);
    const second = sortBySeverity(build()).map((item) => `${item.severity}:${item.filePath}:${item.line}`);
    expect(first).toEqual(second);
  });
});

describe("countAtOrAbove", () => {
  const summary = { critical: 1, high: 2, medium: 3, low: 4, info: 5 };

  it("counts only the threshold and above", () => {
    expect(countAtOrAbove(summary, "critical")).toBe(1);
    expect(countAtOrAbove(summary, "high")).toBe(3);
    expect(countAtOrAbove(summary, "medium")).toBe(6);
    expect(countAtOrAbove(summary, "info")).toBe(15);
  });

  it("returns zero for a clean summary", () => {
    expect(countAtOrAbove(emptySeveritySummary(), "info")).toBe(0);
  });
});
