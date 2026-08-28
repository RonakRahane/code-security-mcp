import { describe, expect, it } from "vitest";
import { dedupeFindings } from "../src/core/findings.js";
import { Finding } from "../src/types/index.js";

const finding = (overrides: Partial<Finding> = {}): Finding => ({
  ruleId: "RULE_A",
  severity: "high",
  category: "injection",
  cweId: "CWE-89",
  message: "SQL injection",
  filePath: "/repo/src/app.ts",
  line: 10,
  lineContent: "db.query(...)",
  remediation: "Use parameterized queries",
  ...overrides,
});

describe("dedupeFindings", () => {
  it("returns an empty array unchanged", () => {
    expect(dedupeFindings([])).toEqual([]);
  });

  it("keeps a single finding", () => {
    expect(dedupeFindings([finding()])).toHaveLength(1);
  });

  it("collapses identical rule, file, and line", () => {
    expect(dedupeFindings([finding(), finding()])).toHaveLength(1);
  });

  it("keeps findings on different lines", () => {
    expect(dedupeFindings([finding({ line: 10 }), finding({ line: 11 })])).toHaveLength(2);
  });

  it("keeps findings in different files", () => {
    expect(dedupeFindings([finding({ filePath: "/a.ts" }), finding({ filePath: "/b.ts" })])).toHaveLength(2);
  });

  it("treats Windows and POSIX separators as the same file", () => {
    const posix = finding({ filePath: "/repo/src/app.ts" });
    const windows = finding({ filePath: "\\repo\\src\\app.ts" });
    expect(dedupeFindings([posix, windows])).toHaveLength(1);
  });

  it("collapses two engines reporting the same CWE at the same location", () => {
    const regexHit = finding({ ruleId: "SQL_INJECTION_CONCAT", source: "compatibility" });
    const semgrepHit = finding({ ruleId: "sentinel.sql-injection", source: "semgrep" });

    const result = dedupeFindings([regexHit, semgrepHit]);
    expect(result).toHaveLength(1);
    // The AST-aware engine carries more context, so it should be the survivor.
    expect(result[0].source).toBe("semgrep");
  });

  it("keeps the more severe copy when duplicates disagree", () => {
    const low = finding({ severity: "low", source: "compatibility" });
    const critical = finding({ severity: "critical", source: "compatibility" });
    expect(dedupeFindings([low, critical])[0].severity).toBe("critical");
  });

  it("does not collapse different weakness classes on the same line", () => {
    const sqli = finding({ ruleId: "A", cweId: "CWE-89" });
    const xss = finding({ ruleId: "B", cweId: "CWE-79" });
    expect(dedupeFindings([sqli, xss])).toHaveLength(2);
  });

  it("does not collapse by CWE when collapseOverlappingRules is disabled", () => {
    const a = finding({ ruleId: "A" });
    const b = finding({ ruleId: "B" });
    expect(dedupeFindings([a, b], { collapseOverlappingRules: false })).toHaveLength(2);
  });

  it("never collapses findings that carry no CWE mapping", () => {
    const a = finding({ ruleId: "A", cweId: "CWE-0" });
    const b = finding({ ruleId: "B", cweId: "CWE-0" });
    expect(dedupeFindings([a, b])).toHaveLength(2);
  });
});
