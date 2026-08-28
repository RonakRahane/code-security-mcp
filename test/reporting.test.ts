import { describe, expect, it } from "vitest";
import { renderMarkdownReport } from "../src/reporting/markdown-report.js";
import { generateSarif } from "../src/scanner/sarif.js";
import { computeSeveritySummary } from "../src/core/severity.js";
import { Finding, ScanResult } from "../src/types/index.js";

const finding = (overrides: Partial<Finding> = {}): Finding => ({
  ruleId: "SQL_INJECTION_CONCAT",
  severity: "critical",
  category: "injection",
  cweId: "CWE-89",
  message: "SQL injection via string concatenation",
  filePath: "/repo/src/app.ts",
  line: 42,
  lineContent: "db.query('SELECT ' + id)",
  remediation: "Use parameterized queries",
  ...overrides,
});

const scanResult = (findings: Finding[]): ScanResult => ({
  filePath: findings[0]?.filePath ?? "/repo/src/app.ts",
  language: "typescript",
  totalFindings: findings.length,
  findings,
  summary: computeSeveritySummary(findings),
});

describe("renderMarkdownReport", () => {
  it("renders a report for an empty scan", () => {
    const report = renderMarkdownReport({ projectName: "demo", findings: [], dependencies: [] });
    expect(report).toContain("# Sentinel Security Report");
    expect(report).toContain("demo");
  });

  it("is deterministic for identical input", () => {
    const input = { projectName: "demo", generatedAt: "2024-01-01T00:00:00Z", findings: [finding()] };
    expect(renderMarkdownReport(input)).toBe(renderMarkdownReport(input));
  });

  it("does not echo source snippets, so a secret finding cannot leak through the report", () => {
    const secret = "AKIAIOSFODNN7EXAMPLE";
    const report = renderMarkdownReport({
      projectName: "demo",
      findings: [finding({ category: "secrets", ruleId: "AWS_ACCESS_KEY_ID", lineContent: `key = "${secret}"` })],
    });
    expect(report).not.toContain(secret);
  });

  it("escapes markdown control characters in the project name", () => {
    const report = renderMarkdownReport({ projectName: "evil [x](http://a) `code`", findings: [] });
    expect(report).not.toContain("](http://a)");
  });

  describe("scan coverage section", () => {
    it("is omitted when no coverage information is supplied", () => {
      expect(renderMarkdownReport({ projectName: "demo", findings: [] })).not.toContain("## Scan Coverage");
    });

    it("reports the engine that ran", () => {
      const report = renderMarkdownReport({
        projectName: "demo",
        findings: [],
        engine: { engine: "compatibility", available: false, used: false },
      });
      expect(report).toContain("## Scan Coverage");
      expect(report).toMatch(/Built-in pattern engine only/i);
    });

    it("names Semgrep when it was actually used", () => {
      const report = renderMarkdownReport({
        projectName: "demo",
        findings: [],
        engine: { engine: "semgrep", available: true, used: true },
      });
      expect(report).toMatch(/Semgrep/);
    });

    it("warns prominently when the scan was truncated", () => {
      const report = renderMarkdownReport({
        projectName: "demo",
        findings: [],
        coverage: { filesScanned: 100, filesSkipped: 0, filesUnreadable: 0, truncated: true, durationMs: 10 },
      });
      // A partial scan must not read like a clean bill of health.
      expect(report).toMatch(/Incomplete scan/i);
    });

    it("warns when files could not be read", () => {
      const report = renderMarkdownReport({
        projectName: "demo",
        findings: [],
        coverage: { filesScanned: 10, filesSkipped: 0, filesUnreadable: 4, truncated: false, durationMs: 10 },
      });
      expect(report).toMatch(/Coverage gap/i);
      expect(report).toMatch(/4 files/);
    });

    it("lists warnings", () => {
      const report = renderMarkdownReport({
        projectName: "demo",
        findings: [],
        warnings: ["OSV advisory lookup failed", "Semgrep unavailable"],
      });
      expect(report).toContain("OSV advisory lookup failed");
      expect(report).toContain("Semgrep unavailable");
    });

    it("caps the warning list rather than printing an unbounded wall of text", () => {
      const warnings = Array.from({ length: 40 }, (_, i) => `warning number ${i}`);
      const report = renderMarkdownReport({ projectName: "demo", findings: [], warnings });
      expect(report).toMatch(/further warning/);
      expect(report).not.toContain("warning number 39");
    });
  });
});

describe("findings in detail", () => {
  // The summary tables truncate every column to stay readable in a terminal,
  // which cuts messages mid-word and shows no remediation at all. Without the
  // detail section the report says what is wrong but never what to do.

  it("renders the full message rather than the truncated table cell", () => {
    const long = "This message is deliberately far longer than the seventy-six characters the summary table allows, so truncation would be visible.";
    const report = renderMarkdownReport({
      projectName: "demo",
      findings: [finding({ message: long })],
    });

    expect(report).toContain("## Findings in Detail");
    expect(report).toContain(long);
  });

  it("renders the remediation, which the tables never show", () => {
    const report = renderMarkdownReport({
      projectName: "demo",
      findings: [finding({ remediation: "Use a parameterized query." })],
    });

    expect(report).toMatch(/\*\*Fix:\*\* Use a parameterized query\./);
  });

  it("renders the rule identifier and CWE so a finding can be looked up", () => {
    const report = renderMarkdownReport({
      projectName: "demo",
      findings: [finding({ ruleId: "SQL_INJECTION_CONCAT", cweId: "CWE-89" })],
    });

    expect(report).toContain("SQL\\_INJECTION\\_CONCAT");
    expect(report).toMatch(/\*\*CWE:\*\* CWE-89/);
  });

  it("groups findings under the file they belong to", () => {
    const report = renderMarkdownReport({
      projectName: "demo",
      projectRoot: "/repo",
      findings: [
        finding({ filePath: "/repo/src/a.ts", line: 1 }),
        finding({ filePath: "/repo/src/a.ts", line: 2 }),
        finding({ filePath: "/repo/src/b.ts", line: 1 }),
      ],
    });

    expect(report).toContain("### src/a.ts");
    expect(report).toContain("### src/b.ts");
  });

  it("puts the worst file first so the top of the section is what to fix first", () => {
    const report = renderMarkdownReport({
      projectName: "demo",
      projectRoot: "/repo",
      findings: [
        finding({ filePath: "/repo/src/low.ts", severity: "low" }),
        finding({ filePath: "/repo/src/critical.ts", severity: "critical" }),
      ],
    });

    expect(report.indexOf("### src/critical.ts")).toBeLessThan(report.indexOf("### src/low.ts"));
  });

  it("never reproduces a source line, and says why", () => {
    // A report gets committed and shared. Echoing the matched line would carry
    // the secret along with it.
    const secret = "AKIAIOSFODNN7EXAMPLE";
    const report = renderMarkdownReport({
      projectName: "demo",
      findings: [finding({ category: "secrets", lineContent: `const k = "${secret}";` } as never)],
    });

    expect(report).not.toContain(secret);
    expect(report).toMatch(/Source lines are deliberately not reproduced/);
  });

  it("can be turned off", () => {
    const report = renderMarkdownReport(
      { projectName: "demo", findings: [finding()] },
      { includeFindingDetail: false }
    );

    expect(report).not.toContain("## Findings in Detail");
  });

  it("is omitted for a clean scan rather than left as an empty heading", () => {
    const report = renderMarkdownReport({ projectName: "demo", findings: [] });
    expect(report).not.toContain("## Findings in Detail");
  });
});

describe("risk level", () => {
  const riskFrom = (report: string) =>
    report.split("\n").find((line) => /\| Risk level/.test(line))?.split("|")[2]?.trim();

  it("derives the level from the findings when the caller supplies none", () => {
    // sanitizeCellValue turns an empty value into "-", which was then treated
    // as a caller-supplied level. Every CLI report showed "-" regardless of
    // what it found.
    const report = renderMarkdownReport({
      projectName: "demo",
      findings: [finding({ severity: "critical" })],
    });

    expect(riskFrom(report)).toBe("CRITICAL");
  });

  it("steps down through the severities", () => {
    const levelFor = (severity: Finding["severity"]) =>
      riskFrom(renderMarkdownReport({ projectName: "demo", findings: [finding({ severity })] }));

    expect(levelFor("high")).toBe("HIGH");
    expect(levelFor("medium")).toBe("MEDIUM");
    expect(levelFor("low")).toBe("LOW");
  });

  it("reports CLEAN for a scan with no findings", () => {
    const report = renderMarkdownReport({ projectName: "demo", findings: [] });
    expect(riskFrom(report)).toBe("CLEAN");
  });

  it("still honours a level the caller does supply", () => {
    const report = renderMarkdownReport({
      projectName: "demo",
      riskLevel: "elevated",
      findings: [finding({ severity: "critical" })],
    });

    expect(riskFrom(report)).toBe("ELEVATED");
  });
});

describe("renderMarkdownReport file counts", () => {
  const countFrom = (report: string) => {
    const row = report.split("\n").find((line) => /files with findings/i.test(line));
    return Number(row?.match(/(\d+)/g)?.pop());
  };

  it("counts a file once however many findings it holds", () => {
    // De-duplicating on "path:line" counted every finding as its own file, so
    // three issues in one file were reported as three files with findings.
    const report = renderMarkdownReport({
      projectName: "demo",
      filesScanned: 10,
      findings: [
        finding({ filePath: "/repo/src/app.ts", line: 1 }),
        finding({ filePath: "/repo/src/app.ts", line: 2 }),
        finding({ filePath: "/repo/src/app.ts", line: 3 }),
      ],
    });

    expect(countFrom(report)).toBe(1);
  });

  it("counts distinct files separately", () => {
    const report = renderMarkdownReport({
      projectName: "demo",
      filesScanned: 10,
      findings: [
        finding({ filePath: "/repo/src/a.ts", line: 1 }),
        finding({ filePath: "/repo/src/a.ts", line: 9 }),
        finding({ filePath: "/repo/src/b.ts", line: 1 }),
      ],
    });

    expect(countFrom(report)).toBe(2);
  });

  it("never reports more files with findings than files scanned", () => {
    const report = renderMarkdownReport({
      projectName: "demo",
      filesScanned: 1,
      findings: [
        finding({ filePath: "/repo/src/app.ts", line: 1 }),
        finding({ filePath: "/repo/src/app.ts", line: 2 }),
      ],
    });

    expect(countFrom(report)!).toBeLessThanOrEqual(1);
  });
});

describe("generateSarif", () => {
  const parse = (findings: Finding[]) => JSON.parse(generateSarif([scanResult(findings)], "demo"));

  it("produces a valid SARIF 2.1.0 envelope", () => {
    const sarif = parse([finding()]);
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.$schema).toContain("sarif");
    expect(sarif.runs).toHaveLength(1);
    expect(sarif.runs[0].tool.driver.name).toBeTruthy();
  });

  it("handles an empty result set", () => {
    const sarif = JSON.parse(generateSarif([], "demo"));
    expect(sarif.runs[0].results).toEqual([]);
    expect(sarif.runs[0].tool.driver.rules).toEqual([]);
  });

  it("emits one result per finding", () => {
    const sarif = parse([finding({ line: 1 }), finding({ line: 2 })]);
    expect(sarif.runs[0].results).toHaveLength(2);
  });

  it("de-duplicates the rule catalogue", () => {
    const sarif = parse([finding({ line: 1 }), finding({ line: 2 })]);
    expect(sarif.runs[0].tool.driver.rules).toHaveLength(1);
  });

  it("maps severities onto SARIF levels", () => {
    expect(parse([finding({ severity: "critical" })]).runs[0].results[0].level).toBe("error");
    expect(parse([finding({ severity: "high" })]).runs[0].results[0].level).toBe("error");
    expect(parse([finding({ severity: "medium" })]).runs[0].results[0].level).toBe("warning");
    expect(parse([finding({ severity: "low" })]).runs[0].results[0].level).toBe("note");
    expect(parse([finding({ severity: "info" })]).runs[0].results[0].level).toBe("note");
  });

  it("records a 1-based line region, as the SARIF schema requires", () => {
    const region = parse([finding({ line: 42 })]).runs[0].results[0].locations[0].physicalLocation.region;
    expect(region.startLine).toBe(42);
  });

  it("carries the CWE mapping through to rule properties", () => {
    expect(parse([finding()]).runs[0].tool.driver.rules[0].properties.cwe).toBe("CWE-89");
  });

  it("emits parseable JSON for every severity and category combination", () => {
    const findings = (["critical", "high", "medium", "low", "info"] as const).map((severity, i) =>
      finding({ severity, line: i + 1, ruleId: `RULE_${i}` })
    );
    expect(() => parse(findings)).not.toThrow();
  });

  describe("artifact locations resolve against the scan root", () => {
    // GitHub Code Scanning maps every result onto a file in the checkout. An
    // absolute machine path with its leading slash removed matches nothing
    // there, so the whole upload lands with no annotations on any line.

    const withRoot = (findings: Finding[], root: string) =>
      JSON.parse(generateSarif([scanResult(findings)], "demo", root));

    it("writes the path relative to the scan root", () => {
      const sarif = withRoot([finding({ filePath: "/repo/src/app.ts" })], "/repo");
      const location = sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation;

      expect(location.uri).toBe("src/app.ts");
      expect(location.uri.startsWith("repo/")).toBe(false);
    });

    it("names the base the relative path is resolved against", () => {
      const sarif = withRoot([finding({ filePath: "/repo/src/app.ts" })], "/repo");
      const location = sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation;
      const bases = sarif.runs[0].originalUriBaseIds;

      expect(location.uriBaseId).toBeTruthy();
      expect(bases[location.uriBaseId].uri).toMatch(/^file:\/\//);
      // Without the trailing separator, resolution drops the last segment.
      expect(bases[location.uriBaseId].uri.endsWith("/")).toBe(true);
    });

    it("keeps a path that lies outside the scan root visible as absolute", () => {
      const sarif = withRoot([finding({ filePath: "/elsewhere/app.ts" })], "/repo");
      const uri = sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri;

      expect(uri).not.toContain("..");
      expect(uri).toContain("elsewhere/app.ts");
    });
  });
});
