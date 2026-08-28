import { describe, expect, it } from "vitest";
import { generateHTML, DashboardData } from "../src/dashboard/generate-report.js";
import { Finding } from "../src/types/index.js";

/**
 * The report is written to disk and opened in a browser immediately after a
 * scan. Every string it renders comes from the scanned repository: file paths,
 * rule identifiers, messages and remediation text. Interpolating any of them
 * unescaped turns a hostile filename into script that runs in the reader's
 * browser, so escaping is the property under test here.
 */

const PAYLOAD = '<img src=x onerror="alert(1)">';

const finding = (overrides: Partial<Finding> = {}): Finding => ({
  ruleId: "EVAL_USAGE",
  severity: "high",
  category: "dangerous-functions",
  cweId: "CWE-95",
  message: "eval() executes arbitrary code",
  filePath: "/project/app.js",
  line: 1,
  lineContent: "eval(x)",
  remediation: "Remove eval().",
  ...overrides,
});

const data = (overrides: Partial<DashboardData> = {}): DashboardData => ({
  projectName: "demo",
  projectPath: "/project",
  scanDate: new Date(0).toISOString(),
  filesScanned: 1,
  filesWithIssues: 1,
  totalFindings: 1,
  taintFlows: 0,
  fixesAvailable: 0,
  riskLevel: "HIGH",
  summary: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
  categoryBreakdown: { "dangerous-functions": 1 },
  languageBreakdown: { javascript: 1 },
  topFiles: [{ file: "app.js", findings: 1, critical: 0, high: 1 }],
  allFindings: [{ file: "app.js", findings: [finding()] }],
  rawResults: [],
  ...overrides,
});

describe("generateHTML", () => {
  it("escapes a hostile file path in the file table and the section heading", () => {
    const html = generateHTML(data({
      topFiles: [{ file: `${PAYLOAD}.js`, findings: 1, critical: 0, high: 1 }],
      allFindings: [{ file: `${PAYLOAD}.js`, findings: [finding()] }],
    }));

    expect(html).not.toContain(PAYLOAD);
    expect(html).toContain("&lt;img src=x onerror=");
  });

  it("escapes the finding message, rule identifier and remediation", () => {
    const html = generateHTML(data({
      allFindings: [{
        file: "app.js",
        findings: [finding({ message: PAYLOAD, ruleId: PAYLOAD, remediation: PAYLOAD, cweId: PAYLOAD })],
      }],
    }));

    expect(html).not.toContain(PAYLOAD);
  });

  it("escapes the project name in both the title and the header", () => {
    const html = generateHTML(data({ projectName: PAYLOAD, projectPath: PAYLOAD }));

    expect(html).not.toContain(PAYLOAD);
    expect(html).not.toMatch(/<title>[^<]*<img/);
  });

  it("escapes the category label rendered in the breakdown bars", () => {
    const html = generateHTML(data({ categoryBreakdown: { [PAYLOAD]: 3 } }));
    expect(html).not.toContain(PAYLOAD);
  });

  it("escapes single quotes, which close an attribute just as well as double", () => {
    const html = generateHTML(data({ projectName: "it's" }));
    expect(html).toContain("it&#39;s");
  });

  it("still renders the report content it was given", () => {
    const html = generateHTML(data());

    expect(html).toContain("<!DOCTYPE html>");
    expect(html).toContain("EVAL_USAGE");
    expect(html).toContain("app.js");
  });
});
