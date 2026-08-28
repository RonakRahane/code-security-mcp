import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { scanProject, generateHTML } from "../src/dashboard/generate-report.js";
import { generateSarif } from "../src/scanner/sarif.js";

/**
 * The dashboard runs a real scan and turns it into HTML and SARIF. It is the
 * one path a user drives with a single command and never inspects the
 * intermediate data, so a wrong number or a broken path here is invisible until
 * someone acts on it.
 *
 * These exercise the pipeline end to end against real files rather than the
 * renderer alone.
 */

let root: string;

beforeEach(() => {
  root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "sentinel-dash-")));
});

afterEach(() => {
  fs.rmSync(root, { recursive: true, force: true });
});

const write = (relativePath: string, contents: string) => {
  const full = path.join(root, relativePath);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, contents, "utf-8");
  return full;
};

const VULNERABLE = [
  'const key = "AKIAIOSFODNN7EXAMPLE";',
  'const h = crypto.createHash("md5").update(pw).digest("hex");',
  "eval(req.body.code);",
].join("\n");

describe("scanProject", () => {
  it("counts findings, files and severities consistently", async () => {
    write("src/app.js", `${VULNERABLE}\n`);

    const data = await scanProject(root);

    expect(data.totalFindings).toBeGreaterThan(0);
    expect(data.filesScanned).toBeGreaterThan(0);
    expect(data.filesWithIssues).toBeGreaterThan(0);

    // The summary must add up to the finding count, or the report contradicts
    // itself between its headline number and its severity table.
    const summed = data.summary.critical + data.summary.high + data.summary.medium +
      data.summary.low + data.summary.info;
    expect(summed).toBe(data.totalFindings);
  });

  it("reports a clean project as CLEAN with nothing to show", async () => {
    write("src/safe.js", "export const add = (a, b) => a + b;\n");

    const data = await scanProject(root);

    expect(data.totalFindings).toBe(0);
    expect(data.riskLevel).toBe("CLEAN");
    expect(data.topFiles).toEqual([]);
  });

  it("raises the risk level to CRITICAL when a critical finding is present", async () => {
    write("src/app.js", `${VULNERABLE}\n`);

    const data = await scanProject(root);

    expect(data.summary.critical).toBeGreaterThan(0);
    expect(data.riskLevel).toBe("CRITICAL");
  });

  it("keeps absolute paths in rawResults so SARIF can relativise them", async () => {
    write("src/app.js", `${VULNERABLE}\n`);

    const data = await scanProject(root);

    for (const result of data.rawResults) {
      expect(path.isAbsolute(result.filePath)).toBe(true);
    }
  });

  it("shows project-relative paths in the tables a reader sees", async () => {
    write("src/app.js", `${VULNERABLE}\n`);

    const data = await scanProject(root);

    for (const entry of data.topFiles) {
      expect(path.isAbsolute(entry.file)).toBe(false);
      expect(entry.file.startsWith("./")).toBe(false);
      expect(entry.file).toContain("src/app.js");
    }
  });

  it("counts a taint finding as a taint flow", async () => {
    // The counter reads source and category off each finding. When rule
    // metadata stopped being read, every Semgrep result was filed as
    // "miscellaneous" and this silently reported zero.
    write("src/app.js", [
      "app.get('/u', (req, res) => {",
      "  const q = 'SELECT * FROM users WHERE id = ' + req.params.id;",
      "  db.query(q);",
      "});",
    ].join("\n"));

    const data = await scanProject(root);
    const taintable = data.rawResults
      .flatMap((r) => r.findings)
      .filter((f) => f.source === "semgrep");

    // Only meaningful when Semgrep is installed; the counter must agree with
    // the findings either way.
    if (taintable.length > 0) {
      expect(data.taintFlows).toBeGreaterThan(0);
    } else {
      expect(data.taintFlows).toBe(0);
    }
  });

  it("counts the fixes the auto-fixer can actually generate", async () => {
    write("src/app.js", 'const h = crypto.createHash("md5").update(pw).digest("hex");\n');

    const data = await scanProject(root);

    expect(data.fixesAvailable).toBeGreaterThan(0);
  });

  it("does not scan the reports a previous run wrote", async () => {
    write("src/app.js", `${VULNERABLE}\n`);

    const baseline = await scanProject(root);

    // A SARIF report embeds the matched line of every finding, which is enough
    // to trip the rules that produced it. Asserting only that no finding names
    // the report would pass whether or not it was skipped, since a file with no
    // findings never appears either way; the file count is what shows it.
    write("sentinel-report.sarif", JSON.stringify({
      runs: [{ results: [{ snippet: 'crypto.createHash("md5").update(pw)' }] }],
    }));
    write("sentinel-report.html", '<html>crypto.createHash("md5").update(pw)</html>');

    const afterReports = await scanProject(root);

    expect(afterReports.filesScanned).toBe(baseline.filesScanned);
    expect(afterReports.totalFindings).toBe(baseline.totalFindings);
    for (const result of afterReports.rawResults) {
      expect(path.basename(result.filePath)).not.toMatch(/^sentinel-report\./);
    }
  });
});

describe("dashboard outputs", () => {
  it("produces HTML and SARIF that agree on the finding count", async () => {
    write("src/app.js", `${VULNERABLE}\n`);

    const data = await scanProject(root);
    const sarif = JSON.parse(generateSarif(data.rawResults, data.projectName, data.projectPath));

    const inRawResults = data.rawResults.reduce((total, r) => total + r.findings.length, 0);
    expect(sarif.runs[0].results).toHaveLength(inRawResults);
  });

  it("writes SARIF artifact URIs that are project-relative and clean", async () => {
    write("src/app.js", `${VULNERABLE}\n`);

    const data = await scanProject(root);
    const sarif = JSON.parse(generateSarif(data.rawResults, data.projectName, data.projectPath));

    for (const result of sarif.runs[0].results) {
      const uri = result.locations[0].physicalLocation.artifactLocation.uri;
      // "./src/app.js" is what a pre-relativised path produced, and GitHub
      // Code Scanning does not match it against a file in the checkout.
      expect(uri.startsWith("./")).toBe(false);
      expect(path.isAbsolute(uri)).toBe(false);
      expect(uri).toBe("src/app.js");
    }
  });

  it("renders HTML that carries the findings and escapes them", async () => {
    write("src/app.js", `${VULNERABLE}\n`);

    const data = await scanProject(root);
    const html = generateHTML(data);

    expect(html).toContain("<!DOCTYPE html>");
    expect(html).toContain("src/app.js");
    expect(html).not.toContain("AKIAIOSFODNN7EXAMPLE");
  });

  it("renders a clean project without inventing findings", async () => {
    write("src/safe.js", "export const add = (a, b) => a + b;\n");

    const data = await scanProject(root);
    const html = generateHTML(data);

    expect(html).toContain("<!DOCTYPE html>");
    expect(html).toContain("CLEAN");
  });
});
