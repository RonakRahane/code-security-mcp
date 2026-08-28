import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { runUnifiedScan } from "../src/scanner/unified-scanner.js";

/**
 * End-to-end scans over a temporary project tree.
 *
 * Every scan runs with offline: true so results never depend on network access
 * to the OSV database or the Semgrep registry, since a suite that changes its
 * verdict based on connectivity cannot gate a release.
 */

let root: string;

beforeEach(() => {
  root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "sentinel-scan-")));
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

const scan = () => runUnifiedScan(root, { offline: true });

describe("runUnifiedScan", () => {
  it("returns a clean, well-formed result for a project with no issues", async () => {
    write("src/app.js", "export function add(a, b) {\n  return a + b;\n}\n");

    const result = await scan();

    expect(result.findings).toHaveLength(0);
    expect(result.summary).toEqual({ critical: 0, high: 0, medium: 0, low: 0, info: 0 });
    expect(result.filesScanned).toBeGreaterThan(0);
    expect(result.coverage.filesUnreadable).toBe(0);
    expect(result.coverage.truncated).toBe(false);
    expect(new Date(result.generatedAt).toString()).not.toBe("Invalid Date");
  });

  it("detects injection in a project file", async () => {
    write("src/app.js", "app.get('/u', (req, res) => {\n  db.query('SELECT * FROM u WHERE id = ' + req.params.id);\n});\n");

    const result = await scan();
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings.some((finding) => finding.cweId === "CWE-89")).toBe(true);
  });

  it("detects a hardcoded secret and never echoes it back", async () => {
    const secret = "AKIAIOSFODNN7EXAMPLE";
    write("src/config.js", `const awsKey = "${secret}";\n`);

    const result = await scan();
    const secretFindings = result.findings.filter((finding) => finding.category === "secrets");

    expect(secretFindings.length).toBeGreaterThan(0);
    expect(JSON.stringify(result)).not.toContain(secret);
  });

  it("reports each issue once rather than once per engine", async () => {
    write("src/app.js", 'const apiKey = "AKIAIOSFODNN7EXAMPLE";\n');

    const result = await scan();
    const keys = result.findings.map((finding) => `${finding.ruleId}:${finding.filePath}:${finding.line}`);
    expect(new Set(keys).size).toBe(keys.length);
  });

  it("keeps the summary consistent with the returned findings", async () => {
    write("src/app.js", "eval(req.body.code);\ndb.query('SELECT ' + req.query.q);\n");

    const result = await scan();
    const summed = Object.values(result.summary).reduce((total, count) => total + count, 0);
    expect(summed).toBe(result.findings.length + result.dependencyVulnerabilities.length);
  });

  it("does not descend into node_modules", async () => {
    write("src/app.js", "const a = 1;\n");
    write("node_modules/evil/index.js", "eval(req.body.code);\n");

    const result = await scan();
    expect(result.findings.every((finding) => !finding.filePath.includes("node_modules"))).toBe(true);
  });

  it("honours ignorePaths from sentinel.config.json", async () => {
    write("sentinel.config.json", JSON.stringify({ ignorePaths: ["generated"] }));
    write("generated/build.js", "eval(req.body.code);\n");
    write("src/app.js", "const a = 1;\n");

    const result = await scan();
    expect(result.findings.every((finding) => !finding.filePath.includes("generated"))).toBe(true);
  });

  it("honours minimumSeverity from configuration", async () => {
    write("sentinel.config.json", JSON.stringify({ minimumSeverity: "critical" }));
    write("src/app.js", "eval(req.body.code);\ndb.query('SELECT ' + req.query.q);\n");

    const result = await scan();
    expect(result.findings.every((finding) => finding.severity === "critical")).toBe(true);
  });

  it("honours ignoreRules from configuration", async () => {
    const before = await (async () => {
      write("src/app.js", "eval(req.body.code);\n");
      return scan();
    })();
    const suppressed = before.findings[0]?.ruleId;
    expect(suppressed).toBeTruthy();

    write("sentinel.config.json", JSON.stringify({ ignoreRules: [suppressed] }));
    const after = await scan();
    expect(after.findings.some((finding) => finding.ruleId === suppressed)).toBe(false);
  });

  it("surfaces a malformed config as a warning instead of failing silently", async () => {
    write("sentinel.config.json", "{ broken");
    write("src/app.js", "const a = 1;\n");

    const result = await scan();
    expect(result.warnings.join(" ")).toMatch(/could not be loaded/i);
  });

  it("reports truncation when the file limit is reached", async () => {
    for (let i = 0; i < 12; i++) write(`src/file${i}.js`, "const a = 1;\n");

    const result = await runUnifiedScan(root, { offline: true, maxFiles: 4 });
    expect(result.coverage.truncated).toBe(true);
    expect(result.warnings.join(" ")).toMatch(/file limit/i);
  });

  it("states that advisory lookups were skipped in offline mode", async () => {
    write("package.json", JSON.stringify({ name: "x", version: "1.0.0", dependencies: { lodash: "4.17.20" } }));

    const result = await runUnifiedScan(root, { offline: true });
    expect(result.warnings.join(" ")).toMatch(/offline/i);
  });

  it("skips binary files without treating them as unreadable", async () => {
    fs.writeFileSync(path.join(root, "blob.bin"), Buffer.from([0, 1, 2, 0, 3]));
    write("src/app.js", "const a = 1;\n");

    const result = await scan();
    expect(result.coverage.filesUnreadable).toBe(0);
    expect(result.findings).toHaveLength(0);
  });

  it("produces identical findings across repeated runs", async () => {
    write("src/app.js", "eval(req.body.code);\ndb.query('SELECT ' + req.query.q);\n");
    write("src/config.js", 'const apiKey = "AKIAIOSFODNN7EXAMPLE";\n');

    const first = await scan();
    const second = await scan();

    const identity = (result: Awaited<ReturnType<typeof scan>>) =>
      result.findings.map((f) => `${f.ruleId}|${f.filePath}|${f.line}|${f.severity}`);

    // Determinism is a hard requirement: a CI gate that flips between runs on
    // an unchanged commit is not a gate.
    expect(identity(first)).toEqual(identity(second));
    expect(first.summary).toEqual(second.summary);
  });

  it("records the engine that produced the results", async () => {
    write("src/app.js", "const a = 1;\n");
    const result = await scan();
    expect(["semgrep", "hybrid", "compatibility"]).toContain(result.engine.engine);
  });

  /**
   * Semgrep applies its own built-in ignore list when pointed at a directory,
   * and that list excludes test directories outright. Letting Semgrep pick its
   * targets means every file under `test/` gets reported as scanned while
   * receiving no analysis at all.
   */
  it("analyses source under a test directory, which Semgrep ignores by default", async () => {
    write("test/fixtures/vulnerable.js", [
      'const crypto = require("crypto");',
      'const hash = crypto.createHash("md5").update(secret).digest("hex");',
      "",
    ].join("\n"));

    const result = await scan();

    expect(result.findings.some((f) => f.filePath.includes("vulnerable.js"))).toBe(true);
  });

  it("leaves no scanned file without a static-analysis pass", async () => {
    write("src/app.js", "eval(userInput);\n");
    write("test/helper.py", 'import os\nos.system("ls " + name)\n');

    const result = await scan();

    expect(result.coverage.filesWithoutStaticAnalysis).toBe(0);
    expect(result.engine.filesAnalyzedByPatternEngine).toBeGreaterThan(0);
  });

  it("counts Semgrep coverage from what it analysed, not from what it was given", async () => {
    write("src/app.js", "const a = 1;\n");
    const result = await scan();

    const semgrepFiles = result.engine.filesAnalyzedBySemgrep ?? 0;
    // Never claim more analysed files than were read. The old code reported
    // engine "semgrep" with full coverage even when Semgrep analysed nothing.
    expect(semgrepFiles).toBeLessThanOrEqual(result.coverage.filesScanned);
    if (!result.engine.used) expect(semgrepFiles).toBe(0);
  });

  it("scans a single file without inventing a coverage gap", async () => {
    const file = write("src/app.js", "eval(userInput);\n");

    const result = await runUnifiedScan(file, { offline: true });

    expect(result.coverage.filesScanned).toBe(1);
    expect(result.warnings.some((w) => w.includes("could not be read"))).toBe(false);
  });
});

describe("dependency manifest selection", () => {
  // A loose manifest records a range; a lockfile records what is installed.
  // Auditing both asked the advisory database about the floor of the range, so
  // "^1.12.0" resolved to 1.29.0 was reported as vulnerable at 1.12.0.

  it("audits the lockfile and ignores package.json beside it", async () => {
    write("package.json", JSON.stringify({ dependencies: { lodash: "^4.17.20" } }));
    write("package-lock.json", JSON.stringify({
      lockfileVersion: 3,
      packages: { "node_modules/lodash": { version: "4.17.21" } },
    }));

    const result = await runUnifiedScan(root, { offline: true });
    const audited = result.warnings.join(" ");

    // The floor version must never be what gets audited.
    for (const vulnerability of result.dependencyVulnerabilities) {
      expect(vulnerability.installedVersion).not.toBe("4.17.20");
    }
    expect(audited).not.toMatch(/no dependencies could be parsed from package\.json/i);
  });

  it("still audits package.json when no lockfile sits beside it", async () => {
    write("package.json", JSON.stringify({ dependencies: { lodash: "4.17.20" } }));

    const result = await runUnifiedScan(root, { offline: true });

    expect(result.dependencyVulnerabilities.length).toBeGreaterThan(0);
  });

  it("keeps a lockfile in one directory from masking a manifest in another", async () => {
    write("package.json", JSON.stringify({ dependencies: { lodash: "4.17.20" } }));
    write("web/package.json", JSON.stringify({ dependencies: { lodash: "4.17.20" } }));
    write("web/package-lock.json", JSON.stringify({
      lockfileVersion: 3,
      packages: { "node_modules/lodash": { version: "4.17.21" } },
    }));

    const result = await runUnifiedScan(root, { offline: true });

    // The root package.json has no lockfile of its own, so it is still audited.
    expect(result.dependencyVulnerabilities.length).toBeGreaterThan(0);
  });
});

describe("ignoreBaseline", () => {
  // Writing a baseline needs everything the scan found. Building one from
  // results an existing baseline has already suppressed would record only the
  // new findings and resurface every old one on the next scan.

  it("reports suppressed findings again when the baseline is bypassed", async () => {
    write("legacy.js", 'const h = crypto.createHash("md5").update(pw).digest("hex");\n');

    const first = await runUnifiedScan(root, { offline: true });
    expect(first.findings.length).toBeGreaterThan(0);

    const { createBaseline, getBaselinePath, writeBaseline } =
      await import("../src/scanner/baseline.js");
    writeBaseline(
      getBaselinePath(root),
      createBaseline(first.findings, first.dependencyVulnerabilities, { rootPath: root })
    );

    const suppressed = await runUnifiedScan(root, { offline: true });
    expect(suppressed.findings).toHaveLength(0);

    const bypassed = await runUnifiedScan(root, { offline: true, ignoreBaseline: true });
    expect(bypassed.findings.length).toBe(first.findings.length);
  }, 120_000);

  it("still reports a finding added after the baseline was written", async () => {
    write("legacy.js", 'const h = crypto.createHash("md5").update(pw).digest("hex");\n');

    const first = await runUnifiedScan(root, { offline: true });
    const { createBaseline, getBaselinePath, writeBaseline } =
      await import("../src/scanner/baseline.js");
    writeBaseline(
      getBaselinePath(root),
      createBaseline(first.findings, first.dependencyVulnerabilities, { rootPath: root })
    );

    write("legacy.js",
      'const h = crypto.createHash("md5").update(pw).digest("hex");\n' +
      'eval(req.body.code);\n');

    const second = await runUnifiedScan(root, { offline: true });
    expect(second.findings.length).toBeGreaterThan(0);
    expect(second.findings.every((f) => f.line === 2)).toBe(true);
  }, 120_000);
});
