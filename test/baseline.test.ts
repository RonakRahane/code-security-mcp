import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  BASELINE_SCHEMA_VERSION,
  createBaseline,
  filterDependenciesAgainstBaseline,
  filterFindingsAgainstBaseline,
  fingerprintDependency,
  fingerprintFinding,
  loadBaseline,
  parseBaseline,
  writeBaseline,
} from "../src/scanner/baseline.js";
import { DependencyVulnerability, Finding } from "../src/types/index.js";

let root: string;

beforeEach(() => {
  root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "sentinel-baseline-")));
});

afterEach(() => {
  fs.rmSync(root, { recursive: true, force: true });
});

const finding = (overrides: Partial<Finding> = {}): Finding => ({
  ruleId: "SQL_INJECTION",
  severity: "critical",
  category: "injection",
  cweId: "CWE-89",
  message: "SQL injection",
  filePath: "/repo/src/app.ts",
  line: 42,
  lineContent: "db.query('SELECT ' + id)",
  remediation: "Use parameterized queries",
  ...overrides,
});

const dependency = (overrides: Partial<DependencyVulnerability> = {}): DependencyVulnerability => ({
  package: "lodash",
  ecosystem: "npm",
  severity: "high",
  title: "Prototype pollution",
  url: "https://osv.dev/vulnerability/GHSA-x",
  installedVersion: "4.17.20",
  patchedVersion: "4.17.21",
  path: "lodash",
  ...overrides,
});

describe("fingerprintFinding", () => {
  it("is a SHA-256 hex digest", () => {
    expect(fingerprintFinding(finding())).toMatch(/^[a-f0-9]{64}$/);
  });

  it("is stable across calls", () => {
    expect(fingerprintFinding(finding())).toBe(fingerprintFinding(finding()));
  });

  it("ignores the rule id, so the reporting engine does not decide identity", () => {
    // Was: identity changed with the rule id. Deduplication prefers Semgrep
    // where it is installed, so the same code carried a different rule id on a
    // runner without it and a committed baseline suppressed nothing there.
    // Identity is the CWE plus the location and the matched code.
    expect(fingerprintFinding(finding())).toBe(fingerprintFinding(finding({ ruleId: "OTHER" })));
  });

  it("ignores the line number, so an edit above a finding does not resurrect it", () => {
    // Was: identity changed with the line. One comment inserted at the top of a
    // file turned every accepted finding below it into a new CI failure.
    expect(fingerprintFinding(finding())).toBe(fingerprintFinding(finding({ line: 43 })));
  });

  it("still separates findings of different classes and files", () => {
    const base = fingerprintFinding(finding());
    expect(base).not.toBe(fingerprintFinding(finding({ cweId: "CWE-95" })));
    expect(base).not.toBe(fingerprintFinding(finding({ filePath: "/repo/other.js" })));
    expect(base).not.toBe(fingerprintFinding(finding({ lineContent: "something else" })));
  });

  it("ignores severity, so re-rating a rule does not resurrect a known finding", () => {
    expect(fingerprintFinding(finding())).toBe(fingerprintFinding(finding({ severity: "low" })));
  });

  it("is portable across checkouts when a root is supplied", () => {
    const a = fingerprintFinding(finding({ filePath: "/home/alice/repo/src/app.ts" }), "/home/alice/repo");
    const b = fingerprintFinding(finding({ filePath: "/build/ci/repo/src/app.ts" }), "/build/ci/repo");
    expect(a).toBe(b);
  });
});

describe("fingerprintDependency", () => {
  it("is stable and changes with the installed version", () => {
    expect(fingerprintDependency(dependency())).toBe(fingerprintDependency(dependency()));
    expect(fingerprintDependency(dependency())).not.toBe(fingerprintDependency(dependency({ installedVersion: "4.17.21" })));
  });

  it("canonicalises PyPI names per PEP 503", () => {
    const a = fingerprintDependency(dependency({ ecosystem: "pypi", package: "My_Package" }));
    const b = fingerprintDependency(dependency({ ecosystem: "pypi", package: "my-package" }));
    expect(a).toBe(b);
  });
});

describe("createBaseline", () => {
  it("produces a sorted, de-duplicated fingerprint list", () => {
    const baseline = createBaseline(
      [finding(), finding(), finding({ lineContent: "a different line of code" })],
      []
    );
    expect(baseline.version).toBe(BASELINE_SCHEMA_VERSION);
    expect(baseline.findingFingerprints).toHaveLength(2);
    expect([...baseline.findingFingerprints].sort()).toEqual(baseline.findingFingerprints);
  });
});

describe("parseBaseline", () => {
  it("rejects a non-object", () => {
    expect(() => parseBaseline("nope")).toThrow(/expected an object/i);
  });

  it("rejects an unsupported version", () => {
    expect(() => parseBaseline({ version: 99, generatedAt: "x", findingFingerprints: [], dependencyFingerprints: [] }))
      .toThrow(/version/i);
  });

  it("rejects a malformed fingerprint", () => {
    expect(() => parseBaseline({
      version: BASELINE_SCHEMA_VERSION,
      generatedAt: "2024-01-01T00:00:00Z",
      findingFingerprints: ["not-a-hash"],
      dependencyFingerprints: [],
    })).toThrow(/SHA-256/i);
  });
});

describe("loadBaseline and writeBaseline", () => {
  it("returns null when no baseline exists", () => {
    expect(loadBaseline(path.join(root, ".sentinel-baseline.json"))).toBeNull();
  });

  it("round-trips a baseline through disk", () => {
    const target = path.join(root, ".sentinel-baseline.json");
    const baseline = createBaseline([finding()], [dependency()], { generatedAt: "2024-01-01T00:00:00.000Z" });

    writeBaseline(target, baseline);
    expect(loadBaseline(target)).toEqual(baseline);
  });

  it("throws on a corrupt baseline rather than silently suppressing nothing", () => {
    const target = path.join(root, ".sentinel-baseline.json");
    fs.writeFileSync(target, "{ not json", "utf-8");
    expect(() => loadBaseline(target)).toThrow(/unable to parse/i);
  });

  it("leaves no temporary file behind", () => {
    const target = path.join(root, ".sentinel-baseline.json");
    writeBaseline(target, createBaseline([finding()], []));
    expect(fs.readdirSync(root).filter((name) => name.endsWith(".tmp"))).toHaveLength(0);
  });
});

describe("filterFindingsAgainstBaseline", () => {
  it("returns everything when there is no baseline", () => {
    expect(filterFindingsAgainstBaseline([finding()], null)).toHaveLength(1);
  });

  it("suppresses known findings", () => {
    const baseline = createBaseline([finding()], []);
    expect(filterFindingsAgainstBaseline([finding()], baseline)).toHaveLength(0);
  });

  it("still reports a new finding alongside a suppressed one", () => {
    const baseline = createBaseline([finding()], []);
    const result = filterFindingsAgainstBaseline(
      [finding(), finding({ cweId: "CWE-95", lineContent: "eval(req.body.code)", line: 99 })],
      baseline
    );
    expect(result).toHaveLength(1);
    expect(result[0].line).toBe(99);
  });

  it("does not mutate the input", () => {
    const findings = [finding()];
    filterFindingsAgainstBaseline(findings, createBaseline(findings, []));
    expect(findings).toHaveLength(1);
  });
});

describe("filterDependenciesAgainstBaseline", () => {
  it("suppresses known advisories and reports new ones", () => {
    const baseline = createBaseline([], [dependency()]);
    expect(filterDependenciesAgainstBaseline([dependency()], baseline)).toHaveLength(0);
    expect(filterDependenciesAgainstBaseline([dependency({ package: "axios" })], baseline)).toHaveLength(1);
  });
});

describe("fingerprint stability", () => {
  const finding = (overrides: Partial<Finding> = {}): Finding => ({
    ruleId: "WEAK_HASH_MD5",
    severity: "high",
    category: "crypto",
    cweId: "CWE-328",
    message: "m",
    filePath: "/repo/src/a.js",
    line: 1,
    lineContent: 'crypto.createHash("md5")',
    remediation: "r",
    ...overrides,
  });

  it("survives an edit that moves the finding down the file", () => {
    // The line number used to be part of the hash, so one comment inserted
    // above a finding turned every accepted finding below it into a new CI
    // failure.
    const before = fingerprintFinding(finding({ line: 1 }), "/repo");
    const after = fingerprintFinding(finding({ line: 40 }), "/repo");

    expect(after).toBe(before);
  });

  it("survives the same code being reported by a different engine", () => {
    // Which engine wins deduplication decides the rule id, so a baseline
    // written where Semgrep is installed suppressed nothing on a runner
    // without it.
    const pattern = fingerprintFinding(finding({ ruleId: "WEAK_HASH_MD5" }), "/repo");
    const semgrep = fingerprintFinding(
      finding({ ruleId: "sentinel.core.javascript.crypto.md5", source: "semgrep" }),
      "/repo"
    );

    expect(semgrep).toBe(pattern);
  });

  it("still separates genuinely different findings", () => {
    const md5 = fingerprintFinding(finding(), "/repo");
    const evalUsage = fingerprintFinding(
      finding({ cweId: "CWE-95", lineContent: "eval(x)" }),
      "/repo"
    );
    const otherFile = fingerprintFinding(finding({ filePath: "/repo/src/b.js" }), "/repo");

    expect(new Set([md5, evalUsage, otherFile]).size).toBe(3);
  });
});
