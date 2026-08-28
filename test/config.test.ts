import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { Diagnostics } from "../src/core/diagnostics.js";
import {
  filterByMinimumSeverity,
  filterIgnoredFindings,
  isOfflineMode,
  isPathIgnored,
  loadSentinelConfig,
} from "../src/scanner/config.js";
import { Finding, SentinelConfig } from "../src/types/index.js";

let root: string;

beforeEach(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), "sentinel-config-"));
});

afterEach(() => {
  fs.rmSync(root, { recursive: true, force: true });
  delete process.env.SENTINEL_OFFLINE;
});

const writeConfig = (contents: string) =>
  fs.writeFileSync(path.join(root, "sentinel.config.json"), contents, "utf-8");

const makeFinding = (overrides: Partial<Finding> = {}): Finding => ({
  ruleId: "RULE",
  severity: "high",
  category: "injection",
  cweId: "CWE-89",
  message: "m",
  filePath: "a.ts",
  line: 1,
  lineContent: "x",
  remediation: "r",
  ...overrides,
});

describe("loadSentinelConfig", () => {
  it("returns defaults when no config file exists", () => {
    const config = loadSentinelConfig(root);
    expect(config.ignorePaths).toEqual([]);
    expect(config.minimumSeverity).toBeUndefined();
  });

  it("loads valid settings", () => {
    writeConfig(JSON.stringify({
      ignorePaths: ["vendor"],
      ignoreRules: ["RULE_A"],
      minimumSeverity: "medium",
      failOnSeverity: "critical",
      maxFiles: 500,
      offline: true,
    }));

    const config = loadSentinelConfig(root);
    expect(config.ignorePaths).toContain("vendor");
    expect(config.ignoreRules).toContain("RULE_A");
    expect(config.minimumSeverity).toBe("medium");
    expect(config.failOnSeverity).toBe("critical");
    expect(config.maxFiles).toBe(500);
    expect(config.offline).toBe(true);
  });

  it("reports malformed JSON instead of silently ignoring it", () => {
    writeConfig("{ not json");
    const diagnostics = new Diagnostics();
    loadSentinelConfig(root, diagnostics);

    // A config that fails to load leaves the user with a policy they think is
    // active but is not, so the failure has to be visible.
    expect(diagnostics.toWarnings().join(" ")).toMatch(/could not be loaded/i);
  });

  it("rejects an invalid severity but keeps the rest of the config", () => {
    writeConfig(JSON.stringify({ minimumSeverity: "severe", ignorePaths: ["build"] }));
    const diagnostics = new Diagnostics();
    const config = loadSentinelConfig(root, diagnostics);

    expect(config.minimumSeverity).toBeUndefined();
    expect(config.ignorePaths).toContain("build");
    expect(diagnostics.toWarnings().join(" ")).toMatch(/minimumSeverity/);
  });

  it("rejects a non-object config", () => {
    writeConfig("[1,2,3]");
    const diagnostics = new Diagnostics();
    loadSentinelConfig(root, diagnostics);
    expect(diagnostics.toWarnings().join(" ")).toMatch(/JSON object/i);
  });

  it("reads .sentinelignore entries and skips comments", () => {
    fs.writeFileSync(path.join(root, ".sentinelignore"), "# comment\n\ndist\nvendor\n", "utf-8");
    const config = loadSentinelConfig(root);
    expect(config.ignorePaths).toEqual(expect.arrayContaining(["dist", "vendor"]));
    expect(config.ignorePaths).not.toContain("# comment");
  });
});

describe("isPathIgnored", () => {
  const ignored = (patterns: string[], target: string) =>
    isPathIgnored(path.join(root, target), root, { ignorePaths: patterns } as SentinelConfig);

  it("returns false when nothing is configured", () => {
    expect(ignored([], "src/a.ts")).toBe(false);
  });

  it("matches an exact relative path", () => {
    expect(ignored(["src/a.ts"], "src/a.ts")).toBe(true);
  });

  it("matches everything under a directory", () => {
    expect(ignored(["vendor"], "vendor/deep/lib.js")).toBe(true);
  });

  it("does not match a directory prefix that is only a partial name", () => {
    expect(ignored(["vendor"], "vendors/lib.js")).toBe(false);
  });

  it("matches a bare basename anywhere in the tree", () => {
    expect(ignored(["secrets.json"], "config/nested/secrets.json")).toBe(true);
  });

  it("supports single-star globs scoped to one path segment", () => {
    expect(ignored(["*.generated.ts"], "a.generated.ts")).toBe(true);
    expect(ignored(["src/*.ts"], "src/a.ts")).toBe(true);
    expect(ignored(["src/*.ts"], "src/nested/a.ts")).toBe(false);
  });

  it("supports double-star globs across segments", () => {
    expect(ignored(["**/*.spec.ts"], "src/deep/a.spec.ts")).toBe(true);
  });

  it("treats glob metacharacters as literals when escaped by the pattern compiler", () => {
    // A pattern from an untrusted repo must not be able to inject regex syntax.
    expect(ignored(["a+b"], "a+b")).toBe(true);
    expect(ignored(["a+b"], "aab")).toBe(false);
  });

  it("normalizes Windows-style separators", () => {
    expect(isPathIgnored(`${root}\\vendor\\lib.js`, root, { ignorePaths: ["vendor"] })).toBe(true);
  });
});

describe("filterIgnoredFindings", () => {
  it("returns everything when no rules are suppressed", () => {
    const findings = [makeFinding()];
    expect(filterIgnoredFindings(findings, {})).toHaveLength(1);
  });

  it("removes suppressed rule ids", () => {
    const findings = [makeFinding({ ruleId: "A" }), makeFinding({ ruleId: "B" })];
    expect(filterIgnoredFindings(findings, { ignoreRules: ["A"] }).map((f) => f.ruleId)).toEqual(["B"]);
  });

  it("does not mutate the input array", () => {
    const findings = [makeFinding({ ruleId: "A" })];
    filterIgnoredFindings(findings, { ignoreRules: ["A"] });
    expect(findings).toHaveLength(1);
  });
});

describe("filterByMinimumSeverity", () => {
  const findings = [
    makeFinding({ severity: "critical" }),
    makeFinding({ severity: "medium" }),
    makeFinding({ severity: "info" }),
  ];

  it("returns everything when no threshold is set", () => {
    expect(filterByMinimumSeverity(findings, {})).toHaveLength(3);
  });

  it("keeps only findings at or above the threshold", () => {
    expect(filterByMinimumSeverity(findings, { minimumSeverity: "medium" }).map((f) => f.severity))
      .toEqual(["critical", "medium"]);
  });
});

describe("isOfflineMode", () => {
  it("is off by default", () => {
    expect(isOfflineMode({})).toBe(false);
  });

  it("honours the config flag", () => {
    expect(isOfflineMode({ offline: true })).toBe(true);
  });

  it("honours the environment variable", () => {
    process.env.SENTINEL_OFFLINE = "1";
    expect(isOfflineMode({})).toBe(true);
    process.env.SENTINEL_OFFLINE = "true";
    expect(isOfflineMode({})).toBe(true);
  });
});
