import * as path from "node:path";
import { describe, expect, it } from "vitest";
import { normalizeSemgrepRuleId, parseSemgrepOutput, readStringMetadataForTest, resolveRegistryRulesets, resolveTargetBatches } from "../src/scanner/semgrep.js";

/**
 * Semgrep's own reporting is the only evidence of what it covered.
 *
 * Trusting the exit status alone lets a run that analysed nothing, because the
 * built-in ignore list excluded the target directory, pass as a full-coverage
 * scan. These tests pin the two mechanisms that make coverage observable:
 * parsing `paths.scanned`, and naming targets explicitly.
 */

describe("parseSemgrepOutput", () => {
  it("returns null for empty output", () => {
    expect(parseSemgrepOutput("")).toBeNull();
    expect(parseSemgrepOutput("   \n ")).toBeNull();
  });

  it("returns null when the output is not Semgrep JSON", () => {
    expect(parseSemgrepOutput("command not found")).toBeNull();
    expect(parseSemgrepOutput('{"unrelated": true}')).toBeNull();
  });

  it("parses results and the scanned-path list", () => {
    const parsed = parseSemgrepOutput(JSON.stringify({
      results: [{ check_id: "rule", path: "a.js", start: { line: 3 } }],
      paths: { scanned: ["a.js", "b.js"] },
    }));

    expect(parsed?.results).toHaveLength(1);
    expect(parsed?.paths?.scanned).toEqual(["a.js", "b.js"]);
  });

  it("recovers when a diagnostic line is printed before the JSON", () => {
    const parsed = parseSemgrepOutput('A new version is available\n{"results":[],"paths":{"scanned":["a.js"]}}');
    expect(parsed?.paths?.scanned).toEqual(["a.js"]);
  });

  it("treats an empty scanned list as zero coverage rather than as absent data", () => {
    const parsed = parseSemgrepOutput('{"results":[],"paths":{"scanned":[]}}');
    expect(parsed?.paths?.scanned).toEqual([]);
  });
});

describe("resolveTargetBatches", () => {
  const cwd = path.resolve("/project");

  it("falls back to the directory target when no explicit list is given", () => {
    expect(resolveTargetBatches(cwd, cwd, false, undefined)).toEqual([["."]]);
  });

  it("falls back to the file name when the root is a single file", () => {
    const file = path.join(cwd, "app.js");
    expect(resolveTargetBatches(path.dirname(file), file, true, undefined)).toEqual([["app.js"]]);
  });

  it("returns no batches when the caller supplies an empty list", () => {
    // An empty list means "nothing is in scope", which must not silently become
    // "scan the whole directory".
    expect(resolveTargetBatches(cwd, cwd, false, [])).toEqual([]);
  });

  it("relativises targets against the working directory", () => {
    const batches = resolveTargetBatches(cwd, cwd, false, [
      path.join(cwd, "src", "app.js"),
      path.join(cwd, "test", "fixtures", "vulnerable.js"),
    ]);

    expect(batches).toHaveLength(1);
    expect(batches[0]).toEqual([
      path.join("src", "app.js"),
      path.join("test", "fixtures", "vulnerable.js"),
    ]);
  });

  it("drops targets outside the scan root", () => {
    const batches = resolveTargetBatches(cwd, cwd, false, [
      path.join(cwd, "src", "app.js"),
      path.resolve("/etc/passwd"),
    ]);

    expect(batches).toEqual([[path.join("src", "app.js")]]);
  });

  it("splits long target lists so the command line cannot exceed the OS limit", () => {
    const targets = Array.from({ length: 2_000 }, (_, i) => path.join(cwd, `file-${i}.js`));
    const batches = resolveTargetBatches(cwd, cwd, false, targets);

    expect(batches.length).toBeGreaterThan(1);
    expect(batches.flat()).toHaveLength(2_000);
    for (const batch of batches) {
      expect(batch.length).toBeLessThanOrEqual(800);
      expect(Buffer.byteLength(batch.join(" "))).toBeLessThan(100_000);
    }
  });
});

describe("resolveRegistryRulesets", () => {
  it("returns nothing in offline mode", () => {
    expect(resolveRegistryRulesets({ offline: true, registryRulesets: ["p/javascript"] })).toEqual([]);
  });

  it("accepts well-formed registry identifiers", () => {
    expect(resolveRegistryRulesets({ registryRulesets: ["p/javascript", "r/python.lang.security"] }))
      .toEqual(["p/javascript", "r/python.lang.security"]);
  });

  it("rejects anything that is not a registry identifier", () => {
    // Configuration must not be able to redirect rule loading at a URL or a
    // local path chosen by whoever wrote the config file.
    expect(resolveRegistryRulesets({
      registryRulesets: ["https://evil.example/rules.yml", "../../etc/rules.yml", "javascript"],
    })).toEqual([]);
  });
});

describe("normalizeSemgrepRuleId", () => {
  // Semgrep prefixes a rule id with the path of the config file that defined
  // it, so a report or SARIF upload carried the scanning machine's directory
  // layout and usually a username.

  it("strips the config file path from a rule id", () => {
    expect(
      normalizeSemgrepRuleId("Users.someone.projects.app.rules.sentinel.core.javascript.dom-xss.innerhtml")
    ).toBe("sentinel.core.javascript.dom-xss.innerhtml");
  });

  it("removes the username along with the rest of the path", () => {
    const normalized = normalizeSemgrepRuleId("home.alice.work.rules.sentinel.iac.kubernetes.host-pid");
    expect(normalized).not.toContain("alice");
    expect(normalized).toBe("sentinel.iac.kubernetes.host-pid");
  });

  it("leaves a registry pack id alone", () => {
    expect(normalizeSemgrepRuleId("javascript.lang.security.audit.code-string-concat"))
      .toBe("javascript.lang.security.audit.code-string-concat");
  });

  it("leaves an already-clean sentinel id alone", () => {
    expect(normalizeSemgrepRuleId("sentinel.core.python.crypto.md5"))
      .toBe("sentinel.core.python.crypto.md5");
  });
});

describe("rule metadata is actually read", () => {
  // Sentinel's rules carry category, severity and confidence under a
  // `sentinel:` block. A flat lookup never reached it, so every Semgrep
  // finding fell back to Semgrep's own "category: security" (not a Sentinel
  // category, so "miscellaneous") and its coarse ERROR/WARNING severity. The
  // whole block was inert.

  it("reads a nested value through a dotted path", () => {
    const metadata = { category: "security", sentinel: { category: "injection", severity: "critical" } };

    expect(readStringMetadataForTest(metadata, "sentinel.category")).toBe("injection");
    expect(readStringMetadataForTest(metadata, "sentinel.severity")).toBe("critical");
  });

  it("still reads a top-level value", () => {
    expect(readStringMetadataForTest({ cwe: "CWE-89" }, "cwe")).toBe("CWE-89");
  });

  it("returns undefined for a path that does not exist", () => {
    expect(readStringMetadataForTest({ sentinel: { category: "xss" } }, "sentinel.missing")).toBeUndefined();
    expect(readStringMetadataForTest({}, "sentinel.category")).toBeUndefined();
  });

  it("returns undefined rather than throwing when the path runs through a non-object", () => {
    expect(readStringMetadataForTest({ sentinel: "not-an-object" }, "sentinel.category")).toBeUndefined();
    expect(readStringMetadataForTest({ sentinel: null }, "sentinel.category")).toBeUndefined();
  });

  it("ignores a non-string leaf", () => {
    expect(readStringMetadataForTest({ sentinel: { severity: 3 } }, "sentinel.severity")).toBeUndefined();
  });
});

describe("targets can never be read as flags", () => {
  // A scanned repository is untrusted. A file named "--config=evil.yml" was
  // appended to Semgrep's argv as a target and read as an option instead,
  // which let a hostile repository load its own rules, redirect output over an
  // arbitrary file, or switch the engine off and get only a warning.

  it("prefixes a path that begins with a dash", () => {
    const [batch] = resolveTargetBatches("/repo", "/repo", false, [
      "/repo/app.js",
      "/repo/--config=evil.yml",
    ]);

    expect(batch).toContain("app.js");
    expect(batch).not.toContain("--config=evil.yml");
    expect(batch.some((entry) => entry.endsWith("--config=evil.yml"))).toBe(true);
    for (const entry of batch) expect(entry.startsWith("-")).toBe(false);
  });

  it("leaves an ordinary path untouched", () => {
    const [batch] = resolveTargetBatches("/repo", "/repo", false, [
      "/repo/src/app.js",
      "/repo/lib/util.ts",
    ]);

    expect(batch).toEqual(["src/app.js", "lib/util.ts"]);
  });

  it("keeps a dash-leading name out of flag position at every depth", () => {
    const [batch] = resolveTargetBatches("/repo", "/repo", false, [
      "/repo/nested/-rf",
      "/repo/-o",
    ]);

    for (const entry of batch) expect(entry.startsWith("-")).toBe(false);
  });
});
