import { describe, expect, it } from "vitest";
import { scanCode } from "../src/scanner/pattern-engine.js";
import { detectSecrets } from "../src/scanner/secret-detector.js";
import { dedupeFindings } from "../src/core/findings.js";
import { getAllPatterns } from "../src/patterns/index.js";

/**
 * Defects found by a parallel audit, each reproduced before it was fixed.
 * The common thread is a scanner that looked correct while quietly reporting
 * less than it found.
 */

const AWS = "AKIAIOSFODNN7EXAMPLE";
const GH = "ghp_1234567890abcdefghijklmnopqrstuvwxyzAB";

describe("two credentials on one line", () => {
  const line = `const c = { a: "${AWS}", b: "${GH}" };`;
  const findings = () => dedupeFindings(detectSecrets(line, "/proj/k.js"));

  it("reports both, rather than collapsing them into one", () => {
    // Both are CWE-798 at the same path and line, so the cross-engine overlap
    // key merged them and the second credential was never reported.
    const ids = findings().map((f) => f.ruleId);

    expect(ids).toContain("AWS_ACCESS_KEY_ID");
    expect(ids).toContain("GITHUB_TOKEN");
  });

  it("redacts both in every finding, not just the one the rule matched", () => {
    // lineContent is the whole line, so a finding that masked only its own
    // value published the credential beside it into SARIF.
    for (const finding of findings()) {
      expect(finding.lineContent, `${finding.ruleId} leaked a neighbour`).not.toContain(AWS);
      expect(finding.lineContent, `${finding.ruleId} leaked a neighbour`).not.toContain(GH);
    }
  });
});

describe("cross-engine duplicates still collapse", () => {
  it("keeps one finding when two rules describe the same weakness", () => {
    const findings = dedupeFindings([
      { ruleId: "WEAK_HASH_MD5", severity: "high", category: "crypto", cweId: "CWE-328",
        message: "m", filePath: "/p/a.js", line: 1, lineContent: "x", remediation: "r",
        source: "compatibility" },
      { ruleId: "sentinel.core.javascript.crypto.md5", severity: "high", category: "crypto",
        cweId: "CWE-328", message: "m", filePath: "/p/a.js", line: 1, lineContent: "x",
        remediation: "r", source: "semgrep" },
    ]);

    expect(findings).toHaveLength(1);
  });
});

describe("file context is decided by path segments, not substrings", () => {
  const severityAt = (relativePath: string) =>
    scanCode("eval(req.body.expression);", `/proj/${relativePath}`, undefined, "/proj")
      .findings[0]?.severity;

  it("does not treat production directories as test code", () => {
    // "mockingbird" and "fixture-loader" begin with the words the check looked
    // for, so a critical in them was graded low, under the default CI
    // threshold, and the build passed.
    expect(severityAt("src/mockingbird/m.js")).toBe("critical");
    expect(severityAt("src/fixture-loader/m.js")).toBe("critical");
    expect(severityAt("src/real/m.js")).toBe("critical");
  });

  it("does not apply Sentinel's own layout to other projects", () => {
    // "patterns" is an ordinary directory name, and treating it as a rule
    // catalogue silently downgraded every finding inside it.
    expect(severityAt("src/patterns/m.js")).toBe("critical");
  });

  it("still downgrades genuine test and mock directories", () => {
    for (const path of ["test/a.js", "tests/a.js", "__tests__/a.js", "spec/a.js",
                        "src/mocks/a.js", "src/fixtures/a.js", "src/a.test.js"]) {
      expect(severityAt(path), path).toBe("low");
    }
  });
});

describe("configuration that arrives with the scanned tree", () => {
  it("survives a UTF-8 BOM", async () => {
    // PowerShell's Set-Content writes one by default and JSON.parse rejects it,
    // so a Windows user's entire policy silently reverted to defaults.
    const fs = await import("node:fs");
    const os = await import("node:os");
    const path = await import("node:path");
    const { loadSentinelConfig } = await import("../src/scanner/config.js");

    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sentinel-bom-"));
    try {
      fs.writeFileSync(
        path.join(dir, "sentinel.config.json"),
        "\uFEFF" + JSON.stringify({ minimumSeverity: "low", ignoreRules: ["EVAL_USAGE"] }),
        "utf-8"
      );

      const config = loadSentinelConfig(dir);
      expect(config.minimumSeverity).toBe("low");
      expect(config.ignoreRules).toContain("EVAL_USAGE");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("reads a plain config, which a stray return would have silenced", async () => {
    // A comment placed between `return` and its value made every config parse
    // as undefined. Typecheck, build, benchmark and the self-scan all still
    // passed, because a scan with no policy still scans.
    const fs = await import("node:fs");
    const os = await import("node:os");
    const path = await import("node:path");
    const { loadSentinelConfig } = await import("../src/scanner/config.js");

    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sentinel-cfg-"));
    try {
      fs.writeFileSync(
        path.join(dir, "sentinel.config.json"),
        JSON.stringify({ minimumSeverity: "medium" }),
        "utf-8"
      );
      expect(loadSentinelConfig(dir).minimumSeverity).toBe("medium");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("clamps values a scanned repository could otherwise choose", async () => {
    // semgrep.timeoutMs is passed to execFile's timeout, so an unbounded value
    // removes the only deadline on the analyzer.
    const fs = await import("node:fs");
    const os = await import("node:os");
    const path = await import("node:path");
    const { loadSentinelConfig } = await import("../src/scanner/config.js");

    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sentinel-clamp-"));
    try {
      fs.writeFileSync(
        path.join(dir, "sentinel.config.json"),
        JSON.stringify({ maxFiles: 1e12, semgrep: { timeoutMs: 2 ** 40 } }),
        "utf-8"
      );

      const config = loadSentinelConfig(dir);
      expect(config.maxFiles).toBeLessThanOrEqual(1_000_000);
      expect(config.semgrep?.timeoutMs).toBeLessThanOrEqual(30 * 60_000);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("long credentials and risk agreement", () => {
  it("detects a high-entropy secret longer than 200 characters", async () => {
    // The candidate pattern capped values at 200 characters, so the entropy
    // check was blind to exactly the credentials that are long: JWTs, base64
    // key blobs, Azure connection strings. 199 was reported, 201 was not.
    const { detectSecrets } = await import("../src/scanner/secret-detector.js");

    let value = "";
    let seed = 7;
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    while (value.length < 400) {
      seed = (seed * 1103515245 + 12345) % 2147483648;
      value += alphabet[seed % alphabet.length];
    }

    const findings = detectSecrets(`const t = "${value}";\n`, "/proj/a.js");
    expect(findings.map((f) => f.ruleId)).toContain("HIGH_ENTROPY_SECRET");
  });

  it("does not call long ordinary prose a secret", async () => {
    const { detectSecrets } = await import("../src/scanner/secret-detector.js");
    const prose = "the quick brown fox jumps over the lazy dog ".repeat(8);

    const findings = detectSecrets(`const msg = "${prose}";\n`, "/proj/a.js");
    expect(findings.map((f) => f.ruleId)).not.toContain("HIGH_ENTROPY_SECRET");
  });

  it("grades risk the same way in the dashboard as in the report", async () => {
    // Two independent formulas meant one scan read CRITICAL in the CLI report
    // and MEDIUM in the dashboard.
    const { generateHTML } = await import("../src/dashboard/generate-report.js");
    const { renderMarkdownReport } = await import("../src/reporting/markdown-report.js");

    const finding = {
      ruleId: "WEAK_HASH_MD5", severity: "high" as const, category: "crypto",
      cweId: "CWE-328", message: "m", filePath: "/p/a.js", line: 1,
      lineContent: "x", remediation: "r",
    };

    const markdown = renderMarkdownReport({ projectName: "p", findings: [finding] });
    const html = generateHTML({
      projectName: "p", projectPath: "/p", scanDate: new Date(0).toISOString(),
      filesScanned: 1, filesWithIssues: 1, totalFindings: 1, taintFlows: 0,
      fixesAvailable: 0, riskLevel: "HIGH",
      summary: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
      categoryBreakdown: { crypto: 1 }, languageBreakdown: { javascript: 1 },
      topFiles: [{ file: "a.js", findings: 1, critical: 0, high: 1 }],
      allFindings: [{ file: "a.js", findings: [finding] }], rawResults: [],
    });

    expect(markdown).toMatch(/Risk level\s*\|\s*HIGH/);
    expect(html).toContain("HIGH");
  });
});

describe("rules that were dead or half-covered", () => {
  const ids = (code: string, file = "/proj/a.js") =>
    scanCode(code, file, undefined, "/proj").findings.map((f) => f.ruleId);

  it("detects ECB mode at the call, not only in a bare string", () => {
    // Every alternative used to begin inside the string literal, and a
    // literal-scope match is discarded unless it starts in executable code, so
    // the rule never fired on the form that actually appears in source.
    expect(ids('const c = crypto.createCipheriv("aes-256-ecb", key, iv);')).toContain("ECB_MODE");
  });

  it("leaves an authenticated cipher alone", () => {
    expect(ids('const c = crypto.createCipheriv("aes-256-gcm", key, iv);')).not.toContain("ECB_MODE");
  });

  it("treats innerHTML += as the same sink as innerHTML =", () => {
    expect(ids("el.innerHTML += userInput;")).toContain("XSS_INNERHTML");
    expect(ids("el.outerHTML += userInput;")).toContain("XSS_OUTERHTML");
  });

  it("still accepts a sanitised += assignment", () => {
    expect(ids("el.innerHTML += DOMPurify.sanitize(html);")).not.toContain("XSS_INNERHTML");
  });

  it("reports USER 0, which is root written to dodge the check", () => {
    expect(ids("FROM node:20\nUSER 0\n", "/proj/Dockerfile"))
      .toContain("IAC_DOCKERFILE_EXPLICIT_ROOT_USER");
    expect(ids("FROM node:20\nUSER node\n", "/proj/Dockerfile"))
      .not.toContain("IAC_DOCKERFILE_EXPLICIT_ROOT_USER");
  });

  it("does not call js-yaml's load unsafe", () => {
    // js-yaml v4 removed safeLoad and made load() the safe entry point, so
    // matching it across every language flagged correct JavaScript. Python is
    // covered by PY_YAML_LOAD, where the Loader argument decides safety.
    expect(ids("const d = yaml.load(s, { schema: SAFE_SCHEMA });")).not.toContain("UNSERIALIZE");
    expect(ids("const o = unserialize(payload);")).toContain("UNSERIALIZE");
  });
});

describe("exec is two different functions", () => {
  const ids = (code: string, file = "/proj/a.js") =>
    scanCode(code, file, undefined, "/proj").findings.map((f) => f.ruleId);

  it("does not report RegExp.prototype.exec as command injection", () => {
    // Found by running this scanner over its own source: a regex matched
    // against a template literal shares the name `exec` with child_process,
    // and was reported as CRITICAL command injection. A false positive at that
    // severity blocks CI, which is the most expensive kind to ship.
    expect(ids("const m = /Python (\\d+)\\./.exec(`${stdout}${stderr}`);"))
      .not.toContain("COMMAND_INJECTION_EXEC");
    expect(ids("const m = /x/g.exec(`${value}`);")).not.toContain("COMMAND_INJECTION_EXEC");
  });

  it("still reports the real thing", () => {
    expect(ids("child_process.exec(`ls ${req.query.dir}`);")).toContain("COMMAND_INJECTION_EXEC");
    expect(ids('exec("ls " + req.query.dir);')).toContain("COMMAND_INJECTION_EXEC");
    expect(ids('execSync("ls " + userInput);')).toContain("COMMAND_INJECTION_EXEC");
  });
});

describe("rules that duplicate each other must not drift apart", () => {
  it("keeps the two exec rules on the same pattern", () => {
    // COMMAND_INJECTION_EXEC and CHILD_PROCESS_EXEC report the same code under
    // different categories from different files. They had already drifted: the
    // RegExp.prototype.exec exclusion was added to one, so the critical false
    // positive it fixed carried on being reported by the other at high
    // severity, and the self-scan still failed. Whatever else changes, these
    // two have to change together.
    const patterns = getAllPatterns();
    const first = patterns.find((p) => p.id === "COMMAND_INJECTION_EXEC");
    const second = patterns.find((p) => p.id === "CHILD_PROCESS_EXEC");
    expect(first).toBeDefined();
    expect(second).toBeDefined();
    expect(second!.regex.source).toBe(first!.regex.source);
    expect(second!.regex.flags).toBe(first!.regex.flags);
  });
});

describe("benign code that structurally resembles a vulnerability", () => {
  // A false positive costs more than a miss here: it fails a build, and the
  // fix a reader reaches for is to switch the scanner off. Every line below is
  // correct code that shares its shape with something the rules look for.
  const BENIGN = [
    "const m = /Python (\\d+)\\./.exec(`${stdout}${stderr}`);",
    "const m = /x/g.exec(`${value}`);",
    "logger.info(`user ${id} logged in`);",
    "const url = new URL(`${base}/api`);",
    "throw new Error(`bad input: ${value}`);",
    'const q = db.query("SELECT * FROM t WHERE id = ?", [id]);',
    "const p = path.join(root, path.basename(name));",
    'const c = crypto.createCipheriv("aes-256-gcm", key, iv);',
    "res.send(escapeHtml(userInput));",
    "el.textContent = userInput;",
    "const token = process.env.API_TOKEN;",
    "const parsed = JSON.parse(body);",
  ];

  for (const line of BENIGN) {
    it(`stays quiet on: ${line.slice(0, 52)}`, () => {
      const findings = scanCode(line, "/proj/a.js", undefined, "/proj").findings;
      expect(findings.map((f) => `${f.ruleId}/${f.severity}`)).toEqual([]);
    });
  }
});
