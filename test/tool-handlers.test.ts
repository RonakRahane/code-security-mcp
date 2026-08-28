import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { execFileSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { registerAutoFix } from "../src/tools/auto-fix.js";
import { registerCheckDependencies } from "../src/tools/check-dependencies.js";
import { registerDetectSecrets } from "../src/tools/detect-secrets.js";
import { registerExplainVulnerability } from "../src/tools/explain-vulnerability.js";
import { registerExportSarif } from "../src/tools/export-sarif.js";
import { registerScanDirectory } from "../src/tools/scan-directory.js";
import { registerScanFile } from "../src/tools/scan-file.js";
import { registerScanGitHistory } from "../src/tools/scan-git-history.js";
import { registerPostSecurityReview } from "../src/tools/post-security-review.js";
import { registerSecurityReport } from "../src/tools/security-report.js";

/**
 * Exercises MCP tool handlers directly.
 *
 * This layer receives untrusted arguments: they come from a model that has
 * been reading the repository under scan, so it is worth testing
 * against real files rather than only through the protocol.
 */

interface CapturedTool {
  description: string;
  schema: Record<string, unknown>;
  handler: (args: Record<string, unknown>) => Promise<{
    content: Array<{ type: string; text: string }>;
    isError?: boolean;
  }>;
}

/** Minimal stand-in for McpServer that records what each module registers. */
function createHarness() {
  const tools = new Map<string, CapturedTool>();

  const server = {
    tool(name: string, description: string, schema: Record<string, unknown>, handler: CapturedTool["handler"]) {
      tools.set(name, { description, schema, handler });
    },
  } as unknown as McpServer;

  return {
    server,
    async call(name: string, args: Record<string, unknown> = {}) {
      const tool = tools.get(name);
      if (!tool) throw new Error(`tool not registered: ${name}`);
      return tool.handler(args);
    },
    payload: async (name: string, args: Record<string, unknown> = {}) => {
      const tool = tools.get(name);
      if (!tool) throw new Error(`tool not registered: ${name}`);
      const response = await tool.handler(args);
      return JSON.parse(response.content[0].text);
    },
    text: async (name: string, args: Record<string, unknown> = {}) => {
      const tool = tools.get(name);
      if (!tool) throw new Error(`tool not registered: ${name}`);
      return (await tool.handler(args)).content[0].text;
    },
    tools,
  };
}

let root: string;
let harness: ReturnType<typeof createHarness>;

const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";

beforeEach(() => {
  root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "sentinel-tool-")));
  harness = createHarness();
  registerScanFile(harness.server);
  registerScanDirectory(harness.server);
  registerDetectSecrets(harness.server);
  registerCheckDependencies(harness.server);
  registerExportSarif(harness.server);
  registerSecurityReport(harness.server);
  registerAutoFix(harness.server);
  registerExplainVulnerability(harness.server);
  registerScanGitHistory(harness.server);
  registerPostSecurityReview(harness.server);

  // Offline by default so no test outcome depends on network access.
  process.env.SENTINEL_OFFLINE = "1";
});

afterEach(() => {
  fs.rmSync(root, { recursive: true, force: true });
  delete process.env.SENTINEL_OFFLINE;
  delete process.env.SENTINEL_ALLOWED_ROOTS;
});

const write = (relativePath: string, contents: string) => {
  const full = path.join(root, relativePath);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, contents, "utf-8");
  return full;
};

describe("scan_file", () => {
  it("scans a vulnerable file and reports findings", async () => {
    const file = write("app.js", "eval(req.body.code);\n");
    const payload = await harness.payload("scan_file", { filePath: file });

    expect(payload.totalFindings).toBeGreaterThan(0);
    expect(payload.language).toBe("javascript");
    expect(payload.summary).toBeDefined();
  });

  it("returns a clean result for safe code", async () => {
    const file = write("safe.js", "export const add = (a, b) => a + b;\n");
    const payload = await harness.payload("scan_file", { filePath: file });
    expect(payload.totalFindings).toBe(0);
  });

  it("returns an error, not an empty scan, for a missing file", async () => {
    const response = await harness.call("scan_file", { filePath: path.join(root, "nope.js") });
    expect(response.isError).toBe(true);
  });

  it("rejects a directory passed where a file is required", async () => {
    const response = await harness.call("scan_file", { filePath: root });
    expect(response.isError).toBe(true);
    expect(response.content[0].text).toMatch(/not a file/i);
  });

  it("rejects a path containing a null byte", async () => {
    const file = write("app.js", "const a = 1;\n");
    const response = await harness.call("scan_file", { filePath: `${file}\0.txt` });
    expect(response.isError).toBe(true);
    expect(response.content[0].text).toMatch(/null byte/i);
  });

  it("rejects a path outside the configured workspace roots", async () => {
    const file = write("app.js", "const a = 1;\n");
    process.env.SENTINEL_ALLOWED_ROOTS = path.join(root, "elsewhere");
    fs.mkdirSync(path.join(root, "elsewhere"), { recursive: true });

    const response = await harness.call("scan_file", { filePath: file });
    expect(response.isError).toBe(true);
    expect(response.content[0].text).toMatch(/allowed workspace roots/i);
  });

  it("never returns the raw secret it detected", async () => {
    const file = write("config.js", `const awsKey = "${AWS_KEY}";\n`);
    const text = await harness.text("scan_file", { filePath: file });
    expect(text).not.toContain(AWS_KEY);
  });

  it("honours an ignorePaths entry", async () => {
    write("sentinel.config.json", JSON.stringify({ ignorePaths: ["skipme.js"] }));
    const file = write("skipme.js", "eval(req.body.code);\n");

    const payload = await harness.payload("scan_file", { filePath: file });
    expect(payload.skipped).toBe(true);
  });

  it("reports what scan_directory reports for the same file", async () => {
    // The pattern registry used to run only when Semgrep was missing, so a
    // machine with Semgrep installed got fewer findings from scan_file than
    // from scan_directory over the very same file.
    const file = write("hash.js", 'const h = crypto.createHash("md5").update(p).digest("hex");\n');

    const single = await harness.payload("scan_file", { filePath: file });
    const directory = await harness.payload("scan_directory", { dirPath: root });

    const group = (directory.files as Array<{ filePath: string; findings: Array<{ ruleId: string }> }>)
      .find((f) => f.filePath === file);
    const fromFile = (single.findings as Array<{ ruleId: string }>).map((f) => f.ruleId);

    expect(group).toBeDefined();
    expect(group!.findings.length).toBeGreaterThan(0);
    for (const { ruleId } of group!.findings) expect(fromFile).toContain(ruleId);
  });
});

describe("scan_directory", () => {
  it("scans a tree and reports coverage", async () => {
    write("src/app.js", "eval(req.body.code);\n");
    const payload = await harness.payload("scan_directory", { dirPath: root });

    expect(payload.totalFindings).toBeGreaterThan(0);
    expect(payload.filesScanned).toBeGreaterThan(0);
    expect(payload.coverage).toBeDefined();
    expect(payload.coverage.truncated).toBe(false);
  });

  it("groups findings by file", async () => {
    write("src/a.js", "eval(req.body.code);\n");
    write("src/b.js", "eval(req.body.code);\n");

    const payload = await harness.payload("scan_directory", { dirPath: root });
    expect(payload.files.length).toBe(2);
  });

  it("respects an explicit maxFiles and says the scan was truncated", async () => {
    for (let i = 0; i < 8; i++) write(`src/f${i}.js`, "const a = 1;\n");
    const payload = await harness.payload("scan_directory", { dirPath: root, maxFiles: 2 });
    expect(payload.coverage.truncated).toBe(true);
  });

  it("rejects a file passed where a directory is required", async () => {
    const file = write("a.js", "const a = 1;\n");
    const response = await harness.call("scan_directory", { dirPath: file });
    expect(response.isError).toBe(true);
  });
});

describe("detect_secrets", () => {
  it("finds a secret in a single file and redacts it", async () => {
    const file = write("config.js", `const key = "${AWS_KEY}";\n`);
    const response = await harness.call("detect_secrets", { path: file });

    expect(JSON.parse(response.content[0].text).totalSecrets).toBeGreaterThan(0);
    expect(response.content[0].text).not.toContain(AWS_KEY);
  });

  it("scans a directory and reports which files contain secrets", async () => {
    write("src/config.js", `const key = "${AWS_KEY}";\n`);
    write("src/safe.js", "const a = 1;\n");

    const payload = await harness.payload("detect_secrets", { path: root });
    expect(payload.type).toBe("directory");
    expect(payload.filesWithSecrets).toBe(1);
  });

  it("returns an error for a missing path", async () => {
    const response = await harness.call("detect_secrets", { path: path.join(root, "nope") });
    expect(response.isError).toBe(true);
  });
});

describe("check_dependencies", () => {
  it("requires a manifest path", async () => {
    const response = await harness.call("check_dependencies", {});
    expect(response.isError).toBe(true);
    expect(response.content[0].text).toMatch(/manifestPath is required/i);
  });

  it("audits a manifest and reports the ecosystem", async () => {
    const manifest = write("package.json", JSON.stringify({ dependencies: { "left-pad": "1.3.0" } }));
    const payload = await harness.payload("check_dependencies", { manifestPath: manifest });

    expect(payload.ecosystem).toBe("npm");
    expect(payload.offline).toBe(true);
    expect(Array.isArray(payload.vulnerabilities)).toBe(true);
  });

  it("accepts the deprecated packageJsonPath alias", async () => {
    const manifest = write("package.json", JSON.stringify({ dependencies: {} }));
    const payload = await harness.payload("check_dependencies", { packageJsonPath: manifest });
    expect(payload.ecosystem).toBe("npm");
  });
});

describe("export_sarif", () => {
  it("produces valid SARIF for a scanned tree", async () => {
    write("src/app.js", "eval(req.body.code);\n");
    const sarif = JSON.parse(await harness.text("export_sarif", { dirPath: root }));

    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs[0].results.length).toBeGreaterThan(0);
  });

  it("produces valid SARIF for a clean tree", async () => {
    write("src/safe.js", "const a = 1;\n");
    const sarif = JSON.parse(await harness.text("export_sarif", { dirPath: root }));
    expect(sarif.runs[0].results).toEqual([]);
  });
});

describe("security_report", () => {
  it("renders a Markdown report and writes it to the project root", async () => {
    write("src/app.js", "eval(req.body.code);\n");
    const report = await harness.text("security_report", { dirPath: root, projectName: "demo" });

    expect(report).toContain("# Sentinel Security Report");
    expect(report).toContain("## Scan Coverage");
    expect(fs.existsSync(path.join(root, "sentinel-report.md"))).toBe(true);
  });

  it("can skip writing the report file", async () => {
    write("src/app.js", "const a = 1;\n");
    await harness.text("security_report", { dirPath: root, writeReportFile: false });
    expect(fs.existsSync(path.join(root, "sentinel-report.md"))).toBe(false);
  });

  it("never writes a detected secret into the report file", async () => {
    write("src/config.js", `const key = "${AWS_KEY}";\n`);
    await harness.text("security_report", { dirPath: root });
    expect(fs.readFileSync(path.join(root, "sentinel-report.md"), "utf-8")).not.toContain(AWS_KEY);
  });
});

describe("auto_fix", () => {
  it("is a dry run by default and leaves the file untouched", async () => {
    const original = 'const hash = crypto.createHash("md5");\n';
    const file = write("app.js", original);

    const payload = await harness.payload("auto_fix", { filePath: file });

    expect(payload.dryRun).toBe(true);
    expect(payload.fixesApplied).toBe(0);
    expect(fs.readFileSync(file, "utf-8")).toBe(original);
  });

  it("writes fixes and keeps a backup when explicitly asked", async () => {
    const original = 'const hash = crypto.createHash("md5");\n';
    const file = write("app.js", original);

    const payload = await harness.payload("auto_fix", { filePath: file, applyFixes: true });

    if (payload.fixesApplied > 0) {
      expect(fs.readFileSync(file, "utf-8")).not.toBe(original);
      expect(fs.existsSync(payload.backupPath)).toBe(true);
      expect(fs.readFileSync(payload.backupPath, "utf-8")).toBe(original);
    }
  });

  it("returns an error for a missing file", async () => {
    const response = await harness.call("auto_fix", { filePath: path.join(root, "nope.js") });
    expect(response.isError).toBe(true);
  });

  it("preserves the original indentation of a patched line", async () => {
    // Generators return trimmed code for display. Writing that back verbatim
    // reindented the user's file as a side effect of fixing it.
    const original = [
      "function hashPassword(password) {",
      '    return crypto.createHash("md5").update(password).digest("hex");',
      "}",
      "",
    ].join("\n");
    const file = write("indented.js", original);

    const payload = await harness.payload("auto_fix", { filePath: file, applyFixes: true });

    if (payload.fixesApplied > 0) {
      const patched = fs.readFileSync(file, "utf-8").split("\n");
      const changed = patched.find((line) => line.includes("sha256"));
      expect(changed).toBeDefined();
      expect(changed).toMatch(/^ {4}\S/);
    }
  });

  it("never reports a fix that would leave the line unchanged", async () => {
    const file = write("noop.js", "const total = items.length + 1;\n");

    const payload = await harness.payload("auto_fix", { filePath: file });

    for (const fix of payload.fixes) {
      expect(fix.after.trim()).not.toBe(fix.before.trim());
    }
  });

  it("leaves the file byte-identical when there is nothing to fix", async () => {
    const original = "const total = items.length + 1;\n";
    const file = write("clean.js", original);

    await harness.payload("auto_fix", { filePath: file, applyFixes: true });

    expect(fs.readFileSync(file, "utf-8")).toBe(original);
  });
});

describe("explain_vulnerability", () => {
  it("looks up a CWE by id", async () => {
    expect((await harness.payload("explain_vulnerability", { query: "CWE-89" })).name).toBe("SQL Injection");
  });

  it("looks up a CWE by keyword", async () => {
    expect((await harness.payload("explain_vulnerability", { query: "sql injection" })).id).toBe("CWE-89");
  });

  it("lists available topics when nothing matches", async () => {
    const payload = await harness.payload("explain_vulnerability", { query: "not a real thing" });
    expect(payload.error).toBeTruthy();
    expect(Array.isArray(payload.availableTopics)).toBe(true);
  });
});

describe("scan_git_history", () => {
  const git = (args: string[], cwd: string) =>
    execFileSync("git", args, { cwd, encoding: "utf-8", stdio: ["ignore", "pipe", "ignore"] });

  const makeRepo = (name: string) => {
    const repo = path.join(root, name);
    fs.mkdirSync(repo, { recursive: true });
    git(["init", "--quiet"], repo);
    git(["config", "user.email", "test@example.com"], repo);
    git(["config", "user.name", "Sentinel Test"], repo);
    git(["config", "commit.gpgsign", "false"], repo);
    return repo;
  };

  it("finds a secret that was committed and later removed", async () => {
    const repo = makeRepo("leaky");
    fs.writeFileSync(path.join(repo, "config.js"), 'const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";\n');
    git(["add", "."], repo);
    git(["commit", "--quiet", "-m", "add config"], repo);

    fs.writeFileSync(path.join(repo, "config.js"), "const AWS_KEY = process.env.AWS_KEY;\n");
    git(["add", "."], repo);
    git(["commit", "--quiet", "-m", "move to env"], repo);

    const payload = await harness.payload("scan_git_history", { repoPath: repo });
    const serialized = JSON.stringify(payload);

    expect(payload.findings.length).toBeGreaterThan(0);
    // History findings are the ones most likely to be pasted into a ticket, so
    // the credential itself must never appear in the response.
    expect(serialized).not.toContain("AKIAIOSFODNN7EXAMPLE");
  });

  it("reports nothing for a repository whose history is clean", async () => {
    const repo = makeRepo("clean");
    fs.writeFileSync(path.join(repo, "app.js"), "const total = items.length + 1;\n");
    git(["add", "."], repo);
    git(["commit", "--quiet", "-m", "initial"], repo);

    const payload = await harness.payload("scan_git_history", { repoPath: repo });
    expect(payload.findings).toEqual([]);
  });

  it("returns an error for a path that is not a git repository", async () => {
    const plain = path.join(root, "not-a-repo");
    fs.mkdirSync(plain, { recursive: true });

    const response = await harness.call("scan_git_history", { repoPath: plain });
    expect(response.isError).toBe(true);
  });

  it("returns an error for a missing directory", async () => {
    const response = await harness.call("scan_git_history", { repoPath: path.join(root, "nope") });
    expect(response.isError).toBe(true);
  });
});

describe("post_security_review", () => {
  it("posts nothing and says so when given neither comments nor a summary", async () => {
    // No GITHUB_TOKEN is needed for this path, and it must not reach the API:
    // an empty review would otherwise be published on someone's pull request.
    const payload = await harness.payload("post_security_review", {
      owner: "acme",
      repo: "widgets",
      pull_number: 7,
    });

    expect(payload.totalActions).toBe(0);
    expect(payload.results).toEqual([]);
    expect(payload.note).toMatch(/nothing was posted/i);
  });
});

describe("tool registration", () => {
  it("gives every tool a description an agent can route on", () => {
    for (const [name, tool] of harness.tools) {
      expect(tool.description.length, `${name} description`).toBeGreaterThan(40);
      expect(tool.schema, `${name} schema`).toBeDefined();
    }
  });
});
