import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { registerVerifyFix } from "../src/tools/verify-fix.js";
import { registerCreateBaseline } from "../src/tools/create-baseline.js";

/**
 * The loop an agent actually runs: scan, edit, confirm the edit worked, and
 * record what is left so the next scan reports only new problems.
 *
 * Both ends of it were missing. An agent could read a baseline but not write
 * one, so it could not adopt Sentinel on a codebase that was not already
 * clean; and after editing a file it had no way to tell whether the change
 * removed the finding, which invites assuming it did.
 */

let root: string;
let tools: Map<string, (a: Record<string, unknown>) => Promise<{ content: Array<{ text: string }> }>>;

beforeEach(() => {
  root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "sentinel-agent-")));
  tools = new Map();
  const server = { tool: (n: string, _d: string, _s: unknown, h: never) => tools.set(n, h) } as unknown as McpServer;
  registerVerifyFix(server);
  registerCreateBaseline(server);
});

afterEach(() => {
  fs.rmSync(root, { recursive: true, force: true });
});

const call = async (name: string, args: Record<string, unknown>) =>
  JSON.parse((await tools.get(name)!(args)).content[0].text);

const write = (name: string, contents: string) => {
  const full = path.join(root, name);
  fs.writeFileSync(full, contents, "utf-8");
  return full;
};

const WEAK = 'const h = crypto.createHash("md5").update(password).digest("hex");\n';

describe("verify_fix", () => {
  it("reports a finding as unresolved while it is still there", async () => {
    const file = write("app.js", WEAK);

    const result = await call("verify_fix", { filePath: file, ruleId: "WEAK_HASH_MD5", line: 1 });

    expect(result.resolved).toBe(false);
    expect(result.stillPresent.length).toBeGreaterThan(0);
  });

  it("reports it as resolved once the edit removes it", async () => {
    const file = write("app.js", WEAK);
    fs.writeFileSync(file, WEAK.replace('"md5"', '"sha256"'));

    const result = await call("verify_fix", { filePath: file, ruleId: "WEAK_HASH_MD5", line: 1 });

    expect(result.resolved).toBe(true);
    expect(result.stillPresent).toEqual([]);
  });

  it("surfaces the other findings in the file, not only the one asked about", async () => {
    // A fix that leaves a worse problem untouched should not read as success.
    const file = write("app.js", `${WEAK}eval(req.body.code);\n`);
    fs.writeFileSync(file, `${WEAK.replace('"md5"', '"sha256"')}eval(req.body.code);\n`);

    const result = await call("verify_fix", { filePath: file, ruleId: "WEAK_HASH_MD5", line: 1 });

    expect(result.resolved).toBe(true);
    expect(result.otherFindingsInFile.length).toBeGreaterThan(0);
  });

  it("does not call a finding resolved when the code merely moved", async () => {
    // The tool an agent trusts instead of checking. A finding that drifted past
    // the line tolerance fell out of stillPresent (wrong line) and out of
    // otherFindingsInFile (filtered by rule id), so it vanished from both and
    // the response said resolved with the problem still in the file.
    const file = write("app.js", WEAK);
    fs.writeFileSync(file, `${"// pad\n".repeat(20)}${WEAK}`);

    const result = await call("verify_fix", { filePath: file, ruleId: "WEAK_HASH_MD5", line: 1 });

    expect(result.resolved).toBe(false);
    expect(result.movedElsewhere.length).toBeGreaterThan(0);
    expect(result.verdict).toMatch(/moved but is still present/i);
  });

  it("reports resolved once the finding is genuinely gone", async () => {
    const file = write("app.js", WEAK);
    fs.writeFileSync(file, WEAK.replace('"md5"', '"sha256"'));

    const result = await call("verify_fix", { filePath: file, ruleId: "WEAK_HASH_MD5", line: 1 });

    expect(result.resolved).toBe(true);
    expect(result.verdict).toMatch(/no longer reported anywhere/i);
  });

  it("tolerates the line moving, since a fix shifts line numbers", async () => {
    const file = write("app.js", `// added comment\n// another\n${WEAK}`);

    const result = await call("verify_fix", { filePath: file, ruleId: "WEAK_HASH_MD5", line: 1 });

    expect(result.resolved).toBe(false);
  });

  it("checks the whole file when no rule is named", async () => {
    const file = write("app.js", "export const add = (a, b) => a + b;\n");

    const result = await call("verify_fix", { filePath: file });

    expect(result.resolved).toBe(true);
  });
});

describe("create_baseline", () => {
  it("records the current findings and reports the count", async () => {
    write("app.js", WEAK);

    const result = await call("create_baseline", { dirPath: root });

    expect(result.written).toBe(true);
    expect(result.findingsRecorded).toBeGreaterThan(0);
    expect(fs.existsSync(path.join(root, ".sentinel-baseline.json"))).toBe(true);
  });

  it("refuses to replace an existing baseline unless asked", async () => {
    write("app.js", WEAK);
    await call("create_baseline", { dirPath: root });

    const second = await call("create_baseline", { dirPath: root });

    expect(second.written).toBe(false);
    expect(second.reason).toMatch(/already exists/i);
  });

  it("replaces it when overwrite is passed", async () => {
    write("app.js", WEAK);
    await call("create_baseline", { dirPath: root });

    const second = await call("create_baseline", { dirPath: root, overwrite: true });

    expect(second.written).toBe(true);
    expect(second.replacedExisting).toBe(true);
  });

  it("records everything, not only what a previous baseline left visible", async () => {
    // Building a baseline from an already-suppressed scan would record just the
    // new findings and drop the accepted ones, resurfacing them all next scan.
    write("app.js", WEAK);
    const first = await call("create_baseline", { dirPath: root });

    write("second.js", "eval(req.body.code);\n");
    const second = await call("create_baseline", { dirPath: root, overwrite: true });

    expect(second.findingsRecorded).toBeGreaterThan(first.findingsRecorded);
  });
});
