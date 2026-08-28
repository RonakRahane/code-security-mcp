import { execFileSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { scanGitHistoryForSecrets } from "../src/scanner/git-history-secret-scanner.js";

/**
 * These tests run the git scanner against a real repository, including one
 * whose path contains shell metacharacters. That case guards the execFileSync
 * argument-array form: building a shell string instead would be an injection
 * surface, and POSIX quoting does not hold on Windows either way.
 */

let workspace: string;

const gitAvailable = (() => {
  try {
    execFileSync("git", ["--version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
})();

const describeGit = gitAvailable ? describe : describe.skip;

function initRepo(repoPath: string): void {
  fs.mkdirSync(repoPath, { recursive: true });
  const run = (args: string[]) =>
    execFileSync("git", ["-C", repoPath, ...args], {
      stdio: "ignore",
      env: { ...process.env, GIT_TERMINAL_PROMPT: "0" },
    });

  run(["init", "-q"]);
  run(["config", "user.email", "test@example.com"]);
  run(["config", "user.name", "Sentinel Test"]);
  run(["config", "commit.gpgsign", "false"]);
}

function commitFile(repoPath: string, relativePath: string, contents: string, message: string): void {
  fs.writeFileSync(path.join(repoPath, relativePath), contents, "utf-8");
  execFileSync("git", ["-C", repoPath, "add", "."], { stdio: "ignore" });
  execFileSync("git", ["-C", repoPath, "commit", "-q", "-m", message], {
    stdio: "ignore",
    env: { ...process.env, GIT_AUTHOR_DATE: "2024-01-01T00:00:00Z", GIT_COMMITTER_DATE: "2024-01-01T00:00:00Z" },
  });
}

beforeEach(() => {
  workspace = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "sentinel-git-")));
});

afterEach(() => {
  fs.rmSync(workspace, { recursive: true, force: true });
});

describeGit("scanGitHistoryForSecrets", () => {
  it("rejects a path that is not a git repository", async () => {
    await expect(scanGitHistoryForSecrets(workspace)).rejects.toThrow(/not a git repository/i);
  });

  it("rejects a path that does not exist", async () => {
    await expect(scanGitHistoryForSecrets(path.join(workspace, "missing"))).rejects.toThrow(/not found/i);
  });

  it("returns no findings for a clean repository", async () => {
    const repo = path.join(workspace, "clean");
    initRepo(repo);
    commitFile(repo, "app.js", "export const add = (a, b) => a + b;\n", "initial");

    const result = await scanGitHistoryForSecrets(repo);
    expect(result.totalSecrets).toBe(0);
    expect(result.commitsScanned).toBe(1);
  });

  it("finds a secret that was committed and later removed", async () => {
    const repo = path.join(workspace, "leaky");
    initRepo(repo);
    commitFile(repo, "config.js", 'const key = "AKIAIOSFODNN7EXAMPLE";\n', "add config");
    commitFile(repo, "config.js", "const key = process.env.AWS_KEY;\n", "remove hardcoded key");

    const result = await scanGitHistoryForSecrets(repo);

    // The secret is gone from the working tree but still recoverable from
    // history, which is the case this scanner exists for.
    expect(result.totalSecrets).toBeGreaterThan(0);
    expect(result.findings[0].commitHash).toMatch(/^[0-9a-f]{40}$/);
    expect(result.findings[0].filePath).toBe("config.js");
  });

  it("redacts the secret value in its output", async () => {
    const secret = "AKIAIOSFODNN7EXAMPLE";
    const repo = path.join(workspace, "redact");
    initRepo(repo);
    commitFile(repo, "config.js", `const key = "${secret}";\n`, "add config");

    const result = await scanGitHistoryForSecrets(repo);
    expect(result.totalSecrets).toBeGreaterThan(0);
    expect(JSON.stringify(result)).not.toContain(secret);
  });

  it("handles a repository path containing shell metacharacters", async () => {
    // A shell-string implementation would execute or mangle this path.
    // execFileSync passes it through as a single argument.
    const repo = path.join(workspace, "repo; echo pwned && touch hacked $(whoami) 'quoted'");
    initRepo(repo);
    commitFile(repo, "config.js", 'const key = "AKIAIOSFODNN7EXAMPLE";\n', "add config");

    const result = await scanGitHistoryForSecrets(repo);

    expect(result.totalSecrets).toBeGreaterThan(0);
    expect(fs.existsSync(path.join(workspace, "hacked"))).toBe(false);
  });

  it("handles a repository path containing spaces", async () => {
    const repo = path.join(workspace, "my project folder");
    initRepo(repo);
    commitFile(repo, "app.js", "const a = 1;\n", "initial");

    const result = await scanGitHistoryForSecrets(repo);
    expect(result.commitsScanned).toBe(1);
  });

  it("respects the maxCommits limit", async () => {
    const repo = path.join(workspace, "many");
    initRepo(repo);
    for (let i = 0; i < 5; i++) commitFile(repo, "app.js", `const v = ${i};\n`, `commit ${i}`);

    const result = await scanGitHistoryForSecrets(repo, 2);
    expect(result.commitsScanned).toBe(2);
  });

  it("caps an out-of-range maxCommits and says so", async () => {
    const repo = path.join(workspace, "capped");
    initRepo(repo);
    commitFile(repo, "app.js", "const a = 1;\n", "initial");

    const result = await scanGitHistoryForSecrets(repo, 10_000);
    expect(result.warnings.join(" ")).toMatch(/capped/i);
  });

  it("does not report the same secret twice for one commit", async () => {
    const repo = path.join(workspace, "dupes");
    initRepo(repo);
    commitFile(repo, "config.js", 'const key = "AKIAIOSFODNN7EXAMPLE";\n', "add config");

    const result = await scanGitHistoryForSecrets(repo);
    const keys = result.findings.map((f) => `${f.commitHash}:${f.filePath}:${f.line}:${f.ruleId}`);
    expect(new Set(keys).size).toBe(keys.length);
  });
});

describe("the scan does not block the event loop", () => {
  it("lets timers run while it reads history", async () => {
    // execFileSync held the loop for the whole scan - about eighty seconds at
    // the default commit cap - so an MCP server could not answer another tool
    // or respond to a ping, and clients saw it as dead.
    const repo = path.join(workspace, "loop");
    initRepo(repo);
    for (let i = 0; i < 12; i++) {
      commitFile(repo, `f${i}.js`, `const k${i} = "AKIAIOSFODNN7EXAMPLE";\n`, `c${i}`);
    }

    let ticks = 0;
    const timer = setInterval(() => ticks++, 5);
    try {
      const result = await scanGitHistoryForSecrets(repo, 100);
      expect(result.findings.length).toBeGreaterThan(0);
    } finally {
      clearInterval(timer);
    }

    expect(ticks, "the event loop was blocked for the whole scan").toBeGreaterThan(0);
  }, 120_000);
});
