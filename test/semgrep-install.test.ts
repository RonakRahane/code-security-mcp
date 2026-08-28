import { execFileSync, spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { ensureSemgrep, resetSemgrepReadinessCache } from "../src/core/semgrep-install.js";
import { semgrepAvailable } from "./helpers/semgrep-available.js";

/**
 * Semgrep is not an npm dependency, so "absent" is the default state on a new
 * machine. Everything here defends one property: a scan that lost its
 * data-flow engine must never look like a clean scan. That was a real defect -
 * a file carrying `req.query.dir` into `exec()` exited 0 with "Passed" when
 * Semgrep was missing, which in CI is a green build over a live command
 * injection.
 */

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const cli = path.join(repoRoot, "dist", "index.js");
const BROKEN_BIN = path.join(os.tmpdir(), "sentinel-no-such-semgrep");

/**
 * The CLI tests spawn the built entry point, because an exit code only exists
 * at the process boundary. CI builds first; a local run may not have, so the
 * build happens here rather than failing with a module-not-found stack.
 */
beforeAll(() => {
  if (!fs.existsSync(cli)) {
    execFileSync("npm", ["run", "build"], { cwd: repoRoot, stdio: "ignore" });
  }
}, 180_000);

let savedEnv: Record<string, string | undefined>;

beforeEach(() => {
  savedEnv = {
    SENTINEL_SEMGREP_BIN: process.env.SENTINEL_SEMGREP_BIN,
    SENTINEL_NO_AUTO_INSTALL: process.env.SENTINEL_NO_AUTO_INSTALL,
  };
  resetSemgrepReadinessCache();
});

afterEach(() => {
  for (const [key, value] of Object.entries(savedEnv)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  resetSemgrepReadinessCache();
});

describe("locating Semgrep", () => {
  // Asserts a property of the machine, so it can only run where Semgrep is
  // installed. CI's fast matrix deliberately does not install it.
  it.skipIf(!semgrepAvailable)("finds the installed Semgrep and reports a usable version", async () => {
    const readiness = await ensureSemgrep();
    expect(readiness.status).toBe("ready");
    if (readiness.status !== "ready") return;
    expect(readiness.version).toMatch(/^\d+\.\d+\.\d+$/);
    // Already present, so nothing should have been installed for it.
    expect(readiness.installed).toBe(false);
  });

  it("treats an explicitly pinned binary as the only candidate", async () => {
    // Falling back to a different Semgrep than the one an operator pinned
    // would run something other than what they vetted. An earlier revision
    // appended the standard install prefixes even when this was set, so a
    // broken pin silently resolved to the system copy and looked fine.
    process.env.SENTINEL_SEMGREP_BIN = BROKEN_BIN;
    const readiness = await ensureSemgrep();
    expect(readiness.status).toBe("unavailable");
    if (readiness.status !== "unavailable") return;
    expect(readiness.message).toContain(BROKEN_BIN);
    // Installing cannot fix a bad pin, so it must not be attempted.
    expect(readiness.attempted).toEqual([]);
  });

  it("does not install to satisfy a broken pin", async () => {
    // Auto-install is left enabled here: the pin has to short-circuit on its
    // own, not because installing happened to be switched off.
    delete process.env.SENTINEL_NO_AUTO_INSTALL;
    process.env.SENTINEL_SEMGREP_BIN = BROKEN_BIN;
    const readiness = await ensureSemgrep();
    expect(readiness.status).toBe("unavailable");
    if (readiness.status !== "unavailable") return;
    expect(readiness.message).toContain("SENTINEL_SEMGREP_BIN");
  });

  // POSIX only: the stub is a shell script made executable with chmod, and
  // Windows decides executability by file extension instead.
  it.skipIf(process.platform === "win32")("does not install over a Semgrep that is present but stuck", async () => {
    // A machine under load can miss the probe deadline, and an installer that
    // reads "did not answer" as "not installed" would add a second copy of a
    // Semgrep that is already there. Only ENOENT means absent.
    const stub = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "sentinel-stub-")), "semgrep");
    fs.writeFileSync(stub, "#!/bin/sh\nexit 1\n");
    fs.chmodSync(stub, 0o755);
    process.env.SENTINEL_SEMGREP_BIN = stub;
    delete process.env.SENTINEL_NO_AUTO_INSTALL;

    const readiness = await ensureSemgrep();
    expect(readiness.status).toBe("unavailable");
    if (readiness.status !== "unavailable") return;
    expect(readiness.message).toContain("present but did not run");
    expect(readiness.attempted).toEqual([]);
    fs.rmSync(path.dirname(stub), { recursive: true, force: true });
  });

  it("resolves concurrent callers through a single check", async () => {
    // Memoised on the promise, not the result. Memoising the result would let
    // several scans start several installers over the same prefix at once.
    const [first, second, third] = await Promise.all([
      ensureSemgrep(),
      ensureSemgrep(),
      ensureSemgrep(),
    ]);
    expect(second).toBe(first);
    expect(third).toBe(first);
  });
});

/**
 * The verdict is the part CI reads. These run the built CLI, because the exit
 * code is the thing under test and it only exists at the process boundary.
 */
describe("CLI verdict when Semgrep did not run", () => {
  let workdir: string;

  beforeEach(() => {
    workdir = fs.mkdtempSync(path.join(os.tmpdir(), "sentinel-verdict-"));
    // Deliberately clean: the failure being pinned is a *pass* that should not
    // have been one. A file with findings would exit non-zero either way and
    // prove nothing.
    fs.writeFileSync(path.join(workdir, "ok.js"), "const total = 1 + 2;\nconsole.log(total);\n");
  });

  afterEach(() => {
    fs.rmSync(workdir, { recursive: true, force: true });
  });

  // spawnSync rather than execFileSync: the verdict is on stderr and the code
  // is the exit status, and execFileSync surfaces stderr only when it throws -
  // so the passing cases would be asserted against an empty string.
  function scan(env: Record<string, string>): { code: number; stderr: string } {
    const result = spawnSync(process.execPath, [cli, "--scan", workdir, "--no-report-file"], {
      encoding: "utf-8",
      stdio: ["ignore", "ignore", "pipe"],
      env: { ...process.env, ...env },
    });
    return { code: result.status ?? -1, stderr: result.stderr ?? "" };
  }

  it("does not report a pass for a scan its data-flow engine never covered", () => {
    const result = scan({ SENTINEL_SEMGREP_BIN: BROKEN_BIN, SENTINEL_NO_AUTO_INSTALL: "1" });
    expect(result.code).not.toBe(0);
    expect(result.stderr).toContain("Incomplete");
    expect(result.stderr).not.toMatch(/\nPassed: no findings/);
  });

  it("names what to do about it", () => {
    const result = scan({ SENTINEL_SEMGREP_BIN: BROKEN_BIN, SENTINEL_NO_AUTO_INSTALL: "1" });
    expect(result.stderr).toContain("Install Semgrep");
  });

  it("accepts a pattern-only scan the operator asked for", () => {
    // Switching Semgrep off in configuration is a decision, not a failure, and
    // must still be able to pass. Without this the previous test's fix would
    // make the documented opt-out unusable.
    fs.writeFileSync(
      path.join(workdir, "sentinel.config.json"),
      JSON.stringify({ semgrep: { enabled: false } })
    );
    const result = scan({});
    expect(result.code).toBe(0);
    expect(result.stderr).toContain("Passed");
  });

  it.skipIf(!semgrepAvailable)("passes normally when Semgrep is present", () => {
    const result = scan({});
    expect(result.code).toBe(0);
    expect(result.stderr).toContain("Passed");
  });
});
