import { execFileSync } from "node:child_process";

/**
 * Whether a Semgrep binary is reachable for this test run.
 *
 * CI runs `npm test` across four OS and Node combinations without installing
 * Semgrep - it is a Python program, and installing it on every matrix leg would
 * make the fast job slow and add a Windows install path to every run. The
 * Semgrep engine is covered instead by the detection-regression job, which
 * installs it and fails if it is missing.
 *
 * So a test that needs cross-file taint analysis has to skip here rather than
 * fail. Skipping is visible in the report; a red matrix that is red for an
 * environmental reason trains people to ignore it.
 */
export const semgrepAvailable = ((): boolean => {
  const binary = process.env.SENTINEL_SEMGREP_BIN?.trim() || "semgrep";
  try {
    execFileSync(binary, ["--version"], { stdio: "ignore", timeout: 30_000 });
    return true;
  } catch {
    return false;
  }
})();
