import { execFileSync } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { semgrepAvailable } from "./helpers/semgrep-available.js";

/**
 * The Semgrep packs are data, so a mistake in them is not a compile error and
 * not a test failure anywhere else. A single unquoted value containing a colon
 * makes the whole file invalid YAML, Semgrep then loads zero rules, and the
 * scan quietly falls back to the pattern engine while still reporting success.
 * Nothing else in this suite would notice.
 */

const rulesDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../rules");
const packs = fs.readdirSync(rulesDir).filter((f) => f.endsWith(".yml"));

/** semgrep --validate reports on stderr, so both streams are captured. */
function validate(): string {
  return execFileSync(
    "semgrep",
    ["--validate", "--config", rulesDir, "--metrics=off", "--disable-version-check"],
    { encoding: "utf-8", stdio: ["ignore", "pipe", "pipe"] }
  ) + execFileSync(
    "sh",
    ["-c", `semgrep --validate --config ${JSON.stringify(rulesDir)} --metrics=off --disable-version-check 2>&1`],
    { encoding: "utf-8" }
  );
}

describe("Semgrep rule packs", () => {
  it("ships at least one pack", () => {
    expect(packs.length).toBeGreaterThan(0);
  });

  it.skipIf(!semgrepAvailable)("every pack parses and loads", () => {
    const output = validate();

    expect(output).toMatch(/Configuration is valid/);
    // "valid, 0 rules" is the shape a broken file produces once Semgrep gives
    // up on it, and it is indistinguishable from success at the scan level.
    const loaded = Number(output.match(/and (\d+) rule\(s\)/)?.[1] ?? 0);
    expect(loaded, "no rules loaded").toBeGreaterThan(0);
  }, 120_000);

  it.skipIf(!semgrepAvailable)("loads every rule the packs declare", () => {
    const declared = packs.reduce(
      (total, file) =>
        total + (fs.readFileSync(path.join(rulesDir, file), "utf-8").match(/^ {2}- id:/gm) ?? []).length,
      0
    );

    const output = validate();
    const loaded = Number(output.match(/and (\d+) rule\(s\)/)?.[1] ?? 0);

    // A rule Semgrep silently drops is a rule that never runs.
    expect(loaded).toBe(declared);
  }, 120_000);
});
