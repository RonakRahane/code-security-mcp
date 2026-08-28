import { describe, expect, it } from "vitest";
import { parseArgs } from "../src/index.js";

/**
 * The CLI is the interface CI pipelines drive. A flag that silently fails to
 * parse turns an intended gate into a no-op, so each one is pinned here.
 */

describe("parseArgs", () => {
  it("reads the scan target", () => {
    expect(parseArgs(["--scan", "/repo"]).scanTarget).toBe("/repo");
  });

  it("returns no scan target when the flag is absent", () => {
    expect(parseArgs([]).scanTarget).toBeUndefined();
  });

  it("reads the SARIF output path and the log level", () => {
    const args = parseArgs(["--scan", ".", "--sarif", "out.sarif", "--log-level", "debug"]);
    expect(args.sarifPath).toBe("out.sarif");
    expect(args.logLevel).toBe("debug");
  });

  it("treats the boolean flags as absent by default", () => {
    const args = parseArgs(["--scan", "."]);
    expect(args.noReportFile).toBe(false);
    expect(args.writeBaseline).toBe(false);
  });

  it("recognises --write-baseline", () => {
    expect(parseArgs(["--scan", ".", "--write-baseline"]).writeBaseline).toBe(true);
  });

  it("recognises --no-report-file", () => {
    expect(parseArgs(["--scan", ".", "--no-report-file"]).noReportFile).toBe(true);
  });

  it("accepts the flags together and in any order", () => {
    const args = parseArgs(["--write-baseline", "--no-report-file", "--scan", "/repo"]);
    expect(args.scanTarget).toBe("/repo");
    expect(args.writeBaseline).toBe(true);
    expect(args.noReportFile).toBe(true);
  });

  it("leaves a value flag undefined when nothing follows it", () => {
    // "--sarif" as the final argument has no value to read.
    expect(parseArgs(["--scan", ".", "--sarif"]).sarifPath).toBeUndefined();
  });
});
