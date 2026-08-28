import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { Diagnostics } from "../src/core/diagnostics.js";
import { mapWithConcurrency, readTextFile, resolveConcurrency, walkDirectory } from "../src/core/fs-walk.js";

let root: string;

beforeEach(() => {
  // realpath because the walker resolves symlinks: os.tmpdir() is a short path
  // on Windows and a symlink on macOS, so the raw value would not match.
  root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "sentinel-walk-")));
});

afterEach(() => {
  fs.rmSync(root, { recursive: true, force: true });
  delete process.env.SENTINEL_CONCURRENCY;
});

const write = (relativePath: string, contents = "x") => {
  const full = path.join(root, relativePath);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, contents);
  return full;
};

const names = (files: string[]) => files.map((file) => path.relative(root, file).replace(/\\/g, "/")).sort();

describe("walkDirectory", () => {
  it("finds files recursively", async () => {
    write("a.ts");
    write("nested/deep/b.ts");

    const result = await walkDirectory(root, { diagnostics: new Diagnostics() });
    expect(names(result.files)).toEqual(["a.ts", "nested/deep/b.ts"]);
    expect(result.truncated).toBe(false);
  });

  it("skips dependency and build directories by default", async () => {
    write("src/a.ts");
    write("node_modules/pkg/index.js");
    write("dist/bundle.js");
    write(".git/config");

    const result = await walkDirectory(root, { diagnostics: new Diagnostics() });
    expect(names(result.files)).toEqual(["src/a.ts"]);
  });

  it("honours shouldEnterDirectory", async () => {
    write("keep/a.ts");
    write("drop/b.ts");

    const result = await walkDirectory(root, {
      diagnostics: new Diagnostics(),
      shouldEnterDirectory: (_full, name) => name !== "drop",
    });
    expect(names(result.files)).toEqual(["keep/a.ts"]);
  });

  it("honours shouldReadFile", async () => {
    write("a.ts");
    write("b.png");

    const result = await walkDirectory(root, {
      diagnostics: new Diagnostics(),
      shouldReadFile: (_full, name) => name.endsWith(".ts"),
    });
    expect(names(result.files)).toEqual(["a.ts"]);
  });

  it("reports truncation when the file limit is reached", async () => {
    for (let i = 0; i < 10; i++) write(`file${i}.ts`);

    const result = await walkDirectory(root, { diagnostics: new Diagnostics(), maxFiles: 3 });
    expect(result.files.length).toBeLessThanOrEqual(3);
    expect(result.truncated).toBe(true);
  });

  it("stops descending at the configured depth", async () => {
    write("a/b/c/d/deep.ts");
    const result = await walkDirectory(root, { diagnostics: new Diagnostics(), maxDepth: 2 });
    expect(names(result.files)).not.toContain("a/b/c/d/deep.ts");
  });

  it("returns an empty result for a missing directory and records the failure", async () => {
    const diagnostics = new Diagnostics();
    const result = await walkDirectory(path.join(root, "missing"), { diagnostics });

    expect(result.files).toEqual([]);
    // A directory that could not be read is a coverage gap, not a clean scan.
    expect(diagnostics.skippedCount).toBe(1);
    expect(diagnostics.toWarnings().join(" ")).toMatch(/coverage gap/i);
  });

  it("does not follow a symlink that points outside the scan root", async () => {
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), "sentinel-outside-"));
    fs.writeFileSync(path.join(outside, "secret.ts"), "x");
    write("src/a.ts");

    try {
      fs.symlinkSync(outside, path.join(root, "link"), "junction");
    } catch {
      return; // Symlink creation is privileged on some Windows configurations.
    }

    const diagnostics = new Diagnostics();
    const result = await walkDirectory(root, { diagnostics });

    expect(names(result.files)).toEqual(["src/a.ts"]);
    expect(diagnostics.toWarnings().join(" ")).toMatch(/outside the scan root/i);

    fs.rmSync(outside, { recursive: true, force: true });
  });

  it("terminates on a self-referential symlink loop", async () => {
    write("a.ts");
    try {
      fs.symlinkSync(root, path.join(root, "self"), "junction");
    } catch {
      return;
    }

    const result = await walkDirectory(root, { diagnostics: new Diagnostics() });
    expect(result.files.length).toBeGreaterThan(0);
  });
});

describe("readTextFile", () => {
  it("reads a UTF-8 file", async () => {
    const file = write("a.ts", "const a = 1;");
    expect(await readTextFile(file)).toBe("const a = 1;");
  });

  it("returns an empty string for an empty file", async () => {
    expect(await readTextFile(write("empty.ts", ""))).toBe("");
  });

  it("returns null for a file over the size limit", async () => {
    const file = write("big.ts", "a".repeat(1000));
    expect(await readTextFile(file, { maxBytes: 100 })).toBeNull();
  });

  it("returns null for binary content", async () => {
    const file = path.join(root, "bin.dat");
    fs.writeFileSync(file, Buffer.from([0x00, 0x01, 0x02, 0x00]));
    expect(await readTextFile(file)).toBeNull();
  });

  it("returns null and records a diagnostic for a missing file", async () => {
    const diagnostics = new Diagnostics();
    expect(await readTextFile(path.join(root, "nope.ts"), { diagnostics })).toBeNull();
    expect(diagnostics.skippedCount).toBe(1);
  });
});

describe("mapWithConcurrency", () => {
  it("preserves input order", async () => {
    const results = await mapWithConcurrency([1, 2, 3, 4, 5], async (n) => n * 2, 2);
    expect(results).toEqual([2, 4, 6, 8, 10]);
  });

  it("handles an empty input", async () => {
    expect(await mapWithConcurrency([], async (n) => n, 4)).toEqual([]);
  });

  it("never exceeds the concurrency limit", async () => {
    let active = 0;
    let peak = 0;

    await mapWithConcurrency(Array.from({ length: 30 }, (_, i) => i), async () => {
      active++;
      peak = Math.max(peak, active);
      await new Promise((resolve) => setTimeout(resolve, 1));
      active--;
    }, 4);

    expect(peak).toBeLessThanOrEqual(4);
  });

  it("isolates a failing worker instead of aborting the batch", async () => {
    const results = await mapWithConcurrency([1, 2, 3], async (n) => {
      if (n === 2) throw new Error("boom");
      return n;
    }, 2);

    expect(results).toEqual([1, undefined, 3]);
  });
});

describe("resolveConcurrency", () => {
  it("uses the requested value", () => {
    expect(resolveConcurrency(8)).toBe(8);
  });

  it("clamps to a safe range", () => {
    expect(resolveConcurrency(0)).toBe(1);
    expect(resolveConcurrency(1000)).toBe(64);
  });

  it("falls back to the environment variable", () => {
    process.env.SENTINEL_CONCURRENCY = "5";
    expect(resolveConcurrency()).toBe(5);
  });
});
