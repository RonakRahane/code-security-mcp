import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { PathValidationError, isWithin, validatePath } from "../src/core/paths.js";

let root: string;
let filePath: string;

beforeAll(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), "sentinel-paths-"));
  filePath = path.join(root, "app.js");
  fs.writeFileSync(filePath, "const a = 1;\n", "utf-8");
  fs.mkdirSync(path.join(root, "nested"), { recursive: true });
});

afterAll(() => {
  fs.rmSync(root, { recursive: true, force: true });
});

afterEach(() => {
  delete process.env.SENTINEL_ALLOWED_ROOTS;
});

describe("isWithin", () => {
  it("accepts the root itself", () => {
    expect(isWithin("/a/b", "/a/b")).toBe(true);
  });

  it("accepts descendants", () => {
    expect(isWithin("/a/b", "/a/b/c/d")).toBe(true);
  });

  it("rejects ancestors and siblings", () => {
    expect(isWithin("/a/b", "/a")).toBe(false);
    expect(isWithin("/a/b", "/a/bc")).toBe(false);
  });
});

describe("validatePath", () => {
  it("resolves a valid file", () => {
    const result = validatePath(filePath, { kind: "file" });
    expect(result.isFile).toBe(true);
    expect(result.isDirectory).toBe(false);
    expect(path.isAbsolute(result.absolutePath)).toBe(true);
  });

  it("resolves a valid directory", () => {
    expect(validatePath(root, { kind: "directory" }).isDirectory).toBe(true);
  });

  it("rejects a non-string input", () => {
    expect(() => validatePath(42)).toThrow(PathValidationError);
  });

  it("rejects an empty or whitespace-only path", () => {
    expect(() => validatePath("")).toThrow(PathValidationError);
    expect(() => validatePath("   ")).toThrow(PathValidationError);
  });

  it("rejects a path containing a null byte", () => {
    // A NUL truncates the path at the syscall boundary, so a value that passes
    // JavaScript-side checks could address a different file.
    expect(() => validatePath(`${filePath}\0.txt`)).toThrow(/null byte/i);
  });

  it("rejects a path beyond the length limit", () => {
    expect(() => validatePath("a".repeat(5000))).toThrow(/maximum length/i);
  });

  it("rejects a path that does not exist", () => {
    expect(() => validatePath(path.join(root, "missing.js"))).toThrow(/not found/i);
  });

  it("rejects a directory when a file was required", () => {
    expect(() => validatePath(root, { kind: "file" })).toThrow(/not a file/i);
  });

  it("rejects a file when a directory was required", () => {
    expect(() => validatePath(filePath, { kind: "directory" })).toThrow(/not a directory/i);
  });

  it("uses the supplied label in error messages", () => {
    expect(() => validatePath("", { label: "repoPath" })).toThrow(/repoPath/);
  });

  it("allows any path when no workspace allowlist is configured", () => {
    expect(() => validatePath(filePath)).not.toThrow();
  });

  it("rejects a path outside the configured workspace roots", () => {
    process.env.SENTINEL_ALLOWED_ROOTS = path.join(root, "nested");
    expect(() => validatePath(filePath)).toThrow(/allowed workspace roots/i);
  });

  it("accepts a path inside the configured workspace roots", () => {
    process.env.SENTINEL_ALLOWED_ROOTS = root;
    expect(() => validatePath(filePath)).not.toThrow();
  });

  it("accepts a path under any one of several configured roots", () => {
    process.env.SENTINEL_ALLOWED_ROOTS = [os.tmpdir(), root].join(path.delimiter);
    expect(() => validatePath(filePath)).not.toThrow();
  });
});
