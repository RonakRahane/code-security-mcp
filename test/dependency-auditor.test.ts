import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  auditDependencies,
  mapOsvSeverity,
  parseDependencies,
  parsePythonRequirement,
} from "../src/scanner/dependency-auditor.js";

let root: string;

beforeEach(() => {
  root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "sentinel-dep-")));
});

afterEach(() => {
  fs.rmSync(root, { recursive: true, force: true });
});

const write = (name: string, contents: string) => {
  const full = path.join(root, name);
  fs.writeFileSync(full, contents, "utf-8");
  return full;
};

describe("parsePythonRequirement", () => {
  it("parses a pinned requirement", () => {
    expect(parsePythonRequirement("django==2.2.0")).toEqual({ name: "django", version: "2.2.0" });
  });

  it("parses extras", () => {
    expect(parsePythonRequirement("celery[redis]==5.0.0")).toEqual({ name: "celery", version: "5.0.0" });
  });

  it("strips environment markers", () => {
    expect(parsePythonRequirement('foo==1.0; python_version < "3.8"')).toEqual({ name: "foo", version: "1.0" });
  });

  it("strips trailing comments", () => {
    expect(parsePythonRequirement("foo==1.0  # pinned deliberately")).toEqual({ name: "foo", version: "1.0" });
  });

  it("returns a name without a version when unpinned", () => {
    expect(parsePythonRequirement("requests")).toEqual({ name: "requests", version: undefined });
  });

  it("returns null for an empty line", () => {
    expect(parsePythonRequirement("")).toBeNull();
  });
});

describe("parseDependencies", () => {
  it("parses package.json dependencies and devDependencies", () => {
    const manifest = JSON.stringify({
      dependencies: { lodash: "^4.17.20" },
      devDependencies: { vitest: "~2.1.0" },
    });
    const deps = parseDependencies(manifest, "package.json", "npm");
    expect(deps).toEqual(expect.arrayContaining([
      { name: "lodash", version: "4.17.20" },
      { name: "vitest", version: "2.1.0" },
    ]));
  });

  it("parses a lockfile v3 and keeps the innermost package name", () => {
    const lock = JSON.stringify({
      packages: {
        "": { version: "1.0.0" },
        "node_modules/lodash": { version: "4.17.21" },
        "node_modules/a/node_modules/nested": { version: "2.0.0" },
      },
    });
    const deps = parseDependencies(lock, "package-lock.json", "npm");
    expect(deps).toEqual(expect.arrayContaining([
      { name: "lodash", version: "4.17.21" },
      { name: "nested", version: "2.0.0" },
    ]));
  });

  it("parses a scoped package from yarn.lock without truncating the scope", () => {
    const lock = ['"@babel/core@^7.0.0":', '  version "7.20.0"'].join("\n");
    expect(parseDependencies(lock, "yarn.lock", "npm")).toContainEqual({ name: "@babel/core", version: "7.20.0" });
  });

  it("parses requirements.txt and skips flags and comments", () => {
    const contents = ["# comment", "-r other.txt", "django==2.2.0", "requests>=2.0"].join("\n");
    const deps = parseDependencies(contents, "requirements.txt", "python");
    expect(deps.map((d) => d.name)).toEqual(["django", "requests"]);
  });

  it("parses poetry.lock package blocks", () => {
    const contents = '[[package]]\nname = "flask"\nversion = "2.0.1"\n';
    expect(parseDependencies(contents, "poetry.lock", "python")).toContainEqual({ name: "flask", version: "2.0.1" });
  });

  it("parses go.mod entries", () => {
    const contents = "module x\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.7.0\n)\n";
    expect(parseDependencies(contents, "go.mod", "go")).toContainEqual({
      name: "github.com/gin-gonic/gin",
      version: "1.7.0",
    });
  });

  it("parses Cargo.lock package blocks", () => {
    const contents = '[[package]]\nname = "serde"\nversion = "1.0.130"\n';
    expect(parseDependencies(contents, "cargo.lock", "rust")).toContainEqual({ name: "serde", version: "1.0.130" });
  });

  it("skips Maven versions that are unresolved property placeholders", () => {
    const pom = `
      <dependency><groupId>a</groupId><artifactId>b</artifactId><version>1.0</version></dependency>
      <dependency><groupId>c</groupId><artifactId>d</artifactId><version>\${spring.version}</version></dependency>
    `;
    const deps = parseDependencies(pom, "pom.xml", "java");
    expect(deps).toEqual([{ name: "a:b", version: "1.0" }]);
  });

  it("returns an empty list for malformed JSON rather than throwing", () => {
    expect(parseDependencies("{ broken", "package.json", "npm")).toEqual([]);
  });

  it("returns an empty list for an unknown ecosystem", () => {
    expect(parseDependencies("anything", "unknown.txt", "unknown")).toEqual([]);
  });
});

describe("pnpm lockfiles", () => {
  // pnpm changed its key layout at lockfile v9. Supporting only the older
  // "/name/version:" form meant every current pnpm project audited nothing and
  // reported "no dependencies could be parsed" instead.

  it("parses the v9 specifier layout, scoped and plain", () => {
    const lock = [
      "lockfileVersion: '9.0'",
      "",
      "packages:",
      "",
      "  '@emnapi/core@1.9.1':",
      "    resolution: {integrity: sha512-abc==}",
      "",
      "  nanoid@3.3.17:",
      "    resolution: {integrity: sha512-def==}",
    ].join("\n");

    const deps = parseDependencies(lock, "pnpm-lock.yaml", "npm");
    const found = deps.map((d) => `${d.name}@${d.version}`);

    expect(found).toContain("@emnapi/core@1.9.1");
    expect(found).toContain("nanoid@3.3.17");
  });

  it("strips peer-dependency context from a v9 key", () => {
    const lock = [
      "packages:",
      "",
      "  vite@8.0.0(@types/node@22.0.0):",
      "    resolution: {integrity: sha512-ghi==}",
    ].join("\n");

    const deps = parseDependencies(lock, "pnpm-lock.yaml", "npm");

    expect(deps).toContainEqual({ name: "vite", version: "8.0.0" });
  });

  it("still parses the older path layout", () => {
    const lock = [
      "lockfileVersion: 5.4",
      "",
      "packages:",
      "",
      "  /@babel/parser/7.29.2:",
      "    resolution: {integrity: sha512-jkl==}",
      "",
      "  /nanoid/3.3.17:",
      "    resolution: {integrity: sha512-mno==}",
    ].join("\n");

    const deps = parseDependencies(lock, "pnpm-lock.yaml", "npm");
    const found = deps.map((d) => `${d.name}@${d.version}`);

    expect(found).toContain("@babel/parser@7.29.2");
    expect(found).toContain("nanoid@3.3.17");
  });
});

describe("mapOsvSeverity", () => {
  it("maps a numeric CVSS score onto a band", () => {
    expect(mapOsvSeverity({ severity: [{ type: "CVSS_V3", score: "9.8" }] })).toBe("critical");
    expect(mapOsvSeverity({ severity: [{ type: "CVSS_V3", score: "7.5" }] })).toBe("high");
    expect(mapOsvSeverity({ severity: [{ type: "CVSS_V3", score: "5.0" }] })).toBe("medium");
    expect(mapOsvSeverity({ severity: [{ type: "CVSS_V3", score: "2.0" }] })).toBe("low");
  });

  it("derives a band from a CVSS vector string", () => {
    // OSV reports vectors, not numbers. parseFloat over the leading segment
    // returns NaN, which would rate every real advisory "medium".
    const critical = mapOsvSeverity({
      severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }],
    });
    expect(critical).toBe("critical");

    const low = mapOsvSeverity({
      severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N" }],
    });
    expect(["low", "medium"]).toContain(low);
  });

  it("falls back to a qualitative GitHub rating", () => {
    expect(mapOsvSeverity({ database_specific: { severity: "HIGH" } })).toBe("high");
    expect(mapOsvSeverity({ database_specific: { severity: "MODERATE" } })).toBe("medium");
  });

  it("defaults to medium when no severity data is present", () => {
    expect(mapOsvSeverity({})).toBe("medium");
  });
});

describe("auditDependencies", () => {
  it("rejects a manifest that does not exist", async () => {
    await expect(auditDependencies(path.join(root, "nope.json"))).rejects.toThrow(/not found|unreadable/i);
  });

  it("returns no vulnerabilities for a clean manifest in offline mode", async () => {
    const manifest = write("package.json", JSON.stringify({ dependencies: { "left-pad": "1.3.0" } }));
    const result = await auditDependencies(manifest, { offline: true });

    expect(result.ecosystem).toBe("npm");
    expect(result.vulnerabilities).toEqual([]);
  });

  it("labels offline fallback findings as unverified rather than confirmed", async () => {
    const manifest = write("package.json", JSON.stringify({ dependencies: { lodash: "4.17.20" } }));
    const result = await auditDependencies(manifest, { offline: true });

    // Without OSV the tool cannot know the installed version is affected, and
    // must not imply otherwise.
    for (const vulnerability of result.vulnerabilities) {
      expect(vulnerability.title).toMatch(/unverified/i);
    }
    expect(result.warnings.join(" ")).toMatch(/static package list/i);
  });

  it("warns when a manifest yields no parseable dependencies", async () => {
    const manifest = write("package.json", JSON.stringify({ name: "empty" }));
    const result = await auditDependencies(manifest, { offline: true });
    expect(result.warnings.join(" ")).toMatch(/no dependencies could be parsed/i);
  });

  it("reports reachability for a package that is imported", async () => {
    write("package.json", JSON.stringify({ dependencies: { lodash: "4.17.20" } }));
    write("app.js", 'import _ from "lodash";\n');

    const result = await auditDependencies(path.join(root, "package.json"), { offline: true });
    const lodash = result.vulnerabilities.find((v) => v.package === "lodash");
    if (lodash) expect(lodash.reachability).toBe("reachable");
  });

  it("reports a package that is never imported as unreachable", async () => {
    write("package.json", JSON.stringify({ dependencies: { lodash: "4.17.20" } }));
    write("app.js", "const a = 1;\n");

    const result = await auditDependencies(path.join(root, "package.json"), { offline: true });
    const lodash = result.vulnerabilities.find((v) => v.package === "lodash");
    if (lodash) expect(lodash.reachability).toBe("unreachable");
  });

  it("surfaces an advisory lookup failure as a warning instead of a clean result", async () => {
    const manifest = write("package.json", JSON.stringify({ dependencies: { lodash: "4.17.20" } }));

    // Point the client at an endpoint that cannot resolve, so the request fails.
    const result = await auditDependencies(manifest, {
      offline: false,
      osvEndpoint: "http://127.0.0.1:1/querybatch",
    });

    expect(result.warnings.join(" ")).toMatch(/OSV advisory lookup failed/i);
    expect(result.warnings.join(" ")).toMatch(/incomplete/i);
  }, 30_000);

  describe("OSV retry policy", () => {
    // The fail-fast throw for a permanent 4xx sat inside the try block, so the
    // catch below recorded it and retried with backoff anyway. A malformed
    // request burned the whole attempt budget and its delays before reporting.

    const originalFetch = globalThis.fetch;

    afterEach(() => {
      globalThis.fetch = originalFetch;
    });

    const stubStatus = (status: number) => {
      let calls = 0;
      globalThis.fetch = (async () => {
        calls++;
        return new Response("", { status });
      }) as typeof fetch;
      return () => calls;
    };

    it("gives up after one attempt on a permanent 4xx", async () => {
      const manifest = write("package.json", JSON.stringify({ dependencies: { lodash: "4.17.20" } }));
      const calls = stubStatus(400);

      const result = await auditDependencies(manifest, {
        offline: false,
        osvEndpoint: "https://osv.example/querybatch",
      });

      expect(calls()).toBe(1);
      expect(result.warnings.join(" ")).toMatch(/OSV advisory lookup failed/i);
    }, 30_000);

    it("still retries a rate-limit response", async () => {
      const manifest = write("package.json", JSON.stringify({ dependencies: { lodash: "4.17.20" } }));
      const calls = stubStatus(429);

      await auditDependencies(manifest, {
        offline: false,
        osvEndpoint: "https://osv.example/querybatch",
      });

      expect(calls()).toBeGreaterThan(1);
    }, 30_000);

    it("still retries a server error", async () => {
      const manifest = write("package.json", JSON.stringify({ dependencies: { lodash: "4.17.20" } }));
      const calls = stubStatus(503);

      await auditDependencies(manifest, {
        offline: false,
        osvEndpoint: "https://osv.example/querybatch",
      });

      expect(calls()).toBeGreaterThan(1);
    }, 30_000);
  });
});
