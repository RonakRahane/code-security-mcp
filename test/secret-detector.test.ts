import { describe, expect, it } from "vitest";
import {
  calculateEntropy,
  detectSecrets,
  maskSecretValue,
  redactLine,
} from "../src/scanner/secret-detector.js";

describe("calculateEntropy", () => {
  it("returns 0 for an empty string", () => {
    expect(calculateEntropy("")).toBe(0);
  });

  it("returns 0 when every character is identical", () => {
    expect(calculateEntropy("aaaaaaaa")).toBe(0);
  });

  it("returns 1 bit for a balanced two-symbol string", () => {
    expect(calculateEntropy("abab")).toBeCloseTo(1, 10);
  });

  it("returns log2(n) for n distinct equally-frequent characters", () => {
    expect(calculateEntropy("abcd")).toBeCloseTo(2, 10);
    expect(calculateEntropy("abcdefgh")).toBeCloseTo(3, 10);
  });

  it("rates random-looking strings above English prose", () => {
    const random = calculateEntropy("xQ7#kL9!mZ2$pW4&");
    const prose = calculateEntropy("the quick brown fox");
    expect(random).toBeGreaterThan(prose);
  });
});

describe("maskSecretValue", () => {
  it("fully masks short values", () => {
    expect(maskSecretValue("abc")).not.toContain("abc");
    expect(maskSecretValue("abcd1234")).not.toContain("1234");
  });

  it("keeps a four-character prefix so the credential type stays identifiable", () => {
    const masked = maskSecretValue("AKIAIOSFODNN7EXAMPLE");
    expect(masked.startsWith("AKIA")).toBe(true);
    expect(masked).not.toContain("IOSFODNN7EXAMPLE");
  });

  it("never returns the original value", () => {
    const secret = "ghp_1234567890abcdefghijklmnopqrstuvwx";
    expect(maskSecretValue(secret)).not.toBe(secret);
  });
});

describe("redactLine", () => {
  it("removes the secret from the surrounding source line", () => {
    const secret = "AKIAIOSFODNN7EXAMPLE";
    const redacted = redactLine(`const key = "${secret}";`, [secret]);
    expect(redacted).not.toContain(secret);
    expect(redacted).toContain("const key =");
  });

  it("leaves the line unchanged when there is nothing to redact", () => {
    expect(redactLine("const a = 1;", [])).toBe("const a = 1;");
  });

  it("redacts a longer secret that contains a shorter one", () => {
    const long = "sk_live_abcdefghijklmnop";
    const short = "abcdefghijklmnop";
    const redacted = redactLine(`x = "${long}"`, [short, long]);
    expect(redacted).not.toContain(long);
    expect(redacted).not.toContain(short);
  });
});

describe("detectSecrets", () => {
  it("detects an AWS access key id", () => {
    const findings = detectSecrets('const key = "AKIAIOSFODNN7EXAMPLE";', "config.js");
    expect(findings.some((finding) => finding.ruleId === "AWS_ACCESS_KEY_ID")).toBe(true);
  });

  it("never echoes the detected secret back in lineContent", () => {
    const secret = "AKIAIOSFODNN7EXAMPLE";
    const findings = detectSecrets(`const key = "${secret}";`, "config.js");
    expect(findings.length).toBeGreaterThan(0);
    for (const finding of findings) {
      expect(finding.lineContent).not.toContain(secret);
    }
  });

  it("reports the correct 1-indexed line number", () => {
    const code = ["// header", "", 'const t = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";'].join("\n");
    const findings = detectSecrets(code, "a.js");
    expect(findings[0]?.line).toBe(3);
  });

  it("ignores values loaded from the environment", () => {
    const findings = detectSecrets('const key = process.env.API_KEY;', "a.js");
    expect(findings).toHaveLength(0);
  });

  it("ignores commented-out lines", () => {
    const findings = detectSecrets('// const key = "AKIAIOSFODNN7EXAMPLE";', "a.js");
    expect(findings).toHaveLength(0);
  });

  it("does not flag integrity digests in a lockfile", () => {
    const line = '"integrity": "sha512-Ck6dK5j9pJoRQlZ2WHVCG0mfhVLFwLxCFsPMPKQ2ZeKlFvhBiUvBGnbF0LKGN1sfDBcQ3lLTZAmL0nHOwEBFtQ=="';
    expect(detectSecrets(line, "package-lock.json")).toHaveLength(0);
  });

  it("does not flag a git commit SHA", () => {
    expect(detectSecrets('const rev = "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3";', "a.js")).toHaveLength(0);
  });

  it("does not flag a UUID", () => {
    expect(detectSecrets('const id = "550e8400-e29b-41d4-a716-446655440000";', "a.js")).toHaveLength(0);
  });

  it("does not flag obvious placeholders", () => {
    expect(detectSecrets('const key = "your-api-key-goes-here";', "a.js")).toHaveLength(0);
    expect(detectSecrets('const key = "xxxxxxxxxxxxxxxxxxxxxxxx";', "a.js")).toHaveLength(0);
  });

  it("does not flag a URL", () => {
    expect(detectSecrets('const url = "https://example.com/some/long/path/here";', "a.js")).toHaveLength(0);
  });

  it("does not flag regular expression sources as high-entropy secrets", () => {
    // Any codebase that defines patterns is otherwise flooded with these, and
    // a scanner's own rule files worst of all.
    const lines = [
      String.raw`const re = "(?:createHash|hashlib\.md5)\s*\(\s*['\"]?md5['\"]?\s*\)";`,
      String.raw`const re2 = "[A-Za-z0-9+/=]{20,}\\s*[:=]";`,
      String.raw`const re3 = "(?:password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{8,}['\"]";`,
    ];
    for (const line of lines) {
      expect(detectSecrets(line, "patterns.ts").filter((f) => f.ruleId === "HIGH_ENTROPY_SECRET")).toHaveLength(0);
    }
  });

  it("still flags a genuine high-entropy credential", () => {
    const findings = detectSecrets('const value = "xQ7kL9mZ2pW4vB8nR3tY6uI1oP5aS0dF";', "a.js");
    expect(findings.some((f) => f.ruleId === "HIGH_ENTROPY_SECRET")).toBe(true);
  });

  it("skips extremely long lines rather than running regexes over them", () => {
    const line = `const data = "${"a".repeat(50_000)}";`;
    expect(() => detectSecrets(line, "bundle.js")).not.toThrow();
    expect(detectSecrets(line, "bundle.js")).toHaveLength(0);
  });

  it("flags a hardcoded value assigned to a secret-named variable", () => {
    const findings = detectSecrets(`const apiToken = "xQ7kL9mZ2pW4vB8nR3tY6uI1oP5aS0dF";`, "a.js");
    expect(findings.some((finding) => finding.ruleId === "GENERIC_SECRET_CONST")).toBe(true);
  });

  it("still reports a weak hardcoded password rather than dismissing it as prose", () => {
    const findings = detectSecrets(`const password = "correcthorsebattery";`, "a.js");
    expect(findings.length).toBeGreaterThan(0);
  });

  it("finds high-entropy values even without a secret-sounding variable name", () => {
    const findings = detectSecrets(`const value = "xQ7kL9mZ2pW4vB8nR3tY6uI1oP5aS0dF";`, "a.js");
    expect(findings.some((finding) => finding.ruleId === "HIGH_ENTROPY_SECRET")).toBe(true);
  });

  it("reports at most one entropy finding per line", () => {
    const line = `const a = "xQ7kL9mZ2pW4vB8nR3tY6uI1oP5aS0dF", b = "zH4jK8nM3qR7tV1wY5bC9dG2fJ6lN0pS";`;
    const entropyFindings = detectSecrets(line, "a.js").filter((f) => f.ruleId === "HIGH_ENTROPY_SECRET");
    expect(entropyFindings).toHaveLength(1);
  });

  it("returns findings sorted most severe first", () => {
    const code = [
      'const value = "xQ7kL9mZ2pW4vB8nR3tY6uI1oP5aS0dF";',
      'const key = "AKIAIOSFODNN7EXAMPLE";',
    ].join("\n");
    const findings = detectSecrets(code, "a.js");
    expect(findings[0].severity).toBe("critical");
  });

  it("produces identical results across repeated runs", () => {
    const code = 'const key = "AKIAIOSFODNN7EXAMPLE";\nconst t = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";';
    expect(JSON.stringify(detectSecrets(code, "a.js"))).toBe(JSON.stringify(detectSecrets(code, "a.js")));
  });
});
