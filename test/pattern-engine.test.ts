import { describe, expect, it } from "vitest";
import { detectLanguage, maskCode, scanCode, shouldSkipFile } from "../src/scanner/pattern-engine.js";
import { getAllPatterns, getPatternsByLanguage } from "../src/patterns/index.js";

describe("detectLanguage", () => {
  it("maps common extensions", () => {
    expect(detectLanguage("a.ts")).toBe("typescript");
    expect(detectLanguage("a.tsx")).toBe("typescript");
    expect(detectLanguage("a.js")).toBe("javascript");
    expect(detectLanguage("a.py")).toBe("python");
    expect(detectLanguage("a.go")).toBe("go");
    expect(detectLanguage("main.tf")).toBe("terraform");
  });

  it("recognises Dockerfile and .env by name", () => {
    expect(detectLanguage("/srv/Dockerfile")).toBe("docker");
    expect(detectLanguage("/srv/.env")).toBe("env");
    expect(detectLanguage("/srv/.env.production")).toBe("env");
  });

  it("returns unknown for unrecognised extensions", () => {
    expect(detectLanguage("a.xyz")).toBe("unknown");
    expect(detectLanguage("noextension")).toBe("unknown");
  });

  it("is case-insensitive", () => {
    expect(detectLanguage("A.TS")).toBe("typescript");
  });
});

describe("shouldSkipFile", () => {
  it("skips binary and media extensions", () => {
    expect(shouldSkipFile("logo.png")).toBe(true);
    expect(shouldSkipFile("archive.zip")).toBe(true);
  });

  it("skips minified bundles", () => {
    expect(shouldSkipFile("app.min.js")).toBe(true);
    expect(shouldSkipFile("style.min.css")).toBe(true);
  });

  it("skips lockfiles", () => {
    expect(shouldSkipFile("yarn.lock")).toBe(true);
  });

  it("skips dependency and build directories on both separator styles", () => {
    expect(shouldSkipFile("/project/node_modules/pkg/index.js")).toBe(true);
    expect(shouldSkipFile("C:\\project\\node_modules\\pkg\\index.js")).toBe(true);
    expect(shouldSkipFile("/project/dist/out.js")).toBe(true);
  });

  it("does not skip ordinary source files", () => {
    expect(shouldSkipFile("/project/src/app.ts")).toBe(false);
  });

  it("skips the reports Sentinel itself writes", () => {
    // Otherwise a second scan reports findings inside the first scan's report:
    // a SARIF file embeds the matched line of every finding.
    expect(shouldSkipFile("/project/sentinel-report.md")).toBe(true);
    expect(shouldSkipFile("/project/sentinel-report.html")).toBe(true);
    expect(shouldSkipFile("/project/sentinel-report.sarif")).toBe(true);
    expect(shouldSkipFile("/project/.sentinel-baseline.json")).toBe(true);
  });

  it("does not skip a project file that merely mentions the name", () => {
    expect(shouldSkipFile("/project/src/sentinel-reporter.ts")).toBe(false);
    expect(shouldSkipFile("/project/docs/sentinel-report-format.md")).toBe(false);
  });

  it("ignores directory names above the scan root", () => {
    // A checkout living under a directory called "build" or "env" is ordinary.
    // Matching those names against the absolute path skipped every file in the
    // project and the scan reported a clean result.
    expect(shouldSkipFile("/Users/dev/build/myapp/src/app.ts", "/Users/dev/build/myapp")).toBe(false);
    expect(shouldSkipFile("/Users/dev/env/myapp/src/app.ts", "/Users/dev/env/myapp")).toBe(false);
    expect(shouldSkipFile("/home/vendor/site/index.js", "/home/vendor/site")).toBe(false);
  });

  it("still skips those directories when they sit inside the scan root", () => {
    expect(shouldSkipFile("/Users/dev/build/myapp/dist/out.js", "/Users/dev/build/myapp")).toBe(true);
    expect(shouldSkipFile("/Users/dev/build/myapp/node_modules/p/i.js", "/Users/dev/build/myapp")).toBe(true);
  });
});

describe("file context is judged inside the scan root", () => {
  // getFileContext downgrades findings in test and fixture files. Reading the
  // absolute path meant a checkout under a directory named "test" downgraded
  // every finding in the project to low confidence.

  it("treats production code under a parent named test as production", () => {
    const code = 'const h = crypto.createHash("md5").update(p).digest("hex");';
    const inProject = scanCode(code, "/Users/dev/test/myapp/src/hash.js", undefined, "/Users/dev/test/myapp");
    const plain = scanCode(code, "/Users/dev/myapp/src/hash.js", undefined, "/Users/dev/myapp");

    expect(inProject.findings).toHaveLength(1);
    expect(inProject.findings[0].severity).toBe(plain.findings[0].severity);
  });

  it("still downgrades a test file inside the scan root", () => {
    const code = 'const h = crypto.createHash("md5").update(p).digest("hex");';
    const production = scanCode(code, "/Users/dev/myapp/src/hash.js", undefined, "/Users/dev/myapp");
    const test = scanCode(code, "/Users/dev/myapp/test/hash.test.js", undefined, "/Users/dev/myapp");

    expect(production.findings).toHaveLength(1);
    expect(test.findings[0]?.severity).not.toBe(production.findings[0].severity);
  });
});

describe("PY_YAML_LOAD distinguishes the safe call from the unsafe one", () => {
  const scan = (code: string) =>
    scanCode(code, "/proj/load.py", undefined, "/proj").findings.map((f) => f.ruleId);

  it("flags yaml.load with no loader", () => {
    expect(scan("data = yaml.load(stream)")).toContain("PY_YAML_LOAD");
  });

  it("flags a loader that still executes tags", () => {
    expect(scan("data = yaml.load(stream, Loader=yaml.FullLoader)")).toContain("PY_YAML_LOAD");
    expect(scan("data = yaml.load(stream, Loader=yaml.Loader)")).toContain("PY_YAML_LOAD");
  });

  it("leaves the safe loaders alone", () => {
    // The negative lookahead sat after a greedy [^)]*, and backtracking always
    // satisfied it, so the documented safe form was reported as critical RCE.
    expect(scan("data = yaml.load(stream, Loader=yaml.SafeLoader)")).not.toContain("PY_YAML_LOAD");
    expect(scan("data = yaml.load(stream, Loader=yaml.CSafeLoader)")).not.toContain("PY_YAML_LOAD");
    expect(scan("data = yaml.load(stream, Loader=yaml.BaseLoader)")).not.toContain("PY_YAML_LOAD");
  });
});

describe("infrastructure-as-code rules reach their files", () => {
  it("applies Dockerfile rules to a Dockerfile", () => {
    // The rules declared language "dockerfile"; detectLanguage returns
    // "docker", and nothing treats the two as the same, so they never ran.
    const result = scanCode("FROM node:20\nUSER root\n", "/proj/Dockerfile", undefined, "/proj");
    expect(result.findings.map((f) => f.ruleId)).toContain("IAC_DOCKERFILE_EXPLICIT_ROOT_USER");
  });

  it("flags a remote ADD and a curl-pipe-shell build step", () => {
    const dockerfile = [
      "FROM debian:12",
      "ADD https://example.com/tool.tar.gz /tmp/",
      "RUN curl -fsSL https://example.com/install.sh | sh",
    ].join("\n");
    const ids = scanCode(dockerfile, "/proj/Dockerfile", undefined, "/proj").findings.map((f) => f.ruleId);

    expect(ids).toContain("IAC_DOCKERFILE_REMOTE_ADD");
    expect(ids).toContain("IAC_DOCKERFILE_CURL_PIPE_SHELL");
  });

  it("flags an open ingress CIDR on the line that carries it", () => {
    // The rule this replaced spanned two lines with [\s\S]{0,100}, which this
    // engine never sees, so an open security group went unreported.
    const terraform = [
      'resource "aws_security_group" "web" {',
      "  ingress {",
      "    from_port   = 22",
      "    to_port     = 22",
      '    cidr_blocks = ["0.0.0.0/0"]',
      "  }",
      "}",
    ].join("\n");
    const findings = scanCode(terraform, "/proj/main.tf", undefined, "/proj").findings;
    const open = findings.find((f) => f.ruleId === "IAC_TERRAFORM_PUBLIC_INGRESS_CIDR");

    expect(open).toBeDefined();
    expect(open!.line).toBe(5);
  });

  it("leaves a restricted CIDR alone", () => {
    const terraform = '    cidr_blocks = ["10.0.0.0/8"]';
    const ids = scanCode(terraform, "/proj/main.tf", undefined, "/proj").findings.map((f) => f.ruleId);
    expect(ids).not.toContain("IAC_TERRAFORM_PUBLIC_INGRESS_CIDR");
  });
});

describe("credential rules redact whatever category they are filed under", () => {
  // Redaction was keyed on the category alone. HARDCODED_JWT_SECRET is filed
  // under "auth" and matches a literal signing key, so the key was echoed into
  // lineContent and travelled into SARIF uploaded to GitHub code scanning, the
  // HTML report, and MCP responses.

  it("redacts a hardcoded JWT signing secret", () => {
    const secret = "S3cr3t-Pr0d-JWT-Key-9f2a";
    const findings = scanCode(
      `const t = jwt.sign({ id: 1 }, '${secret}');`,
      "/proj/a.js",
      undefined,
      "/proj"
    ).findings;

    const jwt = findings.find((f) => f.ruleId === "HARDCODED_JWT_SECRET");
    expect(jwt).toBeDefined();
    expect(jwt!.category).toBe("auth");
    expect(jwt!.lineContent).not.toContain(secret);
  });

  it("still redacts rules in the secrets category", () => {
    const key = "AKIAIOSFODNN7EXAMPLE";
    const findings = scanCode(`const k = "${key}";`, "/proj/a.js", undefined, "/proj").findings;

    for (const finding of findings) expect(finding.lineContent).not.toContain(key);
  });

  it("leaves an ordinary line readable", () => {
    const findings = scanCode(
      'const h = crypto.createHash("md5").update(pw).digest("hex");',
      "/proj/a.js",
      undefined,
      "/proj"
    ).findings;

    const hash = findings.find((f) => f.ruleId === "WEAK_HASH_MD5");
    expect(hash!.lineContent).toContain("createHash");
  });
});

describe("maskCode", () => {
  it("preserves length so offsets stay valid", () => {
    const code = 'const a = "secret value"; // trailing note';
    expect(maskCode(code, "javascript")).toHaveLength(code.length);
  });

  it("preserves line count so line numbers stay correct", () => {
    const code = "line1\n// comment\nline3\n";
    expect(maskCode(code, "javascript").split("\n")).toHaveLength(code.split("\n").length);
  });

  it("blanks single-line comment contents", () => {
    expect(maskCode("// eval(userInput)", "javascript")).not.toContain("eval");
  });

  it("blanks block comment contents", () => {
    expect(maskCode("/* eval(x) */ const a = 1;", "javascript")).not.toContain("eval");
  });

  it("blanks python comments and docstrings", () => {
    expect(maskCode("# os.system(x)", "python")).not.toContain("os.system");
    expect(maskCode('"""os.system(x)"""', "python")).not.toContain("os.system");
  });

  it("blanks string literal contents but keeps the quotes", () => {
    const masked = maskCode('const a = "eval(x)";', "javascript");
    expect(masked).not.toContain("eval");
    expect(masked).toContain('"');
  });

  it("keeps template literal interpolations visible", () => {
    // The static text of a template is data; ${...} is executable code and is
    // exactly where injection findings live.
    const masked = maskCode("const q = `SELECT * FROM t WHERE id = ${userId}`;", "javascript");
    expect(masked).toContain("userId");
    expect(masked).not.toContain("SELECT");
  });

  it("handles an unterminated string without hanging", () => {
    expect(() => maskCode('const a = "unterminated', "javascript")).not.toThrow();
  });

  it("handles an empty input", () => {
    expect(maskCode("", "javascript")).toBe("");
  });

  it("keeps string contents when maskStrings is disabled", () => {
    const masked = maskCode('crypto.createHash("md5")', "javascript", { maskStrings: false });
    expect(masked).toContain("md5");
  });

  it("still blanks comments when maskStrings is disabled", () => {
    const masked = maskCode('// createHash("md5")', "javascript", { maskStrings: false });
    expect(masked).not.toContain("md5");
  });

  it("still blanks python docstrings when maskStrings is disabled", () => {
    const masked = maskCode('"""os.system(cmd)"""', "python", { maskStrings: false });
    expect(masked).not.toContain("os.system");
  });

  it("preserves length in both scopes so offsets stay comparable", () => {
    const code = 'const h = createHash("md5"); // note';
    expect(maskCode(code, "javascript", { maskStrings: false })).toHaveLength(code.length);
  });
});

describe("literal match scope", () => {
  it("detects a weak hash algorithm named inside a string literal", () => {
    // The evidence ("md5") lives inside the string, so this can only be found
    // by a rule that opts out of string masking.
    const result = scanCode('const h = crypto.createHash("md5").update(p).digest("hex");', "app.js");
    expect(result.findings.some((finding) => finding.ruleId === "WEAK_HASH_MD5")).toBe(true);
  });

  it("detects a disabled JWT signature check written as a string key", () => {
    const result = scanCode('data = jwt.decode(token, options={"verify_signature": False})', "auth.py");
    expect(result.findings.some((finding) => finding.ruleId === "PY_JWT_NO_VERIFY")).toBe(true);
  });

  it("detects a wildcard host allowlist", () => {
    const result = scanCode("ALLOWED_HOSTS = ['*']", "settings.py");
    expect(result.findings.some((finding) => finding.ruleId === "PY_DJANGO_ALLOWED_HOSTS_WILDCARD")).toBe(true);
  });

  it("does not fire literal-scope rules on commented-out code", () => {
    // Comments are blanked in both scopes, so widening to literals must not
    // reintroduce findings from documentation.
    expect(scanCode('// crypto.createHash("md5")', "app.js").findings).toHaveLength(0);
    expect(scanCode('# jwt.decode(t, options={"verify_signature": False})', "auth.py").findings).toHaveLength(0);
  });

  it("does not fire on a code example that is itself a string", () => {
    // The match begins inside the outer string, so this is prose about code.
    // Documentation and CWE examples must not be reported as vulnerabilities.
    const examples = [
      '  "const API_KEY = \'sk_live_abc123def456\'",',
      '  "password = \'admin123\'",',
      "  \"crypto.createHash('md5')\",",
    ].join("\n");
    expect(scanCode(examples, "src/knowledge-base.ts").findings).toHaveLength(0);
  });

  it("still fires when only the argument is a string", () => {
    // The counterpart to the case above: the call itself is executable code.
    const result = scanCode('crypto.createHash("md5");', "app.js");
    expect(result.findings.some((f) => f.ruleId === "WEAK_HASH_MD5")).toBe(true);
  });
});

describe("false positive regressions", () => {
  it("does not flag ordinary English words containing cipher names", () => {
    // "includes" and "overrides" end in "des". A weak-cipher rule that fires on
    // them destroys trust in the entire crypto category.
    const code = [
      "const includeRecommendedUpgrades = options.includeRecommendedUpgrades ?? true;",
      'const overrides = { "a": 1 };',
      "if (list.includes(value)) return;",
    ].join("\n");
    expect(scanCode(code, "app.ts").findings.filter((f) => f.ruleId === "WEAK_CIPHER_DES")).toHaveLength(0);
  });

  it("still flags a genuinely weak cipher", () => {
    expect(
      scanCode('const c = crypto.createCipheriv("des-ede3", key, iv);', "app.js")
        .findings.some((f) => f.ruleId === "WEAK_CIPHER_DES")
    ).toBe(true);
    expect(
      scanCode('const c = crypto.createCipheriv("rc4", key, iv);', "app.js")
        .findings.some((f) => f.ruleId === "WEAK_CIPHER_DES")
    ).toBe(true);
  });

  it("downgrades findings in Sentinel's own rule definitions", () => {
    const yaml = scanCode("pattern: pickle.loads($DATA)", "rules/sentinel-core.yml");
    expect(yaml.summary.critical + yaml.summary.high).toBe(0);
  });

  it("does not flag __proto__ used as a lookup-table key", () => {
    const code = 'const map = { "prototype pollution": "CWE-1321", "__proto__": "CWE-1321" };';
    expect(scanCode(code, "app.ts").findings.filter((f) => f.ruleId === "PROTO_ACCESS")).toHaveLength(0);
  });

  it("still flags real prototype access", () => {
    expect(
      scanCode('obj["__proto__"] = payload;', "app.js").findings.some((f) => f.ruleId === "PROTO_ACCESS")
    ).toBe(true);
    expect(
      scanCode("target.__proto__ = source;", "app.js").findings.some((f) => f.ruleId === "PROTO_ACCESS")
    ).toBe(true);
  });

  it("still flags constructor.prototype access", () => {
    expect(
      scanCode('obj["constructor"]["prototype"].polluted = 1;', "app.js")
        .findings.some((f) => f.ruleId === "CONSTRUCTOR_PROTOTYPE")
    ).toBe(true);
  });

  it("does not flag a numeric log-level constant as debug mode", () => {
    // `debug: 10` in a level map must not match as `debug: 1`.
    const code = "const LEVEL_RANK = { debug: 10, info: 20, warn: 30 };";
    expect(scanCode(code, "logger.ts").findings.filter((f) => f.ruleId === "DEBUG_MODE_PROD")).toHaveLength(0);
  });

  it("flags an unpinned action in both YAML forms", () => {
    // `- uses:` is the inline list-item form most real workflows use. The rule
    // anchored on `^\s*uses:` and silently missed every one of them.
    const listForm = scanCode("      - uses: actions/checkout@v4", ".github/workflows/ci.yml");
    const blockForm = scanCode("        uses: actions/checkout@v4", ".github/workflows/ci.yml");

    expect(listForm.findings.some((f) => f.ruleId === "IAC_GITHUB_ACTIONS_UNPINNED_ACTION")).toBe(true);
    expect(blockForm.findings.some((f) => f.ruleId === "IAC_GITHUB_ACTIONS_UNPINNED_ACTION")).toBe(true);
  });

  it("accepts an action pinned to a full commit SHA", () => {
    const pinned = scanCode(
      "      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4",
      ".github/workflows/ci.yml"
    );
    expect(pinned.findings.filter((f) => f.ruleId === "IAC_GITHUB_ACTIONS_UNPINNED_ACTION")).toHaveLength(0);
  });

  it("still flags debug mode enabled in production config", () => {
    expect(
      scanCode("DEBUG = True", "settings.py").findings.some((f) => f.ruleId === "DEBUG_MODE_PROD")
    ).toBe(true);
    expect(
      scanCode("const config = { debug: true };", "app.js").findings.some((f) => f.ruleId === "DEBUG_MODE_PROD")
    ).toBe(true);
  });
});

describe("pattern registry", () => {
  it("exposes a non-empty pattern set", () => {
    expect(getAllPatterns().length).toBeGreaterThan(0);
  });

  it("returns the identical cached array on repeated calls", () => {
    expect(getAllPatterns()).toBe(getAllPatterns());
    expect(getPatternsByLanguage("python")).toBe(getPatternsByLanguage("python"));
  });

  it("gives every pattern a unique id", () => {
    const ids = getAllPatterns().map((pattern) => pattern.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("gives every pattern the required metadata", () => {
    for (const pattern of getAllPatterns()) {
      expect(pattern.id, `${pattern.id} id`).toBeTruthy();
      expect(pattern.cweId, `${pattern.id} cweId`).toMatch(/^CWE-\d+$/);
      expect(pattern.message, `${pattern.id} message`).toBeTruthy();
      expect(pattern.remediation, `${pattern.id} remediation`).toBeTruthy();
      expect(pattern.languages.length, `${pattern.id} languages`).toBeGreaterThan(0);
    }
  });

  it("filters by language and always includes wildcard patterns", () => {
    const python = getPatternsByLanguage("python");
    expect(python.length).toBeGreaterThan(0);
    expect(python.every((p) => p.languages.includes("python") || p.languages.includes("*"))).toBe(true);
  });
});

describe("scanCode", () => {
  it("returns no findings for benign code", () => {
    const result = scanCode("const total = a + b;\n", "app.js");
    expect(result.findings).toHaveLength(0);
    expect(result.summary).toEqual({ critical: 0, high: 0, medium: 0, low: 0, info: 0 });
  });

  it("detects eval on user input", () => {
    const result = scanCode("eval(req.body.code);", "app.js");
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it("detects SQL string interpolation", () => {
    const result = scanCode("db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);", "app.js");
    expect(result.findings.some((f) => f.cweId === "CWE-89")).toBe(true);
  });

  it("reports 1-indexed line numbers", () => {
    const result = scanCode("const a = 1;\nconst b = 2;\neval(req.body.x);", "app.js");
    expect(result.findings[0]?.line).toBe(3);
  });

  it("does not flag vulnerable-looking code inside comments", () => {
    expect(scanCode("// eval(req.body.code);", "app.js").findings).toHaveLength(0);
  });

  it("skips documentation files entirely", () => {
    expect(scanCode("eval(req.body.code)", "README.md").findings).toHaveLength(0);
  });

  it("downgrades severity in test files so fixtures do not dominate risk scores", () => {
    const production = scanCode("eval(req.body.code);", "src/app.js");
    const test = scanCode("eval(req.body.code);", "test/app.test.js");

    expect(production.findings.length).toBeGreaterThan(0);
    expect(test.findings.length).toBeGreaterThan(0);
    expect(test.summary.critical + test.summary.high).toBe(0);
  });

  it("assigns high confidence when user input is present on the line", () => {
    const result = scanCode("eval(req.body.code);", "app.js");
    expect(result.findings[0]?.confidence).toBe("high");
  });

  it("reports each rule at most once per line", () => {
    const result = scanCode("eval(req.body.a); eval(req.body.b);", "app.js");
    const keys = result.findings.map((f) => `${f.ruleId}:${f.line}`);
    expect(new Set(keys).size).toBe(keys.length);
  });

  it("keeps summary counts consistent with the findings list", () => {
    const result = scanCode("eval(req.body.code);\ndb.query('SELECT ' + req.query.q);", "app.js");
    const total = Object.values(result.summary).reduce((sum, count) => sum + count, 0);
    expect(total).toBe(result.findings.length);
    expect(result.totalFindings).toBe(result.findings.length);
  });

  it("skips minified single-line content instead of running every regex over it", () => {
    const line = `var a=1;${"x".repeat(60_000)}`;
    const start = Date.now();
    expect(scanCode(line, "bundle.js").findings).toHaveLength(0);
    expect(Date.now() - start).toBeLessThan(5_000);
  });

  it("produces identical results across repeated runs", () => {
    const code = "eval(req.body.code);\ndb.query('SELECT ' + req.query.q);";
    expect(JSON.stringify(scanCode(code, "a.js"))).toBe(JSON.stringify(scanCode(code, "a.js")));
  });
});
