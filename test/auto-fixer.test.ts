import { describe, expect, it } from "vitest";
import { generateFixes, getFixableRules } from "../src/scanner/auto-fixer.js";
import { Finding } from "../src/types/index.js";
import * as cryptoModule from "node:crypto";

/**
 * Auto-fix rewrites the user's source. That makes a wrong patch worse than no
 * patch: it silently changes working code on the strength of a regex match.
 *
 * These tests hold every generator to three properties: it never invents a fix
 * for a line it does not understand, it never emits a patch identical to the
 * vulnerable line, and it never claims "high" confidence for a rewrite that
 * needs human judgement.
 */

const finding = (ruleId: string, line: number, overrides: Partial<Finding> = {}): Finding => ({
  ruleId,
  severity: "high",
  category: "injection",
  cweId: "CWE-89",
  message: "test finding",
  filePath: "/project/app.js",
  line,
  lineContent: "",
  remediation: "",
  source: "compatibility",
  ...overrides,
});

describe("generateFixes", () => {
  it("returns nothing for a rule with no generator", () => {
    expect(generateFixes("const a = 1;\n", [finding("NO_SUCH_RULE", 1)])).toEqual([]);
  });

  it("returns nothing when the finding points past the end of the file", () => {
    // An out-of-range line yields an empty string, and a generator must not
    // manufacture a patch from nothing.
    const fixes = generateFixes("const a = 1;\n", [finding("SQL_INJECTION_TEMPLATE", 99)]);
    expect(fixes).toEqual([]);
  });

  it("parameterises an interpolated SQL query", () => {
    const code = "const rows = await db.query(`SELECT * FROM users WHERE id = ${userId}`);\n";
    const [fix] = generateFixes(code, [finding("SQL_INJECTION_TEMPLATE", 1)]);

    expect(fix).toBeDefined();
    expect(fix.after).not.toContain("${userId}");
    expect(fix.after).toContain("userId");
    expect(fix.explanation).toContain("userId");
  });

  it("declines a SQL template it cannot rewrite safely", () => {
    // No recognised query call, so there is nothing the generator can assert
    // about the surrounding code.
    const code = "const label = `id = ${userId}`;\n";
    expect(generateFixes(code, [finding("SQL_INJECTION_TEMPLATE", 1)])).toEqual([]);
  });

  it("rewrites a weak hash to SHA-256", () => {
    const code = 'const h = crypto.createHash("md5").update(pw).digest("hex");\n';
    const [fix] = generateFixes(code, [finding("WEAK_HASH_MD5", 1, { category: "crypto" })]);

    expect(fix).toBeDefined();
    expect(fix.after.toLowerCase()).not.toContain("md5");
    expect(fix.after).toContain("sha256");
  });

  it("replaces Math.random in a security context with a CSPRNG", () => {
    const code = "const token = Math.random().toString(36).substring(2);\n";
    const [fix] = generateFixes(code, [finding("MATH_RANDOM_SECURITY", 1, { category: "crypto" })]);

    expect(fix).toBeDefined();
    expect(fix.after).not.toContain("Math.random");
    expect(fix.after).toMatch(/randomBytes|randomInt|randomUUID|getRandomValues/);
  });

  it("moves a hardcoded secret into the environment", () => {
    const code = 'const JWT_SECRET = "my-jwt-secret-that-should-be-in-env";\n';
    const [fix] = generateFixes(code, [finding("GENERIC_SECRET_CONST", 1, { category: "secrets" })]);

    expect(fix).toBeDefined();
    expect(fix.after).toContain("process.env");
    // The patch is written into the user's file and may be committed. It must
    // never carry the credential it was meant to remove.
    expect(fix.after).not.toContain("my-jwt-secret-that-should-be-in-env");
  });

  it("produces fixes for several findings in one pass", () => {
    const code = [
      'const h = crypto.createHash("md5").update(pw).digest("hex");',
      "const token = Math.random().toString(36);",
      "",
    ].join("\n");

    const fixes = generateFixes(code, [
      finding("WEAK_HASH_MD5", 1, { category: "crypto" }),
      finding("MATH_RANDOM_SECURITY", 2, { category: "crypto" }),
    ]);

    expect(fixes).toHaveLength(2);
    expect(fixes.map((f) => f.line)).toEqual([1, 2]);
  });

  it("never emits a patch that leaves the line unchanged", () => {
    const samples: Array<[string, string]> = [
      ["SQL_INJECTION_TEMPLATE", "const r = await db.query(`SELECT * FROM t WHERE id = ${id}`);"],
      ["SQL_INJECTION_CONCAT", 'const r = await db.query("SELECT * FROM t WHERE n = \'" + n + "\'");'],
      ["COMMAND_INJECTION_EXEC", "exec(`ping -c 1 ${host}`);"],
      ["EVAL_USAGE", "const result = eval(expression);"],
      ["XSS_INNERHTML", 'document.getElementById("out").innerHTML = userData;'],
      ["XSS_DOCUMENT_WRITE", "document.write(userInput);"],
      ["GENERIC_PASSWORD_ASSIGN", 'const dbPassword = "super_secret_password_123";'],
      ["GENERIC_SECRET_CONST", 'const API_KEY = "sk_live_abc123def456";'],
      ["WEAK_HASH_MD5", 'crypto.createHash("md5").update(pw).digest("hex");'],
      ["MATH_RANDOM_SECURITY", "const token = Math.random().toString(36);"],
      ["JWT_NO_VERIFY", "const decoded = jwt.decode(req.headers.authorization);"],
      ["HARDCODED_JWT_SECRET", 'const token = jwt.sign({ id }, "hardcoded-secret-key");'],
      ["BCRYPT_LOW_ROUNDS", "const hash = await bcrypt.hash(password, 4);"],
      ["SESSION_NO_SECURE", "app.use(session({ secret: s, cookie: { secure: false } }));"],
      ["CORS_WILDCARD", 'res.setHeader("Access-Control-Allow-Origin", "*");'],
      ["OPEN_REDIRECT", "res.redirect(req.query.url);"],
      ["PATH_TRAVERSAL_FS", 'const content = fs.readFileSync("/uploads/" + filename, "utf-8");'],
      ["PY_SQL_INJECTION_FORMAT", 'cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)'],
      ["PY_PICKLE_LOAD", "data = pickle.loads(request.data)"],
      ["PY_YAML_LOAD", "config = yaml.load(stream)"],
      ["PY_OS_SYSTEM", 'os.system("ping -c 1 " + host)'],
      ["PY_FLASK_RENDER_STRING", "return render_template_string(template)"],
      ["PY_HASHLIB_MD5", "digest = hashlib.md5(password.encode()).hexdigest()"],
      ["PY_FLASK_DEBUG", "app.run(debug=True)"],
      ["PY_DJANGO_DEBUG", "DEBUG = True"],
    ];

    for (const [ruleId, line] of samples) {
      const fixes = generateFixes(`${line}\n`, [finding(ruleId, 1)]);
      for (const fix of fixes) {
        expect(fix.after.trim(), `${ruleId} produced a no-op patch`).not.toBe(fix.before.trim());
        expect(fix.before.trim()).toBe(line.trim());
        expect(fix.ruleId).toBe(ruleId);
        expect(fix.line).toBe(1);
        expect(fix.explanation.length).toBeGreaterThan(0);
        expect(["high", "medium", "low"]).toContain(fix.confidence);
      }
    }
  });

  it("never claims high confidence for a rewrite that changes call semantics", () => {
    // A "high" confidence fix is documented as safe to apply unreviewed, so a
    // rewrite that changes a call's arguments or callee cannot claim it.
    const semanticRewrites = ["SQL_INJECTION_TEMPLATE", "SQL_INJECTION_CONCAT", "COMMAND_INJECTION_EXEC", "EVAL_USAGE"];

    const lines: Record<string, string> = {
      SQL_INJECTION_TEMPLATE: "const r = await db.query(`SELECT * FROM t WHERE id = ${id}`);",
      SQL_INJECTION_CONCAT: 'const r = await db.query("SELECT * FROM t WHERE n = \'" + n + "\'");',
      COMMAND_INJECTION_EXEC: "exec(`ping -c 1 ${host}`);",
      EVAL_USAGE: "const result = eval(expression);",
    };

    for (const ruleId of semanticRewrites) {
      const fixes = generateFixes(`${lines[ruleId]}\n`, [finding(ruleId, 1)]);
      for (const fix of fixes) {
        expect(fix.confidence, `${ruleId} claims unreviewed-safe confidence`).not.toBe("high");
      }
    }
  });

  describe("GENERIC_PASSWORD_ASSIGN writes into the file's own language", () => {
    // auto_fix applies high-confidence patches in place, so a patch written in
    // the wrong language corrupts the file it was meant to secure.

    it("uses os.environ in Python, not process.env", () => {
      const code = 'password = "hunter2_not_a_real_secret"\n';
      const [fix] = generateFixes(code, [
        finding("GENERIC_PASSWORD_ASSIGN", 1, { filePath: "/project/app.py" }),
      ]);

      expect(fix).toBeDefined();
      expect(fix.after).not.toContain("process.env");
      expect(fix.after).toBe('password = os.environ["PASSWORD"]');
    });

    it("keeps an object literal parseable, separator and trailing comma intact", () => {
      const code = '  password: "hunter2_not_a_real_secret",\n';
      const [fix] = generateFixes(code, [
        finding("GENERIC_PASSWORD_ASSIGN", 1, { filePath: "/project/config.js" }),
      ]);

      expect(fix).toBeDefined();
      // Rebuilding the line from the name alone turned `key: value,` into an
      // assignment statement, which is a syntax error inside an object.
      expect(fix.after).toBe("password: process.env.PASSWORD,");
    });

    it("takes the variable name, not the type, from an annotated declaration", () => {
      const code = 'const dbPassword: string = "hunter2_not_a_real_secret";\n';
      const [fix] = generateFixes(code, [
        finding("GENERIC_PASSWORD_ASSIGN", 1, { filePath: "/project/app.ts" }),
      ]);

      expect(fix).toBeDefined();
      expect(fix.after).toBe("const dbPassword: string = process.env.DB_PASSWORD;");
    });

    it("declines JSON, which cannot read an environment variable at all", () => {
      const code = '  "password": "hunter2_not_a_real_secret"\n';
      const fixes = generateFixes(code, [
        finding("GENERIC_PASSWORD_ASSIGN", 1, { filePath: "/project/config.json" }),
      ]);

      expect(fixes).toEqual([]);
    });

    it("drops to low confidence for a language it has no accessor for", () => {
      const code = 'password: "hunter2_not_a_real_secret"\n';
      const [fix] = generateFixes(code, [
        finding("GENERIC_PASSWORD_ASSIGN", 1, { filePath: "/project/values.yaml" }),
      ]);

      expect(fix).toBeDefined();
      expect(fix.after).not.toContain("process.env");
      expect(fix.confidence).toBe("low");
    });
  });

  it("never claims high confidence for a patch naming identifiers that do not exist", () => {
    // auto_fix applies the high-confidence set in place. A patch that reads
    // "const safePath = path.resolve(BASE_DIR, userInput)" deletes the original
    // call and leaves two undefined names behind, which is worse than leaving
    // the vulnerability alone. Such a patch may be advisory, never automatic.
    const PLACEHOLDER = /\b(BASE_DIR|userInput|user_input|allowedHosts|ALLOWED_HOSTS|yourdomain|arg1|arg2)\b|\/\* args \*\/|\/\* content \*\/|\/\* \.\.\. \*\//;

    const lines: Record<string, string> = {
      PATH_TRAVERSAL_FS: "fs.readFile(req.query.path, cb);",
      OPEN_REDIRECT: "res.redirect(req.query.url);",
      PY_FLASK_RENDER_STRING: "return render_template_string(tpl)",
      COMMAND_INJECTION_EXEC: "exec(`ping ${host}`);",
      XSS_DOCUMENT_WRITE: "document.write(userInput);",
      PY_OS_SYSTEM: "os.system(cmd)",
      PY_PICKLE_LOAD: "obj = pickle.loads(data)",
      SQL_INJECTION_CONCAT: 'db.query("SELECT * FROM t WHERE a = " + req.query.a);',
      PY_SQL_INJECTION_FORMAT: 'cursor.execute(f"SELECT {x}")',
    };

    for (const [ruleId, line] of Object.entries(lines)) {
      for (const fix of generateFixes(`${line}\n`, [finding(ruleId, 1)])) {
        if (!PLACEHOLDER.test(fix.after)) continue;
        expect(
          fix.confidence,
          `${ruleId} would be applied unattended but its patch names identifiers that do not exist`
        ).not.toBe("high");
      }
    }
  });

  it("keeps the original statement whenever it claims high confidence", () => {
    // A high-confidence patch is written in place, so it has to be a complete
    // replacement rather than a sketch that drops the code it replaced.
    const cases: Array<[string, string, string]> = [
      ["WEAK_HASH_MD5", 'crypto.createHash("md5").update(p);', "createHash"],
      ["MATH_RANDOM_SECURITY", "const t = Math.random();", "const t ="],
      ["GENERIC_SECRET_CONST", 'const apiKey = "sk_live_abcdefghijklmnop";', "apiKey"],
      ["PY_HASHLIB_MD5", "h = hashlib.md5(data)", "hashlib"],
    ];

    for (const [ruleId, line, mustKeep] of cases) {
      for (const fix of generateFixes(`${line}\n`, [finding(ruleId, 1)])) {
        if (fix.confidence !== "high") continue;
        expect(fix.after, `${ruleId} dropped the statement it replaced`).toContain(mustKeep);
      }
    }
  });

  it("derives an environment variable name that splits on the case change", () => {
    const [fix] = generateFixes('const apiKey = "sk_live_abcdefghijklmnop";\n', [
      finding("GENERIC_SECRET_CONST", 1),
    ]);

    // Uppercasing before the split destroyed the boundary and produced APIKEY.
    expect(fix.after).toContain("API_KEY");
    expect(fix.after).not.toContain("APIKEY");
  });

  it("declines every generator when the line does not match its pattern", () => {
    // Feeding an unrelated line to each generator proves none of them fall back
    // to rewriting whatever they were handed.
    const unrelated = "const total = items.length + 1;";

    for (const ruleId of getFixableRules()) {
      const fixes = generateFixes(`${unrelated}\n`, [finding(ruleId, 1)]);
      for (const fix of fixes) {
        // A generator may still emit a comment-only advisory patch, but it must
        // not present the unrelated line back as fixed code.
        expect(fix.after.trim(), `${ruleId} rewrote an unrelated line`).not.toBe(unrelated);
      }
    }
  });
});

describe("getFixableRules", () => {
  it("lists rule identifiers, with no duplicates", () => {
    const rules = getFixableRules();
    expect(rules.length).toBeGreaterThan(0);
    expect(new Set(rules).size).toBe(rules.length);
    for (const rule of rules) expect(rule).toMatch(/^[A-Z0-9_]+$/);
  });
});

describe("generated fixes match the surrounding style", () => {
  it("keeps the quote character the line already used", () => {
    // The MD5 fix emitted 'sha256' whatever the source used, so a
    // double-quoted file linted clean before the fix and failed after it. A
    // fix meant to be applied unattended must not break the build it was run
    // to protect.
    const doubled = generateFixes(
      'const h = crypto.createHash("md5").update(x).digest("hex");\n',
      [finding("WEAK_HASH_MD5", 1)]
    );
    expect(doubled[0]?.after).toContain('createHash("sha256")');
    expect(doubled[0]?.after).not.toContain("'sha256'");

    const singled = generateFixes(
      "const h = crypto.createHash('md5').update(x).digest('hex');\n",
      [finding("WEAK_HASH_MD5", 1)]
    );
    expect(singled[0]?.after).toContain("createHash('sha256')");
  });
});

describe("no generator may emit code that will not parse", () => {
  // Three generators shipped patches that corrupted the file when applied: a
  // `// Replace with actual domains` appended mid-expression swallowed the
  // closing `);`, a `/* content */` placeholder produced `el.textContent = ;`,
  // and a trailing comment consumed a statement's own semicolon. Each read
  // fine as a diff. This sweeps every generator rather than pinning the three,
  // because the next one added would have the same opportunity.
  const CASES: Record<string, string> = {
    SQL_INJECTION_CONCAT: 'const r = db.query("SELECT * FROM u WHERE id = " + req.params.id);',
    EVAL_USAGE: "const v = eval(userInput);",
    XSS_INNERHTML: "el.innerHTML = userInput;",
    XSS_DOCUMENT_WRITE: "document.write(userInput);",
    WEAK_HASH_MD5: 'const h = crypto.createHash("md5").update(x).digest("hex");',
    MATH_RANDOM_SECURITY: "const token = Math.random().toString(36);",
    JWT_NO_VERIFY: "const p = jwt.decode(token);",
    HARDCODED_JWT_SECRET: 'const p = jwt.verify(token, "hardcodedsecret123");',
    BCRYPT_LOW_ROUNDS: "const h = await bcrypt.hash(pw, 4);",
    SESSION_NO_SECURE: "app.use(session({ cookie: { secure: false } }));",
    CORS_WILDCARD: 'res.setHeader("Access-Control-Allow-Origin", "*");',
    OPEN_REDIRECT: "res.redirect(req.query.next);",
    PATH_TRAVERSAL_FS: "const b = fs.readFileSync(req.query.file);",
  };

  for (const [ruleId, line] of Object.entries(CASES)) {
    it(`${ruleId} produces parseable JavaScript`, () => {
      const fixes = generateFixes(`${line}\n`, [finding(ruleId, 1)]);
      if (fixes.length === 0) return;   // declining to patch is always allowed
      const after = fixes[0].after;
      // Wrapped in a function body so `await` and bare statements are legal.
      expect(() => new Function(`async function _(){\n${after}\n}`)).not.toThrow();
    });
  }

  it("carries the written value into the document.write replacement", () => {
    // The old patch discarded it, so applying the fix also removed the
    // behaviour the line existed for.
    const fixes = generateFixes('document.write("<b>" + name + "</b>");\n', [
      finding("XSS_DOCUMENT_WRITE", 1),
    ]);
    expect(fixes[0]?.after).toContain('el.textContent = "<b>" + name + "</b>";');
  });

  it("replaces the CORS wildcard without commenting out the rest of the line", () => {
    const fixes = generateFixes('res.setHeader("Access-Control-Allow-Origin", "*");\n', [
      finding("CORS_WILDCARD", 1),
    ]);
    expect(fixes[0]?.after).toBe(
      'res.setHeader("Access-Control-Allow-Origin", "https://yourdomain.example");'
    );
  });

  it("keeps the quote style when the wildcard is single-quoted", () => {
    const fixes = generateFixes("app.use(cors({ origin: '*' }));\n", [
      finding("CORS_WILDCARD", 1),
    ]);
    expect(fixes[0]?.after).toBe("app.use(cors({ origin: 'https://yourdomain.example' }));");
  });
});

describe("a fix must not break the code it is applied to", () => {
  it("produces a Math.random() replacement that actually runs", () => {
    // The patch used crypto.randomInt(0, Number.MAX_SAFE_INTEGER). randomInt
    // accepts a range of at most 2**48, so every rewritten line threw
    // ERR_OUT_OF_RANGE on its first call. It parsed, so no syntax check would
    // have found it - this one has to be executed.
    const fixes = generateFixes(
      'const crypto = require("crypto");\nconst token = Math.random().toString(36);\n',
      [finding("MATH_RANDOM_SECURITY", 2)]
    );
    const expression = fixes[0].after.replace(/^const token = /, "").replace(/;$/, "");
    const evaluate = new Function("crypto", `return ${expression};`);
    // Repeated, because the old bound threw only when the range was sampled.
    for (let attempt = 0; attempt < 100; attempt++) {
      const value = evaluate(cryptoModule);
      expect(typeof value).toBe("string");
      expect(value.length).toBeGreaterThan(0);
    }
  });

  it("produces a hash replacement that actually runs", () => {
    const fixes = generateFixes(
      'const h = crypto.createHash("md5").update("x").digest("hex");\n',
      [finding("WEAK_HASH_MD5", 1)]
    );
    const expression = fixes[0].after.replace(/^const h = /, "").replace(/;$/, "");
    const value = new Function("crypto", `return ${expression};`)(cryptoModule);
    expect(value).toMatch(/^[0-9a-f]{64}$/);   // SHA-256, not MD5's 32
  });
});

describe("a fix that needs an import the file lacks is not applied unattended", () => {
  // Only high-confidence fixes are written to disk. MATH_RANDOM_SECURITY
  // introduced `crypto` into files that never imported it, so code that ran
  // before the fix threw ReferenceError after it. The suggestion is still
  // right, so it is downgraded rather than dropped.
  const line = "const token = Math.random().toString(36);";

  it("downgrades when the module is not in scope", () => {
    const fixes = generateFixes(`function f() {\n  ${line}\n}\n`, [
      finding("MATH_RANDOM_SECURITY", 2),
    ]);
    expect(fixes[0].confidence).toBe("medium");
    expect(fixes[0].explanation).toContain("does not import");
  });

  it("keeps high confidence when the module is required", () => {
    const fixes = generateFixes(`const crypto = require("crypto");\n${line}\n`, [
      finding("MATH_RANDOM_SECURITY", 2),
    ]);
    expect(fixes[0].confidence).toBe("high");
  });

  it("keeps high confidence when the module is imported as ESM", () => {
    const fixes = generateFixes(`import crypto from "node:crypto";\n${line}\n`, [
      finding("MATH_RANDOM_SECURITY", 2),
    ]);
    expect(fixes[0].confidence).toBe("high");
  });

  it("leaves a fix alone when the replaced line already used the module", () => {
    // WEAK_HASH_MD5 rewrites a crypto.createHash call, so crypto is in scope
    // by construction and the check must not downgrade it.
    const fixes = generateFixes(
      'function f() {\n  const h = crypto.createHash("md5").update(x);\n}\n',
      [finding("WEAK_HASH_MD5", 2)]
    );
    expect(fixes[0].confidence).toBe("high");
  });

  it("downgrades a Python fix that reaches for os without an import", () => {
    const fixes = generateFixes("from flask import Flask\napp.run(debug=True)\n", [
      finding("PY_FLASK_DEBUG", 2, { filePath: "/project/app.py" }),
    ]);
    expect(fixes[0].confidence).toBe("medium");
  });

  it("keeps a Python fix high when os is imported", () => {
    const fixes = generateFixes("import os\napp.run(debug=True)\n", [
      finding("PY_FLASK_DEBUG", 2, { filePath: "/project/app.py" }),
    ]);
    expect(fixes[0].confidence).toBe("high");
  });
});
