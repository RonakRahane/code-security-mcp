import { Finding } from "../types/index.js";
import { detectLanguage } from "../core/languages.js";

/** A concrete code patch for one finding. */
export interface AutoFix {
  ruleId: string;
  line: number;
  before: string;
  after: string;
  explanation: string;
  /** high is safe to apply unattended; medium and low need review. */
  confidence: "high" | "medium" | "low";
}

type FixGenerator = (line: string, finding: Finding) => AutoFix | null;

/**
 * How each language reads an environment variable. A rewrite that emits
 * JavaScript into a Python file is worse than no rewrite, so a language absent
 * from this table gets a placeholder and low confidence instead.
 */
const ENV_ACCESSORS: Record<string, ((name: string) => string) | undefined> = {
  javascript: (name) => `process.env.${name}`,
  typescript: (name) => `process.env.${name}`,
  python: (name) => `os.environ["${name}"]`,
  ruby: (name) => `ENV["${name}"]`,
  php: (name) => `getenv("${name}")`,
  java: (name) => `System.getenv("${name}")`,
  go: (name) => `os.Getenv("${name}")`,
  csharp: (name) => `Environment.GetEnvironmentVariable("${name}")`,
  rust: (name) => `std::env::var("${name}").unwrap_or_default()`,
  kotlin: (name) => `System.getenv("${name}")`,
  shell: (name) => `"$${name}"`,
};

const FIX_GENERATORS: Record<string, FixGenerator> = {

  // SQL injection: string concatenation to parameterized query
  SQL_INJECTION_TEMPLATE: (line, finding) => {
    // Match: db.query(`SELECT * FROM users WHERE id = ${userId}`)
    const match = line.match(
      /((?:query|execute|raw)\s*\(\s*)(`[^`]*\$\{(\w+)\}[^`]*`)\s*\)/i
    );
    if (!match) return null;

    const [, prefix, _template, varName] = match;
    return {
      ruleId: finding.ruleId,
      line: finding.line,
      before: line.trim(),
      after: line
        .replace(/`([^`]*)\$\{(\w+)\}([^`]*)`/, "'$1\\$1$3', [$2]")
        .replace(/\$\{\w+\}/g, "?")
        .replace(/\\\$1/g, "?")
        .trim(),
      explanation: `Replaced template literal with parameterized query. Variable '${varName}' is now passed as a parameter instead of interpolated into the SQL string.`,
      confidence: "medium",
    };
  },

  SQL_INJECTION_CONCAT: (line, finding) => {
    return {
      ruleId: finding.ruleId,
      line: finding.line,
      before: line.trim(),
      after: "// TODO: Replace with parameterized query:\n" +
        "// db.query('SELECT * FROM table WHERE col = $1', [userInput])",
      explanation: "String concatenation in SQL queries must be replaced with parameterized queries to prevent injection.",
      confidence: "medium",
    };
  },

  // Command injection: exec to execFile
  COMMAND_INJECTION_EXEC: (line, finding) => {
    const match = line.match(/exec\s*\(\s*`([^`]+)`/);
    if (match) {
      const cmd = match[1].split(/\s+/)[0].replace(/\$\{.*?\}/g, "").trim();
      return {
        ruleId: finding.ruleId,
        line: finding.line,
        before: line.trim(),
        after: `execFile('${cmd || "command"}', [/* args */], (err, stdout) => { /* ... */ })`,
        explanation: "Replaced exec() (shell injection risk) with execFile() which does not invoke a shell. Arguments are passed as an array.",
        confidence: "medium",
      };
    }
    return null;
  },

  // eval to a safe alternative
  EVAL_USAGE: (line, finding) => {
    return {
      ruleId: finding.ruleId,
      line: finding.line,
      before: line.trim(),
      after: line.trim()
        // No trailing comment: it used to be emitted before the statement's
        // own semicolon, so the `;` ended up inside the comment.
        .replace(/eval\s*\(\s*(\w+)\s*\)/, "JSON.parse($1)")
        .trim(),
      explanation: "Replaced eval() with JSON.parse() for data parsing. If evaluating expressions, use a sandboxed evaluator like 'expr-eval'.",
      confidence: "low",
    };
  },

  // innerHTML to textContent
  XSS_INNERHTML: (line, finding) => {
    return {
      ruleId: finding.ruleId,
      line: finding.line,
      before: line.trim(),
      after: line.trim().replace(/\.innerHTML\s*=/, ".textContent ="),
      explanation: "Replaced innerHTML (XSS risk) with textContent (safe, escapes HTML). If you need HTML rendering, use DOMPurify: element.innerHTML = DOMPurify.sanitize(content).",
      confidence: "high",
    };
  },

  XSS_DOCUMENT_WRITE: (line, finding) => {
    // The written value has to be carried into the replacement. The previous
    // version emitted `el.textContent = /* content */;`, which is not valid
    // JavaScript and also discarded whatever was being written, so applying it
    // both broke the file and lost the behaviour.
    const written = line.match(/document\s*\.\s*write(?:ln)?\s*\(([\s\S]+)\)\s*;?\s*$/);
    if (!written) return null;

    const value = written[1].trim();
    if (!value) return null;

    const quote = line.includes('"') ? '"' : "'";
    return {
      ruleId: finding.ruleId,
      line: finding.line,
      before: line.trim(),
      after:
        `const el = document.createElement(${quote}div${quote});\n` +
        `el.textContent = ${value};\n` +
        "document.body.appendChild(el);",
      explanation:
        "Replaced document.write() with createElement/textContent/appendChild. textContent assigns the value as text, " +
        "so markup in it is not parsed. Check that this element belongs at the end of document.body.",
      confidence: "medium",
    };
  },

  // Hardcoded secrets to environment variables
  GENERIC_PASSWORD_ASSIGN: (line, finding) => {
    // A TypeScript annotation puts a second `name: value` pair on the line, so
    // the plain pattern would take the type as the variable name.
    const match =
      line.match(/([\w.]+)\s*:\s*[A-Za-z_$][\w<>[\].|]*\s*=\s*(['"])[^'"]+\2/) ||
      line.match(/([\w.]+)\s*[:=]\s*(['"])[^'"]+\2/);
    if (!match || match.index === undefined) return null;

    const language = detectLanguage(finding.filePath);

    // JSON holds data, not expressions, so no edit to this line can read an
    // environment variable and anything emitted here would be invalid JSON.
    if (language === "json") return null;

    const varName = match[1].split(".").pop() as string;
    const envName = varName.replace(/([a-z0-9])([A-Z])/g, "$1_$2").toUpperCase();
    const accessor = ENV_ACCESSORS[language];
    const replacement = accessor ? accessor(envName) : `\${${envName}}`;

    // Substituting the literal in place keeps the separator, the indentation
    // and any trailing comma, which rebuilding the line from the name loses.
    const literalStart = match.index + match[0].indexOf(match[2]);
    const literalEnd = match.index + match[0].length;
    const after = line.slice(0, literalStart) + replacement + line.slice(literalEnd);

    return {
      ruleId: finding.ruleId,
      line: finding.line,
      before: line.trim(),
      after: after.trim(),
      explanation: accessor
        ? `Moved hardcoded secret to environment variable. Add ${envName} to your .env file and .env.example (without the actual value).`
        : `Replaced the hardcoded secret with a ${envName} placeholder. Sentinel has no environment-variable syntax for ${language}, so check the result before keeping it.`,
      confidence: accessor ? "high" : "low",
    };
  },

  GENERIC_SECRET_CONST: (line, finding) => {
    const match = line.match(/(?:const|let|var|final|static)\s+([\w$]+)\s*=\s*(['"])[^'"]+\2/);
    if (!match || match.index === undefined) return null;

    const language = detectLanguage(finding.filePath);
    if (language === "json") return null;

    const varName = match[1];
    const envName = varName.replace(/([a-z0-9])([A-Z])/g, "$1_$2").toUpperCase();
    const accessor = ENV_ACCESSORS[language];
    const replacement = accessor ? accessor(envName) : `\${${envName}}`;

    // Substituting the literal in place keeps the declaration keyword, any
    // `export`, other declarators on the line, and the trailing punctuation.
    // Rebuilding the line from the name alone silently deleted all of them and
    // turned `let` into `const`, so assignment later in the file threw.
    const literalStart = match.index + match[0].indexOf(match[2]);
    const literalEnd = match.index + match[0].length;
    const after = line.slice(0, literalStart) + replacement + line.slice(literalEnd);

    return {
      ruleId: finding.ruleId,
      line: finding.line,
      before: line.trim(),
      after: after.trim(),
      explanation: accessor
        ? `Moved hardcoded secret to environment variable ${envName}.`
        : `Replaced the hardcoded secret with a ${envName} placeholder. Sentinel has no environment-variable syntax for ${language}, so check the result before keeping it.`,
      confidence: accessor ? "high" : "low",
    };
  },

  // Weak hash to a strong algorithm
  WEAK_HASH_MD5: (line, finding) => {
    return {
      ruleId: finding.ruleId,
      line: finding.line,
      before: line.trim(),
      // The original quote character is kept. Rewriting "md5" as 'sha256'
      // leaves a file that lints clean before the fix and fails after it, and
      // a fix meant to be applied unattended must not break the build it was
      // run to protect.
      after: line.trim().replace(/(['"])md5\1/, "$1sha256$1"),
      explanation: "Replaced MD5 (broken) with SHA-256. For password hashing, use bcrypt instead: await bcrypt.hash(password, 12).",
      confidence: "high",
    };
  },

  MATH_RANDOM_SECURITY: (line, finding) => {
    return {
      ruleId: finding.ruleId,
      line: finding.line,
      before: line.trim(),
      // 2**48 - 1 is the largest range crypto.randomInt accepts. The previous
      // bound was Number.MAX_SAFE_INTEGER (2**53 - 1), so every rewritten line
      // threw ERR_OUT_OF_RANGE on its first call - a high-confidence patch,
      // written to disk unattended, that replaced working code with code that
      // could not run at all.
      after: line.trim().replace(
        /Math\.random\(\)/,
        "(crypto.randomInt(0, 2 ** 48 - 1) / (2 ** 48 - 1))"
      ),
      explanation:
        "Replaced Math.random(), which is predictable and must not seed anything security-relevant, " +
        "with crypto.randomInt(). The bound is 2**48 - 1, the largest range randomInt accepts.",
      confidence: "high",
    };
  },

  // JWT verification
  JWT_NO_VERIFY: (line, finding) => {
    return {
      ruleId: finding.ruleId,
      line: finding.line,
      before: line.trim(),
      after: line.trim().replace(/jwt\.decode\s*\(/, "jwt.verify(")
        .replace(/\)(\s*;?\s*)$/, ", process.env.JWT_SECRET)$1"),
      explanation: "Replaced jwt.decode() (no verification!) with jwt.verify() which validates the signature.",
      confidence: "high",
    };
  },

  HARDCODED_JWT_SECRET: (line, finding) => {
    return {
      ruleId: finding.ruleId,
      line: finding.line,
      before: line.trim(),
      after: line.trim().replace(/,\s*['"][^'"]+['"]/, ", process.env.JWT_SECRET"),
      explanation: "Moved JWT secret to environment variable. Add JWT_SECRET to your .env file.",
      confidence: "high",
    };
  },

  // bcrypt cost factor
  BCRYPT_LOW_ROUNDS: (line, finding) => {
    return {
      ruleId: finding.ruleId,
      line: finding.line,
      before: line.trim(),
      after: line.trim().replace(/,\s*\d+\s*\)/, ", 12)"),
      explanation: "Increased bcrypt rounds from low value to 12 (recommended minimum). Higher is more secure but slower.",
      confidence: "high",
    };
  },

  // Session cookie flags
  SESSION_NO_SECURE: (line, finding) => {
    return {
      ruleId: finding.ruleId,
      line: finding.line,
      before: line.trim(),
      after: line.trim()
        .replace(/secure\s*:\s*false/, "secure: true")
        .replace(/httpOnly\s*:\s*false/, "httpOnly: true"),
      explanation: "Enabled secure (HTTPS only) and httpOnly (no JS access) flags on session cookies.",
      confidence: "high",
    };
  },

  // CORS wildcard origin
  CORS_WILDCARD: (line, finding) => {
    return {
      ruleId: finding.ruleId,
      line: finding.line,
      before: line.trim(),
      // A placeholder origin in the quote style the line already uses. The
      // previous replacement appended `// Replace with actual domains`
      // mid-expression, and the comment swallowed the closing `);` - applying
      // the fix left the file unparseable. Guidance belongs in `explanation`,
      // which the caller already shows.
      after: line.trim().replace(/(['"])\*\1|\*/, (whole) => {
        const quote = whole.startsWith("'") ? "'" : whole.startsWith('"') ? '"' : "";
        return `${quote}https://yourdomain.example${quote}`;
      }),
      explanation: "Replaced wildcard CORS origin with a specific domain allowlist.",
      confidence: "medium",
    };
  },

  // Open redirect
  OPEN_REDIRECT: (line, finding) => {
    return {
      ruleId: finding.ruleId,
      line: finding.line,
      before: line.trim(),
      after: "// TODO: validate the destination against an allowlist before redirecting:\n" +
        "//   const url = new URL(candidate, 'https://yourdomain.example');\n" +
        "//   if (!ALLOWED_HOSTS.includes(url.hostname)) return res.status(400).send('Invalid redirect');\n" +
        line.trim(),
      explanation: "Sketches the allowlist check. The original redirect is kept, because the permitted hosts have to be chosen by hand.",
      confidence: "medium",
    };
  },

  // Path traversal
  PATH_TRAVERSAL_FS: (line, finding) => {
    return {
      ruleId: finding.ruleId,
      line: finding.line,
      before: line.trim(),
      after: "// TODO: resolve against a fixed base and confirm the result stays inside it:\n" +
        "//   const safePath = path.resolve(BASE_DIR, userInput);\n" +
        "//   if (!safePath.startsWith(BASE_DIR)) throw new Error('Path traversal blocked');\n" +
        line.trim(),
      explanation: "Sketches the containment check. The original call is kept, because the base directory and the untrusted value have to be named by hand.",
      // Advisory, never applied unattended: this is a template naming
      // identifiers that do not exist in the file.
      confidence: "medium",
    };
  },

  // Python fixes
  PY_SQL_INJECTION_FORMAT: (line, finding) => {
    return {
      ruleId: finding.ruleId,
      line: finding.line,
      before: line.trim(),
      after: "cursor.execute('SELECT * FROM table WHERE col = %s', (user_input,))",
      explanation: "Replaced f-string/format SQL with parameterized query using %s placeholder and tuple parameter.",
      confidence: "medium",
    };
  },

  PY_PICKLE_LOAD: (line, finding) => {
    return {
      ruleId: finding.ruleId,
      line: finding.line,
      before: line.trim(),
      after: "import json\nobj = json.loads(data)  # Safe alternative to pickle",
      explanation: "Replaced pickle (arbitrary code execution) with json (safe deserialization).",
      confidence: "medium",
    };
  },

  PY_YAML_LOAD: (line, finding) => {
    return {
      ruleId: finding.ruleId,
      line: finding.line,
      before: line.trim(),
      after: line.trim()
        .replace(/yaml\.load\s*\(/, "yaml.safe_load(")
        .replace(/\s*,\s*Loader\s*=\s*[\w.]+/, ""),
      explanation: "Replaced yaml.load() (code execution) with yaml.safe_load() (safe).",
      confidence: "high",
    };
  },

  PY_OS_SYSTEM: (line, finding) => {
    return {
      ruleId: finding.ruleId,
      line: finding.line,
      before: line.trim(),
      after: "import subprocess\nsubprocess.run(['command', arg1, arg2], check=True)  # No shell injection",
      explanation: "Replaced os.system() (shell injection) with subprocess.run() using argument list (no shell).",
      confidence: "medium",
    };
  },

  PY_FLASK_RENDER_STRING: (line, finding) => {
    return {
      ruleId: finding.ruleId,
      line: finding.line,
      before: line.trim(),
      after: "# TODO: move the template into a file and render it by name:\n" +
        "#   return render_template('template.html', name=name)\n" +
        line.trim(),
      explanation: "Sketches the replacement. The original call is kept, because the template has to be extracted to a file first.",
      confidence: "medium",
    };
  },

  PY_HASHLIB_MD5: (line, finding) => {
    return {
      ruleId: finding.ruleId,
      line: finding.line,
      before: line.trim(),
      after: line.trim().replace(/hashlib\.md5/, "hashlib.sha256"),
      explanation: "Replaced MD5 (broken) with SHA-256.",
      confidence: "high",
    };
  },

  PY_FLASK_DEBUG: (line, finding) => {
    return {
      ruleId: finding.ruleId,
      line: finding.line,
      before: line.trim(),
      after: line.trim().replace(/debug\s*=\s*True/, "debug=os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'"),
      explanation: "Made debug mode configurable via environment variable instead of hardcoded True.",
      confidence: "high",
    };
  },

  PY_DJANGO_DEBUG: (line, finding) => {
    return {
      ruleId: finding.ruleId,
      line: finding.line,
      before: line.trim(),
      after: line.replace(
        /\bTrue\b/,
        "os.environ.get('DJANGO_DEBUG', 'False') == 'True'"
      ).trim(),
      explanation: "Made Django DEBUG configurable via environment variable.",
      confidence: "high",
    };
  },
};

/**
 * Generates patches for findings whose rule has a fix generator.
 *
 * Generators rewrite with `String.replace`, which returns the input untouched
 * when the pattern does not match. A patch identical to the original line is
 * not a fix, so it is dropped here rather than in every generator.
 */
export function generateFixes(
  code: string,
  findings: Finding[]
): AutoFix[] {
  const lines = code.split("\n");
  const fixes: AutoFix[] = [];

  for (const finding of findings) {
    const generator = FIX_GENERATORS[finding.ruleId];
    if (!generator) continue;

    // A line number past the end of the file means the findings came from a
    // different revision; patching that offset would corrupt unrelated code.
    if (finding.line < 1 || finding.line > lines.length) continue;

    const lineContent = lines[finding.line - 1];
    if (!lineContent.trim()) continue;

    const fix = generator(lineContent, finding);
    if (!fix) continue;
    if (fix.after.trim() === fix.before.trim()) continue;
    if (!isStructurallySound(fix)) continue;

    fixes.push(withScopeCheckedConfidence(fix, code));
  }

  return fixes;
}

/**
 * Modules a generator can name in a patch, with how each is brought into scope.
 *
 * A patch that references one of these when the file never imported it turns a
 * security warning into a crash. `MATH_RANDOM_SECURITY` rewrote
 * `Math.random()` to `crypto.randomInt(...)` at high confidence, which is
 * written to disk without asking: a file that ran correctly before the fix
 * threw `ReferenceError: crypto is not defined` after it. `PY_FLASK_DEBUG` and
 * `PY_DJANGO_DEBUG` reach for `os.environ` the same way.
 *
 * Node exposes a global `crypto` in recent versions, but that is WebCrypto and
 * carries no `randomInt`, so the global does not rescue this - it only changes
 * the error.
 */
const IMPORTABLE_SYMBOLS: ReadonlyArray<{ symbol: string; inScope: RegExp }> = [
  { symbol: "crypto", inScope: /\b(?:require\(\s*['"](?:node:)?crypto['"]|from\s+['"](?:node:)?crypto['"]|import\s+\*?\s*(?:as\s+)?crypto\b|(?:const|let|var)\s+\{?[^;\n]*\bcrypto\b[^;\n]*\}?\s*=)/ },
  { symbol: "os", inScope: /^\s*(?:import\s+os\b|from\s+os\s+import\b|import\s+[^\n]*\bos\b)/m },
  { symbol: "subprocess", inScope: /^\s*(?:import\s+subprocess\b|from\s+subprocess\s+import\b)/m },
  { symbol: "json", inScope: /^\s*(?:import\s+json\b|from\s+json\s+import\b)|\brequire\(\s*['"]json['"]/m },
];

/**
 * Downgrades a patch that needs an import the file does not have.
 *
 * The confidence is lowered rather than the fix dropped: the suggestion is
 * still right, it just needs a human to add the import, and only "high" is
 * written to disk unattended.
 */
function withScopeCheckedConfidence(fix: AutoFix, code: string): AutoFix {
  if (fix.confidence !== "high") return fix;

  for (const { symbol, inScope } of IMPORTABLE_SYMBOLS) {
    const used = new RegExp(`\\b${symbol}\\s*\\.`);
    // Only a symbol the patch introduces matters. One the replaced line
    // already used is in scope by construction - WEAK_HASH_MD5 rewrites a
    // crypto.createHash call, so crypto was always there.
    if (!used.test(fix.after) || used.test(fix.before)) continue;
    if (inScope.test(code)) continue;

    return {
      ...fix,
      confidence: "medium",
      explanation:
        `${fix.explanation} This patch uses \`${symbol}\`, which this file does not import, ` +
        `so add the import before applying it.`,
    };
  }

  return fix;
}

/**
 * Rejects a patch that would not survive being written back.
 *
 * Three generators shipped replacements that produced unparseable JavaScript:
 * a `// Replace with actual domains` appended mid-expression swallowed the
 * closing `);`, a `/* content *\/` placeholder produced `el.textContent = ;`,
 * and a trailing comment consumed a statement's own semicolon. Each looked
 * plausible read as a diff, and each corrupted the file when applied.
 *
 * A full parse is not usable here: a patch is often a fragment - a line inside
 * an object literal, a case in a switch - which does not parse standalone even
 * when it is correct. These two checks work on fragments.
 */
function isStructurallySound(fix: AutoFix): boolean {
  // Bracket balance has to match the line being replaced. If the original
  // closed two parens and the patch closes one, something consumed a
  // character - which is exactly what a mid-line comment does.
  const before = bracketDelta(fix.before);
  const after = bracketDelta(fix.after);
  if (before.round !== after.round || before.square !== after.square || before.curly !== after.curly) {
    return false;
  }

  // A placeholder that stands where a value must go leaves a syntax error,
  // however well it reads.
  if (/[=:]\s*\/\*[^*]*\*\/\s*[;,)\]}]/.test(fix.after)) return false;

  return true;
}

/**
 * Bracket balance outside strings and comments. Counting inside them would
 * make a fix that legitimately adds "https://..." look unbalanced.
 */
function bracketDelta(text: string): { round: number; square: number; curly: number } {
  const delta = { round: 0, square: 0, curly: 0 };
  let quote: string | null = null;
  let escaped = false;

  for (let index = 0; index < text.length; index++) {
    const char = text[index];

    if (quote) {
      if (escaped) escaped = false;
      else if (char === "\\") escaped = true;
      else if (char === quote) quote = null;
      continue;
    }

    if (char === "'" || char === '"' || char === "`") { quote = char; continue; }
    if (char === "/" && text[index + 1] === "/") break;
    if (char === "/" && text[index + 1] === "*") {
      const end = text.indexOf("*/", index + 2);
      if (end === -1) break;
      index = end + 1;
      continue;
    }

    if (char === "(") delta.round++;
    else if (char === ")") delta.round--;
    else if (char === "[") delta.square++;
    else if (char === "]") delta.square--;
    else if (char === "{") delta.curly++;
    else if (char === "}") delta.curly--;
  }

  return delta;
}

/** Rule IDs that have auto-fix support. */
export function getFixableRules(): string[] {
  return Object.keys(FIX_GENERATORS);
}
