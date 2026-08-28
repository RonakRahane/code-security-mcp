import * as path from "node:path";
import { Finding, ScanResult, Severity } from "../types/index.js";
import { GENERATED_REPORT_FILES, IGNORED_DIRECTORIES, MAX_LINE_LENGTH, SKIP_EXTENSIONS } from "../core/constants.js";
import { detectLanguage } from "../core/languages.js";
import { computeSeveritySummary, emptySeveritySummary, sortBySeverity } from "../core/severity.js";
import { getPatternsByLanguage } from "../patterns/index.js";
import { extractSecretValue, isNonSecretValue, redactLine } from "./secret-detector.js";

// Language detection lives in core/languages.ts so the secret detector can use
// it without a circular import. Re-exported here for existing callers.
export { detectLanguage };

// Replaces the contents of strings and comments with spaces, preserving line
// numbers and character offsets so patterns only match executable code.

export interface MaskOptions {
  /**
   * Blank string literal contents in addition to comments. Default true.
   *
   * Set false to produce the "literal" view used by rules whose evidence is the
   * content of a string (see SecurityPattern.matchScope).
   */
  maskStrings?: boolean;
}

export function maskCode(code: string, language: string, options: MaskOptions = {}): string {
  const maskStrings = options.maskStrings ?? true;
  const chars = code.split("");
  const len = chars.length;
  let i = 0;

  const isJsLike = ["javascript", "typescript", "java", "go", "rust", "csharp", "kotlin", "swift", "c", "cpp"].includes(language);
  const isPython = language === "python";
  const isShell = language === "shell";
  const isRuby = language === "ruby";

  function blank(start: number, end: number): void {
    for (let j = start; j < end && j < len; j++) {
      // Preserve newlines so line numbers stay correct
      if (chars[j] !== "\n") chars[j] = " ";
    }
  }

  while (i < len) {
    // Single-line comments
    if (isJsLike && chars[i] === "/" && chars[i + 1] === "/") {
      const start = i;
      while (i < len && chars[i] !== "\n") i++;
      blank(start, i);
      continue;
    }
    if ((isPython || isShell || isRuby) && chars[i] === "#") {
      const start = i;
      while (i < len && chars[i] !== "\n") i++;
      blank(start, i);
      continue;
    }

    // Block comments (/* ... */)
    if (isJsLike && chars[i] === "/" && chars[i + 1] === "*") {
      const start = i;
      i += 2;
      while (i < len - 1 && !(chars[i] === "*" && chars[i + 1] === "/")) i++;
      i += 2; // skip closing */
      blank(start, i);
      continue;
    }

    // Python triple-quoted strings/docstrings
    // Always blanked: a docstring is documentation regardless of scope.
    if (isPython && (
      (chars[i] === '"' && chars[i + 1] === '"' && chars[i + 2] === '"') ||
      (chars[i] === "'" && chars[i + 1] === "'" && chars[i + 2] === "'")
    )) {
      const quote = chars[i];
      const start = i;
      i += 3;
      while (i < len - 2 && !(chars[i] === quote && chars[i + 1] === quote && chars[i + 2] === quote)) i++;
      i += 3;
      blank(start, i);
      continue;
    }

    // Template literals (backtick strings)
    // Only blank the static text portions, preserve ${...} expressions
    if (isJsLike && maskStrings && chars[i] === "`") {
      i++; // skip opening backtick
      while (i < len && chars[i] !== "`") {
        if (chars[i] === "\\" && i + 1 < len) {
          blank(i, i + 2);
          i += 2;
          continue;
        }
        if (chars[i] === "$" && chars[i + 1] === "{") {
          // Skip the ${...} expression and leave it unmasked
          i += 2; // skip ${
          let depth = 1;
          while (i < len && depth > 0) {
            if (chars[i] === "{") depth++;
            else if (chars[i] === "}") depth--;
            if (depth > 0) i++;
          }
          i++; // skip closing }
          continue;
        }
        if (chars[i] !== "\n") chars[i] = " ";
        i++;
      }
      if (i < len) i++; // skip closing backtick
      continue;
    }

    // Regular string literals ("..." and '...')
    if (maskStrings && (chars[i] === '"' || chars[i] === "'")) {
      const quote = chars[i];
      const start = i;
      i++; // skip opening quote
      while (i < len && chars[i] !== quote && chars[i] !== "\n") {
        if (chars[i] === "\\" && i + 1 < len) {
          i += 2; // skip escaped character
          continue;
        }
        i++;
      }
      if (i < len && chars[i] === quote) i++; // skip closing quote
      // Blank the inner content only (keep the quotes so structure is visible)
      blank(start + 1, i - 1);
      continue;
    }

    i++;
  }

  return chars.join("");
}

/**
 * The path that directory checks should run against.
 *
 * Checking the absolute path lets a directory above the project decide the
 * result for everything beneath it: a checkout under `~/test` marks every file
 * as test code, and one under `/build` is skipped in full. Reducing the path to
 * the scan root first keeps those checks inside the project. The root defaults
 * to the working directory so single-file scans, which have no root of their
 * own, still get project-relative answers.
 */
function pathRelativeToRoot(filePath: string, rootDir?: string): string {
  const root = rootDir ?? process.cwd();
  const relative = path.relative(root, filePath);

  // An empty result means the path is the root itself; a leading ".." means it
  // lies outside, where nothing relative is meaningful. Both keep the original.
  if (!relative || relative.startsWith("..")) return filePath;

  return relative;
}

// Severity is adjusted for test, fixture, and pattern-definition files.

type FileContext = "production" | "test" | "config" | "pattern-definition";

function getFileContext(filePath: string, rootDir?: string): FileContext {
  const scoped = pathRelativeToRoot(filePath, rootDir);
  // Leading slash added so a directory check matches a relative path
  // ("rules/x.yml") as readily as an absolute one ("/repo/rules/x.yml").
  const normalized = `/${scoped.replace(/\\/g, "/").replace(/^\/+/, "").toLowerCase()}`;
  const basename = path.basename(normalized);

  // Sentinel's own rule definitions exist to contain the shapes they detect.
  // At full severity they would bury real findings under the rule catalogue.

  if (normalized.includes("/rules/") && (normalized.endsWith(".yml") || normalized.endsWith(".yaml"))) {
    return "pattern-definition";
  }

  // Test and fixture files
  if (
    normalized.includes("/test/") ||
    normalized.includes("/tests/") ||
    normalized.includes("/__tests__/") ||
    normalized.includes("/spec/") ||
    normalized.includes("/fixture/") ||
    normalized.includes("/fixtures/") ||
    normalized.includes("/mock/") ||
    normalized.includes("/mocks/") ||
    basename.includes(".test.") ||
    basename.includes(".spec.") ||
    basename.startsWith("test_") ||
    basename.includes("vulnerable-") ||
    basename.includes("insecure-")
  ) {
    return "test";
  }

  // Non-executable config/documentation files
  const ext = path.extname(normalized);
  if ([".md", ".txt", ".example", ".sample", ".rst"].includes(ext)) {
    return "config";
  }

  return "production";
}

/**
 * Lines where a weak hash is a cache key or a change detector rather than a
 * security control. MD5 for an ETag is not a vulnerability, and reporting it as
 * high severity trains people to ignore the category.
 */
const NON_SECURITY_HASH_USE =
  /\b(etag|e_tag|cache[_-]?key|cachekey|checksum|fingerprint|dedupe|dedup|content[_-]?hash|revision|shard|bucket|colou?r|avatar|gravatar)\b/i;

/** Rules whose severity depends on what the hash is used for. */
const CONTEXT_SENSITIVE_HASH_RULES: ReadonlySet<string> = new Set([
  "WEAK_HASH_MD5",
  "WEAK_HASH_SHA1",
  "PY_HASHLIB_MD5",
  "PY_HASHLIB_SHA1",
]);

function isNonSecurityHashUse(ruleId: string, line: string): boolean {
  return CONTEXT_SENSITIVE_HASH_RULES.has(ruleId) && NON_SECURITY_HASH_USE.test(line);
}

/**
 * Grades a secret-detector finding by the same file context the pattern engine
 * uses.
 *
 * The two engines disagreed: a fake AWS key in `test/` was downgraded when the
 * pattern engine reported it and left at critical when the secret detector did.
 * A repository with security tests or fixtures then drew a wall of criticals,
 * which is the shape of false positive that gets a scanner switched off. This
 * repository hid it with `.sentinelignore`, so its own scan looked clean for a
 * reason that had nothing to do with the tool handling the case.
 */
export function gradeFindingByContext<T extends Finding>(finding: T, rootDir?: string): T {
  if (finding.contextGraded) return finding;
  return {
    ...finding,
    severity: adjustSeverity(finding.severity, getFileContext(finding.filePath, rootDir)),
    contextGraded: true,
  };
}

function adjustSeverity(severity: Severity, context: FileContext): Severity {
  if (context === "production") return severity;

  // Downgrade test/fixture findings so they don't inflate risk scores
  if (context === "test" || context === "pattern-definition") {
    switch (severity) {
      case "critical": return "low";
      case "high": return "low";
      case "medium": return "info";
      case "low": return "info";
      default: return "info";
    }
  }

  return severity;
}

// Confidence is assigned from contextual indicators on the matched line.

type Confidence = "high" | "medium" | "low";

const USER_INPUT_INDICATORS = /(?:req\.|request\.|params\.|body\.|query\.|input\b|user\b|args\b|argv\b|ctx\.)/i;
const DYNAMIC_CONTENT_INDICATORS = /(?:\$\{|`[^`]*\+|\+\s*\w|\.format\(|f['"]|%s|%d)/;

function scoreConfidence(line: string): Confidence {
  if (USER_INPUT_INDICATORS.test(line)) return "high";
  if (DYNAMIC_CONTENT_INDICATORS.test(line)) return "medium";
  return "low";
}

// Extension and directory sets live in core/constants.ts so every scan path
// applies identical exclusions.

export function shouldSkipFile(filePath: string, rootDir?: string): boolean {
  const basename = path.basename(filePath);
  const lowerBasename = basename.toLowerCase();

  // Sentinel's own output. Scanning it reports findings in the report rather
  // than in the project.
  if (GENERATED_REPORT_FILES.has(lowerBasename)) return true;

  if (SKIP_EXTENSIONS.has(path.extname(lowerBasename))) return true;
  if (lowerBasename.endsWith(".min.js") || lowerBasename.endsWith(".min.css")) return true;
  if (lowerBasename.endsWith(".lock")) return true;

  // Split on both separators: a path built on one platform can be inspected on
  // the other (CI containers, WSL, mounted volumes).
  for (const part of pathRelativeToRoot(filePath, rootDir).split(/[\\/]/)) {
    if (IGNORED_DIRECTORIES.has(part)) return true;
  }

  return false;
}

export function scanCode(
  code: string,
  filePath: string,
  language?: string,
  rootDir?: string
): ScanResult {
  const detectedLang = language || detectLanguage(filePath);
  const patterns = getPatternsByLanguage(detectedLang);
  const fileContext = getFileContext(filePath, rootDir);

  // Skip non-executable config/documentation files entirely
  if (fileContext === "config" || patterns.length === 0) {
    return {
      filePath,
      language: detectedLang,
      totalFindings: 0,
      findings: [],
      summary: emptySeveritySummary(),
      analyzed: false,
    };
  }

  const findings: Finding[] = [];

  // Two views of the source. "masked" blanks strings and comments so a rule
  // fires only on executable code; "literal" blanks comments alone, for rules
  // whose evidence is the content of a string. Both preserve length and line
  // count, so offsets stay valid against the original.
  const originalLines = code.split("\n");
  const maskedLines = maskCode(code, detectedLang).split("\n");

  const needsLiteralScope = patterns.some((pattern) => pattern.matchScope === "literal");
  const literalLines = needsLiteralScope
    ? maskCode(code, detectedLang, { maskStrings: false }).split("\n")
    : maskedLines;

  // Lines in the outer loop, so one length check skips every pattern on a
  // minified line instead of repeating the check per pattern.
  for (let i = 0; i < maskedLines.length; i++) {
    const maskedLine = maskedLines[i];
    if (!maskedLine.trim()) continue;
    // Generated single-line bundles are the practical ReDoS exposure here.
    if (maskedLine.length > MAX_LINE_LENGTH) continue;

    const literalLine = literalLines[i] ?? maskedLine;
    const originalLine = originalLines[i] ?? "";
    const lineNumber = i + 1;
    const matchedRules = new Set<string>();
    const confidence = scoreConfidence(maskedLine);

    for (const pattern of patterns) {
      if (matchedRules.has(pattern.id)) continue;

      const useLiteral = pattern.matchScope === "literal";
      const subject = useLiteral ? literalLine : maskedLine;
      pattern.regex.lastIndex = 0;
      const match = pattern.regex.exec(subject);
      if (!match) continue;

      // A literal-scope match counts only when it begins in executable code.
      // `createHash("md5")` starts at the call, so it is code. A documentation
      // example such as `"const API_KEY = 'sk_live_x'"` starts inside the outer
      // string, so it is prose about code.
      if (useLiteral && !beginsInExecutableCode(maskedLine, literalLine, match.index)) continue;

      // Credential rules also run in the secret detector, which filters
      // placeholders and environment lookups. Without the same filter here the
      // two engines disagree on the same line.
      if (pattern.category === "secrets" && isNonSecretValue(extractSecretValue(match))) continue;

      matchedRules.add(pattern.id);

      // A weak hash used as a cache key is not a security finding. It is still
      // worth surfacing, so it drops to informational rather than disappearing.
      const effectiveSeverity = isNonSecurityHashUse(pattern.id, originalLine)
        ? "info"
        : pattern.severity;

      findings.push({
        ruleId: pattern.id,
        severity: adjustSeverity(effectiveSeverity, fileContext),
        contextGraded: true,
        category: pattern.category,
        cweId: pattern.cweId,
        message: pattern.message,
        filePath,
        line: lineNumber,
        // Credential patterns must never echo the credential itself into a
        // report, a SARIF upload, or an MCP response.
        lineContent: renderLineContent(originalLine, pattern.category, pattern.cweId, match),
        remediation: pattern.remediation,
        confidence,
        source: "compatibility",
      });
    }
  }

  sortBySeverity(findings);

  return {
    filePath,
    language: detectedLang,
    totalFindings: findings.length,
    findings,
    summary: computeSeveritySummary(findings),
    analyzed: true,
  };
}

/**
 * True when the character at `index` survived string masking, meaning it is
 * executable code rather than the interior of a string literal. Masking is
 * one-for-one, so a position that differs between views was inside a string.
 */
function beginsInExecutableCode(maskedLine: string, literalLine: string, index: number): boolean {
  if (index >= maskedLine.length) return false;
  return maskedLine[index] === literalLine[index];
}

/**
 * Trims a source line for display, redacting it when the rule matched a secret.
 * The regex ran against the masked line, so the matched region is re-read from
 * the original; maskCode() is one-for-one, so the offsets line up.
 */
/**
 * CWEs whose whole subject is a credential written into source. A rule carrying
 * one of these matches the secret itself, whatever category it is filed under.
 */
const CREDENTIAL_CWES: ReadonlySet<string> = new Set([
  "CWE-798", // hardcoded credentials
  "CWE-259", // hardcoded password
  "CWE-321", // hardcoded cryptographic key
]);

function renderLineContent(
  originalLine: string,
  category: string,
  cweId: string,
  match: RegExpExecArray
): string {
  // Keyed on the rule, not only its category. HARDCODED_JWT_SECRET is filed
  // under "auth" and matches a literal signing key, so a category test alone
  // echoed the key into SARIF, the HTML report and MCP responses.
  if (category !== "secrets" && !CREDENTIAL_CWES.has(cweId)) {
    return originalLine.trim().slice(0, 200);
  }

  const matchedText = originalLine.slice(match.index, match.index + match[0].length);
  const secretValue = extractSecretValue(
    Object.assign([matchedText], { index: 0, input: matchedText }) as unknown as RegExpExecArray
  );

  return redactLine(originalLine.trim(), secretValue ? [secretValue] : []).slice(0, 200);
}
