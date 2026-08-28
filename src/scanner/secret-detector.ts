import * as path from "node:path";
import { SecretFinding } from "../types/index.js";
import { MAX_FILE_BYTES, MAX_LINE_LENGTH, SECRET_SCAN_EXTENSIONS } from "../core/constants.js";
import { Diagnostics } from "../core/diagnostics.js";
import { mapWithConcurrency, readTextFile, resolveConcurrency, walkDirectory } from "../core/fs-walk.js";
import { CODE_LANGUAGES, detectLanguage } from "../core/languages.js";
import { sortBySeverity } from "../core/severity.js";
import { secretPatterns } from "../patterns/secrets.js";

// Shannon Entropy

export function calculateEntropy(str: string): number {
  if (!str || str.length === 0) return 0;

  const freq = new Map<string, number>();
  for (const char of str) {
    freq.set(char, (freq.get(char) || 0) + 1);
  }

  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / str.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

const ENTROPY_THRESHOLD = 4.5;
const MIN_SECRET_LENGTH = 16;

// Redaction

/**
 * Masks a detected secret, keeping a short prefix so a developer can locate it.
 *
 * Findings end up in markdown reports, SARIF uploads, MCP responses, and CI
 * logs. Echoing the raw credential would make each of those a new copy of it.
 */
export function maskSecretValue(value: string): string {
  if (value.length <= 8) return "*".repeat(Math.max(value.length, 4));
  // Prefixes like "AKIA" or "ghp_" identify the credential type and are not
  // themselves sensitive.
  return `${value.slice(0, 4)}${"*".repeat(Math.min(value.length - 4, 24))}`;
}

/** Replaces every occurrence of the given secret values in a line of source. */
export function redactLine(line: string, secrets: readonly string[]): string {
  let redacted = line;
  // Longest first, so a short secret nested inside a longer one cannot leave a
  // fragment of the longer value visible.
  for (const secret of [...secrets].sort((a, b) => b.length - a.length)) {
    if (secret.length < 4) continue;
    redacted = redacted.split(secret).join(maskSecretValue(secret));
  }
  return redacted;
}

// False positive suppression

const FALSE_POSITIVE_PATTERNS: readonly RegExp[] = [
  /^0+$/,
  /^[fF]+$/,
  /test|example|sample|dummy|fake|mock/i,
  /placeholder|changeme|your[-_]?key|insert[-_]?here|redacted|xxxxx/i,
  /^(abc|123|xxx)/i,
  /lorem|ipsum|dolor/i,
  /^[a-z]{20,}$/,
  /^[A-Z]{20,}$/,
  /node_modules|dist\/|build\//,
  /^https?:\/\//,
  /^[0-9a-f]{40}$/i,                                        // git object SHA-1
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i, // UUID
  /^(sha256|sha512|sha384|md5)-/i,                          // subresource integrity
  /^data:[a-z]+\/[a-z0-9.+-]+;base64,/i,                    // inline data URI
  /^\d+$/,                                                  // ids and timestamps
];

function isFalsePositive(value: string): boolean {
  return FALSE_POSITIVE_PATTERNS.some((pattern) => pattern.test(value));
}

/**
 * Rules that fire on a variable name (`const apiKey = "..."`) rather than a
 * recognisable credential format. Their matches get an extra plausibility check.
 */
const GENERIC_RULE_IDS: ReadonlySet<string> = new Set([
  "GENERIC_PASSWORD_ASSIGN",
  "GENERIC_SECRET_CONST",
]);

/**
 * Obvious non-credentials: template markers, documentation stand-ins, masked
 * values. Applied only to generic rules, since a provider-prefixed key such as
 * an AWS `AKIA` identifier is evidence on its own.
 *
 * Narrower than FALSE_POSITIVE_PATTERNS on purpose: a weak hardcoded password
 * such as "correcthorsebattery" still has to be reported.
 */
const PLACEHOLDER_VALUE: readonly RegExp[] = [
  /example|sample|dummy|fake|mock|placeholder|changeme|redacted/i,
  /^your[-_ ]/i,
  /goes[-_ ]here/i,
  /^insert[-_ ]/i,
  /^<.+>$/,          // <your-token-here>
  /^\$\{.+\}$/,      // ${API_KEY}
  /^\{\{.+\}\}$/,    // {{ secret }}
  /^%[A-Z_]+%$/,     // %API_KEY%
  /^x{6,}$/i,
  /^\*{4,}$/,
  /^\.{3,}$/,
  /^(?:foo|bar|baz|abc123|password|secret|changeit|123456|hunter2)$/i,
];

/**
 * Whether a credential-shaped match is noise rather than a secret.
 *
 * The secret detector and the pattern engine both run the credential rules, so
 * this decision has to be shared. Applied in only one of them, the same line is
 * reported by one engine and filtered by the other, and `const passwordField =
 * "password"` comes back as a hardcoded credential.
 */
export function isNonSecretValue(value: string | undefined): boolean {
  if (!value) return false;
  return SAFE_REFERENCE.test(value) || isPlaceholderValue(value);
}

function isPlaceholderValue(value: string): boolean {
  return PLACEHOLDER_VALUE.some((pattern) => pattern.test(value));
}

/** Lockfiles are full of integrity digests: high-entropy by design and never secret. */
const ENTROPY_EXEMPT_FILES = new Set([
  "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json",
  "composer.lock", "gemfile.lock", "poetry.lock", "cargo.lock", "pipfile.lock",
  "go.sum", "bun.lockb",
]);

/** Keys whose values are checksums or identifiers rather than credentials. */
const NON_SECRET_CONTEXT = /\b(integrity|checksum|sha256|sha512|hash|digest|etag|commit|revision|fingerprint|thumbprint|uuid|guid)\b/i;

function isCommentOrDocLine(line: string): boolean {
  const trimmed = line.trim();
  return (
    trimmed.startsWith("//") ||
    trimmed.startsWith("#") ||
    trimmed.startsWith("*") ||
    trimmed.startsWith("/*") ||
    trimmed.startsWith("*/") ||
    trimmed.startsWith("<!--") ||
    trimmed.startsWith('"""') ||
    trimmed.startsWith("'''")
  );
}

/** Values read from the environment or a secrets manager are the correct pattern. */
const SAFE_REFERENCE = /(process\.env|os\.environ|getenv|System\.getenv|ENV\[|secrets?\.|vault|SecretManager|\$\{?[A-Z_]+\}?$)/;

/**
 * Regex sources, character classes, and format strings score high on entropy
 * but are never credentials. Credentials use base64, hex, or URL-safe
 * alphabets and carry no backslash escapes or regex group syntax.
 */
const LOOKS_LIKE_PATTERN_SOURCE = /\\[dwsSWDbnrt.+*?(){}[\]|^$]|\(\?[:=!<]|\[\^|\{\d+,\d*\}/;

export function detectSecrets(code: string, filePath: string): SecretFinding[] {
  const findings: SecretFinding[] = [];
  const lines = code.split("\n");
  const basename = path.basename(filePath).toLowerCase();
  const entropyEnabled = !ENTROPY_EXEMPT_FILES.has(basename);
  const codeLanguage = CODE_LANGUAGES.has(detectLanguage(filePath));

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Long lines are minified or generated output. Skipping them bounds regex
    // work per line, which is the practical ReDoS control for a pattern engine.
    if (line.length > MAX_LINE_LENGTH) continue;

    const trimmed = line.trim();
    if (!trimmed || isCommentOrDocLine(trimmed)) continue;

    const lineNumber = i + 1;
    const matchedRules = new Set<string>();

    // Every credential on this line, gathered before any finding is built.
    // lineContent is the whole line, so redacting only the value the matching
    // rule happened to extract published the other secrets beside it in the
    // clear: an AWS key and a GitHub token on one line each masked their own
    // value and printed the other, into SARIF uploaded to code scanning.
    const secretsOnLine: string[] = [];
    for (const pattern of secretPatterns) {
      pattern.regex.lastIndex = 0;
      const found = pattern.regex.exec(line);
      if (!found) continue;
      const value = extractSecretValue(found);
      if (value) secretsOnLine.push(value);
    }

    // Pattern-based detection
    for (const pattern of secretPatterns) {
      pattern.regex.lastIndex = 0;
      const match = pattern.regex.exec(line);
      if (!match) continue;
      if (matchedRules.has(pattern.id)) continue;
      matchedRules.add(pattern.id);

      const secretValue = extractSecretValue(match);
      if (secretValue && SAFE_REFERENCE.test(secretValue)) continue;

      if (GENERIC_RULE_IDS.has(pattern.id)) {
        // A name-based rule matching a documentation stand-in is noise.
        if (secretValue && isPlaceholderValue(secretValue)) continue;
        // `"const API_KEY = 'sk_live_…'"` inside a source file is a code example
        // in a string, not an assignment. Only applied to code files: in JSON
        // and YAML the key itself is legitimately quoted.
        if (codeLanguage && isInsideStringLiteral(line, match.index)) continue;
      }

      findings.push({
        ruleId: pattern.id,
        severity: pattern.severity,
        category: "secrets",
        cweId: pattern.cweId,
        message: pattern.message,
        filePath,
        line: lineNumber,
        lineContent: truncate(redactLine(trimmed, secretsOnLine), 200),
        remediation: pattern.remediation,
        confidence: "high",
        source: "secret-detector",
        entropyScore: secretValue ? round(calculateEntropy(secretValue)) : 0,
        secretType: pattern.id.toLowerCase().replace(/_/g, "-"),
      });
    }

    // Entropy-based detection
    // Only assignments are considered: a bare high-entropy token in prose or
    // data is far more often a hash than a credential.
    if (!entropyEnabled || matchedRules.size > 0) continue;
    if (NON_SECRET_CONTEXT.test(line)) continue;
    if (!/[:=]\s*['"`]/.test(line)) continue;

    for (const candidate of extractQuotedValues(line)) {
      if (candidate.length < MIN_SECRET_LENGTH) continue;
      // Credentials are single tokens. Whitespace means prose, which scores
      // high on entropy purely from varied casing and punctuation.
      if (/\s/.test(candidate)) continue;
      if (isFalsePositive(candidate)) continue;
      if (SAFE_REFERENCE.test(candidate)) continue;
      if (LOOKS_LIKE_PATTERN_SOURCE.test(candidate)) continue;

      const entropy = calculateEntropy(candidate);
      if (entropy < ENTROPY_THRESHOLD) continue;

      findings.push({
        ruleId: "HIGH_ENTROPY_SECRET",
        severity: "medium",
        category: "secrets",
        cweId: "CWE-798",
        message: `High-entropy string detected (entropy ${entropy.toFixed(2)}, length ${candidate.length}). This may be a hardcoded secret.`,
        filePath,
        line: lineNumber,
        lineContent: truncate(redactLine(trimmed, [...secretsOnLine, candidate]), 200),
        remediation: "If this value is a credential, revoke and rotate it, then load it from an environment variable or secrets manager.",
        confidence: "medium",
        source: "secret-detector",
        entropyScore: round(entropy),
        secretType: "high-entropy-string",
      });
      break; // One entropy finding per line is enough to prompt review.
    }
  }

  return sortBySeverity(findings);
}

/**
 * Extracts the credential from a pattern match: an explicit capture group
 * first, then a quoted value inside the match (so `aws_secret_key = "..."`
 * redacts the value but keeps the key name), then the whole match.
 */
export function extractSecretValue(match: RegExpExecArray): string | undefined {
  for (let group = 1; group < match.length; group++) {
    const value = match[group];
    if (typeof value === "string" && value.length >= 8) return value;
  }

  const whole = match[0] || "";
  const quoted = whole.match(/['"`]([^'"`\n]{8,})['"`]/);
  if (quoted) return quoted[1];

  return whole.length >= 8 ? whole : undefined;
}

/**
 * True when `index` falls inside a string literal on this line. Separates an
 * assignment from a code example embedded in a string. Escapes are tracked so
 * `\"` does not toggle the quote state.
 */
function isInsideStringLiteral(line: string, index: number): boolean {
  let quote: string | null = null;

  for (let i = 0; i < index && i < line.length; i++) {
    const char = line[i];

    if (char === "\\") {
      i++; // Skip the escaped character.
      continue;
    }

    if (quote) {
      if (char === quote) quote = null;
    } else if (char === '"' || char === "'" || char === "`") {
      quote = char;
    }
  }

  return quote !== null;
}

/** Candidates inspected per line. Bounds the entropy work without a length cap. */
const MAX_ENTROPY_CANDIDATES = 24;

function extractQuotedValues(line: string): string[] {
  const values: string[] = [];

  // No upper length bound. The previous limit of 200 characters made the
  // entropy check blind to exactly the credentials that are long: JWTs, base64
  // key blobs, Azure connection strings. A 199-character token was reported and
  // a 201-character one was not. The line length cap already bounds the work,
  // and the candidate count bounds it further.
  for (const match of line.matchAll(/['"`]([^'"`\n]{16,})['"`]/g)) {
    values.push(match[1]);
    if (values.length >= MAX_ENTROPY_CANDIDATES) break;
  }

  return values;
}

function truncate(value: string, maxLength: number): string {
  return value.length > maxLength ? `${value.slice(0, maxLength)}…` : value;
}

function round(value: number): number {
  return Math.round(value * 100) / 100;
}

// Directory scanning

export interface DirectorySecretScan {
  results: Array<{ filePath: string; findings: SecretFinding[] }>;
  warnings: string[];
  filesScanned: number;
}

/**
 * Scans a directory tree for secrets. Returns coverage warnings alongside
 * results, so an empty finding list is distinguishable from an unreadable tree.
 */
export async function detectSecretsInDirectory(
  dirPath: string,
  options: { diagnostics?: Diagnostics; maxFiles?: number; concurrency?: number } = {}
): Promise<DirectorySecretScan> {
  const diagnostics = options.diagnostics ?? new Diagnostics();

  const { files, truncated } = await walkDirectory(dirPath, {
    diagnostics,
    maxFiles: options.maxFiles,
    shouldReadFile: (fullPath, name) => {
      const lower = name.toLowerCase();
      return SECRET_SCAN_EXTENSIONS.has(path.extname(lower)) || lower.startsWith(".env");
    },
  });

  if (truncated) {
    diagnostics.add(`Secret scan stopped at the file limit; part of the tree was not examined.`);
  }

  const results: Array<{ filePath: string; findings: SecretFinding[] }> = [];
  let filesScanned = 0;

  await mapWithConcurrency(
    files,
    async (filePath) => {
      const code = await readTextFile(filePath, { maxBytes: MAX_FILE_BYTES, diagnostics });
      if (code === null) return;

      filesScanned++;
      const findings = detectSecrets(code, filePath);
      if (findings.length > 0) results.push({ filePath, findings });
    },
    resolveConcurrency(options.concurrency)
  );

  results.sort((a, b) => a.filePath.localeCompare(b.filePath));

  return { results, warnings: diagnostics.toWarnings(), filesScanned };
}
