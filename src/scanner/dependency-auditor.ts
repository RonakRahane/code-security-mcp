import * as path from "node:path";
import { DependencyVulnerability, Severity } from "../types/index.js";
import { Diagnostics } from "../core/diagnostics.js";
import { mapWithConcurrency, readTextFile, resolveConcurrency, walkDirectory } from "../core/fs-walk.js";
import { errorMessage, logger } from "../core/logger.js";
import { isOfflineMode } from "./config.js";

export interface AuditResult {
  ecosystem: string;
  scannedManifest: string;
  totalVulnerabilities: number;
  vulnerabilities: DependencyVulnerability[];
  summary: Record<string, number>;
  /** Non-fatal problems: unparsed manifests, advisory lookups that failed. */
  warnings: string[];
}

export interface AuditOptions {
  offline?: boolean;
  diagnostics?: Diagnostics;
  /** Overridable for tests; defaults to the public OSV API. */
  osvEndpoint?: string;
}

interface PackageCoordinate {
  name: string;
  version?: string;
}

/** Subset of the OSV schema Sentinel consumes. https://ossf.github.io/osv-schema/ */
interface OsvSeverityEntry {
  type?: string;
  score?: string;
}

interface OsvEvent {
  introduced?: string;
  fixed?: string;
}

interface OsvRange {
  type?: string;
  events?: OsvEvent[];
}

interface OsvAffected {
  ranges?: OsvRange[];
}

interface OsvVulnerability {
  id?: string;
  summary?: string;
  details?: string;
  severity?: OsvSeverityEntry[];
  affected?: OsvAffected[];
  references?: Array<{ type?: string; url?: string }>;
  database_specific?: { severity?: string };
}

interface OsvBatchResponse {
  results?: Array<{ vulns?: OsvVulnerability[] }>;
}

// Network policy

const OSV_ENDPOINT = "https://api.osv.dev/v1/querybatch";
const OSV_TIMEOUT_MS = 20_000;
const OSV_MAX_BATCH = 500;
const OSV_MAX_ATTEMPTS = 3;

/** Files consulted when deciding whether a vulnerable package is actually used. */
const REACHABILITY_EXTENSIONS = new Set([
  ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts",
  ".py", ".go", ".java", ".rb", ".php", ".rs",
]);

const REACHABILITY_MAX_FILES = 1_500;

/**
 * Packages whose older releases are known to carry advisories. Used only as a
 * fallback when OSV is unreachable, and findings are marked as such: a name
 * match is not evidence that the installed version is affected.
 */
const KNOWN_RISKY_PACKAGES: Record<string, { ecosystem: string; message: string; severity: Severity }> = {
  "node-serialize": { ecosystem: "npm", message: "Known RCE via insecure deserialization", severity: "critical" },
  "serialize-javascript": { ecosystem: "npm", message: "Older versions have prototype pollution issues", severity: "high" },
  "lodash": { ecosystem: "npm", message: "Versions < 4.17.21 have prototype pollution issues", severity: "medium" },
  "minimist": { ecosystem: "npm", message: "Versions < 1.2.6 have prototype pollution issues", severity: "medium" },
  "jsonwebtoken": { ecosystem: "npm", message: "Older versions have JWT security issues", severity: "high" },
  "axios": { ecosystem: "npm", message: "Older versions have SSRF-related vulnerabilities", severity: "medium" },
  "yaml": { ecosystem: "npm", message: "Older versions may allow unsafe code execution", severity: "high" },
  "pyyaml": { ecosystem: "python", message: "Unsafe yaml.load() usage can lead to code execution", severity: "high" },
  "jinja2": { ecosystem: "python", message: "Older versions have sandbox escape and XSS-related issues", severity: "medium" },
  "django": { ecosystem: "python", message: "Outdated Django releases frequently carry security advisories", severity: "medium" },
  "flask": { ecosystem: "python", message: "Check Flask and Werkzeug versions for current security fixes", severity: "low" },
  "requests": { ecosystem: "python", message: "Older requests releases have known transport/security issues", severity: "low" },
};

export async function auditDependencies(
  manifestPath: string,
  options: AuditOptions = {}
): Promise<AuditResult> {
  const diagnostics = options.diagnostics ?? new Diagnostics();
  const absoluteManifestPath = path.resolve(manifestPath);

  const content = await readTextFile(absoluteManifestPath, { diagnostics });
  if (content === null) {
    throw new Error(`Manifest not found or unreadable: ${absoluteManifestPath}`);
  }

  const { ecosystem, osvEcosystem } = detectEcosystem(absoluteManifestPath);
  const dependencies = parseDependencies(content, absoluteManifestPath, ecosystem, diagnostics);

  if (dependencies.length === 0) {
    diagnostics.add(`No dependencies could be parsed from ${path.basename(absoluteManifestPath)}; it was not audited.`);
  }

  const offline = options.offline ?? isOfflineMode();
  let vulnerabilities: DependencyVulnerability[] = [];
  let osvSucceeded = false;

  if (dependencies.length > 0 && osvEcosystem && !offline) {
    try {
      vulnerabilities = await queryOsv(osvEcosystem, dependencies, absoluteManifestPath, options.osvEndpoint);
      osvSucceeded = true;
    } catch (error) {
      // A coverage gap, not a clean result: the advisory database was never
      // consulted and the user has to know that.
      diagnostics.add(
        `OSV advisory lookup failed for ${path.basename(absoluteManifestPath)}: ${errorMessage(error)}. ` +
        `Dependency results are incomplete and fall back to a local package list.`
      );
      logger.warn("osv lookup failed", { manifest: absoluteManifestPath, error: errorMessage(error) });
    }
  }

  // The heuristic list only runs when the authoritative source was unavailable.
  if (!osvSucceeded && (ecosystem === "npm" || ecosystem === "python")) {
    const heuristic = scanKnownRiskPackages(dependencies, ecosystem);
    if (heuristic.length > 0) {
      diagnostics.add(
        `${heuristic.length} dependency finding(s) for ${path.basename(absoluteManifestPath)} come from a static ` +
        `package list, not the OSV database. They indicate packages worth checking, not confirmed vulnerable versions.`
      );
    }
    vulnerabilities = heuristic;
  }

  const projectRoot = path.dirname(absoluteManifestPath);
  const reachability = await buildReachabilityIndex(projectRoot, ecosystem, vulnerabilities, diagnostics);

  for (const vulnerability of vulnerabilities) {
    vulnerability.manifestPath = absoluteManifestPath;
    vulnerability.reachability = reachability.get(vulnerability.package) ?? "unknown";
  }

  const deduped = dedupeVulnerabilities(vulnerabilities);

  return {
    ecosystem,
    scannedManifest: absoluteManifestPath,
    totalVulnerabilities: deduped.length,
    vulnerabilities: deduped,
    summary: summarizeVulnerabilities(deduped),
    warnings: diagnostics.toWarnings(),
  };
}

// Ecosystem detection

function detectEcosystem(manifestPath: string): { ecosystem: string; osvEcosystem: string | null } {
  const basename = path.basename(manifestPath).toLowerCase();

  if (["package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json"].includes(basename)) {
    return { ecosystem: "npm", osvEcosystem: "npm" };
  }
  if (basename.startsWith("requirements") || ["poetry.lock", "pyproject.toml", "pipfile", "pipfile.lock"].includes(basename)) {
    return { ecosystem: "python", osvEcosystem: "PyPI" };
  }
  if (basename === "go.mod" || basename === "go.sum") return { ecosystem: "go", osvEcosystem: "Go" };
  if (basename === "cargo.lock" || basename === "cargo.toml") return { ecosystem: "rust", osvEcosystem: "crates.io" };
  if (basename === "pom.xml" || basename === "build.gradle") return { ecosystem: "java", osvEcosystem: "Maven" };
  if (basename === "gemfile.lock" || basename === "gemfile") return { ecosystem: "ruby", osvEcosystem: "RubyGems" };
  if (basename === "composer.lock" || basename === "composer.json") return { ecosystem: "php", osvEcosystem: "Packagist" };

  return { ecosystem: "unknown", osvEcosystem: null };
}

// Manifest parsing

export function parseDependencies(
  content: string,
  manifestPath: string,
  ecosystem: string,
  diagnostics?: Diagnostics
): PackageCoordinate[] {
  const basename = path.basename(manifestPath).toLowerCase();

  try {
    switch (ecosystem) {
      case "npm": return parseNpm(content, basename);
      case "python": return parsePython(content, basename);
      case "go": return parseGo(content, basename);
      case "rust": return parseRust(content, basename);
      case "java": return parseJava(content, basename);
      case "ruby": return parseRuby(content, basename);
      case "php": return parsePhp(content, basename);
      default: return [];
    }
  } catch (error) {
    // A malformed manifest leaves its dependencies unaudited, which is a
    // coverage gap worth reporting.
    diagnostics?.add(`Could not parse ${basename}: ${errorMessage(error)}. Its dependencies were not audited.`);
    return [];
  }
}

function parseNpm(content: string, basename: string): PackageCoordinate[] {
  if (basename === "package.json") {
    const pkg = JSON.parse(content) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
      optionalDependencies?: Record<string, string>;
    };
    const allDeps = { ...pkg.dependencies, ...pkg.devDependencies, ...pkg.optionalDependencies };
    return Object.entries(allDeps).map(([name, version]) => ({
      name,
      version: normalizeVersion(String(version)),
    }));
  }

  if (basename === "package-lock.json" || basename === "npm-shrinkwrap.json") {
    const lock = JSON.parse(content) as {
      packages?: Record<string, { version?: string }>;
      dependencies?: Record<string, { version?: string }>;
    };
    const deps: PackageCoordinate[] = [];

    if (lock.packages) {
      for (const [key, value] of Object.entries(lock.packages)) {
        if (!key || !value?.version) continue;
        // Lockfile v2/v3 keys are paths: "node_modules/a/node_modules/b".
        const marker = "node_modules/";
        const index = key.lastIndexOf(marker);
        const name = index >= 0 ? key.slice(index + marker.length) : key;
        if (name) deps.push({ name, version: value.version });
      }
    } else if (lock.dependencies) {
      for (const [name, value] of Object.entries(lock.dependencies)) {
        if (value?.version) deps.push({ name, version: value.version });
      }
    }
    return dedupeCoordinates(deps);
  }

  if (basename === "yarn.lock") {
    const deps: PackageCoordinate[] = [];
    let currentPackage = "";

    for (const line of content.split("\n")) {
      if (line.startsWith("#") || !line.trim()) continue;

      if (!line.startsWith(" ") && line.includes(":")) {
        const spec = line.split(",")[0].trim().replace(/^"/, "").replace(/"$/, "").replace(/:$/, "");
        // Scoped names keep their leading @; the version follows the last @.
        const at = spec.lastIndexOf("@");
        currentPackage = at > 0 ? spec.slice(0, at) : spec;
      } else if (line.trim().startsWith("version")) {
        const version = line.replace("version", "").replace(/"/g, "").replace(/:/g, "").trim();
        if (currentPackage && version) deps.push({ name: currentPackage, version });
      }
    }
    return dedupeCoordinates(deps);
  }

  if (basename === "pnpm-lock.yaml") {
    const deps: PackageCoordinate[] = [];

    // pnpm has used two key layouts. Lockfile v5 and v6 write a path,
    // "/name/1.2.3:" or "/@scope/name/1.2.3:". Lockfile v9 writes a specifier,
    // "'name@1.2.3':" or "'@scope/name@1.2.3':", optionally followed by peer
    // context in parentheses. Supporting only the older layout meant every
    // current pnpm project was reported as having no parseable dependencies.
    const pathStyle = /^\s+['"]?\/((?:@[^/]+\/)?[^/'"]+)\/([0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9_.+-]*)['"]?:/gm;
    const specifierStyle = /^\s+['"]?((?:@[^/'"]+\/)?[^@/'"\s][^@'"\s]*)@([0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9_.+-]*)(?:\([^)]*\))*['"]?:/gm;

    for (const match of content.matchAll(pathStyle)) {
      deps.push({ name: match[1], version: match[2] });
    }
    for (const match of content.matchAll(specifierStyle)) {
      deps.push({ name: match[1], version: match[2] });
    }

    return dedupeCoordinates(deps);
  }

  return [];
}

function parsePython(content: string, basename: string): PackageCoordinate[] {
  if (basename.startsWith("requirements")) {
    return content
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith("#") && !line.startsWith("-"))
      .map(parsePythonRequirement)
      .filter((value): value is PackageCoordinate => Boolean(value));
  }

  if (basename === "poetry.lock") {
    return parseTomlPackageBlocks(content);
  }

  if (basename === "pyproject.toml") {
    const deps: PackageCoordinate[] = [];

    const projectDepsBlock = content.match(/dependencies\s*=\s*\[((?:.|\n)*?)\]/m)?.[1];
    if (projectDepsBlock) {
      for (const match of projectDepsBlock.match(/"([^"]+)"/g) || []) {
        const parsed = parsePythonRequirement(match.slice(1, -1));
        if (parsed) deps.push(parsed);
      }
    }

    const poetryBlock = content.match(/\[tool\.poetry\.dependencies\]((?:.|\n)*?)(?:\n\[|$)/m)?.[1];
    if (poetryBlock) {
      for (const line of poetryBlock.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("python")) continue;
        const match = trimmed.match(/^([A-Za-z0-9_.-]+)\s*=\s*["']?([^"']+)["']?/);
        if (match) deps.push({ name: match[1], version: normalizeVersion(match[2]) });
      }
    }
    return dedupeCoordinates(deps);
  }

  if (basename === "pipfile" || basename === "pipfile.lock") {
    const deps: PackageCoordinate[] = [];
    for (const match of content.matchAll(/"([^"]+)"\s*:\s*\{[^}]*"version"\s*:\s*"==([^"]+)"/g)) {
      deps.push({ name: match[1], version: match[2] });
    }
    return dedupeCoordinates(deps);
  }

  return [];
}

function parseGo(content: string, basename: string): PackageCoordinate[] {
  if (basename !== "go.mod" && basename !== "go.sum") return [];

  const deps: PackageCoordinate[] = [];
  for (const match of content.matchAll(/^\s*([A-Za-z0-9_./-]+)\s+v([0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9_.+-]*)/gm)) {
    deps.push({ name: match[1], version: match[2] });
  }
  return dedupeCoordinates(deps);
}

function parseRust(content: string, basename: string): PackageCoordinate[] {
  return basename === "cargo.lock" ? parseTomlPackageBlocks(content) : [];
}

function parseJava(content: string, basename: string): PackageCoordinate[] {
  if (basename !== "pom.xml") return [];

  const deps: PackageCoordinate[] = [];
  for (const match of content.matchAll(/<dependency>([\s\S]*?)<\/dependency>/g)) {
    const block = match[1];
    const groupId = block.match(/<groupId>([^<]+)<\/groupId>/)?.[1]?.trim();
    const artifactId = block.match(/<artifactId>([^<]+)<\/artifactId>/)?.[1]?.trim();
    const version = block.match(/<version>([^<]+)<\/version>/)?.[1]?.trim();
    // A property placeholder such as ${spring.version} is not a resolvable
    // version; sending it to OSV would produce a meaningless query.
    if (groupId && artifactId && version && !version.startsWith("${")) {
      deps.push({ name: `${groupId}:${artifactId}`, version: normalizeVersion(version) });
    }
  }
  return dedupeCoordinates(deps);
}

function parseRuby(content: string, basename: string): PackageCoordinate[] {
  if (basename !== "gemfile.lock") return [];

  const specsSection = content.split("specs:")[1]?.split("PLATFORMS")[0];
  if (!specsSection) return [];

  const deps: PackageCoordinate[] = [];
  for (const match of specsSection.matchAll(/^ {4}([A-Za-z0-9_.-]+)\s+\(([0-9A-Za-z_.-]+)\)/gm)) {
    deps.push({ name: match[1], version: match[2] });
  }
  return dedupeCoordinates(deps);
}

function parsePhp(content: string, basename: string): PackageCoordinate[] {
  if (basename !== "composer.lock") return [];

  const lock = JSON.parse(content) as {
    packages?: Array<{ name?: string; version?: string }>;
    "packages-dev"?: Array<{ name?: string; version?: string }>;
  };

  const deps: PackageCoordinate[] = [];
  for (const pkg of [...(lock.packages || []), ...(lock["packages-dev"] || [])]) {
    if (pkg.name && pkg.version) deps.push({ name: pkg.name, version: normalizeVersion(pkg.version) });
  }
  return dedupeCoordinates(deps);
}

/** Shared by poetry.lock and Cargo.lock, which use the same [[package]] layout. */
function parseTomlPackageBlocks(content: string): PackageCoordinate[] {
  const deps: PackageCoordinate[] = [];
  for (const block of content.split("[[package]]")) {
    const name = block.match(/^\s*name\s*=\s*"([^"]+)"/m)?.[1];
    const version = block.match(/^\s*version\s*=\s*"([^"]+)"/m)?.[1];
    if (name) deps.push({ name, version });
  }
  return dedupeCoordinates(deps);
}

export function parsePythonRequirement(line: string): PackageCoordinate | null {
  const cleaned = line.split(";")[0].split("#")[0].trim();
  if (!cleaned) return null;

  const match = cleaned.match(/^([A-Za-z0-9_.-]+)\s*(?:\[.*?\])?\s*(==|~=|>=|<=|>|<)?\s*([^,\s]+)?/);
  if (!match) return null;

  return { name: match[1], version: normalizeVersion(match[3]) };
}

function normalizeVersion(version?: string): string | undefined {
  if (!version) return undefined;
  return version.replace(/^[=~^><! v]+/, "").trim() || undefined;
}

// OSV advisory lookup

/**
 * Queries the OSV database in bounded batches. Requests carry an explicit
 * timeout and retry with exponential backoff, so a hung connection cannot stall
 * a scan and one rate-limit response cannot drop every dependency finding.
 */
async function queryOsv(
  ecosystem: string,
  dependencies: readonly PackageCoordinate[],
  manifestPath: string,
  endpoint: string = OSV_ENDPOINT
): Promise<DependencyVulnerability[]> {
  const exactDeps = dependencies.filter((dep): dep is Required<PackageCoordinate> => Boolean(dep.version));
  if (exactDeps.length === 0) return [];

  const vulnerabilities: DependencyVulnerability[] = [];

  for (let offset = 0; offset < exactDeps.length; offset += OSV_MAX_BATCH) {
    const batch = exactDeps.slice(offset, offset + OSV_MAX_BATCH);
    const response = await postOsvBatch(endpoint, batch, ecosystem);

    for (let i = 0; i < batch.length; i++) {
      const dep = batch[i];
      for (const vuln of response.results?.[i]?.vulns || []) {
        vulnerabilities.push(toVulnerability(vuln, dep, ecosystem, manifestPath));
      }
    }
  }

  return vulnerabilities;
}

async function postOsvBatch(
  endpoint: string,
  batch: readonly Required<PackageCoordinate>[],
  ecosystem: string
): Promise<OsvBatchResponse> {
  const body = JSON.stringify({
    queries: batch.map((dep) => ({
      package: { name: dep.name, ecosystem },
      version: dep.version,
    })),
  });

  let lastError = "";

  for (let attempt = 1; attempt <= OSV_MAX_ATTEMPTS; attempt++) {
    // Set when the response says retrying cannot help. Throwing from inside the
    // try below only fed the catch, which recorded the message and retried with
    // backoff anyway, so a malformed request still took the full attempt budget.
    let permanent = false;

    try {
      const response = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json", "User-Agent": "sentinel-mcp" },
        body,
        signal: AbortSignal.timeout(OSV_TIMEOUT_MS),
      });

      if (response.ok) {
        return (await response.json()) as OsvBatchResponse;
      }

      // 4xx other than rate limiting will not succeed on retry.
      if (response.status !== 429 && response.status < 500) {
        permanent = true;
      }
      lastError = `HTTP ${response.status}`;
    } catch (error) {
      lastError = errorMessage(error);
      // AbortSignal.timeout() rejects with TimeoutError; only an explicit
      // controller.abort() produces AbortError. Testing for one alone left the
      // timeout reported as a generic failure.
      if (error instanceof Error && (error.name === "TimeoutError" || error.name === "AbortError")) {
        lastError = `request timed out after ${OSV_TIMEOUT_MS}ms`;
      }
    }

    if (permanent) {
      throw new Error(`OSV returned ${lastError}`);
    }

    if (attempt < OSV_MAX_ATTEMPTS) {
      await delay(250 * 2 ** (attempt - 1));
    }
  }

  throw new Error(`OSV request failed after ${OSV_MAX_ATTEMPTS} attempts (${lastError})`);
}

function toVulnerability(
  vuln: OsvVulnerability,
  dep: Required<PackageCoordinate>,
  ecosystem: string,
  manifestPath: string
): DependencyVulnerability {
  return {
    package: dep.name,
    ecosystem: ecosystem.toLowerCase(),
    severity: mapOsvSeverity(vuln),
    title: vuln.summary || vuln.details?.slice(0, 200) || vuln.id || "Known vulnerability",
    url: vuln.references?.find((ref) => ref.url)?.url || `https://osv.dev/vulnerability/${vuln.id ?? ""}`,
    installedVersion: dep.version,
    patchedVersion: extractPatchedVersion(vuln) || "Check advisory",
    path: dep.name,
    manifestPath,
    advisoryId: vuln.id,
  };
}

export function mapOsvSeverity(vuln: OsvVulnerability): Severity {
  const vector = vuln.severity?.find((entry) => entry.type === "CVSS_V3" || entry.type === "CVSS_V4")?.score;
  const numeric = vector ? parseCvssBaseScore(vector) : null;

  if (numeric !== null) {
    if (numeric >= 9) return "critical";
    if (numeric >= 7) return "high";
    if (numeric >= 4) return "medium";
    return "low";
  }

  // GitHub advisories imported into OSV often carry a qualitative rating only.
  switch (vuln.database_specific?.severity?.toUpperCase()) {
    case "CRITICAL": return "critical";
    case "HIGH": return "high";
    case "MODERATE":
    case "MEDIUM": return "medium";
    case "LOW": return "low";
    default: return "medium";
  }
}

/**
 * OSV reports CVSS as a vector string ("CVSS:3.1/AV:N/...") rather than a
 * number, so a plain parseFloat yields NaN for every real advisory.
 */
function parseCvssBaseScore(score: string): number | null {
  const direct = Number.parseFloat(score);
  if (!Number.isNaN(direct) && !score.includes("/")) return direct;

  const embedded = score.match(/(?:^|\/)(\d+(?:\.\d+)?)$/);
  if (embedded) {
    const value = Number.parseFloat(embedded[1]);
    if (!Number.isNaN(value) && value <= 10) return value;
  }

  return score.startsWith("CVSS:") ? estimateFromVector(score) : null;
}

/**
 * Approximates a qualitative band from a CVSS vector when no numeric score is
 * supplied. Coarse by design: it picks a severity bucket, not a score.
 */
function estimateFromVector(vector: string): number | null {
  const parts = new Map(
    vector.split("/").slice(1).map((part) => {
      const [key, value] = part.split(":");
      return [key, value] as const;
    })
  );

  const impacts = ["C", "I", "A"].map((key) => parts.get(key));
  if (impacts.every((value) => value === undefined)) return null;

  const high = impacts.filter((value) => value === "H").length;
  const networkAccessible = parts.get("AV") === "N";
  const noPrivileges = parts.get("PR") === "N";
  const noInteraction = parts.get("UI") === "N";

  if (high >= 2 && networkAccessible && noPrivileges && noInteraction) return 9.5;
  if (high >= 1 && networkAccessible && noPrivileges) return 7.5;
  if (high >= 1) return 5.5;
  return 3.5;
}

function extractPatchedVersion(vuln: OsvVulnerability): string | undefined {
  for (const affected of vuln.affected || []) {
    for (const range of affected.ranges || []) {
      for (const event of range.events || []) {
        if (event.fixed) return event.fixed;
      }
    }
  }
  return undefined;
}

function scanKnownRiskPackages(
  dependencies: readonly PackageCoordinate[],
  ecosystem: string
): DependencyVulnerability[] {
  const vulnerabilities: DependencyVulnerability[] = [];

  for (const dep of dependencies) {
    const risk = KNOWN_RISKY_PACKAGES[dep.name.toLowerCase()];
    if (!risk || risk.ecosystem !== ecosystem) continue;

    vulnerabilities.push({
      package: dep.name,
      ecosystem,
      // Capped at low regardless of the package's worst historical severity.
      // This is a name match, not a version match: the installed version may
      // be fully patched. At the package's own severity these entries counted
      // toward the CI failure threshold, so an up-to-date dependency failed a
      // build with nothing to fix.
      severity: "low",
      title: `${risk.message} (unverified: OSV was unavailable, so the installed version was not checked)`,
      url: ecosystem === "npm"
        ? `https://www.npmjs.com/package/${dep.name}`
        : `https://pypi.org/project/${dep.name}/`,
      installedVersion: dep.version || "unknown",
      patchedVersion: "Check the latest safe version",
      path: dep.name,
    });
  }

  return vulnerabilities;
}

// Reachability

/**
 * Determines which vulnerable packages are actually imported by project code.
 * The source tree is read once and every package is tested against it.
 */
async function buildReachabilityIndex(
  projectRoot: string,
  ecosystem: string,
  vulnerabilities: readonly DependencyVulnerability[],
  diagnostics: Diagnostics
): Promise<Map<string, "reachable" | "unreachable" | "unknown">> {
  const index = new Map<string, "reachable" | "unreachable" | "unknown">();
  if (vulnerabilities.length === 0) return index;

  const packages = [...new Set(vulnerabilities.map((vuln) => vuln.package))];
  for (const name of packages) index.set(name, "unreachable");

  const matchers = packages.map((name) => ({ name, regex: buildImportRegex(name, ecosystem) }));

  const { files, truncated } = await walkDirectory(projectRoot, {
    diagnostics,
    maxFiles: REACHABILITY_MAX_FILES,
    shouldReadFile: (_fullPath, name) => REACHABILITY_EXTENSIONS.has(path.extname(name).toLowerCase()),
  });

  if (truncated) {
    // Say so rather than reporting "unreachable" from an incomplete search.
    for (const name of packages) index.set(name, "unknown");
    diagnostics.add(
      `Reachability analysis examined only the first ${REACHABILITY_MAX_FILES} source files; ` +
      `dependency reachability is reported as "unknown".`
    );
    return index;
  }

  let remaining = new Set(packages);

  await mapWithConcurrency(
    files,
    async (filePath) => {
      if (remaining.size === 0) return;

      const content = await readTextFile(filePath, { diagnostics });
      if (content === null) return;

      for (const { name, regex } of matchers) {
        if (!remaining.has(name)) continue;
        if (regex.test(content)) {
          index.set(name, "reachable");
          remaining.delete(name);
        }
      }
    },
    resolveConcurrency()
  );

  return index;
}

function buildImportRegex(packageName: string, ecosystem: string): RegExp {
  const escaped = escapeRegExp(packageName);

  switch (ecosystem) {
    case "npm":
      return new RegExp(
        `(?:from\\s*['"]${escaped}(?:/[^'"]*)?['"]|require\\s*\\(\\s*['"]${escaped}(?:/[^'"]*)?['"]|import\\s*['"]${escaped}(?:/[^'"]*)?['"])`,
        "i"
      );
    case "python": {
      const module = escapeRegExp(packageName.replace(/-/g, "_"));
      return new RegExp(`(?:^|\\n)\\s*(?:import\\s+${module}\\b|from\\s+${module}[\\s.]+import)`, "i");
    }
    case "go":
      return new RegExp(`"${escaped}(?:/[^"]*)?"`);
    case "rust":
      return new RegExp(`\\buse\\s+${escapeRegExp(packageName.replace(/-/g, "_"))}\\b`);
    case "java":
      return new RegExp(`\\bimport\\s+${escapeRegExp(packageName.split(":")[0])}\\b`);
    case "ruby":
      return new RegExp(`require\\s*['"]${escaped}['"]`, "i");
    case "php":
      return new RegExp(`\\buse\\s+${escapeRegExp(packageName.replace(/\//g, "\\"))}`, "i");
    default:
      return new RegExp(escaped, "i");
  }
}

function escapeRegExp(value: string): string {
  return value.replace(/[-/\\^$*+?.()|[\]{}]/g, "\\$&");
}

function dedupeVulnerabilities(vulnerabilities: readonly DependencyVulnerability[]): DependencyVulnerability[] {
  const seen = new Set<string>();
  return vulnerabilities.filter((vuln) => {
    const key = [vuln.package, vuln.installedVersion, vuln.advisoryId || vuln.title].join(":");
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function summarizeVulnerabilities(vulnerabilities: readonly DependencyVulnerability[]): Record<string, number> {
  const summary: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const vuln of vulnerabilities) {
    summary[vuln.severity] = (summary[vuln.severity] || 0) + 1;
  }
  return summary;
}

function dedupeCoordinates(deps: readonly PackageCoordinate[]): PackageCoordinate[] {
  const seen = new Set<string>();
  return deps.filter((dep) => {
    const key = `${dep.name}:${dep.version || ""}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
