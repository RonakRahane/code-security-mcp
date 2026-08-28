/**
 * Traversal and resource limits shared by every scan entry point, so coverage
 * does not depend on which entry point a caller uses.
 */

/** Directories never worth scanning: build output, dependency trees, VCS metadata. */
export const IGNORED_DIRECTORIES: ReadonlySet<string> = new Set([
  ".git",
  ".hg",
  ".svn",
  ".next",
  ".nuxt",
  ".output",
  ".turbo",
  ".cache",
  ".gradle",
  ".idea",
  ".vscode",
  ".mypy_cache",
  ".pytest_cache",
  ".tox",
  ".nyc_output",
  ".terraform",
  "node_modules",
  "bower_components",
  "vendor",
  "dist",
  "build",
  "out",
  "target",
  "coverage",
  "__pycache__",
  "venv",
  ".venv",
  "env",
  ".env.d",
  "site-packages",
  "bin",
  "obj",
]);

/** Binary or generated file extensions that cannot contain reviewable source. */
/**
 * Sentinel's own output, skipped so a second scan does not report findings in
 * the report the first one wrote. A report quotes rule names and redacted
 * matches, which is enough to trip the very rules that produced it.
 */
export const GENERATED_REPORT_FILES: ReadonlySet<string> = new Set([
  "sentinel-report.md",
  "sentinel-report.html",
  "sentinel-report.sarif",
  ".sentinel-baseline.json",
]);

export const SKIP_EXTENSIONS: ReadonlySet<string> = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp", ".tiff",
  ".mp4", ".mp3", ".wav", ".avi", ".mov", ".mkv", ".flac", ".ogg",
  ".woff", ".woff2", ".ttf", ".eot", ".otf",
  ".zip", ".tar", ".gz", ".bz2", ".xz", ".rar", ".7z", ".jar", ".war",
  ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
  ".exe", ".dll", ".so", ".dylib", ".class", ".pyc", ".pyo", ".o", ".a",
  ".map", ".min.js", ".min.css",
  ".pack", ".idx", ".bin", ".dat", ".db", ".sqlite", ".sqlite3",
]);

/** Extensions the secret detector reads. Secrets hide in config as often as code. */
export const SECRET_SCAN_EXTENSIONS: ReadonlySet<string> = new Set([
  ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts",
  ".py", ".rb", ".php", ".java", ".go", ".rs", ".cs", ".kt", ".swift",
  ".c", ".cpp", ".h", ".hpp", ".scala", ".groovy", ".pl", ".lua",
  ".env", ".yml", ".yaml", ".json", ".json5", ".toml", ".properties",
  ".cfg", ".conf", ".ini", ".sh", ".bash", ".zsh", ".fish", ".ps1",
  ".xml", ".tf", ".tfvars", ".hcl", ".gradle", ".plist", ".pem", ".key",
]);

/** Files above this size are skipped: bundles and data blobs dominate scan time and yield nothing actionable. */
export const MAX_FILE_BYTES = 1_000_000;

/** Regex matching skips longer lines. Minified single-line files are the main ReDoS exposure. */
export const MAX_LINE_LENGTH = 5_000;

/** Upper bound on files visited in one scan, protecting against runaway monorepos. */
export const DEFAULT_MAX_FILES = 25_000;

/** Directory-walk recursion depth limit; also a symlink-cycle backstop. */
export const MAX_DIRECTORY_DEPTH = 40;

/** Default parallel file reads. Bounded so a scan cannot exhaust file handles. */
export const DEFAULT_CONCURRENCY = 16;

/** Warning list cap, so a pathological repository cannot produce unbounded output. */
export const MAX_WARNINGS = 100;

/** Dependency manifests recognised by the SCA stage. */
/**
 * Loose manifests and the lockfiles that supersede them.
 *
 * A loose manifest records a range ("^1.12.0"); a lockfile records what is
 * actually installed. Auditing both queries the advisory database for the range
 * floor, which reports vulnerabilities the project does not have: `^1.12.0`
 * resolved to 1.29.0 is asked about as 1.12.0. Where a lockfile sits beside a
 * loose manifest, the lockfile is the only truthful source.
 */
export const MANIFEST_SUPERSEDED_BY: Readonly<Record<string, readonly string[]>> = {
  "package.json": ["package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"],
  "pyproject.toml": ["poetry.lock"],
  "pipfile": ["pipfile.lock"],
  "cargo.toml": ["cargo.lock"],
  "composer.json": ["composer.lock"],
  "gemfile": ["gemfile.lock"],
};

export const DEPENDENCY_MANIFESTS: readonly string[] = [
  "package.json",
  "package-lock.json",
  "npm-shrinkwrap.json",
  "yarn.lock",
  "pnpm-lock.yaml",
  "requirements.txt",
  "poetry.lock",
  "pyproject.toml",
  "pipfile",
  "pipfile.lock",
  "go.mod",
  "go.sum",
  "cargo.lock",
  "cargo.toml",
  "pom.xml",
  "build.gradle",
  "gemfile",
  "gemfile.lock",
  "composer.json",
  "composer.lock",
];
