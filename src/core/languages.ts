/**
 * Language detection by file extension and name. Lives in core because both the
 * pattern engine and the secret detector need it, and the pattern engine
 * already imports the secret detector for redaction.
 */

import * as path from "node:path";

const EXTENSION_MAP: Record<string, string> = {
  ".js": "javascript",
  ".jsx": "javascript",
  ".mjs": "javascript",
  ".cjs": "javascript",
  ".ts": "typescript",
  ".tsx": "typescript",
  ".mts": "typescript",
  ".cts": "typescript",
  ".py": "python",
  ".rb": "ruby",
  ".php": "php",
  ".java": "java",
  ".go": "go",
  ".rs": "rust",
  ".c": "c",
  ".cpp": "cpp",
  ".h": "c",
  ".hpp": "cpp",
  ".cs": "csharp",
  ".swift": "swift",
  ".kt": "kotlin",
  ".yml": "yaml",
  ".yaml": "yaml",
  ".json": "json",
  ".env": "env",
  ".sh": "shell",
  ".bash": "shell",
  ".zsh": "shell",
  ".sql": "sql",
  ".html": "html",
  ".htm": "html",
  ".xml": "xml",
  ".tf": "terraform",
  ".tfvars": "terraform",
  ".dockerfile": "docker",
};

/** Languages where a quoted region is a string literal rather than a data key. */
export const CODE_LANGUAGES: ReadonlySet<string> = new Set([
  "javascript", "typescript", "python", "ruby", "php", "java", "go", "rust",
  "csharp", "kotlin", "swift", "c", "cpp",
]);

export function detectLanguage(filePath: string): string {
  const basename = path.basename(filePath).toLowerCase();
  if (basename === "dockerfile" || basename.startsWith("dockerfile.")) return "docker";
  if (basename === ".env" || basename.startsWith(".env.")) return "env";

  return EXTENSION_MAP[path.extname(filePath).toLowerCase()] || "unknown";
}
