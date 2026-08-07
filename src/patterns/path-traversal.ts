import { SecurityPattern } from "../types/index.js";

export const pathTraversalPatterns: SecurityPattern[] = [
  {
    id: "PATH_TRAVERSAL_FS",
    regex: /(?:readFile|writeFile|readFileSync|writeFileSync|createReadStream|createWriteStream|unlink|unlinkSync|readdir|readdirSync)\s*\(\s*(?:req\.|params\.|input|user|\w+\s*\+|`[^`]*\$\{)/i,
    severity: "high",
    category: "path-traversal",
    cweId: "CWE-22",
    message: "Path traversal risk: user input in file system operation.",
    remediation: "Use path.resolve() and verify the result is within allowed directory: resolvedPath.startsWith(baseDir).",
    languages: ["javascript", "typescript"],
  },
  {
    id: "PATH_TRAVERSAL_JOIN",
    regex: /path\.join\s*\([^)]*(?:req\.|params\.|input|user|body)/i,
    severity: "medium",
    category: "path-traversal",
    cweId: "CWE-22",
    message: "User input in path.join(). '../' sequences can escape the intended directory.",
    remediation: "Validate: const safe = path.resolve(base, input); if (!safe.startsWith(base)) throw new Error('Invalid path');",
    languages: ["javascript", "typescript"],
  },

  {
    id: "PATH_TRAVERSAL_SEND_FILE",
    regex: /(?:sendFile|download|serve)\s*\(\s*(?:req\.|params\.|input|user)/i,
    severity: "high",
    category: "path-traversal",
    cweId: "CWE-22",
    message: "File serve operation with user input. Attackers can download arbitrary files.",
    remediation: "Use res.sendFile(filename, { root: '/safe/dir' }) with a fixed root directory.",
    languages: ["javascript", "typescript"],
  },
];
