import { SecurityPattern } from "../types/index.js";

/**
 * How an untrusted path arrives. `request` is as common as `req` in real
 * handlers, and `.url` is as common a source as `.query`: a missed path
 * traversal in logto used `path.join(staticPath, request.url)`, which neither
 * name nor property matched.
 */
const UNTRUSTED_PATH_SOURCE =
  "(?:req|request|ctx|context|httpRequest|incoming)\\s*\\.\\s*(?:query|body|params|url|path|originalUrl|headers)|params\\.|input|user|body";

export const pathTraversalPatterns: SecurityPattern[] = [
  {
    id: "PATH_TRAVERSAL_FS",
    // `open` and `stat` were absent, and they are how a file is read in
    // streaming handlers, which is where traversal usually lives.
    regex: new RegExp(
      "(?:readFile|writeFile|readFileSync|writeFileSync|createReadStream|createWriteStream|" +
      "unlink|unlinkSync|readdir|readdirSync|open|openSync|stat|statSync|lstat|copyFile|rename)" +
      "\\s*\\(\\s*(?:" + UNTRUSTED_PATH_SOURCE + "|\\w+\\s*\\+|`[^`]*\\$\\{)",
      "i"
    ),
    severity: "high",
    category: "path-traversal",
    cweId: "CWE-22",
    message: "Path traversal risk: user input in file system operation.",
    remediation: "Use path.resolve() and verify the result is within allowed directory: resolvedPath.startsWith(baseDir).",
    languages: ["javascript", "typescript"],
  },
  {
    id: "PATH_TRAVERSAL_JOIN",
    regex: new RegExp("path\\s*\\.\\s*join\\s*\\([^)]*(?:" + UNTRUSTED_PATH_SOURCE + ")", "i"),
    severity: "medium",
    category: "path-traversal",
    cweId: "CWE-22",
    message: "User input in path.join(). '../' sequences can escape the intended directory.",
    remediation: "Resolve against a fixed base and confirm the result stays inside it: const safe = path.resolve(base, input); if (!safe.startsWith(base)) throw new Error('Invalid path'); path.resolve with that check is the safe form and is not reported.",
    languages: ["javascript", "typescript"],
  },

  {
    id: "PATH_TRAVERSAL_SEND_FILE",
    // A `root` option is the documented fix: Express resolves against it and
    // rejects anything that escapes, so matching it reported the remediation.
    regex: new RegExp(
      "(?:sendFile|download|serve)\\s*\\((?![^)]*\\broot\\s*:)\\s*(?:" + UNTRUSTED_PATH_SOURCE + ")",
      "i"
    ),
    severity: "high",
    category: "path-traversal",
    cweId: "CWE-22",
    message: "File serve operation with user input. Attackers can download arbitrary files.",
    remediation: "Use res.sendFile(filename, { root: '/safe/dir' }) with a fixed root directory.",
    languages: ["javascript", "typescript"],
  },
];
