import { SecurityPattern } from "../types/index.js";

export const dangerousFunctionPatterns: SecurityPattern[] = [
  {
    id: "EVAL_USAGE",
    regex: /(?<!\w)eval\s*\(/,
    severity: "critical",
    category: "dangerous-functions",
    cweId: "CWE-95",
    message: "eval() executes arbitrary code. If user input reaches eval, it's RCE.",
    remediation: "Remove eval(). Use JSON.parse() for data, or a safe expression parser.",
    languages: ["javascript", "typescript", "python"],
  },
  {
    id: "FUNCTION_CONSTRUCTOR",
    regex: /new\s+Function\s*\(/,
    severity: "critical",
    category: "dangerous-functions",
    cweId: "CWE-95",
    message: "Function constructor is equivalent to eval(). Executes arbitrary code.",
    remediation: "Avoid the Function constructor. Use predefined functions or safe alternatives.",
    languages: ["javascript", "typescript"],
  },
  {
    id: "CHILD_PROCESS_EXEC",
    // Deliberately identical to COMMAND_INJECTION_EXEC in injection.ts, which
    // reports the same code under a different category. A test asserts the two
    // stay in step: they had already diverged once, when the RegExp.exec
    // exclusion was added to one and not the other, so the false positive it
    // fixed carried on being reported by this rule instead.
    regex: /(?<!\/[gimsuy]{0,4}\.)\b(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{|['"].*?\+\s*(?:req\.|params\.|input|user|arg))/i,
    severity: "high",
    category: "dangerous-functions",
    cweId: "CWE-78",
    message: "child_process.exec() with dynamic input. Shell injection risk.",
    remediation: "Use execFile() or spawn() with argument arrays. Never pass user input to exec().",
    languages: ["javascript", "typescript"],
  },
  {
    id: "VM_RUN_IN_CONTEXT",
    regex: /vm\.(?:runInNewContext|runInContext|runInThisContext|createContext)\s*\(/,
    severity: "high",
    category: "dangerous-functions",
    cweId: "CWE-94",
    message: "Node.js vm module is NOT a security sandbox. Code can escape.",
    remediation: "Use isolated-vm or worker_threads for sandboxing. vm module is for dev tools only.",
    languages: ["javascript", "typescript"],
  },
  {
    id: "UNSERIALIZE",
    // yaml.load is deliberately absent: js-yaml v4 made it the safe entry point,
    // so matching it here flagged correct JavaScript. PY_YAML_LOAD covers
    // Python, where the Loader argument decides safety.
    regex: /(?:unserialize|deserialize|pickle\.loads?)\s*\(/i,
    severity: "critical",
    category: "dangerous-functions",
    cweId: "CWE-502",
    message: "Insecure deserialization. Crafted payloads can execute arbitrary code.",
    remediation: "Use JSON.parse() or safe loaders: yaml.safe_load(), pickle with restricted unpickler.",
    languages: ["*"],
  },
  {
    id: "SETTIMEOUT_STRING",
    regex: /(?:setTimeout|setInterval)\s*\(\s*['"`]/,
    severity: "medium",
    category: "dangerous-functions",
    cweId: "CWE-95",
    message: "setTimeout/setInterval with string argument acts like eval().",
    remediation: "Pass a function reference: setTimeout(() => { ... }, delay).",
    languages: ["javascript", "typescript"],
  },
  {
    id: "DYNAMIC_REQUIRE",
    regex: /require\s*\(\s*(?:req\.|params\.|input|user|\w+\s*\+)/i,
    severity: "high",
    category: "dangerous-functions",
    cweId: "CWE-94",
    message: "Dynamic require with user input. Can load arbitrary modules.",
    remediation: "Use a whitelist of allowed modules. Never use dynamic require with user input.",
    languages: ["javascript", "typescript"],
  },
  {
    id: "DYNAMIC_IMPORT",
    regex: /import\s*\(\s*(?:req\.|params\.|input|user|\w+\s*\+)/i,
    severity: "high",
    category: "dangerous-functions",
    cweId: "CWE-94",
    message: "Dynamic import() with user input. Can load arbitrary code.",
    remediation: "Use a whitelist of allowed module paths.",
    languages: ["javascript", "typescript"],
  },
];
