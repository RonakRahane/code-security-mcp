import { SecurityPattern } from "../types/index.js";

export const prototypePollutionPatterns: SecurityPattern[] = [
  {
    id: "PROTO_ACCESS",
    // Requires a real property access, bracket or dot. Without that, the rule
    // fires on any occurrence of "__proto__", including a lookup-table key.
    regex: /(?:\[\s*['"]__proto__['"]\s*\]|\.__proto__\b|['"]__proto__['"]\s*\]|__proto__\s*\]\s*=)/,
    severity: "high",
    category: "prototype-pollution",
    cweId: "CWE-1321",
    message: "__proto__ access detected. Can modify Object prototype and affect all objects.",
    remediation: "Use Object.create(null) for dictionaries. Validate keys and reject '__proto__', 'constructor', 'prototype'.",
    languages: ["javascript", "typescript"],
    matchScope: "literal",
  },
  {
    id: "CONSTRUCTOR_PROTOTYPE",
    // Both segments must be real property accesses, as in PROTO_ACCESS above.
    regex: /(?:\[\s*['"]constructor['"]\s*\]|\.constructor\b)\s*(?:\[\s*['"]prototype['"]\s*\]|\.prototype\b)/,
    severity: "high",
    category: "prototype-pollution",
    cweId: "CWE-1321",
    message: "constructor.prototype access. Prototype pollution gadget chain.",
    remediation: "Sanitize object keys. Use a safe merge library like lodash.merge (v4.6.2+).",
    languages: ["javascript", "typescript"],
    matchScope: "literal",
  },
  {
    id: "UNSAFE_DEEP_MERGE",
    regex: /(?:deepMerge|deepExtend|merge|assign|extend)\s*\(\s*(?:target|dest|obj|\{\})\s*,\s*(?:req\.|body\.|params\.|input|user|source)/i,
    severity: "medium",
    category: "prototype-pollution",
    cweId: "CWE-1321",
    message: "Deep merge with user input. Can lead to prototype pollution if merge is recursive.",
    remediation: "Use Object.assign() for shallow merge, or filter keys: reject '__proto__', 'constructor'.",
    languages: ["javascript", "typescript"],
  },
  {
    id: "BRACKET_NOTATION_USER_INPUT",
    // The leading identifier is bounded and preceded by a word boundary. An
    // unbounded `\w+` restarts inside every word of a long line that holds no
    // "[" at all, which is quadratic: a 5000-character line cost 136ms, and a
    // file of such lines stalls a scan.
    regex: /(?<![\w$])[\w$]{1,64}\s{0,8}\[\s{0,8}(?:req\.|params\.|body\.|query\.|input|user)[\w$]{0,64}\s{0,8}\]/i,
    severity: "medium",
    category: "prototype-pollution",
    cweId: "CWE-1321",
    message: "Dynamic property access with user input via bracket notation.",
    remediation: "Validate property names against an allowlist. Use Map instead of plain objects for user-keyed data.",
    languages: ["javascript", "typescript"],
  },
];
