import { SecurityPattern } from "../types/index.js";

// SQL Injection

export const injectionPatterns: SecurityPattern[] = [
  // Server-side request forgery. The taint rules in rules/ follow a URL across
  // statements; these catch the direct form, which is what the pattern engine
  // can see on one line and is the shape most SSRF actually takes.
  {
    id: "SSRF_FETCH_USER_URL",
    regex: /\b(?:fetch|got|superagent\s*\.\s*\w+|axios(?:\s*\.\s*\w+)?)\s*\(\s*(?:req|request|ctx)\s*\.\s*(?:query|body|params)\b/,
    severity: "high",
    category: "injection",
    cweId: "CWE-918",
    message: "Outbound request to a URL taken straight from user input. An attacker can reach internal services and cloud metadata endpoints.",
    remediation: "Validate the URL against an allowlist of hosts and schemes, resolve the hostname and reject private and link-local ranges, and disable redirect following.",
    languages: ["javascript", "typescript"],
  },
  {
    id: "SSRF_NODE_HTTP_USER_URL",
    regex: /\bhttps?\s*\.\s*(?:get|request)\s*\(\s*(?:req|request|ctx)\s*\.\s*(?:query|body|params)\b/,
    severity: "high",
    category: "injection",
    cweId: "CWE-918",
    message: "Outbound request to a URL taken straight from user input. An attacker can reach internal services and cloud metadata endpoints.",
    remediation: "Validate the URL against an allowlist of hosts and schemes, and reject private address ranges after resolving the hostname.",
    languages: ["javascript", "typescript"],
  },
  {
    id: "PY_SSRF_REQUESTS_USER_URL",
    regex: /\b(?:requests\s*\.\s*(?:get|post|put|delete|head|request)|httpx\s*\.\s*(?:get|post)|urlopen)\s*\(\s*(?:request\s*\.\s*(?:args|form|json|GET|POST)|flask\s*\.\s*request\s*\.)/,
    severity: "high",
    category: "injection",
    cweId: "CWE-918",
    message: "Outbound request to a URL taken straight from user input. An attacker can reach internal services and cloud metadata endpoints.",
    remediation: "Validate the URL against an allowlist of hosts and schemes, and reject private address ranges after resolving the hostname.",
    languages: ["python"],
  },
  // XML external entity processing. The dangerous setting is explicit in every
  // case here, so these are line-local rather than dataflow rules.
  {
    id: "XXE_LXML_RESOLVE_ENTITIES",
    regex: /XMLParser\s*\([^)]*resolve_entities\s*=\s*True/,
    severity: "high",
    category: "injection",
    cweId: "CWE-611",
    message: "XML parser resolves external entities. A crafted document can read local files or reach internal services.",
    remediation: "Use etree.XMLParser(resolve_entities=False, no_network=True), or parse with defusedxml.",
    languages: ["python"],
  },
  {
    id: "XXE_LIBXMLJS_NOENT",
    regex: /parseXml\w*\s*\([^)]*noent\s*:\s*true/i,
    severity: "high",
    category: "injection",
    cweId: "CWE-611",
    message: "libxmljs is configured to substitute external entities, which allows XXE.",
    remediation: "Remove noent: true. Entity substitution is off by default and should stay off for untrusted XML.",
    languages: ["javascript", "typescript"],
  },
  // String concatenation in a query
  {
    id: "SQL_INJECTION_CONCAT",
    regex: /(?:query|execute|raw|prepare)\s*\(\s*(?:['"`].*?\$\{|['"`].*?\+\s*(?:req\.|params\.|body\.|query\.|input|user))/i,
    severity: "critical",
    category: "injection",
    cweId: "CWE-89",
    message: "Possible SQL injection via string concatenation. User input appears to be directly embedded in a SQL query.",
    remediation: "Use parameterized queries instead of string concatenation. Example: db.query('SELECT * FROM users WHERE id = $1', [userId])",
    languages: ["javascript", "typescript", "python", "ruby", "php"],
  },
  // Template literal in a query
  {
    id: "SQL_INJECTION_TEMPLATE",
    regex: /(?:query|execute|raw)\s*\(\s*`[^`]*\$\{[^}]*\}[^`]*`/i,
    severity: "critical",
    category: "injection",
    cweId: "CWE-89",
    message: "SQL injection risk: template literal with interpolated values in database query.",
    remediation: "Never use template literals for SQL queries. Use parameterized queries: db.query('SELECT * FROM users WHERE id = $1', [id])",
    languages: ["javascript", "typescript"],
  },
  // ORM raw query
  {
    id: "SQL_INJECTION_ORM_RAW",
    regex: /\.\s*(?:rawQuery|raw|literal|sequelize\.query|knex\.raw|prisma\.\$queryRaw)\s*\(\s*(?:`[^`]*\$\{|['"].*?\+)/i,
    severity: "high",
    category: "injection",
    cweId: "CWE-89",
    message: "Raw ORM query with potential user input interpolation. Even with an ORM, raw queries can be injectable.",
    remediation: "Use the ORM's parameterized raw query API. Example: prisma.$queryRaw`SELECT * FROM users WHERE id = ${Prisma.sql`${id}`}`",
    languages: ["javascript", "typescript"],
  },

  // NoSQL Injection

  {
    id: "NOSQL_INJECTION",
    regex: /(?:find|findOne|findMany|deleteOne|deleteMany|updateOne|updateMany|aggregate)\s*\(\s*(?:req\.body|req\.query|req\.params|JSON\.parse)/i,
    severity: "high",
    category: "injection",
    cweId: "CWE-943",
    message: "Possible NoSQL injection: user input passed directly as a MongoDB query operator.",
    remediation: "Validate and sanitize user input before using in NoSQL queries. Use a schema validator like Joi or Zod to enforce expected types.",
    languages: ["javascript", "typescript"],
  },

  // Command Injection

  {
    id: "COMMAND_INJECTION_EXEC",
    // The leading lookbehind rejects RegExp.prototype.exec, which shares its
    // name with child_process.exec: `/Python (\d+)\./.exec(`${a}${b}`)` is a
    // regex match, not a shell. Without it every regex .exec() called on a
    // template literal was reported as critical command injection - found by
    // running this scanner over its own source.
    regex: /(?<!\/[gimsuy]{0,4}\.)\b(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{|['"].*?\+\s*(?:req\.|params\.|input|user|arg))/i,
    severity: "critical",
    category: "injection",
    cweId: "CWE-78",
    message: "Command injection risk: user input in exec() or execSync(). Attacker can execute arbitrary system commands.",
    remediation: "Use execFile() or spawn() with argument arrays instead of exec() with string interpolation. Never pass user input to shell commands.",
    languages: ["javascript", "typescript"],
  },
  {
    id: "COMMAND_INJECTION_SPAWN",
    regex: /(?:spawn|spawnSync)\s*\(\s*(?:req\.|params\.|input|user|arg)/i,
    severity: "high",
    category: "injection",
    cweId: "CWE-78",
    message: "Potential command injection via spawn with user-controlled command name.",
    remediation: "Hardcode the command name and only allow user input in the arguments array. Validate and sanitize all arguments.",
    languages: ["javascript", "typescript"],
  },
  {
    id: "COMMAND_INJECTION_SYSTEM",
    regex: /(?:os\.system|os\.popen|subprocess\.call|subprocess\.run|subprocess\.Popen)\s*\(\s*(?:f['"]|['"].*?\+|.*?\.format\()/i,
    severity: "critical",
    category: "injection",
    cweId: "CWE-78",
    message: "Command injection in Python: user input in system command execution.",
    remediation: "Use subprocess.run() with a list of arguments and shell=False (default). Never use shell=True with user input.",
    languages: ["python"],
  },

  // LDAP Injection

  {
    id: "LDAP_INJECTION",
    regex: /(?:search|bind)\s*\(\s*(?:`[^`]*\$\{|['"].*?\+\s*(?:req\.|user|input))/i,
    severity: "high",
    category: "injection",
    cweId: "CWE-90",
    message: "Possible LDAP injection: user input in LDAP query without sanitization.",
    remediation: "Escape special LDAP characters (*, (, ), \\, NUL) in user input before building LDAP filters.",
    languages: ["javascript", "typescript", "java", "python"],
  },

  // Header Injection

  {
    id: "HEADER_INJECTION",
    regex: /(?:setHeader|writeHead|res\.header)\s*\(\s*['"][^'"]*['"]\s*,\s*(?:req\.|params\.|input|user)/i,
    severity: "medium",
    category: "injection",
    cweId: "CWE-113",
    message: "HTTP header injection: user input in response headers can lead to response splitting attacks.",
    remediation: "Validate and sanitize header values. Remove newline characters (\\r\\n) from user input before setting headers.",
    languages: ["javascript", "typescript"],
    matchScope: "literal",
  },

  // Expression Language Injection

  {
    id: "EXPRESSION_INJECTION",
    regex: /new\s+Function\s*\(\s*(?:req\.|params\.|input|user|`[^`]*\$\{)/i,
    severity: "critical",
    category: "injection",
    cweId: "CWE-917",
    message: "Expression injection via Function constructor: user input executed as code.",
    remediation: "Never use the Function constructor with user input. Use a safe expression parser or sandboxed evaluation.",
    languages: ["javascript", "typescript"],
  },
];
