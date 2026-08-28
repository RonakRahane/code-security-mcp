import { SecurityPattern } from "../types/index.js";

export const miscPatterns: SecurityPattern[] = [
  // Unrestricted file upload, CWE-434 and number 10 on the CWE Top 25. An
  // upload endpoint that accepts any type and any size lets an attacker place
  // a script inside the served tree or exhaust the disk.
  {
    id: "UPLOAD_NO_RESTRICTIONS",
    // Neither limits nor fileFilter anywhere in the options object. Both are
    // the documented hardening, and reporting a configuration that already has
    // them is worse than staying quiet.
    regex: /\bmulter\s*\(\s*\{(?![^}]*\b(?:limits|fileFilter)\s*:)[^}]*\bdest\s*:/,
    severity: "medium",
    category: "miscellaneous",
    cweId: "CWE-434",
    message: "File upload configured with a destination but no type or size limit. Any file of any size is accepted.",
    remediation: "Pass fileFilter to reject unexpected MIME types and limits: { fileSize } to cap the size. Store uploads outside the web root and never trust the client-supplied filename.",
    languages: ["javascript", "typescript"],
  },
  {
    id: "UPLOAD_MEMORY_STORAGE_UNBOUNDED",
    regex: /multer\s*\.\s*memoryStorage\s*\(\s*\)(?![\s\S]{0,120}\blimits\s*:)/,
    severity: "medium",
    category: "miscellaneous",
    cweId: "CWE-434",
    message: "Uploads buffered in memory. Without a size limit a large upload exhausts the process heap.",
    remediation: "Add limits: { fileSize } alongside memoryStorage, or stream to disk instead.",
    languages: ["javascript", "typescript"],
  },
  {
    id: "PY_UPLOAD_UNSAFE_FILENAME",
    regex: /\.\s*save\s*\((?![^)]*secure_filename)[^)]*\w*file\w*\s*\.\s*filename/i,
    severity: "high",
    category: "miscellaneous",
    cweId: "CWE-434",
    message: "Uploaded file saved under its client-supplied name. The name can contain path separators or an executable extension.",
    remediation: "Use werkzeug.utils.secure_filename(), or generate a name yourself and keep the original only as metadata.",
    languages: ["python"],
  },
  {
    id: "CORS_WILDCARD",
    regex: /(?:Access-Control-Allow-Origin|origin)\s*[:=]\s*['"]?\*/i,
    severity: "medium",
    category: "miscellaneous",
    cweId: "CWE-942",
    message: "CORS wildcard '*' allows any domain to make requests to your API.",
    remediation: "Restrict to specific trusted origins: origin: ['https://yourdomain.com'].",
    languages: ["*"],
    matchScope: "literal",
  },
  {
    id: "CSRF_DISABLED",
    regex: /csrf\s*[:=]\s*false|csurf.*disable/i,
    severity: "high",
    category: "miscellaneous",
    cweId: "CWE-352",
    message: "CSRF protection appears disabled. State-changing requests can be forged.",
    remediation: "Enable CSRF protection for all state-changing endpoints. Use csurf middleware or SameSite cookies.",
    languages: ["javascript", "typescript"],
  },
  {
    id: "HTTP_NO_TLS",
    regex: /http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0|::1|schemas?\.|www\.w3\.org|xml\.org|example\.com|placeholder|fonts\.googleapis|cdn\.|unpkg|jsdelivr)/,
    severity: "low",
    category: "miscellaneous",
    cweId: "CWE-319",
    message: "Non-localhost HTTP URL detected. Data transmitted without encryption.",
    remediation: "Use HTTPS for all non-localhost connections.",
    languages: ["*"],
  },
  {
    id: "DEBUG_MODE_PROD",
    // `1` is anchored with \b so a log-level constant such as `debug: 10` does
    // not match as `debug: 1`.
    regex: /(?:^|[^\w.])(?:DEBUG|debug)\s*[:=]\s*(?:true\b|1\b|['"]true['"])|app\.set\s*\(\s*['"]env['"]\s*,\s*['"]development['"]\)/i,
    severity: "medium",
    category: "miscellaneous",
    cweId: "CWE-489",
    message: "Debug mode may be enabled. Debug info can leak internal details to attackers.",
    remediation: "Ensure DEBUG is disabled in production. Use environment-based config.",
    languages: ["*"],
    matchScope: "literal",
  },
  {
    id: "STACK_TRACE_LEAK",
    regex: /(?:res\.(?:send|json)\s*\(\s*(?:err|error)\.(?:stack|message)|console\.(?:log|error)\s*\(\s*(?:err|error)\.stack)/,
    severity: "medium",
    category: "miscellaneous",
    cweId: "CWE-209",
    message: "Error stack trace may be exposed to clients. Leaks internal paths and code structure.",
    remediation: "Log errors server-side. Send generic error messages to clients in production.",
    languages: ["javascript", "typescript"],
  },
  {
    id: "OPEN_REDIRECT",
    regex: /(?:redirect|location)\s*(?:\(|=)\s*(?:req\.|params\.|query\.|body\.|input|user)/i,
    severity: "medium",
    category: "miscellaneous",
    cweId: "CWE-601",
    message: "Open redirect: user input controls redirect destination. Phishing risk.",
    remediation: "Validate redirect URLs against a whitelist of allowed domains.",
    languages: ["javascript", "typescript", "python"],
  },

  {
    id: "RATE_LIMIT_MISSING",
    regex: /app\.(?:post|put|patch|delete)\s*\(\s*['"]\/(?:login|auth|register|signup|reset|forgot)/i,
    severity: "medium",
    category: "miscellaneous",
    cweId: "CWE-307",
    message: "Auth endpoint without apparent rate limiting. Brute-force risk.",
    remediation: "Add rate limiting: npm install express-rate-limit. Apply to auth routes.",
    languages: ["javascript", "typescript"],
    matchScope: "literal",
  },
];
