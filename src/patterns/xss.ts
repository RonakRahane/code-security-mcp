import { SecurityPattern } from "../types/index.js";

export const xssPatterns: SecurityPattern[] = [
  // innerHTML assignment
  {
    id: "XSS_INNERHTML",
    // Sanitising before assigning is the documented fix, so flagging it tells a
    // developer their correct code is wrong. A string literal is
    // author-controlled and equally not a finding.
    regex: /\.innerHTML\s*\+?=(?!\s*['"]|\s*`[^`$]*`|\s*(?:DOMPurify|purify)\s*\.\s*sanitize\b|\s*\w*[Ss]anitiz\w*\s*\(|\s*\w*[Ee]scape(?:Html)?\s*\()/,
    severity: "high",
    category: "xss",
    cweId: "CWE-79",
    message: "XSS risk: innerHTML assignment with dynamic content. Malicious scripts can be injected.",
    remediation: "Use textContent instead of innerHTML for text. If HTML is needed, use DOMPurify.sanitize() to clean input first.",
    languages: ["javascript", "typescript"],
  },
  // outerHTML assignment
  {
    id: "XSS_OUTERHTML",
    // Whitespace inside the lookahead: outside it, `\s*` backtracks to empty and
    // the lookahead is applied at the space, bypassing every exclusion.
    regex: /\.outerHTML\s*\+?=(?!\s*['"]|\s*`[^`$]*`|\s*(?:DOMPurify|purify)\s*\.\s*sanitize\b|\s*\w*[Ss]anitiz\w*\s*\(|\s*\w*[Ee]scape(?:Html)?\s*\()/,
    severity: "high",
    category: "xss",
    cweId: "CWE-79",
    message: "XSS risk: outerHTML assignment with dynamic content.",
    remediation: "Avoid outerHTML with dynamic content. Use safe DOM manipulation methods instead.",
    languages: ["javascript", "typescript"],
  },
  // document.write
  {
    id: "XSS_DOCUMENT_WRITE",
    regex: /document\.write(?:ln)?\s*\(/,
    severity: "high",
    category: "xss",
    cweId: "CWE-79",
    message: "XSS risk: document.write() can inject arbitrary HTML and scripts into the page.",
    remediation: "Replace document.write() with safe DOM methods like createElement() and appendChild().",
    languages: ["javascript", "typescript"],
  },
  // dangerouslySetInnerHTML (React)
  {
    id: "XSS_REACT_DANGEROUSLY",
    regex: /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:/,
    severity: "high",
    category: "xss",
    cweId: "CWE-79",
    message: "XSS risk: dangerouslySetInnerHTML in React. If the value contains user input, it will be rendered as raw HTML.",
    remediation: "Sanitize HTML with DOMPurify before passing to dangerouslySetInnerHTML. Consider if you really need raw HTML rendering.",
    languages: ["javascript", "typescript"],
  },
  // jQuery html() method
  {
    id: "XSS_JQUERY_HTML",
    regex: /\$\s*\(.*?\)\s*\.\s*html\s*\(\s*(?!['"`]\s*['"`])\s*(?:req\.|params\.|input|user|\$|data|response|result|val\()/i,
    severity: "high",
    category: "xss",
    cweId: "CWE-79",
    message: "XSS risk: jQuery .html() with dynamic content can inject scripts.",
    remediation: "Use .text() for plain text content, or sanitize HTML with DOMPurify before using .html().",
    languages: ["javascript", "typescript"],
  },
  // Template rendering without escaping
  {
    id: "XSS_UNESCAPED_TEMPLATE",
    regex: /<%[-=]?\s*(?:req\.|params\.|body\.|query\.)|{{{.*?}}}/,
    severity: "high",
    category: "xss",
    cweId: "CWE-79",
    message: "XSS risk: unescaped template variable. Use escaped syntax to prevent script injection.",
    remediation: "Use escaped template syntax: <%= variable %> (EJS) or {{ variable }} (Handlebars). Avoid raw output markers.",
    languages: ["javascript", "typescript"],
  },
  // window.location with user input
  {
    id: "XSS_LOCATION_HASH",
    // Requires a sink, not merely the source. Matching the source alone flagged
    // `if (location.hash === "#about")` and an assignment to textContent, and
    // no rewrite could close the finding because the rule never looked at the
    // use. The taint rules in rules/ follow these sources properly.
    regex: /(?:innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval|new\s+Function)\s*(?:=|\()[^;\n]*(?:window\.location|location\.hash|location\.search|document\.URL|document\.referrer)/,
    severity: "medium",
    category: "xss",
    cweId: "CWE-79",
    message: "DOM-based XSS source: window.location/document properties contain user-controllable data.",
    remediation: "Always sanitize values from location.hash, location.search, document.URL before using in DOM operations.",
    languages: ["javascript", "typescript"],
  },
  // Server-side response with unsanitized input
  {
    id: "XSS_RESPONSE_WRITE",
    regex: /res\.(?:send|write|end)\s*\(\s*(?:req\.|params\.|`[^`]*\$\{.*?req)/i,
    severity: "high",
    category: "xss",
    cweId: "CWE-79",
    message: "Reflected XSS: user input directly in HTTP response without sanitization.",
    remediation: "HTML-encode user input before including in responses. Use a templating engine with auto-escaping enabled.",
    languages: ["javascript", "typescript"],
  },
];
