import { describe, expect, it } from "vitest";
import { scanCode } from "../src/scanner/pattern-engine.js";

/**
 * Accuracy is the product. A scanner that flags correct code teaches people to
 * ignore it, and one that misses a whole vulnerability class is worse than no
 * scanner because it grants false confidence.
 *
 * These pin the specific confusions found by scanning code written to look
 * dangerous while being safe, and vice versa. Only the pattern engine is
 * exercised, since it runs everywhere; Semgrep's rules are gated by the
 * detection benchmark.
 */

const scan = (code: string, file = "/proj/app.js") =>
  scanCode(code, file, undefined, "/proj").findings;

const ruleIds = (code: string, file?: string) => scan(code, file).map((f) => f.ruleId);

describe("safe code is not reported", () => {
  it("accepts sanitised innerHTML, which is the documented fix", () => {
    // Flagging the remediation is the fastest way to have the tool ignored.
    expect(ruleIds('el.innerHTML = DOMPurify.sanitize(userHtml);')).not.toContain("XSS_INNERHTML");
    expect(ruleIds('el.innerHTML = sanitizeHtml(userHtml);')).not.toContain("XSS_INNERHTML");
    expect(ruleIds('el.innerHTML = escapeHtml(userHtml);')).not.toContain("XSS_INNERHTML");
    expect(ruleIds('el.outerHTML = DOMPurify.sanitize(userHtml);')).not.toContain("XSS_OUTERHTML");
  });

  it("accepts an author-controlled literal assigned to innerHTML", () => {
    expect(ruleIds('el.innerHTML = "";')).not.toContain("XSS_INNERHTML");
    expect(ruleIds('el.innerHTML = "<b>static</b>";')).not.toContain("XSS_INNERHTML");
    expect(ruleIds("el.innerHTML = `<b>static</b>`;")).not.toContain("XSS_INNERHTML");
  });

  it("still reports innerHTML fed from a variable or an interpolation", () => {
    expect(ruleIds("el.innerHTML = userInput;")).toContain("XSS_INNERHTML");
    expect(ruleIds("el.innerHTML = `<b>${userInput}</b>`;")).toContain("XSS_INNERHTML");
    expect(ruleIds("el.innerHTML = a + b;")).toContain("XSS_INNERHTML");
  });

  it("does not call a field name a hardcoded credential", () => {
    // The value is a common word, not a secret. The secret detector filters
    // these; the pattern engine has to apply the same filter or the two
    // engines disagree about the same line.
    expect(ruleIds('const passwordFieldName = "password";')).not.toContain("GENERIC_SECRET_CONST");
    expect(ruleIds('const tokenKey = "changeme";')).not.toContain("GENERIC_SECRET_CONST");
  });

  it("does not call an environment lookup a hardcoded credential", () => {
    expect(ruleIds('const apiKey = process.env.API_KEY;')).not.toContain("GENERIC_SECRET_CONST");
  });

  it("still reports a real hardcoded credential", () => {
    expect(ruleIds('const apiSecret = "sk_live_notarealkeyusedasfix";'))
      .toContain("GENERIC_SECRET_CONST");
  });

  it("does not treat a parameterised query as injection", () => {
    expect(ruleIds('db.query("SELECT * FROM users WHERE id = $1", [req.params.id]);'))
      .not.toContain("SQL_INJECTION_CONCAT");
    expect(ruleIds('db.execute("SELECT * FROM t WHERE a = ?", [a]);'))
      .not.toContain("SQL_INJECTION_CONCAT");
  });

  it("does not treat a constant URL as request forgery", () => {
    expect(ruleIds('const r = await fetch("https://api.example.com/health");'))
      .not.toContain("SSRF_FETCH_USER_URL");
    expect(ruleIds("const r = await fetch(config.serviceUrl);"))
      .not.toContain("SSRF_FETCH_USER_URL");
  });
});

describe("path traversal, the shapes it takes in real code", () => {
  // Found by scoring against real advisories: logto served files outside its
  // root through `path.join(staticPath, request.url)`. Neither the object name
  // `request` nor the property `.url` was recognised, so a textbook traversal
  // went unreported while the tutorial form was caught.

  it("recognises request as well as req", () => {
    expect(ruleIds("const p = path.join(staticPath, request.url);"))
      .toContain("PATH_TRAVERSAL_JOIN");
    expect(ruleIds("const p = path.join(base, req.query.file);"))
      .toContain("PATH_TRAVERSAL_JOIN");
  });

  it("recognises url and path as sources, not only query and body", () => {
    expect(ruleIds("const p = path.join(root, request.originalUrl);"))
      .toContain("PATH_TRAVERSAL_JOIN");
    expect(ruleIds("const p = path.join(root, ctx.path);"))
      .toContain("PATH_TRAVERSAL_JOIN");
  });

  it("covers the file operations streaming handlers actually use", () => {
    // open and stat were absent, and they are how a file gets read when a
    // handler streams a range, which is where traversal tends to live.
    expect(ruleIds("const h = await fs.open(req.query.path, 'r');"))
      .toContain("PATH_TRAVERSAL_FS");
    expect(ruleIds("const s = await fs.stat(request.url);"))
      .toContain("PATH_TRAVERSAL_FS");
  });

  it("does not report path.resolve, which is the documented fix", () => {
    // The containment check sits on the next line, where a line-local rule
    // cannot see it. Reporting the remediation is worse than staying quiet.
    const ids = ruleIds("const safe = path.resolve(base, userInput);");
    expect(ids).not.toContain("PATH_TRAVERSAL_JOIN");
  });

  it("leaves a path built entirely from constants alone", () => {
    expect(ruleIds('const p = path.join(__dirname, "templates", "index.html");'))
      .not.toContain("PATH_TRAVERSAL_JOIN");
  });
});

describe("severity reflects what the code is doing", () => {
  it("grades a weak hash used as a cache key as informational", () => {
    const [finding] = scan('const etag = crypto.createHash("md5").update(buf).digest("hex");')
      .filter((f) => f.ruleId === "WEAK_HASH_MD5");

    expect(finding).toBeDefined();
    expect(finding.severity).toBe("info");
  });

  it("keeps a weak hash over a password at full severity", () => {
    const [finding] = scan('const h = crypto.createHash("md5").update(password).digest("hex");')
      .filter((f) => f.ruleId === "WEAK_HASH_MD5");

    expect(finding).toBeDefined();
    expect(finding.severity).toBe("high");
  });
});

describe("vulnerability classes that were previously invisible", () => {
  it("reports request forgery from user-controlled URLs", () => {
    expect(ruleIds("const r = await fetch(req.query.url);")).toContain("SSRF_FETCH_USER_URL");
    expect(ruleIds("https.get(req.query.target);")).toContain("SSRF_NODE_HTTP_USER_URL");
    expect(ruleIds("r = requests.get(request.args.get('url'))", "/proj/a.py"))
      .toContain("PY_SSRF_REQUESTS_USER_URL");
  });

  it("reports XML parsers configured to resolve external entities", () => {
    expect(ruleIds("p = etree.XMLParser(resolve_entities=True)", "/proj/a.py"))
      .toContain("XXE_LXML_RESOLVE_ENTITIES");
    expect(ruleIds("const d = libxmljs.parseXml(xml, { noent: true });"))
      .toContain("XXE_LIBXMLJS_NOENT");
  });

  it("no longer carries a line-local Java XXE rule that flagged hardened code", () => {
    // DocumentBuilderFactory is hardened on a later line, which a line-local
    // rule cannot see. It reported correctly hardened code as vulnerable, so
    // the check moved to rules/sentinel-core.yml where the hardening is
    // visible. Measured on the OWASP Benchmark: 20 false positives before.
    const ids = ruleIds("javax.xml.parsers.DocumentBuilderFactory.newInstance();", "/proj/A.java");
    expect(ids).not.toContain("XXE_JAVA_UNSAFE_FACTORY");
  });

  it("leaves a safely configured XML parser alone", () => {
    expect(ruleIds("p = etree.XMLParser(resolve_entities=False, no_network=True)", "/proj/a.py"))
      .not.toContain("XXE_LXML_RESOLVE_ENTITIES");
    expect(ruleIds("const d = libxmljs.parseXml(xml);")).not.toContain("XXE_LIBXMLJS_NOENT");
  });
});
