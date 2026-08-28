/**
 * End-to-end feature audit: drives all 16 MCP tools over stdio against a
 * fixture whose correct answers are known in advance.
 *
 * Run `npm run build` first, then `npm run audit:features`.
 *
 * The point is accuracy, not liveness. A tool that answers without error and
 * with the wrong content passes a smoke test and fails a user, so every check
 * asserts on what came back: the taint case that needs Semgrep, the clean file
 * that must stay silent, the credential that must be found and redacted rather
 * than echoed, the SARIF that must parse at 2.1.0, the fix that must leave the
 * file both correct and still parseable.
 *
 * The four GitHub tools need a token. Without one the only correct outcome is
 * an explicit refusal, and that is what is asserted here - returning empty
 * results would read as "nothing found", which is the failure this project
 * keeps having to design against.
 */

import { spawn, execFileSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE";
const results = [];

function record(feature, ok, detail) {
  results.push({ feature, ok, detail });
  console.log(`${ok ? "PASS" : "FAIL"}  ${feature.padEnd(34)} ${detail}`);
}

// ---------------------------------------------------------------- fixture ---

const work = fs.mkdtempSync(path.join(os.tmpdir(), "sentinel-audit-"));
const proj = path.join(work, "proj");
fs.mkdirSync(proj, { recursive: true });

// Taint: HTTP parameter through a variable into a shell. Needs data flow.
fs.writeFileSync(path.join(proj, "cmd.js"), `const { exec } = require("child_process");
function run(req) {
  const dir = req.query.dir;
  exec("ls " + dir);
}
module.exports = { run };
`);

// Line-local forms the pattern engine must catch on its own.
fs.writeFileSync(path.join(proj, "misc.js"), `const crypto = require("crypto");
const hash = crypto.createHash("md5").update(pw).digest("hex");
function render(el, userInput) { el.innerHTML = userInput; }
function loose(src) { return eval(src); }
module.exports = { hash, render, loose };
`);

// Secrets: one real credential, one obvious non-secret placeholder.
fs.writeFileSync(path.join(proj, "config.js"), `const awsKey = "${AWS_KEY}";
const placeholder = "your-api-key-here";
module.exports = { awsKey, placeholder };
`);

// Must produce nothing at all.
fs.writeFileSync(path.join(proj, "clean.js"), `function add(a, b) { return a + b; }
const safe = encodeURIComponent(String(add(1, 2)));
module.exports = { add, safe };
`);

// Python: the tool claims Python support, so it is exercised as its own language.
fs.writeFileSync(path.join(proj, "app.py"), `import subprocess, hashlib, yaml
def run(user_input):
    subprocess.call("ls " + user_input, shell=True)
def digest(pw):
    return hashlib.md5(pw.encode()).hexdigest()
def load(stream):
    return yaml.load(stream)
`);

fs.writeFileSync(path.join(proj, "Dockerfile"), "FROM node:20\nUSER root\nCMD [\"node\"]\n");

fs.writeFileSync(path.join(proj, "package.json"), JSON.stringify({
  name: "audit-fixture", version: "1.0.0",
  dependencies: { lodash: "4.17.4" },   // known-vulnerable release
}, null, 2));

// Git history: a secret committed and then removed. Only history finds it.
execFileSync("git", ["init", "-q"], { cwd: proj });
execFileSync("git", ["config", "user.email", "audit@example.com"], { cwd: proj });
execFileSync("git", ["config", "user.name", "Audit"], { cwd: proj });
fs.writeFileSync(path.join(proj, "leaked.js"), `const key = "${AWS_KEY}";\n`);
execFileSync("git", ["add", "-A"], { cwd: proj });
execFileSync("git", ["commit", "-qm", "initial"], { cwd: proj });
fs.rmSync(path.join(proj, "leaked.js"));
execFileSync("git", ["add", "-A"], { cwd: proj });
execFileSync("git", ["commit", "-qm", "remove the key"], { cwd: proj });

// ------------------------------------------------------------- mcp client ---

const server = spawn("node", [path.join(REPO, "dist", "index.js")], {
  cwd: REPO, stdio: ["pipe", "pipe", "pipe"],
});
let buffer = "";
let nextId = 1;
const pending = new Map();
server.stdout.on("data", (chunk) => {
  buffer += chunk.toString();
  const lines = buffer.split("\n");
  buffer = lines.pop() || "";
  for (const line of lines) {
    if (!line.trim()) continue;
    try {
      const msg = JSON.parse(line);
      if (msg.id && pending.has(msg.id)) { pending.get(msg.id)(msg); pending.delete(msg.id); }
    } catch { /* server logs share the stream */ }
  }
});
server.stderr.on("data", () => {});

function rpc(method, params) {
  return new Promise((resolve, reject) => {
    const id = nextId++;
    const timer = setTimeout(() => reject(new Error(`timeout on ${method}`)), 180_000);
    pending.set(id, (msg) => { clearTimeout(timer); resolve(msg); });
    server.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
  });
}

/** Tool responses carry their payload as concatenated text blocks. */
async function call(name, args) {
  const res = await rpc("tools/call", { name, arguments: args });
  if (res.error) return { failed: res.error.message ?? JSON.stringify(res.error), text: "" };
  const text = (res.result?.content ?? []).map((c) => c.text ?? "").join("\n");
  return { failed: res.result?.isError ? text : null, text, raw: res.result };
}

/** Tools answer with a JSON document; parse it rather than matching prose. */
function json(text) {
  const start = text.indexOf("{");
  if (start < 0) return null;
  try { return JSON.parse(text.slice(start, text.lastIndexOf("}") + 1)); } catch { return null; }
}

await rpc("initialize", {
  protocolVersion: "2024-11-05",
  capabilities: {},
  clientInfo: { name: "feature-audit", version: "1.0.0" },
});

// ------------------------------------------------------------------ tests ---

// 1. tools/list — the contract itself
{
  const res = await rpc("tools/list", {});
  const names = (res.result?.tools ?? []).map((t) => t.name).sort();
  const expected = ["auto_fix", "check_dependencies", "create_baseline", "detect_secrets",
    "explain_vulnerability", "export_sarif", "get_pr_diff", "list_open_prs", "list_rules",
    "post_security_review", "scan_directory", "scan_file", "scan_git_history", "scan_pr_diff",
    "security_report", "verify_fix"];
  const missing = expected.filter((n) => !names.includes(n));
  record("tools/list", missing.length === 0 && names.length === 16,
    `${names.length} tools${missing.length ? `, missing ${missing.join(",")}` : ""}`);
}

// 2. scan_file — the taint case, which only Semgrep can see
{
  const r = await call("scan_file", { filePath: path.join(proj, "cmd.js") });
  const found = /CWE-78|command injection/i.test(r.text);
  record("scan_file (taint)", !r.failed && found,
    r.failed ? r.failed.slice(0, 60) : found ? "found command injection through a variable" : "MISSED the taint flow");
}

// 3. scan_file — clean file must stay silent
{
  const r = await call("scan_file", { filePath: path.join(proj, "clean.js") });
  const doc = json(r.text);
  const quiet = doc?.totalFindings === 0 && Array.isArray(doc.findings) && doc.findings.length === 0;
  record("scan_file (clean)", !r.failed && quiet,
    quiet ? "totalFindings 0, correct" : `REPORTED ${doc?.totalFindings ?? "?"} on clean code`);
}

// 4. scan_directory — must find the planted set across files
{
  const r = await call("scan_directory", { dirPath: proj });
  const hits = {
    md5: /md5|CWE-327|weak hash/i.test(r.text),
    xss: /innerHTML|CWE-79|XSS/i.test(r.text),
    evalCall: /eval|CWE-95|CWE-94/i.test(r.text),
    cmd: /CWE-78|command injection/i.test(r.text),
  };
  const got = Object.entries(hits).filter(([, v]) => v).map(([k]) => k);
  record("scan_directory", got.length === 4, `${got.length}/4 planted classes: ${got.join(",")}`);
}

// 5. detect_secrets — must find the key and must not echo it
{
  const r = await call("detect_secrets", { path: path.join(proj, "config.js") });
  const found = /AWS|AKIA/i.test(r.text);
  const leaked = r.text.includes(AWS_KEY);
  record("detect_secrets", found && !leaked,
    `${found ? "found" : "MISSED"} AWS key; ${leaked ? "LEAKED IT IN OUTPUT" : "redacted"}`);
}

// 6. detect_secrets — placeholder must not be reported
{
  const r = await call("detect_secrets", { path: path.join(proj, "config.js") });
  const fp = /your-api-key-here/.test(r.text);
  record("detect_secrets (no FP)", !fp, fp ? "flagged an obvious placeholder" : "ignored the placeholder");
}

// 7. scan_git_history — the deleted secret
{
  const r = await call("scan_git_history", { repoPath: proj, maxCommits: 20 });
  const found = /AKIA|AWS|secret/i.test(r.text) && !/no secrets found/i.test(r.text);
  record("scan_git_history", !r.failed && found,
    r.failed ? r.failed.slice(0, 60) : found ? "found the removed credential" : "MISSED it");
}

// 8. check_dependencies — lodash 4.17.4 has advisories
{
  const r = await call("check_dependencies", { manifestPath: path.join(proj, "package.json") });
  const known = /lodash|CVE|GHSA|advisor/i.test(r.text);
  const offlineHonest = /offline|network|unavailable|incomplete/i.test(r.text);
  record("check_dependencies", !r.failed && (known || offlineHonest),
    r.failed ? r.failed.slice(0, 60) : known ? "reported advisories for lodash 4.17.4" : "reported it could not reach the network");
}

// 9. list_rules
{
  const r = await call("list_rules", {});
  const doc = json(r.text);
  const ok = doc?.totalRules === 124 && Object.keys(doc.byCategory ?? {}).length >= 10;
  record("list_rules", !r.failed && ok,
    ok ? `${doc.totalRules} rules across ${Object.keys(doc.byCategory).length} categories` : `unexpected shape: ${r.text.slice(0, 60)}`);
}

// 9b. list_rules with details must carry CWE ids, which is what a fix needs
{
  const r = await call("list_rules", { includeRuleDetails: true, category: "injection" });
  const cwes = (r.text.match(/CWE-\d+/g) ?? []).length;
  record("list_rules (details)", cwes > 5, `${cwes} CWE ids in the injection category`);
}

// 10. explain_vulnerability
{
  const r = await call("explain_vulnerability", { query: "sql injection" });
  const useful = r.text.length > 200 && /parameteri|prepared statement|bind/i.test(r.text);
  record("explain_vulnerability", !r.failed && useful,
    useful ? "explained SQL injection with the real remedy" : "thin or wrong explanation");
}

// 11. security_report
{
  const r = await call("security_report", { dirPath: proj, writeReportFile: false });
  const structured = /##|summary|severity/i.test(r.text) && r.text.length > 300;
  record("security_report", !r.failed && structured,
    r.failed ? r.failed.slice(0, 60) : `${r.text.length} char report`);
}

// 12. export_sarif - returns the document in the response
{
  const r = await call("export_sarif", { dirPath: proj, projectName: "audit-fixture" });
  let valid = false, detail = r.failed ? r.failed.slice(0, 70) : "no parseable SARIF in response";
  const start = r.text.indexOf("{");
  if (!r.failed && start >= 0) {
    try {
      const doc = JSON.parse(r.text.slice(start, r.text.lastIndexOf("}") + 1));
      const n = doc.runs?.[0]?.results?.length ?? 0;
      valid = doc.version === "2.1.0" && Array.isArray(doc.runs) && doc.runs.length > 0;
      detail = `SARIF ${doc.version}, ${n} results`;
    } catch (e) { detail = `unparseable: ${e.message.slice(0, 50)}`; }
  }
  record("export_sarif", valid, detail);
}

// 13. auto_fix — must actually correct the code, in dry-run
{
  const r = await call("auto_fix", { filePath: path.join(proj, "misc.js"), applyFixes: false });
  const proposes = /sha256|createHash|fix|diff|\+/i.test(r.text) && !/no fixes/i.test(r.text);
  const unchanged = fs.readFileSync(path.join(proj, "misc.js"), "utf-8").includes('createHash("md5")');
  record("auto_fix (dry run)", !r.failed && proposes && unchanged,
    `${proposes ? "proposed a fix" : "proposed nothing"}; ${unchanged ? "file untouched" : "WROTE DESPITE dryRun"}`);
}

// 14. verify_fix
{
  const r = await call("verify_fix", { filePath: path.join(proj, "clean.js") });
  record("verify_fix", !r.failed, r.failed ? r.failed.slice(0, 60) : "returned a verdict for a clean file");
}

// 15. create_baseline — then confirm it actually suppresses
{
  const r = await call("create_baseline", { dirPath: proj });
  const bl = path.join(proj, ".sentinel-baseline.json");
  let ok = !r.failed && fs.existsSync(bl);
  let detail = ok ? "baseline written" : (r.failed ? r.failed.slice(0, 60) : "no baseline file");
  if (ok) {
    const after = await call("scan_directory", { dirPath: proj });
    const suppressed = /suppress|baseline/i.test(after.text);
    detail += suppressed ? ", and the next scan applied it" : ", but the next scan did not mention it";
    ok = suppressed;
  }
  record("create_baseline", ok, detail);
  if (fs.existsSync(bl)) fs.rmSync(bl);
}

// 16-19. GitHub tools without a token: must fail clearly, not silently.
for (const [tool, args] of [
  ["list_open_prs", { owner: "anthropics", repo: "claude-code" }],
  ["get_pr_diff", { owner: "anthropics", repo: "claude-code", pull_number: 1 }],
  ["scan_pr_diff", { owner: "anthropics", repo: "claude-code", pull_number: 1 }],
  ["post_security_review", { owner: "anthropics", repo: "claude-code", pull_number: 1, summary: "audit probe", action: "COMMENT" }],
]) {
  const r = await call(tool, args);
  // No token is configured, so the only correct outcome is an explicit,
  // actionable refusal. Returning empty results would read as "nothing found".
  const explains = /token|GITHUB_TOKEN|auth|credential|not configured/i.test((r.failed ?? "") + r.text);
  record(`${tool} (no token)`, explains,
    explains ? "refused with an actionable message" : `unclear: ${((r.failed ?? r.text) || "").slice(0, 70)}`);
}

// 20. IaC — the Dockerfile plant
{
  const r = await call("scan_directory", { dirPath: proj });
  const iac = /USER root|root user|IAC_DOCKERFILE|CWE-250|CWE-269/i.test(r.text);
  record("IaC (Dockerfile root)", iac, iac ? "flagged USER root" : "MISSED USER root");
}

// 21. Python — its own language path, not the JavaScript rules
{
  const r = await call("scan_file", { filePath: path.join(proj, "app.py") });
  const doc = json(r.text);
  const ids = (doc?.findings ?? []).map((f) => `${f.ruleId ?? ""} ${f.cweId ?? ""}`).join(" ");
  const hits = {
    shell: /CWE-78/.test(ids),
    md5: /CWE-327|CWE-328/.test(ids),
    yaml: /CWE-502|YAML/i.test(ids),
  };
  const got = Object.entries(hits).filter(([, v]) => v).map(([k]) => k);
  record("python detection", doc?.language === "python" && got.length >= 2,
    `language=${doc?.language}, ${got.length}/3 classes: ${got.join(",")}`);
}

// 22. auto_fix applying for real — the output must be correct code, not just different
{
  const target = path.join(proj, "fixme.js");
  fs.writeFileSync(target, 'const crypto = require("crypto");\nconst h = crypto.createHash("md5").update(x).digest("hex");\n');
  const before = fs.readFileSync(target, "utf-8");
  const r = await call("auto_fix", { filePath: target, applyFixes: true });
  const after = fs.readFileSync(target, "utf-8");
  const changed = before !== after;
  // The quote style must survive: a fix that lints clean before and fails
  // after is a fix that breaks the build it was run to protect.
  const correct = /createHash\("sha256"\)/.test(after) && !/md5/i.test(after);
  // Still parseable afterwards: a fix that corrupts the file is worse than
  // none. `node --check` parses without evaluating, which the Function
  // constructor would not - and which this scanner rightly flags as dynamic
  // code execution when it sees it.
  let parses = false;
  try {
    execFileSync(process.execPath, ["--check", target], { stdio: "ignore" });
    parses = true;
  } catch { /* a syntax error is the answer, not an error */ }
  record("auto_fix (applied)", changed && correct && parses,
    `${changed ? "rewrote" : "NO CHANGE"}; ${correct ? "md5 to sha256" : "WRONG replacement"}; ${parses ? "still parses" : "CORRUPTED THE FILE"}`);
  fs.rmSync(target);
}

// ---------------------------------------------------------------- summary ---

server.stdin.end();
server.kill();
fs.rmSync(work, { recursive: true, force: true });

const failed = results.filter((r) => !r.ok);
console.log(`\n${results.length - failed.length}/${results.length} features verified`);
if (failed.length) {
  console.log("\nFAILURES:");
  for (const f of failed) console.log(`  ${f.feature}: ${f.detail}`);
}
process.exit(failed.length ? 1 : 0);
