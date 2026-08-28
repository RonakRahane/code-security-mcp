/**
 * Manual smoke test for the MCP server over stdio.
 *
 * Run `npm run build` first, then `node scripts/mcp-smoke-test.mjs`. It drives a
 * handful of tools against the test fixtures and prints their raw responses.
 */

import { spawn } from "node:child_process";
import * as path from "node:path";
import * as fs from "node:fs";

const mcpServer = spawn("node", ["dist/index.js"], {
  cwd: process.cwd(),
  stdio: ["pipe", "pipe", "inherit"],
});

let buffer = "";
let requestId = 1;
const pending = new Map();

mcpServer.stdout.on("data", (chunk) => {
  buffer += chunk.toString();
  const lines = buffer.split("\n");
  buffer = lines.pop() || "";

  for (const line of lines) {
    if (!line.trim()) continue;
    try {
      const msg = JSON.parse(line);
      if (msg.id && pending.has(msg.id)) {
        pending.get(msg.id)(msg);
        pending.delete(msg.id);
      }
    } catch {
      // Not a JSON-RPC frame: server log output on the same stream.
    }
  }
});

let failures = 0;

function callMcp(method, params) {
  return new Promise((resolve) => {
    const id = requestId++;
    pending.set(id, resolve);
    const req = JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n";
    mcpServer.stdin.write(req);
  });
}

/**
 * A smoke test that prints an error and exits 0 is not a gate. Every call is
 * checked for a JSON-RPC error and for a tool-level isError response, and the
 * script exits non-zero if any of them failed.
 */
function check(label, response) {
  if (response.error) {
    console.error(`FAIL ${label}: ${response.error.message ?? JSON.stringify(response.error)}`);
    failures++;
    return false;
  }
  if (response.result?.isError) {
    const text = response.result.content?.[0]?.text ?? "(no detail)";
    console.error(`FAIL ${label}: tool reported an error: ${text}`);
    failures++;
    return false;
  }
  return true;
}

// Handshake
await callMcp("initialize", {
  protocolVersion: "2024-11-05",
  capabilities: {},
  clientInfo: { name: "test-client", version: "1.0.0" },
});

console.log("=== MCP tool smoke test ===");

const expRes = await callMcp("tools/call", {
  name: "explain_vulnerability",
  arguments: { query: "CWE-89" },
});
console.log("\n--- Tool: explain_vulnerability (CWE-89) ---");
if (check("explain_vulnerability", expRes)) console.log(expRes.result.content[0].text);

const targetFile = path.resolve("./test/fixtures/vulnerable-app.js");
const secRes = await callMcp("tools/call", {
  name: "detect_secrets",
  arguments: { path: targetFile },
});
console.log("\n--- Tool: detect_secrets (vulnerable-app.js) ---");
if (check("detect_secrets", secRes)) console.log(secRes.result.content[0].text);

const scanRes = await callMcp("tools/call", {
  name: "scan_file",
  arguments: { filePath: targetFile },
});
console.log("\n--- Tool: scan_file (vulnerable-app.js) ---");
if (check("scan_file", scanRes)) console.log(scanRes.result.content[0].text);

const rulesRes = await callMcp("tools/call", {
  name: "list_rules",
  arguments: { category: "injection" },
});
console.log("\n--- Tool: list_rules (category=injection) ---");
if (check("list_rules", rulesRes)) console.log(rulesRes.result.content[0].text.slice(0, 400));

const listRulesEmptyRes = await callMcp("tools/call", {
  name: "list_rules",
  arguments: { category: "no-such-category" },
});
console.log("\n--- Tool: list_rules (unknown category) ---");
if (check("list_rules unknown category", listRulesEmptyRes)) {
  console.log(listRulesEmptyRes.result.content[0].text.slice(0, 200));
}

const fixRes = await callMcp("tools/call", {
  name: "auto_fix",
  arguments: { filePath: targetFile, applyFixes: false },
});
console.log("\n--- Tool: auto_fix (dry run on vulnerable-app.js) ---");
if (check("auto_fix", fixRes)) console.log(fixRes.result.content[0].text);

const verifyRes = await callMcp("tools/call", {
  name: "verify_fix",
  arguments: { filePath: targetFile },
});
console.log("\n--- Tool: verify_fix (whole file) ---");
if (check("verify_fix", verifyRes)) console.log(verifyRes.result.content[0].text.slice(0, 300));

mcpServer.kill();

if (failures > 0) {
  console.error(`\nSmoke test failed: ${failures} tool call(s) did not succeed.`);
  process.exit(1);
}
console.log("\nSmoke test passed: every tool call succeeded.");
process.exit(0);
