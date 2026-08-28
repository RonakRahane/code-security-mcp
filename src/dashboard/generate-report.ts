#!/usr/bin/env node

/**
 * Generates a standalone HTML security report for a project.
 *
 * Usage: node dist/dashboard/generate-report.js /path/to/project
 *        npm run dashboard -- /path/to/project
 */

import * as fs from "fs";
import * as path from "path";
import { detectLanguage } from "../scanner/pattern-engine.js";
import { generateFixes } from "../scanner/auto-fixer.js";
import { runUnifiedScan } from "../scanner/unified-scanner.js";
import { ScanResult, SeveritySummary, Finding } from "../types/index.js";

export interface DashboardData {
  projectName: string;
  projectPath: string;
  scanDate: string;
  filesScanned: number;
  filesWithIssues: number;
  totalFindings: number;
  taintFlows: number;
  fixesAvailable: number;
  riskLevel: string;
  summary: SeveritySummary;
  categoryBreakdown: Record<string, number>;
  languageBreakdown: Record<string, number>;
  topFiles: { file: string; findings: number; critical: number; high: number }[];
  allFindings: { file: string; findings: Finding[] }[];
  rawResults: ScanResult[];
}

/** Project-relative path for display. Falls back to the full path if outside. */
function displayPath(filePath: string, projectRoot: string): string {
  const relative = path.relative(projectRoot, filePath);
  if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) return filePath;
  return relative.split(path.sep).join("/");
}

export async function scanProject(dirPath: string): Promise<DashboardData> {
  const projectName = path.basename(dirPath);
  const scanResult = await runUnifiedScan(dirPath);

  // Group findings per file for the report tables.
  const filesMap = new Map<string, Finding[]>();
  for (const finding of scanResult.findings) {
    if (!filesMap.has(finding.filePath)) {
      filesMap.set(finding.filePath, []);
    }
    filesMap.get(finding.filePath)!.push(finding);
  }

  let fixesAvailable = 0;
  const languageBreakdown: Record<string, number> = {};
  const categoryBreakdown: Record<string, number> = {};
  const rawResults: ScanResult[] = [];

  for (const [filePath, findings] of filesMap.entries()) {
    // Display path only. rawResults keeps the absolute path, because
    // generateSarif relativises it against the project root itself, and a path
    // that has already been made relative resolves against the wrong base and
    // produces artifact URIs GitHub cannot match to a file.
    const relativePath = displayPath(filePath, dirPath);
    const lang = detectLanguage(filePath);
    languageBreakdown[lang] = (languageBreakdown[lang] || 0) + 1;

    try {
      if (fs.existsSync(filePath)) {
        const code = fs.readFileSync(filePath, "utf-8");
        const fixes = generateFixes(code, findings);
        fixesAvailable += fixes.length;
      }
    } catch {
      // An unreadable file just loses its snippet.
    }

    const fileSummary = {
      critical: findings.filter((f) => f.severity === "critical").length,
      high: findings.filter((f) => f.severity === "high").length,
      medium: findings.filter((f) => f.severity === "medium").length,
      low: findings.filter((f) => f.severity === "low").length,
      info: findings.filter((f) => f.severity === "info").length,
    };

    rawResults.push({
      filePath,
      language: lang,
      totalFindings: findings.length,
      findings,
      summary: fileSummary,
      analyzed: true,
    });

    for (const f of findings) {
      categoryBreakdown[f.category] = (categoryBreakdown[f.category] || 0) + 1;
    }
  }

  const codeSummary: SeveritySummary = {
    critical: scanResult.findings.filter((f) => f.severity === "critical").length,
    high: scanResult.findings.filter((f) => f.severity === "high").length,
    medium: scanResult.findings.filter((f) => f.severity === "medium").length,
    low: scanResult.findings.filter((f) => f.severity === "low").length,
    info: scanResult.findings.filter((f) => f.severity === "info").length,
  };

  // Same thresholds the markdown report uses. Two independent formulas meant
  // one scan was CRITICAL in the CLI report and MEDIUM in the dashboard, and a
  // dependency-only project read as CLEAN in one and LOW in the other.
  let riskLevel = "CLEAN";
  if (codeSummary.critical > 0) riskLevel = "CRITICAL";
  else if (codeSummary.high > 0) riskLevel = "HIGH";
  else if (codeSummary.medium > 0) riskLevel = "MEDIUM";
  else if (codeSummary.low > 0) riskLevel = "LOW";
  else if (codeSummary.info > 0) riskLevel = "INFO";

  const topFiles = rawResults
    .sort((a, b) => b.totalFindings - a.totalFindings)
    .slice(0, 15)
    .map((r) => ({
      file: displayPath(r.filePath, dirPath),
      findings: r.totalFindings,
      critical: r.summary.critical,
      high: r.summary.high,
    }));

  const allFindings = rawResults.map((r) => ({
    file: displayPath(r.filePath, dirPath),
    findings: r.findings.map((f) => ({ ...f, filePath: r.filePath })),
  }));

  const taintFlows = scanResult.findings.filter(
    (f) => f.source === "semgrep" && (f.category === "injection" || f.category === "xss")
  ).length;

  return {
    projectName,
    projectPath: dirPath,
    scanDate: scanResult.generatedAt,
    filesScanned: scanResult.filesScanned,
    filesWithIssues: rawResults.length,
    totalFindings: scanResult.findings.length,
    taintFlows,
    fixesAvailable,
    riskLevel,
    summary: codeSummary,
    categoryBreakdown,
    languageBreakdown,
    topFiles,
    allFindings,
    rawResults,
  };
}

export function generateHTML(data: DashboardData): string {
  const riskColors: Record<string, string> = {
    CRITICAL: "#ef4444",
    HIGH: "#f97316",
    MEDIUM: "#eab308",
    LOW: "#22c55e",
    CLEAN: "#10b981",
  };

  const riskColor = riskColors[data.riskLevel] || "#6b7280";

  const maxCat = Math.max(...Object.values(data.categoryBreakdown), 1);
  const categoryBars = Object.entries(data.categoryBreakdown)
    .sort((a, b) => b[1] - a[1])
    .map(([cat, count]) => {
      const pct = (count / maxCat) * 100;
      const catColors: Record<string, string> = {
        injection: "#ef4444",
        xss: "#f97316",
        secrets: "#a855f7",
        auth: "#3b82f6",
        crypto: "#06b6d4",
        "dangerous-functions": "#ec4899",
        "path-traversal": "#84cc16",
        "prototype-pollution": "#f59e0b",
        miscellaneous: "#6b7280",
        iac: "#10b981",
        ai: "#3b82f6",
      };
      return `<div class="cat-row">
        <span class="cat-label">${escapeHtml(cat)}</span>
        <div class="cat-bar-bg"><div class="cat-bar" style="width:${pct}%;background:${catColors[cat] || '#6b7280'}"></div></div>
        <span class="cat-count">${count}</span>
      </div>`;
    }).join("");

  const fileRows = data.topFiles.map((f) => `
    <tr>
      <td class="file-name">${escapeHtml(f.file)}</td>
      <td class="num">${f.critical > 0 ? `<span class="badge critical">${f.critical}</span>` : "-"}</td>
      <td class="num">${f.high > 0 ? `<span class="badge high">${f.high}</span>` : "-"}</td>
      <td class="num">${f.findings}</td>
    </tr>
  `).join("");

  const findingDetails = data.allFindings.slice(0, 20).map((fileGroup) => {
    const rows = fileGroup.findings.slice(0, 10).map((f) => `
      <div class="finding-card severity-${escapeHtml(f.severity)}">
        <div class="finding-header">
          <span class="severity-badge ${escapeHtml(f.severity)}">${escapeHtml(f.severity.toUpperCase())}</span>
          <span class="finding-rule">${escapeHtml(f.ruleId)}</span>
          <span class="finding-cwe">${escapeHtml(f.cweId)}</span>
          <span class="finding-line">Line ${f.line}</span>
        </div>
        <p class="finding-msg">${escapeHtml(f.message)}</p>
        <code class="finding-code">${escapeHtml(f.lineContent)}</code>
        <p class="finding-fix">Fix: ${escapeHtml(f.remediation)}</p>
      </div>
    `).join("");
    return `<div class="file-section">
      <h3 class="file-heading">${escapeHtml(fileGroup.file)} <span class="file-count">${fileGroup.findings.length} issues</span></h3>
      ${rows}
    </div>`;
  }).join("");

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sentinel Security Report: ${escapeHtml(data.projectName)}</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
:root{--bg:#ffffff;--bg2:#f8fafc;--border:#e2e8f0;--text:#0f172a;--text2:#475569;--text3:#94a3b8;--card:#ffffff;--code-bg:#f1f5f9;--code-text:#be185d;--link:#2563eb;--hover:#f8fafc}
[data-theme="dark"]{--bg:#0f172a;--bg2:#1e293b;--border:#334155;--text:#f1f5f9;--text2:#94a3b8;--text3:#64748b;--card:#1e293b;--code-bg:#0f172a;--code-text:#f472b6;--link:#93c5fd;--hover:rgba(255,255,255,0.03)}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter',sans-serif;background:var(--bg);color:var(--text);min-height:100vh;transition:background .3s,color .3s}
.container{max-width:960px;margin:0 auto;padding:32px 24px}
.theme-toggle{position:fixed;top:16px;right:16px;background:var(--card);border:1px solid var(--border);border-radius:8px;padding:8px 12px;cursor:pointer;font-size:14px;z-index:10;transition:all .2s}
.theme-toggle:hover{background:var(--bg2)}
.header{padding:40px 0 24px;border-bottom:1px solid var(--border)}
.header h1{font-size:24px;font-weight:700;color:var(--text);margin-bottom:4px}
.header .subtitle{color:var(--text2);font-size:13px}
.header .scan-date{color:var(--text3);font-size:11px;margin-top:2px}
.risk-container{margin:24px 0;display:flex;justify-content:center}
.risk-badge{display:inline-flex;align-items:center;gap:10px;padding:12px 24px;border-radius:8px;background:var(--bg2);border:1px solid var(--border)}
.risk-dot{width:10px;height:10px;border-radius:50%}
.risk-label{font-size:12px;color:var(--text3)}
.risk-value{font-size:18px;font-weight:700}
.stats-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:24px 0}
.stat-card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:16px;text-align:center}
.stat-value{font-size:24px;font-weight:700;margin-bottom:2px}
.stat-label{font-size:10px;color:var(--text3);text-transform:uppercase;letter-spacing:.5px}
.severity-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin:16px 0}
.sev-card{padding:12px;border-radius:8px;text-align:center;border:1px solid var(--border)}
.sev-card.critical{border-color:#fca5a5}.sev-card.high{border-color:#fdba74}
.sev-card.medium{border-color:#fde047}.sev-card.low{border-color:#86efac}
.sev-count{font-size:28px;font-weight:700}
.sev-label{font-size:10px;text-transform:uppercase;letter-spacing:.5px;color:var(--text3);margin-top:2px}
.sev-card.critical .sev-count{color:#dc2626}.sev-card.high .sev-count{color:#ea580c}
.sev-card.medium .sev-count{color:#ca8a04}.sev-card.low .sev-count{color:#16a34a}
.footer{text-align:center;padding:24px 0;color:var(--text3);font-size:11px;border-top:1px solid var(--border);margin-top:40px}
.section{margin:32px 0}
.section-title{font-size:14px;font-weight:600;margin-bottom:12px;color:var(--text);display:flex;align-items:center;gap:6px}
.cat-row{display:flex;align-items:center;gap:8px;margin:6px 0}
.cat-label{width:130px;font-size:11px;color:var(--text2);text-transform:capitalize}
.cat-bar-bg{flex:1;height:20px;background:var(--bg2);border-radius:4px;overflow:hidden;border:1px solid var(--border)}
.cat-bar{height:100%;border-radius:3px}
.cat-count{width:28px;text-align:right;font-size:12px;font-weight:600;color:var(--text)}
table{width:100%;border-collapse:collapse}
th{text-align:left;padding:8px 10px;font-size:10px;text-transform:uppercase;letter-spacing:.5px;color:var(--text3);border-bottom:1px solid var(--border)}
td{padding:8px 10px;border-bottom:1px solid var(--border);font-size:12px;color:var(--text)}
.file-name{font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--link)}
.num{text-align:center}
tr:hover{background:var(--hover)}
.badge{padding:1px 6px;border-radius:4px;font-size:10px;font-weight:600}
.badge.critical{background:#fef2f2;color:#dc2626}.badge.high{background:#fff7ed;color:#ea580c}
[data-theme="dark"] .badge.critical{background:rgba(239,68,68,0.15);}
[data-theme="dark"] .badge.high{background:rgba(249,115,22,0.15);}
.file-section{margin:20px 0}
.file-heading{font-size:13px;font-weight:600;color:var(--link);margin-bottom:8px;display:flex;align-items:center;gap:6px}
.file-count{font-size:10px;color:var(--text3);font-weight:400}
.finding-card{background:var(--card);border:1px solid var(--border);border-radius:6px;padding:12px;margin:6px 0;border-left:3px solid}
.finding-card.severity-critical{border-left-color:#dc2626}
.finding-card.severity-high{border-left-color:#ea580c}
.finding-card.severity-medium{border-left-color:#ca8a04}
.finding-card.severity-low{border-left-color:#16a34a}
.finding-card.severity-info{border-left-color:#6b7280}
.finding-header{display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin-bottom:6px}
.severity-badge{padding:1px 6px;border-radius:3px;font-size:9px;font-weight:700;letter-spacing:.3px}
.severity-badge.critical{background:#fef2f2;color:#dc2626}
.severity-badge.high{background:#fff7ed;color:#ea580c}
.severity-badge.medium{background:#fefce8;color:#ca8a04}
.severity-badge.low{background:#f0fdf4;color:#16a34a}
.severity-badge.info{background:#f8fafc;color:#64748b}
[data-theme="dark"] .severity-badge.critical{background:rgba(239,68,68,0.15)}
[data-theme="dark"] .severity-badge.high{background:rgba(249,115,22,0.15)}
[data-theme="dark"] .severity-badge.medium{background:rgba(234,179,8,0.15)}
[data-theme="dark"] .severity-badge.low{background:rgba(34,197,94,0.15)}
[data-theme="dark"] .severity-badge.info{background:rgba(100,116,139,0.15)}
.finding-rule{font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--text3)}
.finding-cwe{font-size:10px;color:var(--text3)}
.finding-line{font-size:10px;color:var(--text3);margin-left:auto}
.finding-msg{font-size:12px;color:var(--text2);margin:4px 0}
.finding-code{display:block;background:var(--code-bg);padding:6px 10px;border-radius:4px;font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--code-text);margin:6px 0;overflow-x:auto;white-space:pre;border:1px solid var(--border)}
.finding-fix{font-size:11px;color:#16a34a}
</style>
</head>
<body>
<button class="theme-toggle" onclick="toggleTheme()">Dark</button>
<script>
function toggleTheme(){const h=document.documentElement;const d=h.getAttribute('data-theme')==='dark';h.setAttribute('data-theme',d?'':'dark');document.querySelector('.theme-toggle').textContent=d?'Dark':'Light';localStorage.setItem('sentinel-theme',d?'light':'dark')}
(function(){const t=localStorage.getItem('sentinel-theme');if(t==='dark'){document.documentElement.setAttribute('data-theme','dark');document.querySelector('.theme-toggle').textContent='Light'}})();
</script>
<div class="container">

<div class="header">
  <h1>Sentinel Security Report</h1>
  <div class="subtitle">${escapeHtml(data.projectName)} &mdash; ${escapeHtml(data.projectPath)}</div>
  <div class="scan-date">Scanned ${new Date(data.scanDate).toLocaleString()}</div>
</div>

<div class="risk-container">
  <div class="risk-badge">
    <div class="risk-dot" style="background:${riskColor}"></div>
    <div>
      <div class="risk-label">Risk Level</div>
      <div class="risk-value" style="color:${riskColor}">${escapeHtml(data.riskLevel)}</div>
    </div>
  </div>
</div>

<div class="stats-grid">
  <div class="stat-card"><div class="stat-value">${data.filesScanned}</div><div class="stat-label">Files Scanned</div></div>
  <div class="stat-card"><div class="stat-value">${data.totalFindings}</div><div class="stat-label">Total Findings</div></div>
  <div class="stat-card"><div class="stat-value">${data.taintFlows}</div><div class="stat-label">Taint Flows</div></div>
  <div class="stat-card"><div class="stat-value">${data.fixesAvailable}</div><div class="stat-label">Auto-Fixes</div></div>
</div>

<div class="severity-grid">
  <div class="sev-card critical"><div class="sev-count">${data.summary.critical}</div><div class="sev-label">Critical</div></div>
  <div class="sev-card high"><div class="sev-count">${data.summary.high}</div><div class="sev-label">High</div></div>
  <div class="sev-card medium"><div class="sev-count">${data.summary.medium}</div><div class="sev-label">Medium</div></div>
  <div class="sev-card low"><div class="sev-count">${data.summary.low + data.summary.info}</div><div class="sev-label">Low / Info</div></div>
</div>

<div class="section">
  <div class="section-title">Vulnerability Categories</div>
  ${categoryBars}
</div>

<div class="section">
  <div class="section-title">Most Affected Files</div>
  <table>
    <thead><tr><th>File</th><th>Critical</th><th>High</th><th>Total</th></tr></thead>
    <tbody>${fileRows}</tbody>
  </table>
</div>

<div class="section">
  <div class="section-title">Detailed Findings</div>
  ${findingDetails}
</div>

<div class="footer">
  Sentinel MCP v4.0 &middot; Powered by Semgrep &middot; OSV Supply Chain
</div>

</div>
</body>
</html>`;
}

/**
 * Everything interpolated into the report is attacker-controlled: file paths,
 * rule identifiers and messages all come from the scanned repository, and the
 * report is opened in a browser straight after a scan. A file named
 * `<img src=x onerror=...>.js` is enough to make an unescaped path execute.
 */
function escapeHtml(str: string): string {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// CLI Entry Point

import { pathToFileURL } from "node:url";
import { generateSarif } from "../scanner/sarif.js";

async function main() {
  const targetDir = process.argv[2];

  if (!targetDir) {
    console.log("Usage: npx tsx src/dashboard/generate-report.ts /path/to/project");
    console.log("   Or: npm run dashboard -- /path/to/project");
    process.exit(1);
  }

  const resolvedDir = path.resolve(targetDir);

  if (!fs.existsSync(resolvedDir)) {
    console.error(`Directory not found: ${resolvedDir}`);
    process.exit(1);
  }

  console.log(`Scanning ${resolvedDir}...`);
  const data = await scanProject(resolvedDir);
  console.log(`   ${data.filesScanned} files scanned`);
  console.log(`   ${data.totalFindings} findings (${data.summary.critical} critical, ${data.summary.high} high)`);
  console.log(`   ${data.taintFlows} taint flows detected`);
  console.log(`   ${data.fixesAvailable} auto-fixes available`);

  const html = generateHTML(data);
  const htmlOutputPath = path.join(resolvedDir, "sentinel-report.html");
  fs.writeFileSync(htmlOutputPath, html, "utf-8");

  const sarif = generateSarif(data.rawResults, data.projectName, data.projectPath);
  const sarifOutputPath = path.join(resolvedDir, "sentinel-report.sarif");
  fs.writeFileSync(sarifOutputPath, sarif, "utf-8");

  console.log(`\nReports generated:`);
  console.log(`   HTML:  ${htmlOutputPath}`);
  console.log(`   SARIF: ${sarifOutputPath}`);

  openInBrowser(htmlOutputPath);
}

/**
 * Opens the generated report in the default browser.
 *
 * execFile with an argument array, not a shell string: the path comes from a
 * caller-supplied directory, so interpolating it would be a command-injection
 * sink (CWE-78) in the scanner itself. `start` is avoided on Windows because it
 * is a cmd.exe builtin and would bring a shell back.
 */
function openInBrowser(filePath: string): void {
  const opener =
    process.platform === "darwin" ? "open" :
    process.platform === "win32" ? "explorer.exe" :
    "xdg-open";

  import("node:child_process").then(({ execFile }) => {
    execFile(opener, [filePath], { windowsHide: true }, (error) => {
      // explorer.exe exits non-zero even on success, and a headless
      // environment has no opener. Neither should fail the run.
      if (error && process.platform !== "win32") {
        console.log(`   Open the report manually: ${filePath}`);
        return;
      }
    });
    console.log("Opening in browser...");
  }).catch(() => {
    console.log(`   Open the report manually: ${filePath}`);
  });
}

// Only when run as a command. Importing this module for its renderer must not
// start a scan or exit the process.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => {
    console.error("Dashboard generation failed:", err);
    process.exit(1);
  });
}
