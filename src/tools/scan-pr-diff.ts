import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { z } from "zod";
import { Finding } from "../types/index.js";
import { dedupeFindings } from "../core/findings.js";
import { computeSeveritySummary, sortBySeverity } from "../core/severity.js";
import { getFileAtRef, getPrFiles, getPrHeadSha } from "../github/client.js";
import { scanCode } from "../scanner/pattern-engine.js";
import { scanWithSemgrep } from "../scanner/semgrep.js";
import { detectSecrets } from "../scanner/secret-detector.js";
import { filterByMinimumSeverity, filterIgnoredFindings, isOfflineMode, loadSentinelConfig } from "../scanner/config.js";
import { isWithin } from "../core/paths.js";
import { jsonResponse, runTool } from "./shared.js";

/** GitHub owner and repository name grammar. Validated before use in API paths. */
const GITHUB_NAME = /^[A-Za-z0-9._-]+$/;

/**
 * Whether a path from the GitHub API is safe to join onto a local directory.
 *
 * The name is whatever a pull-request author committed. Git paths always use
 * forward slashes, so a backslash is never legitimate and is a separator on
 * Windows, where such a name escapes the scratch directory and writes
 * attacker-controlled content to an arbitrary path. A ".." segment escapes
 * everywhere.
 */
function isSafeRepositoryPath(filename: string): boolean {
  if (!filename) return false;
  if (filename.includes("\\") || filename.includes("\0")) return false;
  if (filename.startsWith("/") || /^[A-Za-z]:/.test(filename)) return false;
  return !filename.split("/").includes("..");
}

/** Files fetched in full per pull request. Each one costs an API call. */
const MAX_FILES_FETCHED = 60;

/** Skip anything larger; a generated bundle is not worth a Semgrep pass. */
const MAX_FILE_BYTES_FETCHED = 600_000;

/**
 * Scans a file as it stands at the pull-request head, then keeps only the
 * findings that land on lines the pull request added.
 *
 * The previous approach concatenated the added lines into a buffer and scanned
 * that. It could not see a value assigned on one line and used on the next, and
 * Semgrep cannot parse such a buffer at all, so pull-request review had no
 * dataflow analysis: `const q = "..." + req.query.x; db.query(q);` was reported
 * by scan_file and missed here.
 */
async function scanFileAtHead(
  filename: string,
  contents: string,
  addedLineNumbers: ReadonlySet<number>,
  offline: boolean
): Promise<Finding[]> {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "sentinel-pr-"));
  const target = path.resolve(directory, filename);

  try {
    // Belt and braces after isSafeRepositoryPath: resolve and confirm.
    if (!isWithin(directory, target)) return [];

    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, contents, "utf-8");

    const findings: Finding[] = [];

    const semgrep = await scanWithSemgrep(target, { offline, timeoutMs: 30_000 });
    if (semgrep.status.used) for (const item of semgrep.findings) findings.push(item);

    findings.push(...scanCode(contents, target, undefined, directory).findings);
    findings.push(...detectSecrets(contents, target));

    // Only what this pull request introduced. Pre-existing findings elsewhere
    // in the file belong to whoever wrote them, not to this author.
    return dedupeFindings(findings)
      .filter((finding) => addedLineNumbers.has(finding.line))
      .map((finding) => ({ ...finding, filePath: filename }));
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
}

export function registerScanPrDiff(server: McpServer): void {
  server.tool(
    "scan_pr_diff",
    "Fetch a GitHub pull request diff and scan the added lines for vulnerabilities and secrets. Findings are mapped back to real PR line numbers. Requires GITHUB_TOKEN.",
    {
      owner: z.string().min(1).max(100).regex(GITHUB_NAME).describe("GitHub repository owner (user or org)"),
      repo: z.string().min(1).max(100).regex(GITHUB_NAME).describe("GitHub repository name"),
      pull_number: z.number().int().positive().max(1_000_000).describe("Pull request number"),
    },
    async ({ owner, repo, pull_number }) => runTool("scan_pr_diff", async () => {
      const files = await getPrFiles(owner, repo, pull_number);
      // Policy deliberately comes from defaults, not from the directory the
      // server happens to run in: ignoreRules and minimumSeverity belonging to
      // one project must not silently suppress findings in someone else's
      // pull request.
      const config = loadSentinelConfig(process.cwd());
      const offline = isOfflineMode(config);
      const headSha = await getPrHeadSha(owner, repo, pull_number);

      // Only the offline setting is taken from the local environment. Filtering
      // policy stays at defaults so a local sentinel.config.json cannot hide
      // findings in a pull request from another repository.
      const policy = { ignorePaths: [], ignoreRules: [] };

      const perFile: Array<{
        file: string;
        status: string;
        totalFindings: number;
        findings: Finding[];
      }> = [];

      const candidates = files.filter((file) => file.patch && extractAddedLines(file.patch).length > 0);
      const scanned = candidates.slice(0, MAX_FILES_FETCHED);
      const notFetched: string[] = [];
      /** Names that could not be written safely to a scratch directory. */
      const refused: string[] = [];

      for (const file of scanned) {
        const addedLines = extractAddedLines(file.patch!);
        const addedLineNumbers = new Set(addedLines.map((entry) => entry.lineNumber));

        // One hostile name must not abort the review of everything else.
        if (!isSafeRepositoryPath(file.filename)) {
          refused.push(file.filename);
          continue;
        }

        const contents = await getFileAtRef(owner, repo, headSha, file.filename);
        if (contents === null || contents.length > MAX_FILE_BYTES_FETCHED) {
          notFetched.push(file.filename);
          continue;
        }

        const findings = await scanFileAtHead(file.filename, contents, addedLineNumbers, offline);
        const filtered = filterByMinimumSeverity(filterIgnoredFindings(findings, policy), policy);

        if (filtered.length > 0) {
          sortBySeverity(filtered);
          perFile.push({
            file: file.filename,
            status: file.status,
            totalFindings: filtered.length,
            findings: filtered,
          });
        }
      }

      const allFindings = perFile.flatMap((entry) => entry.findings);
      const truncated = candidates.length > scanned.length;

      return jsonResponse({
        pr: `${owner}/${repo}#${pull_number}`,
        filesInPr: files.length,
        filesAnalyzed: scanned.length - notFetched.length - refused.length,
        filesWithIssues: perFile.length,
        totalFindings: allFindings.length,
        summary: computeSeveritySummary(allFindings),
        files: perFile,
        coverage: {
          // Silence about what was not read would let a partial scan read as a
          // clean one.
          filesNotFetched: notFetched,
          ...(refused.length > 0
            ? {
                filesRefused: refused,
                refusedNote: "These paths were not scanned: a git path never contains a backslash or a '..' segment, and joining one to a scratch directory can escape it.",
              }
            : {}),
          truncated,
          ...(truncated
            ? { truncationNotice: `Only the first ${MAX_FILES_FETCHED} changed files were scanned, of ${candidates.length}.` }
            : {}),
        },
      });
    })
  );
}

interface AddedLine {
  lineNumber: number;
  content: string;
}

/**
 * Extracts added lines from a unified diff, tracking the line number each one
 * occupies in the post-merge file.
 */
export function extractAddedLines(patch: string): AddedLine[] {
  const added: AddedLine[] = [];
  let currentLine = 0;
  // The "--- a/x" and "+++ b/x" headers appear only before the first hunk.
  // Inside a hunk every "+" line is content, so testing for a "+++" prefix
  // there discards an added line that happens to begin with "++", such as
  // "++counter;", and any finding on it goes unreported.
  let insideHunk = false;

  for (const patchLine of patch.split("\n")) {
    const hunkMatch = patchLine.match(/^@@\s+-\d+(?:,\d+)?\s+\+(\d+)(?:,\d+)?\s+@@/);
    if (hunkMatch) {
      currentLine = Number.parseInt(hunkMatch[1], 10);
      insideHunk = true;
      continue;
    }

    if (patchLine.startsWith("+") && (insideHunk || !patchLine.startsWith("+++"))) {
      added.push({ lineNumber: currentLine, content: patchLine.slice(1) });
      currentLine++;
    } else if (patchLine.startsWith("-") || patchLine.startsWith("\\")) {
      // Removed lines and "\ No newline at end of file" do not advance the
      // new-file line counter.
      continue;
    } else if (insideHunk || !patchLine.startsWith("---")) {
      currentLine++;
    }
  }

  return added;
}
