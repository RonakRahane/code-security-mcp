/**
 * Git history secret scanning.
 *
 * Every git invocation uses `execFileSync` with an argument array and no shell.
 * Interpolating values into a shell string would be a command-injection sink
 * (CWE-78), and POSIX quoting does not hold on Windows in any case.
 */

import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
import * as fs from "node:fs";
import * as path from "node:path";
import { HistorySecretFinding, SentinelConfig } from "../types/index.js";
import { Diagnostics } from "../core/diagnostics.js";
import { errorMessage, logger } from "../core/logger.js";
import { sortBySeverity } from "../core/severity.js";
import { detectSecrets } from "./secret-detector.js";
import { filterByMinimumSeverity, filterIgnoredFindings, isPathIgnored, loadSentinelConfig } from "./config.js";

interface CommitInfo {
  hash: string;
  date: string;
}

/** Commit hashes are the only untrusted value interpolated into git arguments. */
const COMMIT_HASH = /^[0-9a-f]{7,64}$/;

const MAX_COMMITS_LIMIT = 5_000;
const GIT_TIMEOUT_MS = 60_000;
const MAX_PATCH_BYTES = 20 * 1024 * 1024;

export interface GitHistoryScanResult {
  repoPath: string;
  commitsScanned: number;
  totalSecrets: number;
  findings: HistorySecretFinding[];
  warnings: string[];
}

export async function scanGitHistoryForSecrets(
  repoPath: string,
  maxCommits = 100
): Promise<GitHistoryScanResult> {
  if (!fs.existsSync(repoPath)) {
    throw new Error(`Path not found: ${repoPath}`);
  }

  const absoluteRepoPath = path.resolve(repoPath);
  const diagnostics = new Diagnostics();
  await ensureGitRepository(absoluteRepoPath);

  const config = loadSentinelConfig(absoluteRepoPath, diagnostics);
  const commitLimit = clampCommitLimit(maxCommits, diagnostics);
  const commits = await listCommits(absoluteRepoPath, commitLimit, diagnostics);

  const findings: HistorySecretFinding[] = [];
  const seen = new Set<string>();

  for (const commit of commits) {
    const patch = await readCommitPatch(absoluteRepoPath, commit.hash, diagnostics);
    if (patch === null) continue;

    collectFromPatch(patch, commit, absoluteRepoPath, config, findings, seen);
  }

  sortBySeverity(findings);

  return {
    repoPath: absoluteRepoPath,
    commitsScanned: commits.length,
    totalSecrets: findings.length,
    findings,
    warnings: diagnostics.toWarnings(),
  };
}

/** Parses a unified diff, scanning only added lines. */
function collectFromPatch(
  patch: string,
  commit: CommitInfo,
  repoRoot: string,
  config: SentinelConfig,
  findings: HistorySecretFinding[],
  seen: Set<string>
): void {
  let currentFile = "";
  let currentLine = 0;
  let insideHunk = false;
  let fileIsIgnored = false;

  for (const line of patch.split("\n")) {
    if (line.startsWith("+++ b/")) {
      currentFile = line.slice(6).trim();
      // A new file's hunks have not started yet, so its headers are headers
      // again rather than content.
      insideHunk = false;
      fileIsIgnored = currentFile
        ? isPathIgnored(path.join(repoRoot, currentFile), repoRoot, config)
        : false;
      continue;
    }

    const hunkMatch = line.match(/^@@\s+-\d+(?:,\d+)?\s+\+(\d+)(?:,\d+)?\s+@@/);
    if (hunkMatch) {
      currentLine = Number.parseInt(hunkMatch[1], 10);
      insideHunk = true;
      continue;
    }

    // "+++ b/path" is a header and appears only before the first hunk. Inside
    // a hunk every "+" line is content, so a "+++" test there drops an added
    // line beginning with "++" and any credential on it goes unseen.
    if (!line.startsWith("+")) continue;
    if (!insideHunk && line.startsWith("+++")) continue;
    if (!currentFile) continue;

    if (fileIsIgnored) {
      currentLine++;
      continue;
    }

    const fullPath = path.join(repoRoot, currentFile);
    const addedLine = line.slice(1);

    const secretFindings = filterByMinimumSeverity(
      filterIgnoredFindings(detectSecrets(addedLine, fullPath), config),
      config
    );

    for (const finding of secretFindings) {
      // lineContent is already redacted by the detector, so it is safe to use
      // as part of the dedupe identity.
      const dedupeKey = [commit.hash, currentFile, currentLine, finding.ruleId, finding.lineContent].join(":");
      if (seen.has(dedupeKey)) continue;
      seen.add(dedupeKey);

      findings.push({
        ...finding,
        filePath: currentFile,
        line: currentLine,
        commitHash: commit.hash,
        commitDate: commit.date,
      });
    }

    currentLine++;
  }
}

function clampCommitLimit(requested: number, diagnostics: Diagnostics): number {
  if (!Number.isFinite(requested) || requested < 1) {
    diagnostics.add(`Invalid maxCommits value; defaulting to 100.`);
    return 100;
  }
  if (requested > MAX_COMMITS_LIMIT) {
    diagnostics.add(`maxCommits was capped at ${MAX_COMMITS_LIMIT}; history beyond that was not scanned.`);
    return MAX_COMMITS_LIMIT;
  }
  return Math.floor(requested);
}

async function ensureGitRepository(repoPath: string): Promise<void> {
  try {
    await git(repoPath, ["rev-parse", "--is-inside-work-tree"]);
  } catch {
    throw new Error(`Not a git repository: ${repoPath}`);
  }
}

async function listCommits(repoPath: string, maxCommits: number, diagnostics: Diagnostics): Promise<CommitInfo[]> {
  let output: string;
  try {
    output = await git(repoPath, [
      "log",
      "--all",
      "--no-show-signature",
      "--date=iso-strict",
      "--format=%H%x09%aI",
      "-n",
      String(maxCommits),
    ]);
  } catch (error) {
    diagnostics.add(`Unable to list commits: ${errorMessage(error)}. No history was scanned.`);
    return [];
  }

  const commits: CommitInfo[] = [];
  for (const line of output.split("\n")) {
    const [hash, date] = line.trim().split("\t");
    // Reject anything that is not a hash before it is used as a git argument.
    if (hash && COMMIT_HASH.test(hash)) {
      commits.push({ hash, date: date || "" });
    }
  }
  return commits;
}

async function readCommitPatch(repoPath: string, commitHash: string, diagnostics: Diagnostics): Promise<string | null> {
  if (!COMMIT_HASH.test(commitHash)) {
    diagnostics.add(`Skipped a commit with an unexpected identifier format.`);
    return null;
  }

  try {
    return await git(repoPath, ["show", "--format=", "--unified=0", "--no-color", "--no-show-signature", "--no-textconv", commitHash], MAX_PATCH_BYTES);
  } catch (error) {
    // A single unreadable commit (large binary blob, shallow clone boundary)
    // must not abort the scan, but the gap has to be visible.
    diagnostics.add(`Commit ${commitHash.slice(0, 8)} could not be read and was skipped: ${errorMessage(error)}`);
    logger.debug("commit read failed", { commit: commitHash, error: errorMessage(error) });
    return null;
  }
}

/**
 * Runs git with an argument array. No shell is spawned, so no argument can
 * become a command.
 *
 * The configuration flags matter as much as the arguments. A repository carries
 * its own `.git/config`, and a diff driver declared there names a *command* that
 * git runs while producing a diff: a `.gitattributes` entry of `* diff=x` plus
 * `[diff "x"] textconv = ...` executes that command during `git show`. Scanning
 * a hostile repository's history therefore ran attacker-chosen code as the
 * scanner, which in CI holds a GITHUB_TOKEN. `--no-textconv` on the diff is the
 * load-bearing fix; the rest close neighbouring hooks that also take commands
 * from the repository.
 */
async function git(repoPath: string, args: string[], maxBuffer = 5 * 1024 * 1024): Promise<string> {
  const hardened = [
    "-c", "diff.external=",
    "-c", "core.fsmonitor=",
    "-c", "core.hooksPath=/dev/null",
    "-c", "core.quotepath=false",
  ];

  // Asynchronous on purpose. execFileSync blocked the event loop for the whole
  // scan, so an MCP server could not read stdin, answer another tool, or
  // respond to a ping for the duration: roughly eighty seconds at the default
  // commit cap, past most clients' request timeout, and the server looked dead.
  const { stdout } = await execFileAsync("git", ["-C", repoPath, ...hardened, ...args], {
    encoding: "utf-8",
    maxBuffer,
    timeout: GIT_TIMEOUT_MS,
    windowsHide: true,
    // Prevent git from prompting for credentials on a repository with remotes.
    env: { ...process.env, GIT_TERMINAL_PROMPT: "0", GIT_OPTIONAL_LOCKS: "0" },
    // SIGTERM is a request a child can ignore; this is the deadline.
    killSignal: "SIGKILL",
  });

  return stdout;
}
