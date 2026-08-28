/** Thin wrapper over the GitHub REST API for the PR review tools. */

import { Octokit } from "@octokit/rest";
import { PrInfo, PrDiffFile } from "../types/index.js";

let _octokit: Octokit | null = null;

function getOctokit(): Octokit {
  if (!_octokit) {
    const token = process.env.GITHUB_TOKEN;
    if (!token) {
      throw new Error(
        "GITHUB_TOKEN environment variable is not set. " +
        "Create a token at https://github.com/settings/tokens with 'repo' scope."
      );
    }
    _octokit = new Octokit({ auth: token });
  }
  return _octokit;
}

export async function listOpenPrs(
  owner: string,
  repo: string
): Promise<PrInfo[]> {
  const octokit = getOctokit();

  // A single page caps at 100. Reading one page returned the first 30 open
  // pull requests and presented them as the list, so an agent asked to review
  // everything open reviewed a fraction and reported done. getPrFiles already
  // paginates for the same reason.
  const data = await octokit.paginate(octokit.pulls.list, {
    owner,
    repo,
    state: "open",
    per_page: 100,
    sort: "updated",
    direction: "desc",
  });

  // The list endpoint omits changed_files, additions and deletions; they come
  // back only when a single pull request is fetched. Defaulting them to 0 made
  // every listed pull request look like an empty change, so they stay undefined
  // when absent and callers can tell "unknown" from "nothing changed".
  return data.map((pr: any) => ({
    number: pr.number,
    title: pr.title,
    author: pr.user?.login || "unknown",
    createdAt: pr.created_at,
    changedFiles: pr.changed_files,
    additions: pr.additions,
    deletions: pr.deletions,
  }));
}

export async function getPrDiff(
  owner: string,
  repo: string,
  pullNumber: number
): Promise<string> {
  const octokit = getOctokit();
  const { data } = await octokit.pulls.get({
    owner,
    repo,
    pull_number: pullNumber,
    mediaType: { format: "diff" },
  });
  return data as unknown as string;
}

export async function getPrFiles(
  owner: string,
  repo: string,
  pullNumber: number
): Promise<PrDiffFile[]> {
  const octokit = getOctokit();

  // A single page caps at 100 files. Reading one page silently analysed the
  // first 100 files of a larger pull request and reported that count as the
  // whole diff, so changes past the cap were never reviewed.
  const data = await octokit.paginate(octokit.pulls.listFiles, {
    owner,
    repo,
    pull_number: pullNumber,
    per_page: 100,
  });

  return data.map((file) => ({
    filename: file.filename,
    status: file.status,
    additions: file.additions,
    deletions: file.deletions,
    patch: file.patch,
  }));
}

/** The head commit of a pull request, needed to read files as the PR leaves them. */
export async function getPrHeadSha(
  owner: string,
  repo: string,
  pullNumber: number
): Promise<string> {
  const octokit = getOctokit();
  const { data } = await octokit.pulls.get({ owner, repo, pull_number: pullNumber });
  return data.head.sha;
}

/**
 * A file's full contents at a given ref.
 *
 * Scanning a pull request needs the whole file, not just the lines it adds: a
 * value assigned on one line and used on the next is invisible in a buffer of
 * added lines alone, and Semgrep cannot parse such a buffer at all.
 *
 * Returns null for anything that is not readable text: a deleted path, a
 * directory, a submodule, or a file too large for the contents endpoint.
 */
export async function getFileAtRef(
  owner: string,
  repo: string,
  ref: string,
  filePath: string
): Promise<string | null> {
  const octokit = getOctokit();
  try {
    const { data } = await octokit.repos.getContent({ owner, repo, ref, path: filePath });
    if (Array.isArray(data) || data.type !== "file" || typeof data.content !== "string") {
      return null;
    }
    return Buffer.from(data.content, "base64").toString("utf-8");
  } catch {
    return null;
  }
}

export async function postReviewComment(
  owner: string,
  repo: string,
  pullNumber: number,
  body: string,
  path: string,
  line: number
): Promise<{ id: number; url: string }> {
  const octokit = getOctokit();

  // Get the latest commit SHA
  const { data: pr } = await octokit.pulls.get({
    owner,
    repo,
    pull_number: pullNumber,
  });

  const { data: comment } = await octokit.pulls.createReviewComment({
    owner,
    repo,
    pull_number: pullNumber,
    body,
    path,
    line,
    commit_id: pr.head.sha,
  });

  return { id: comment.id, url: comment.html_url };
}

export async function postReview(
  owner: string,
  repo: string,
  pullNumber: number,
  body: string,
  event: "APPROVE" | "REQUEST_CHANGES" | "COMMENT"
): Promise<{ id: number; url: string }> {
  const octokit = getOctokit();

  const { data: review } = await octokit.pulls.createReview({
    owner,
    repo,
    pull_number: pullNumber,
    body,
    event,
  });

  return { id: review.id, url: review.html_url };
}
