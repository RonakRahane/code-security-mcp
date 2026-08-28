/**
 * Asynchronous, bounded-concurrency filesystem traversal.
 *
 * Everything here is promise-based: synchronous I/O blocks the event loop for
 * the whole scan, which starves the MCP transport until the client times out.
 * Concurrency and file counts are capped so a scan cannot exhaust file
 * descriptors or memory.
 */

import type { Dirent } from "node:fs";
import * as fsp from "node:fs/promises";
import * as path from "node:path";
import {
  DEFAULT_CONCURRENCY,
  DEFAULT_MAX_FILES,
  IGNORED_DIRECTORIES,
  MAX_DIRECTORY_DEPTH,
  MAX_FILE_BYTES,
} from "./constants.js";
import { Diagnostics } from "./diagnostics.js";
import { safeRealpath } from "./paths.js";

export interface WalkOptions {
  /** Collects unreadable paths so coverage gaps are reported, never silent. */
  diagnostics: Diagnostics;
  maxFiles?: number;
  maxDepth?: number;
  /** Return false to skip an entire directory subtree. */
  shouldEnterDirectory?: (absolutePath: string, name: string) => boolean;
  /** Return false to skip a file without counting it as an error. */
  shouldReadFile?: (absolutePath: string, name: string) => boolean;
}

export interface WalkResult {
  files: string[];
  /** True when `maxFiles` was hit and the tree was only partially enumerated. */
  truncated: boolean;
}

/**
 * Enumerates files beneath `root`. Symlinks are resolved and de-duplicated by
 * real path, which prevents recursion through link cycles and stops a link
 * pointing outside the scan root from widening its scope.
 */
export async function walkDirectory(root: string, options: WalkOptions): Promise<WalkResult> {
  const maxFiles = options.maxFiles ?? DEFAULT_MAX_FILES;
  const maxDepth = options.maxDepth ?? MAX_DIRECTORY_DEPTH;
  const rootReal = safeRealpath(path.resolve(root));

  const files: string[] = [];
  const visitedDirectories = new Set<string>([rootReal]);
  let truncated = false;
  let depthLimitReported = false;

  const queue: Array<{ dir: string; depth: number }> = [{ dir: rootReal, depth: 0 }];

  while (queue.length > 0) {
    if (files.length >= maxFiles) {
      truncated = true;
      break;
    }

    const { dir, depth } = queue.shift()!;

    let entries: Dirent[];
    try {
      entries = await fsp.readdir(dir, { withFileTypes: true });
    } catch (error) {
      options.diagnostics.skipped("directory", dir, error);
      continue;
    }

    for (const entry of entries) {
      if (files.length >= maxFiles) {
        truncated = true;
        break;
      }

      const fullPath = path.join(dir, entry.name);

      if (entry.isSymbolicLink()) {
        await queueSymlink(fullPath, entry.name, depth);
        continue;
      }

      if (entry.isDirectory()) {
        queueDirectory(fullPath, entry.name, depth);
      } else if (entry.isFile()) {
        if (options.shouldReadFile && !options.shouldReadFile(fullPath, entry.name)) continue;
        files.push(fullPath);
      }
      // Sockets, FIFOs and device files are intentionally ignored: reading them
      // can block indefinitely and they never contain source code.
    }
  }

  return { files, truncated };

  function queueDirectory(fullPath: string, name: string, depth: number): void {
    if (depth >= maxDepth) {
      // maxFiles reports truncation; this cap did not, so a subtree below the
      // limit disappeared from the scan with no diagnostic and no flag.
      if (!depthLimitReported) {
        depthLimitReported = true;
        options.diagnostics.add(
          `Directory nesting deeper than ${maxDepth} levels was not scanned, starting at ${fullPath}. ` +
          `Files below that depth were not analysed.`
        );
      }
      return;
    }
    if (IGNORED_DIRECTORIES.has(name)) return;
    if (options.shouldEnterDirectory && !options.shouldEnterDirectory(fullPath, name)) return;

    const real = safeRealpath(fullPath);
    if (visitedDirectories.has(real)) return;
    visitedDirectories.add(real);

    queue.push({ dir: fullPath, depth: depth + 1 });
  }

  /**
   * A symlink is followed only when its target stays inside the scan root.
   * Otherwise a repository could point the scanner at arbitrary host files and
   * have their contents reported back through findings.
   */
  async function queueSymlink(fullPath: string, name: string, depth: number): Promise<void> {
    const real = safeRealpath(fullPath);
    const relative = path.relative(rootReal, real);
    if (relative !== "" && (relative.startsWith("..") || path.isAbsolute(relative))) {
      options.diagnostics.add(`Skipped symbolic link pointing outside the scan root: ${name}`);
      return;
    }

    let stats;
    try {
      stats = await fsp.stat(fullPath);
    } catch (error) {
      options.diagnostics.skipped("file", fullPath, error);
      return;
    }

    if (stats.isDirectory()) {
      queueDirectory(fullPath, name, depth);
    } else if (stats.isFile()) {
      if (options.shouldReadFile && !options.shouldReadFile(fullPath, name)) return;
      files.push(fullPath);
    }
  }
}

export interface ReadTextOptions {
  maxBytes?: number;
  diagnostics?: Diagnostics;
}

/**
 * Reads a UTF-8 source file, or returns null when it is unreadable, oversized,
 * or binary. Size is checked against the open handle rather than the path, so a
 * file that grows between check and read cannot bypass the limit.
 */
export async function readTextFile(filePath: string, options: ReadTextOptions = {}): Promise<string | null> {
  const maxBytes = options.maxBytes ?? MAX_FILE_BYTES;

  let handle: fsp.FileHandle | undefined;
  try {
    handle = await fsp.open(filePath, "r");
    const stats = await handle.stat();

    if (!stats.isFile()) return null;
    if (stats.size === 0) return "";
    if (stats.size > maxBytes) return null;

    const buffer = await handle.readFile();
    if (isBinary(buffer)) return null;

    return buffer.toString("utf-8");
  } catch (error) {
    options.diagnostics?.skipped("file", filePath, error);
    return null;
  } finally {
    await handle?.close().catch(() => {
      // Close failures cannot be acted on and must not mask the read result.
    });
  }
}

/** A NUL byte in the leading bytes is the standard heuristic for binary content. */
function isBinary(buffer: Buffer): boolean {
  const window = buffer.subarray(0, Math.min(buffer.length, 8_000));
  return window.includes(0);
}

/**
 * Applies `worker` across `items` with at most `limit` in flight, preserving
 * input order. A worker that throws yields `undefined` for that item rather
 * than aborting the batch, so one unreadable file cannot discard a whole scan.
 */
export async function mapWithConcurrency<T, R>(
  items: readonly T[],
  worker: (item: T, index: number) => Promise<R>,
  limit: number = DEFAULT_CONCURRENCY,
  onError?: (item: T, index: number, error: unknown) => void
): Promise<Array<R | undefined>> {
  const effectiveLimit = Math.max(1, Math.min(limit, items.length || 1));
  const results = new Array<R | undefined>(items.length);
  let cursor = 0;

  async function run(): Promise<void> {
    while (true) {
      const index = cursor++;
      if (index >= items.length) return;
      try {
        results[index] = await worker(items[index], index);
      } catch (error) {
        results[index] = undefined;
        // A swallowed failure here is indistinguishable from a file with
        // nothing wrong in it, which is the worst outcome a scanner can
        // produce. The caller decides how to report it, but it must be told.
        onError?.(items[index], index, error);
      }
    }
  }

  await Promise.all(Array.from({ length: effectiveLimit }, run));
  return results;
}

/** Resolves the scan concurrency, allowing operators to tune it per environment. */
export function resolveConcurrency(requested?: number): number {
  const fromEnv = Number.parseInt(process.env.SENTINEL_CONCURRENCY || "", 10);
  const candidate = requested ?? (Number.isFinite(fromEnv) ? fromEnv : DEFAULT_CONCURRENCY);
  return Math.max(1, Math.min(64, candidate));
}
