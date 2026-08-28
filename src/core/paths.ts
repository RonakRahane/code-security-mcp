/**
 * Validation for every filesystem path arriving from an MCP tool call.
 *
 * Tool arguments come from an LLM acting on text it read, including the
 * repository under scan, so they are untrusted. A path is accepted only after
 * it is resolved, length-checked, symlink-resolved, and (when a workspace
 * allowlist is configured) confirmed to sit inside an allowed root.
 */

import * as fs from "node:fs";
import * as path from "node:path";

/** Upper bound on an accepted path. Longer values are rejected before syscalls. */
export const MAX_PATH_LENGTH = 4096;

export class PathValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PathValidationError";
  }
}

export type TargetKind = "file" | "directory" | "any";

export interface ValidatedPath {
  /** Fully resolved path with symlinks followed. Use this for all I/O. */
  readonly absolutePath: string;
  readonly isDirectory: boolean;
  readonly isFile: boolean;
}

/**
 * Reads the optional workspace allowlist. `SENTINEL_ALLOWED_ROOTS`
 * (path-delimited) restricts every tool to the listed directories. Unset means
 * no restriction, which suits a local developer but not a hosted deployment,
 * so shared deployments have to opt in.
 */
function getAllowedRoots(): string[] {
  const raw = process.env.SENTINEL_ALLOWED_ROOTS;
  if (!raw || !raw.trim()) return [];

  return raw
    .split(path.delimiter)
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map((entry) => safeRealpath(path.resolve(entry)));
}

/** True when `candidate` is `root` itself or lives beneath it. */
export function isWithin(root: string, candidate: string): boolean {
  const relative = path.relative(root, candidate);
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

/**
 * Resolves and validates a caller-supplied path.
 *
 * @throws PathValidationError when the path is malformed, missing, of the wrong
 * kind, or outside the configured workspace allowlist.
 */
export function validatePath(
  input: unknown,
  options: { kind?: TargetKind; label?: string } = {}
): ValidatedPath {
  const label = options.label || "path";
  const kind = options.kind || "any";

  if (typeof input !== "string") {
    throw new PathValidationError(`${label} must be a string.`);
  }

  const trimmed = input.trim();
  if (!trimmed) {
    throw new PathValidationError(`${label} must not be empty.`);
  }
  if (trimmed.length > MAX_PATH_LENGTH) {
    throw new PathValidationError(`${label} exceeds the maximum length of ${MAX_PATH_LENGTH} characters.`);
  }
  // A NUL byte truncates the path at the libc boundary, so a value that passes
  // JavaScript-side checks can still address a different file.
  if (trimmed.includes("\0")) {
    throw new PathValidationError(`${label} contains a null byte.`);
  }

  const resolved = path.resolve(trimmed);

  let stats: fs.Stats;
  try {
    // statSync (not lstatSync) so a symlink is judged by its target.
    stats = fs.statSync(resolved);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ENOENT") throw new PathValidationError(`${label} not found: ${resolved}`);
    if (code === "EACCES" || code === "EPERM") throw new PathValidationError(`${label} is not readable: ${resolved}`);
    if (code === "ELOOP") throw new PathValidationError(`${label} resolves through a symbolic link loop: ${resolved}`);
    throw new PathValidationError(`${label} could not be accessed: ${resolved}`);
  }

  if (kind === "file" && !stats.isFile()) {
    throw new PathValidationError(`${label} is not a file: ${resolved}`);
  }
  if (kind === "directory" && !stats.isDirectory()) {
    throw new PathValidationError(`${label} is not a directory: ${resolved}`);
  }
  if (!stats.isFile() && !stats.isDirectory()) {
    throw new PathValidationError(`${label} is neither a file nor a directory: ${resolved}`);
  }

  // Compare the *real* path against the allowlist: a symlink inside an allowed
  // root must not grant access to a target outside it.
  const realPath = safeRealpath(resolved);
  const allowedRoots = getAllowedRoots();
  if (allowedRoots.length > 0 && !allowedRoots.some((root) => isWithin(root, realPath))) {
    throw new PathValidationError(
      `${label} is outside the allowed workspace roots configured by SENTINEL_ALLOWED_ROOTS.`
    );
  }

  return {
    absolutePath: realPath,
    isDirectory: stats.isDirectory(),
    isFile: stats.isFile(),
  };
}


/** realpath that degrades to the input path when resolution is not permitted. */
export function safeRealpath(target: string): string {
  try {
    return fs.realpathSync.native(target);
  } catch {
    return target;
  }
}
