/**
 * The server's advertised version.
 *
 * Its own module rather than a constant in index.ts: index.ts imports every
 * tool, so a tool importing the version back from it would close a cycle.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

function readPackageVersion(): string {
  try {
    const packagePath = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../package.json");
    const parsed = JSON.parse(fs.readFileSync(packagePath, "utf-8")) as { version?: unknown };
    if (typeof parsed.version === "string" && parsed.version) return parsed.version;
  } catch {
    // An unreadable manifest must not stop the server from starting; the
    // version is metadata, not a precondition for scanning.
  }
  return "0.0.0-unknown";
}

/** Read from package.json so the version advertised to MCP clients cannot drift. */
export const SERVER_VERSION = readPackageVersion();
