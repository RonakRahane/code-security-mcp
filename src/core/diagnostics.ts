import { MAX_WARNINGS } from "./constants.js";
import { errorMessage, logger } from "./logger.js";

/**
 * Collects non-fatal problems hit during a scan and surfaces them in
 * `warnings[]`. A scan that could not read half a repository must not report
 * itself as a clean result.
 */
export class Diagnostics {
  private readonly messages: string[] = [];
  private readonly seen = new Set<string>();
  private truncated = 0;

  /** Counts of skipped paths by reason, used to summarise repeated failures. */
  private readonly skipCounts = new Map<string, number>();

  add(message: string): void {
    const trimmed = message.trim();
    if (!trimmed || this.seen.has(trimmed)) return;

    if (this.messages.length >= MAX_WARNINGS) {
      this.truncated++;
      return;
    }

    this.seen.add(trimmed);
    this.messages.push(trimmed);
  }

  addAll(messages: readonly string[]): void {
    for (const message of messages) this.add(message);
  }

  /**
   * Records a path that could not be processed. Failures are aggregated into one
   * warning per reason, so a permission problem across 900 files is one line.
   */
  skipped(kind: "file" | "directory", targetPath: string, error: unknown): void {
    const reason = classify(error);
    const key = `${kind}:${reason}`;
    this.skipCounts.set(key, (this.skipCounts.get(key) || 0) + 1);
    logger.debug("skipped path", { kind, path: targetPath, reason: errorMessage(error) });
  }

  /** Number of paths skipped for any reason. Reported as a coverage gap. */
  get skippedCount(): number {
    let total = 0;
    for (const count of this.skipCounts.values()) total += count;
    return total;
  }

  /** Finalises aggregated counters into human-readable warnings. */
  toWarnings(): string[] {
    const output = [...this.messages];

    for (const [key, count] of [...this.skipCounts.entries()].sort()) {
      const [kind, reason] = key.split(":");
      output.push(
        `Coverage gap: ${count} ${kind}${count === 1 ? "" : "s"} could not be read (${reason}). ` +
        `Results may be incomplete. Re-run with SENTINEL_LOG_LEVEL=debug for per-path detail.`
      );
    }

    if (this.truncated > 0) {
      output.push(`${this.truncated} additional warnings were suppressed (limit ${MAX_WARNINGS}).`);
    }

    return output;
  }
}

/** Maps an errno to a short, user-actionable reason. */
function classify(error: unknown): string {
  const code = typeof error === "object" && error !== null && "code" in error
    ? String((error as NodeJS.ErrnoException).code)
    : "";

  switch (code) {
    case "EACCES":
    case "EPERM":
      return "permission denied";
    case "ENOENT":
      return "path disappeared during scan";
    case "ELOOP":
      return "symbolic link loop";
    case "EMFILE":
    case "ENFILE":
      return "too many open files";
    case "EISDIR":
      return "unexpected directory";
    case "ENOTDIR":
      return "not a directory";
    case "EINVAL":
      return "invalid or non-UTF-8 content";
    default:
      return code ? code.toLowerCase() : "read error";
  }
}
