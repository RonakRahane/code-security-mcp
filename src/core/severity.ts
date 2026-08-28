/** Severity ordering and counting, defined once so the severity set cannot drift. */

import { Severity, SeveritySummary } from "../types/index.js";

export const SEVERITY_ORDER: readonly Severity[] = ["critical", "high", "medium", "low", "info"];

const RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export function severityRank(severity: Severity): number {
  return RANK[severity] ?? RANK.info;
}

/** True when `severity` is at least as serious as `threshold`. */
export function isSeverityAtOrAbove(severity: Severity, threshold: Severity): boolean {
  return severityRank(severity) <= severityRank(threshold);
}

export function isSeverity(value: unknown): value is Severity {
  return typeof value === "string" && (SEVERITY_ORDER as readonly string[]).includes(value);
}

export function emptySeveritySummary(): SeveritySummary {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
}

/** Counts findings by severity in a single pass. */
export function computeSeveritySummary(
  ...groups: ReadonlyArray<ReadonlyArray<{ severity: Severity }>>
): SeveritySummary {
  const summary = emptySeveritySummary();
  for (const group of groups) {
    for (const item of group) {
      if (isSeverity(item.severity)) summary[item.severity]++;
    }
  }
  return summary;
}

/**
 * Sorts most-severe-first, in place. Ties break on file path then line so two
 * runs over the same tree produce byte-identical report ordering.
 */
export function sortBySeverity<T extends { severity: Severity; filePath?: string; line?: number }>(
  items: T[]
): T[] {
  return items.sort((a, b) => {
    const bySeverity = severityRank(a.severity) - severityRank(b.severity);
    if (bySeverity !== 0) return bySeverity;

    const byPath = (a.filePath || "").localeCompare(b.filePath || "");
    if (byPath !== 0) return byPath;

    return (a.line || 0) - (b.line || 0);
  });
}

/** Total findings at or above `threshold`, which is what a CI gate compares against `failOnSeverity`. */
export function countAtOrAbove(summary: SeveritySummary, threshold: Severity): number {
  return SEVERITY_ORDER.filter((severity) => isSeverityAtOrAbove(severity, threshold))
    .reduce((total, severity) => total + summary[severity], 0);
}
