import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import * as fsp from "node:fs/promises";
import * as path from "node:path";
import { z } from "zod";
import { MAX_FILE_BYTES } from "../core/constants.js";
import { Diagnostics } from "../core/diagnostics.js";
import { readTextFile } from "../core/fs-walk.js";
import { logger } from "../core/logger.js";
import { scanCode } from "../scanner/pattern-engine.js";
import { generateFixes, getFixableRules } from "../scanner/auto-fixer.js";
import { errorResponse, jsonResponse, pathArgument, requirePath, runTool } from "./shared.js";

/**
 * Copies the file aside before it is rewritten, without overwriting a backup
 * that is already there.
 *
 * A single fixed name was overwritten on every run, so a second run replaced
 * the pristine original with the output of the first and the real original was
 * gone. A hand-written .bak was destroyed the same way.
 */
async function writeBackup(filePath: string): Promise<string> {
  const base = `${filePath}.sentinel.bak`;

  for (let attempt = 0; attempt < 100; attempt++) {
    const candidate = attempt === 0 ? base : `${base}.${attempt}`;
    try {
      // wx fails when the path exists, so an existing backup is never clobbered.
      const handle = await fsp.open(candidate, "wx");
      await handle.close();
      await fsp.copyFile(filePath, candidate);
      return candidate;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    }
  }

  throw new Error(`Could not create a backup beside ${filePath}: too many existing backups.`);
}

export function registerAutoFix(server: McpServer): void {
  server.tool(
    "auto_fix",
    "Scan a file and generate concrete before/after patches for each finding. Runs as a dry run by default; set applyFixes to true to write high-confidence fixes to disk.",
    {
      filePath: pathArgument("Absolute path to the file to scan and fix"),
      applyFixes: z.boolean().optional()
        .describe("Write high-confidence fixes to the file. Default false (dry run). The file is modified in place, so review the dry-run output first."),
    },
    async ({ filePath, applyFixes }) => runTool("auto_fix", async () => {
      const target = requirePath(filePath, "file", "filePath");
      const resolvedPath = target.absolutePath;
      const diagnostics = new Diagnostics();

      const code = await readTextFile(resolvedPath, { maxBytes: MAX_FILE_BYTES, diagnostics });
      if (code === null) {
        return errorResponse(`File could not be read, is binary, or exceeds ${MAX_FILE_BYTES} bytes.`);
      }

      const result = scanCode(code, resolvedPath, undefined, path.dirname(resolvedPath));
      const fixes = generateFixes(code, result.findings);
      // High confidence alone is not enough to write to someone's file. A
      // multi-line patch replaces one line with several, and a comment-only
      // patch is guidance - applying it would delete the working statement and
      // leave a TODO behind. Both were previously excluded only by the fact
      // that no current generator produced them at high confidence, which is a
      // property of today's rules rather than a guarantee.
      const highConfidenceFixes = fixes.filter(
        (fix) =>
          fix.confidence === "high" &&
          !fix.after.includes("\n") &&
          !isGuidanceOnly(fix.after)
      );

      let applied = 0;

      /** Rules whose patch was not written because another already rewrote that line. */

      const skippedSameLine: string[] = [];
      let backupPath: string | undefined;

      if (applyFixes && highConfidenceFixes.length > 0) {
        // Only high-confidence, single-line replacements are written back.
        // Anything else is left for a human to apply.
        const lines = code.split("\n");
        const sorted = [...highConfidenceFixes].sort((a, b) => b.line - a.line);

        // One line, one rewrite. Each patch is derived from the original line,
        // so a second patch on the same line overwrites the first rather than
        // composing with it, and counting both reported work that never landed.
        const rewritten = new Set<number>();

        for (const fix of sorted) {
          if (fix.line < 1 || fix.line > lines.length) continue;
          if (rewritten.has(fix.line)) {
            skippedSameLine.push(fix.ruleId);
            continue;
          }

          // Generators return trimmed code for display, so restore the
          // original indentation before writing it back.
          lines[fix.line - 1] = reindent(fix.after, lines[fix.line - 1]);
          rewritten.add(fix.line);
          applied++;
        }

        // Copy the original bytes rather than re-encoding the decoded string.
        // readTextFile decodes as UTF-8, so a latin-1 source came back with
        // U+FFFD in place of every high byte and the backup preserved the
        // damage rather than the file, leaving no way back.
        backupPath = await writeBackup(resolvedPath);

        // The generators substitute into the decoded text, so a file that does
        // not round-trip through UTF-8 would be rewritten with replacement
        // characters. Refuse rather than corrupt it.
        const originalBytes = await fsp.readFile(resolvedPath);
        if (!Buffer.from(code, "utf-8").equals(originalBytes)) {
          return errorResponse(
            `${resolvedPath} is not valid UTF-8. Rewriting it would replace the bytes that could not be decoded, so no fix was applied.`
          );
        }

        const original = await fsp.stat(resolvedPath);
        await writeAtomically(resolvedPath, lines.join("\n"));
        // An atomic rename installs a fresh inode, which would otherwise drop
        // the original mode: an executable entry point came back non-executable
        // and a 0600 secrets file came back world-readable.
        await fsp.chmod(resolvedPath, original.mode);

        logger.info("auto-fix applied", { file: resolvedPath, fixes: applied });
      }

      return jsonResponse({
        filePath: resolvedPath,
        dryRun: !applyFixes,
        totalFindings: result.totalFindings,
        fixesGenerated: fixes.length,
        fixesApplied: applied,
        ...(skippedSameLine.length > 0
          ? {
              skippedSameLine,
              skippedNote: "These patches target a line another patch already rewrote. Apply them by hand, or re-run after the first change.",
            }
          : {}),
        ...(backupPath ? { backupPath, note: "The original file was saved alongside the modified one." } : {}),
        fixableRules: getFixableRules().length,
        summary: result.summary,
        fixes: fixes.map((fix) => ({
          ruleId: fix.ruleId,
          line: fix.line,
          confidence: fix.confidence,
          before: fix.before,
          after: fix.after,
          explanation: fix.explanation,
        })),
        unfixableFindings: result.findings
          .filter((finding) => !fixes.some((fix) => fix.ruleId === finding.ruleId && fix.line === finding.line))
          .map((finding) => ({
            ruleId: finding.ruleId,
            line: finding.line,
            severity: finding.severity,
            message: finding.message,
            remediation: finding.remediation,
          })),
        warnings: diagnostics.toWarnings(),
      });
    })
  );
}

/** True when a patch is entirely commentary, with no code left to run. */
function isGuidanceOnly(after: string): boolean {
  const lines = after.split("\n").filter((line) => line.trim());
  return lines.length > 0 && lines.every((line) => /^\s*(\/\/|#|\/\*)/.test(line));
}

/**
 * Restores the original line's leading whitespace on replacement text, applying
 * it to every line of a multi-line patch.
 */
function reindent(replacement: string, originalLine: string): string {
  const indent = originalLine.match(/^[\t ]*/)?.[0] ?? "";
  if (!indent) return replacement;

  return replacement
    .split("\n")
    .map((line) => (line.trim() ? indent + line.replace(/^[\t ]*/, "") : line))
    .join("\n");
}

/**
 * Writes via a temporary file and rename, so an interrupted write cannot leave
 * the user's source truncated.
 */
async function writeAtomically(filePath: string, content: string): Promise<void> {
  const temporaryPath = path.join(
    path.dirname(filePath),
    `.${path.basename(filePath)}.${process.pid}.tmp`
  );

  try {
    await fsp.writeFile(temporaryPath, content, "utf-8");
    await fsp.rename(temporaryPath, filePath);
  } catch (error) {
    await fsp.unlink(temporaryPath).catch(() => {
      // Best-effort cleanup; the original error is the one worth reporting.
    });
    throw error;
  }
}
