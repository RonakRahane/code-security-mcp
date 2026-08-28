/**
 * Rule catalogue discovery.
 *
 * Without this an agent cannot answer "can Sentinel detect X?" except by
 * scanning something and seeing what comes back. explain_vulnerability covers a
 * hand-written set of CWE entries, which is a different and much smaller list
 * than the rules that actually run.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { SecurityPattern } from "../types/index.js";
import { getAllPatterns, getPatternCount, getPatternsByCategory, getPatternsByLanguage } from "../patterns/index.js";
import { jsonResponse, runTool } from "./shared.js";

/** The rule as an agent needs to see it. The regex is deliberately omitted. */
function describe(pattern: SecurityPattern) {
  return {
    id: pattern.id,
    severity: pattern.severity,
    category: pattern.category,
    cweId: pattern.cweId,
    message: pattern.message,
    remediation: pattern.remediation,
    languages: pattern.languages,
  };
}

export function registerListRules(server: McpServer): void {
  server.tool(
    "list_rules",
    "List the built-in detection rules, optionally filtered by category or language. Use to answer what Sentinel can detect before scanning, or to explain its coverage. Does not include the Semgrep rule packs or entropy-based secret detection, which run alongside these.",
    {
      category: z.string().min(1).max(64).optional()
        .describe("Filter by category, for example 'injection', 'secrets', 'xss', 'crypto', 'iac'"),
      language: z.string().min(1).max(64).optional()
        .describe("Filter by language, for example 'javascript', 'python', 'terraform', 'docker'"),
      includeRuleDetails: z.boolean().optional()
        .describe("Return each rule in full. Defaults to false, which returns identifiers and counts only."),
    },
    async ({ category, language, includeRuleDetails }) => runTool("list_rules", async () => {
      let patterns = getAllPatterns();
      if (category) patterns = getPatternsByCategory(category);
      // Applied second so the two filters compose rather than replace.
      if (language) {
        const forLanguage = new Set(getPatternsByLanguage(language).map((p) => p.id));
        patterns = patterns.filter((p) => forLanguage.has(p.id));
      }

      const byCategory: Record<string, number> = {};
      const byLanguage: Record<string, number> = {};
      for (const pattern of patterns) {
        byCategory[pattern.category] = (byCategory[pattern.category] ?? 0) + 1;
        for (const lang of pattern.languages) {
          byLanguage[lang] = (byLanguage[lang] ?? 0) + 1;
        }
      }

      return jsonResponse({
        totalRules: getPatternCount(),
        matchingRules: patterns.length,
        filters: { category: category ?? null, language: language ?? null },
        byCategory,
        byLanguage,
        rules: includeRuleDetails
          ? patterns.map(describe)
          : patterns.map((pattern) => pattern.id),
        note: "The built-in rule registry, secret-detection rules included. Two further sources are not listed here: the Semgrep packs in rules/, which run alongside these when Semgrep is installed and carry the cross-function taint rules, and entropy analysis in the secret detector, which flags high-entropy strings no named rule matches.",
      });
    })
  );
}
