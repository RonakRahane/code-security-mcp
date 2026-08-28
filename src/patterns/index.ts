import { SecurityPattern } from "../types/index.js";
import { injectionPatterns } from "./injection.js";
import { xssPatterns } from "./xss.js";
import { secretPatterns } from "./secrets.js";
import { authPatterns } from "./auth.js";
import { aiPatterns } from "./ai.js";
import { cryptoPatterns } from "./crypto.js";
import { dangerousFunctionPatterns } from "./dangerous-functions.js";
import { pathTraversalPatterns } from "./path-traversal.js";
import { prototypePollutionPatterns } from "./prototype-pollution.js";
import { miscPatterns } from "./miscellaneous.js";
import { pythonPatterns } from "./python.js";
import { iacPatterns } from "./iac.js";

/**
 * Registry of every security pattern, covering JS/TS, Python and IaC. The
 * registry and its per-language projections are built once and cached, since a
 * directory scan asks for them once per file.
 */
let allPatternsCache: readonly SecurityPattern[] | null = null;
const byLanguageCache = new Map<string, readonly SecurityPattern[]>();

export function getAllPatterns(): readonly SecurityPattern[] {
  if (!allPatternsCache) {
    allPatternsCache = Object.freeze([
      ...injectionPatterns,
      ...xssPatterns,
      ...secretPatterns,
      ...aiPatterns,
      ...authPatterns,
      ...cryptoPatterns,
      ...dangerousFunctionPatterns,
      ...pathTraversalPatterns,
      ...prototypePollutionPatterns,
      ...miscPatterns,
      ...pythonPatterns,
      ...iacPatterns,
    ]);
  }
  return allPatternsCache;
}

/** Number of registered patterns. Reported alongside scan results. */
export function getPatternCount(): number {
  return getAllPatterns().length;
}

export function getPatternsByCategory(category: string): readonly SecurityPattern[] {
  return getAllPatterns().filter((pattern) => pattern.category === category);
}

/** Patterns applicable to a language, memoised per language. */
export function getPatternsByLanguage(language: string): readonly SecurityPattern[] {
  const cached = byLanguageCache.get(language);
  if (cached) return cached;

  const patterns = Object.freeze(
    getAllPatterns().filter(
      (pattern) => pattern.languages.includes(language) || pattern.languages.includes("*")
    )
  );
  byLanguageCache.set(language, patterns);
  return patterns;
}

// Individual pattern sets, for callers that need one category.
export {
  injectionPatterns,
  xssPatterns,
  secretPatterns,
  aiPatterns,
  authPatterns,
  cryptoPatterns,
  dangerousFunctionPatterns,
  pathTraversalPatterns,
  prototypePollutionPatterns,
  miscPatterns,
  pythonPatterns,
  iacPatterns,
};
