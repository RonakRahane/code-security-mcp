import * as path from "node:path";
import { pathToFileURL } from "node:url";
import { Finding, ScanResult, Severity } from "../types/index.js";
import { SERVER_VERSION } from "../version.js";

/** SARIF 2.1.0 result levels. */
type SarifLevel = "error" | "warning" | "note" | "none";

function mapSeverityToSarifLevel(severity: Severity): SarifLevel {
  switch (severity) {
    case "critical":
    case "high":
      return "error";
    case "medium":
      return "warning";
    case "low":
    case "info":
      return "note";
    default:
      return "none";
  }
}

/** SARIF's identifier for the directory the relative URIs are resolved against. */
const URI_BASE_ID = "SRCROOT";

/**
 * Path for a SARIF artifactLocation: relative to the scan root, forward
 * slashes, no leading separator.
 *
 * GitHub Code Scanning resolves every result against the repository checkout,
 * so an absolute machine path with its leading slash trimmed matches no file in
 * the repository and every result is dropped on ingest.
 */
function artifactUri(filePath: string, rootDir: string): string {
  const relative = path.relative(rootDir, filePath);

  // A path outside the root has no meaningful relative form. Keeping the
  // basename is wrong too, so the absolute path is preserved and the reader
  // can see it did not belong to the scan.
  const chosen = !relative || relative.startsWith("..") ? filePath : relative;

  return chosen.replace(/\\/g, "/").replace(/^\/+/, "");
}

export function generateSarif(
  results: ScanResult[],
  projectName: string,
  rootDir: string = process.cwd()
): string {
  const root = path.resolve(rootDir);
  const sarifResults: any[] = [];
  const rulesMap = new Map<string, any>();

  for (const result of results) {
    for (const finding of result.findings) {
      // Collect rule metadata for tool.driver.rules.
      if (!rulesMap.has(finding.ruleId)) {
        rulesMap.set(finding.ruleId, {
          id: finding.ruleId,
          name: finding.ruleId,
          shortDescription: {
            text: finding.message,
          },
          help: {
            text: finding.remediation,
          },
          properties: {
            category: finding.category,
            cwe: finding.cweId,
            severity: finding.severity,
          },
        });
      }

      const relativeUri = artifactUri(result.filePath, root);

      sarifResults.push({
        ruleId: finding.ruleId,
        level: mapSeverityToSarifLevel(finding.severity),
        message: {
          text: `[${finding.cweId}] ${finding.message}\nFix: ${finding.remediation}`,
        },
        locations: [
          {
            physicalLocation: {
              artifactLocation: {
                uri: relativeUri,
                uriBaseId: URI_BASE_ID,
              },
              region: {
                startLine: finding.line,
                snippet: {
                  text: finding.lineContent,
                },
              },
            },
          },
        ],
      });
    }
  }

  const sarifLog = {
    version: "2.1.0",
    $schema: "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
    runs: [
      {
        tool: {
          driver: {
            name: "Sentinel MCP",
            version: SERVER_VERSION,
            informationUri: "https://github.com/sentinel-mcp",
            rules: Array.from(rulesMap.values()),
          },
        },
        originalUriBaseIds: {
          [URI_BASE_ID]: {
            // Trailing separator required: SARIF resolves relative URIs against
            // this value, and without it the last path segment is replaced.
            uri: pathToFileURL(root.endsWith(path.sep) ? root : `${root}${path.sep}`).href,
          },
        },
        results: sarifResults,
      },
    ],
  };

  return JSON.stringify(sarifLog, null, 2);
}
