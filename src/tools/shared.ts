/**
 * Shared plumbing for MCP tool handlers.
 *
 * Tool arguments come from an LLM that has been reading the repository under
 * scan, so they are untrusted. Every handler validates through here and returns
 * the same response envelope, because the caller is a model and an inconsistent
 * error shape produces inconsistent behaviour.
 */

import { z } from "zod";
import { errorMessage, logger } from "../core/logger.js";
import { MAX_PATH_LENGTH, PathValidationError, ValidatedPath, validatePath } from "../core/paths.js";

export interface ToolResponse {
  [key: string]: unknown;
  content: Array<{ type: "text"; text: string }>;
  isError?: boolean;
}

/** JSON payload response. */
export function jsonResponse(payload: unknown): ToolResponse {
  return { content: [{ type: "text", text: JSON.stringify(payload, null, 2) }] };
}

/** Plain-text response, for tools that return rendered documents. */
export function textResponse(text: string): ToolResponse {
  return { content: [{ type: "text", text }] };
}

/**
 * Error response. `isError` lets clients tell a failed call apart from a scan
 * that ran and found nothing.
 */
export function errorResponse(message: string, hint?: string): ToolResponse {
  return {
    content: [{ type: "text", text: JSON.stringify({ error: message, ...(hint ? { hint } : {}) }, null, 2) }],
    isError: true,
  };
}

/** Zod schema for a filesystem path argument. */
export function pathArgument(description: string) {
  return z.string().min(1).max(MAX_PATH_LENGTH).describe(description);
}

/**
 * Wraps a handler so no exception escapes as a protocol-level failure and no
 * stack trace or absolute host path reaches the client.
 */
export async function runTool(
  toolName: string,
  handler: () => Promise<ToolResponse>
): Promise<ToolResponse> {
  const startedAt = Date.now();
  try {
    const response = await handler();
    logger.debug("tool completed", { tool: toolName, durationMs: Date.now() - startedAt });
    return response;
  } catch (error) {
    if (error instanceof PathValidationError) {
      return errorResponse(error.message);
    }

    logger.error("tool failed", { tool: toolName, error: errorMessage(error) });
    return errorResponse(`${toolName} failed: ${errorMessage(error)}`);
  }
}

/** Validates a path argument. Throws PathValidationError, which runTool converts into a client-facing error. */
export function requirePath(
  input: string,
  kind: "file" | "directory" | "any",
  label: string
): ValidatedPath {
  return validatePath(input, { kind, label });
}
