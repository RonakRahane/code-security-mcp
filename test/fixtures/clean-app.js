/**
 * Secure-by-construction Express service.
 *
 * This file is part of the benchmark corpus and is labelled "clean": any alert
 * raised here is an unambiguous false positive. It deliberately contains the
 * It deliberately contains the shapes naive pattern matching over-reports:
 * SQL text, template literals, crypto calls, credential-sounding identifiers,
 * and file paths, all used correctly.
 */

import crypto from "node:crypto";
import path from "node:path";
import { execFile } from "node:child_process";

const UPLOAD_ROOT = path.resolve("/srv/uploads");

// Parameterised query: the SQL is a static string, values travel separately.
export async function findUserById(db, userId) {
  return db.query("SELECT id, email FROM users WHERE id = $1", [userId]);
}

// Template literal containing only static SQL text, no interpolation.
export async function listActiveUsers(db) {
  const sql = `
    SELECT id, email
    FROM users
    WHERE active = true
    ORDER BY created_at DESC
  `;
  return db.query(sql);
}

// Credentials come from the environment, never from source.
export function getApiClient() {
  const apiKey = process.env.SERVICE_API_KEY;
  if (!apiKey) throw new Error("SERVICE_API_KEY is not configured");
  return { apiKey };
}

// Strong hashing with a random salt.
export function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  return crypto.scryptSync(password, salt, 64).toString("hex");
}

// Authenticated encryption with a random IV.
export function encrypt(plaintext, key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return { iv, ciphertext, tag: cipher.getAuthTag() };
}

// Path traversal is prevented by resolving and then checking containment.
export function resolveUploadPath(filename) {
  const candidate = path.resolve(UPLOAD_ROOT, path.basename(filename));
  if (!candidate.startsWith(`${UPLOAD_ROOT}${path.sep}`)) {
    throw new Error("Invalid upload path");
  }
  return candidate;
}

// Command execution with an argument array and an allowlist, no shell.
const ALLOWED_TOOLS = new Set(["identify", "exiftool"]);

export function inspectImage(tool, filePath, callback) {
  if (!ALLOWED_TOOLS.has(tool)) {
    callback(new Error("Unsupported tool"));
    return;
  }
  execFile(tool, ["--", resolveUploadPath(filePath)], callback);
}

// Output encoding rather than raw HTML assignment.
export function renderGreeting(element, displayName) {
  element.textContent = `Welcome, ${displayName}`;
}

// Prototype-pollution-safe lookup table.
export function buildIndex(entries) {
  const index = new Map();
  for (const [key, value] of entries) index.set(key, value);
  return index;
}

// JSON parsing instead of dynamic evaluation.
export function parsePayload(raw) {
  return JSON.parse(raw);
}
