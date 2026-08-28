import { SecurityPattern } from "../types/index.js";

export const cryptoPatterns: SecurityPattern[] = [
  {
    id: "WEAK_HASH_MD5",
    regex: /(?:createHash|hashlib\.md5|MD5|md5)\s*\(\s*['"]?md5['"]?\s*\)/i,
    severity: "high",
    category: "crypto",
    cweId: "CWE-328",
    message: "MD5 is cryptographically broken. Not suitable for passwords or integrity checks.",
    remediation: "Use SHA-256 or SHA-3 for hashing. Use bcrypt/argon2 for passwords.",
    languages: ["*"],
    matchScope: "literal",
  },
  {
    id: "WEAK_HASH_SHA1",
    regex: /(?:createHash|hashlib\.sha1)\s*\(\s*['"]?sha1['"]?\s*\)/i,
    severity: "medium",
    category: "crypto",
    cweId: "CWE-328",
    message: "SHA-1 has known collision vulnerabilities. Use SHA-256+.",
    remediation: "Replace with SHA-256: crypto.createHash('sha256').",
    languages: ["*"],
    matchScope: "literal",
  },
  {
    id: "MATH_RANDOM_SECURITY",
    regex: /Math\.random\s*\(\s*\)/,
    severity: "medium",
    category: "crypto",
    cweId: "CWE-338",
    message: "Math.random() is not cryptographically secure. Predictable for security contexts.",
    remediation: "Use crypto.randomBytes() or crypto.getRandomValues() for tokens/secrets.",
    languages: ["javascript", "typescript"],
  },
  {
    id: "WEAK_CIPHER_DES",
    // Anchored to a crypto call or an algorithm assignment. Without the left
    // word boundary this matches the "des" in "includes" and "overrides".
    regex: /(?:createCipher(?:iv)?|createDecipher(?:iv)?|Cipher\.getInstance|new\s+Cipher|algorithm\s*[:=]|cipher\s*[:=])\s*\(?\s*['"](?:des(?:-[a-z0-9]+)*|rc4|rc2|blowfish)['"]/i,
    severity: "high",
    category: "crypto",
    cweId: "CWE-327",
    message: "Weak/deprecated cipher algorithm (DES, RC4, RC2). Easily broken.",
    remediation: "Use AES-256-GCM: crypto.createCipheriv('aes-256-gcm', key, iv).",
    languages: ["*"],
    matchScope: "literal",
  },
  {
    id: "ECB_MODE",
    // Anchored at the call. Every alternative used to start inside the string
    // literal, and a literal-scope match is discarded unless it begins in
    // executable code, so createCipheriv("aes-256-ecb", ...) never reported.
    regex: /(?:createCipheriv|createDecipheriv|Cipher\s*\.\s*getInstance|algorithm\s*[:=]|mode\s*[:=])\s*\(?\s*['"][^'"]*(?:aes[-_]?\d*[-_]?ecb|AES\/ECB|\bECB\b)/i,
    severity: "high",
    category: "crypto",
    cweId: "CWE-327",
    message: "ECB mode leaks patterns in encrypted data. Never use for anything > 1 block.",
    remediation: "Use GCM or CBC mode with proper IV: 'aes-256-gcm'.",
    languages: ["*"],
    matchScope: "literal",
  },
];
