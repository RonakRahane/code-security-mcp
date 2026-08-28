// Safe code that superficially resembles vulnerabilities.
const crypto = require("crypto");

// 1. Parameterized queries: the canonical safe form.
db.query("SELECT * FROM users WHERE id = $1", [req.params.id]);
db.execute("SELECT * FROM t WHERE a = ? AND b = ?", [a, b]);

// 2. MD5 for a non-security purpose (cache key / ETag).
const etag = crypto.createHash("md5").update(fileBuffer).digest("hex");

// 3. Placeholder and example credentials.
const apiKey = process.env.API_KEY;
const example = "YOUR_API_KEY_HERE";
const placeholder = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

// 4. Safe DOM writes.
element.textContent = userInput;
element.setAttribute("data-value", userInput);

// 5. Sanitised HTML.
element.innerHTML = DOMPurify.sanitize(userHtml);

// 6. execFile with an argument array.
execFile("git", ["log", "--oneline"], (e, out) => {});

// 7. Static SQL built over lines.
const sql = `
  SELECT id FROM users
  WHERE active = true
`;
db.query(sql);

// 8. A variable literally named password holding a config key, not a secret.
const passwordFieldName = "password";
const passwordMinLength = 12;
