// Intentionally vulnerable fixture. Test corpus only, never runnable code.
// Use this to test sentinel-mcp: scan_file({ filePath: "/path/to/this/file" })

const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { exec } = require("child_process");
const fs = require("fs");

const app = express();

// SECRET: Hardcoded credentials
const API_KEY = "sk_live_notarealkeyusedasfix";
const dbPassword = "super_secret_database_password_123!";
const JWT_SECRET = "my-jwt-secret-that-should-be-in-env";
const awsKey = "AKIAIOSFODNN7EXAMPLE";
const privateKey = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQ...";

// SQL INJECTION
app.get("/users", async (req, res) => {
  const userId = req.query.id;
  const result = await db.query(`SELECT * FROM users WHERE id = ${userId}`);
  res.json(result);
});

app.post("/search", async (req, res) => {
  const name = req.body.name;
  const result = await db.query("SELECT * FROM products WHERE name = '" + name + "'");
  res.json(result);
});

// COMMAND INJECTION
app.get("/ping", (req, res) => {
  const host = req.query.host;
  exec(`ping -c 1 ${host}`, (err, stdout) => {
    res.send(stdout);
  });
});

// XSS
app.get("/greet", (req, res) => {
  const name = req.query.name;
  res.send(`<h1>Hello ${name}</h1>`);
});

app.get("/profile", (req, res) => {
  document.getElementById("output").innerHTML = userData;
});

// EVAL
app.post("/calculate", (req, res) => {
  const expression = req.body.expr;
  const result = eval(expression);
  res.json({ result });
});

// PATH TRAVERSAL
app.get("/file", (req, res) => {
  const filename = req.query.name;
  const content = fs.readFileSync("/uploads/" + filename, "utf-8");
  res.send(content);
});

// WEAK CRYPTO
const crypto = require("crypto");
function hashPassword(password) {
  return crypto.createHash("md5").update(password).digest("hex");
}

function generateToken() {
  return Math.random().toString(36).substring(2);
}

// JWT ISSUES
app.post("/login", async (req, res) => {
  const user = await findUser(req.body.email);
  const passwordMatch = await bcrypt.hash(req.body.password, 4); // Low rounds

  // Hardcoded JWT secret
  const token = jwt.sign({ userId: user.id, role: user.role }, "hardcoded-secret-key");
  res.json({ token });
});

app.get("/profile", (req, res) => {
  // Decoding without verification!
  const decoded = jwt.decode(req.headers.authorization);
  res.json(decoded);
});

// PROTOTYPE POLLUTION
function merge(target, source) {
  for (const key in source) {
    if (typeof source[key] === "object") {
      target[key] = merge(target[key] || {}, source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

app.post("/settings", (req, res) => {
  const settings = {};
  merge(settings, req.body); // Prototype pollution!
  res.json(settings);
});

// OPEN REDIRECT
app.get("/redirect", (req, res) => {
  const url = req.query.url;
  res.redirect(req.query.url);
});

// NOSQL INJECTION
app.post("/api/login", async (req, res) => {
  const user = await User.findOne(req.body);
  res.json(user);
});

// CORS MISCONFIGURATION
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  next();
});

// INFO DISCLOSURE
app.use((err, req, res, next) => {
  res.send(err.stack);
});

app.listen(3000);
console.log("Server running on http://localhost:3000");
