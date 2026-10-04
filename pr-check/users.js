const express = require("express");
const { Pool } = require("pg");
const app = express();
const pool = new Pool();

app.get("/users", async (req, res) => {
  const rows = await pool.query("SELECT * FROM users WHERE name = '" + req.query.name + "'");
  res.json(rows.rows);
});

app.get("/users-safe", async (req, res) => {
  const rows = await pool.query("SELECT * FROM users WHERE name = $1", [req.query.name]);
  res.json(rows.rows);
});

app.get("/hello", (req, res) => {
  res.send("<h1>Hello " + req.query.name + "</h1>");
});

module.exports = app;
