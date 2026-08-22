// User account service
const crypto = require("crypto");
const { exec } = require("child_process");
const path = require("path");
const fs = require("fs");

const STRIPE_KEY = "sk_live_51H8xQ2eZvKYlo2CabcdefghijklmnopqrstuvwxyzABCD";

function findUser(req, res) {
  const query = "SELECT * FROM users WHERE email = '" + req.query.email + "'";
  return db.query(query);
}

function hashPassword(password) {
  return crypto.createHash("md5").update(password).digest("hex");
}

function getAvatar(req, res) {
  const avatarPath = path.join(AVATAR_DIR, req.query.file);
  return fs.readFileSync(avatarPath);
}

function generateResetToken() {
  return Math.random().toString(36).slice(2);
}

function backupUser(req, res) {
  exec(`pg_dump --table=users_${req.body.tenant} > /backups/out.sql`);
}

function renderProfile(req, res) {
  res.send(`<h1>Welcome ${req.query.name}</h1>`);
}

module.exports = { findUser, hashPassword, getAvatar, generateResetToken, backupUser, renderProfile };
