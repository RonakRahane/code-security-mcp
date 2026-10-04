// Existing code on the base branch, outside the pull request's change.
const express = require("express");
const { exec } = require("child_process");
const app = express();

app.get("/legacy-ping", (req, res) => {
  exec("ping -c 1 " + req.query.host, (err, out) => res.send(out));
});

app.get("/legacy-calc", (req, res) => {
  res.json({ result: eval(req.query.expr) });
});

app.get("/archive", (req, res) => {
  exec("tar czf /tmp/out.tgz " + req.query.dir, () => res.end());
});

module.exports = app;
