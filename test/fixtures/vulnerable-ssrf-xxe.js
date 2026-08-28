// Server-side request forgery and XML external entity handling.
const libxmljs = require("libxmljs");

app.get("/proxy", async (req, res) => {
  const target = req.query.url;
  const upstream = await fetch(target);
  res.send(await upstream.text());
});

app.post("/xml", (req, res) => {
  const doc = libxmljs.parseXml(req.body.xml, { noent: true });
  res.json(doc.root().text());
});
