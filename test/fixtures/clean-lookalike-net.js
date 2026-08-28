// Safe outbound requests and XML handling.
const r1 = await fetch("https://api.example.com/status");
const r2 = await fetch(`${process.env.API_BASE}/health`);
const r3 = await axios.get(config.serviceUrl);

const ALLOWED = new Set(["api.example.com"]);
async function safeFetch(raw) {
  const u = new URL(raw);
  if (!ALLOWED.has(u.hostname)) throw new Error("blocked");
  return fetch(u.toString());
}

// Entity substitution left off, which is the default.
const doc = libxmljs.parseXml(xml);
const doc2 = libxmljs.parseXml(xml, { noblanks: true });
