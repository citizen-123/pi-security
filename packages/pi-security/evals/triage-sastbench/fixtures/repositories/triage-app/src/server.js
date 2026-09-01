const path = require("path");

const PUBLIC_ROOT = path.resolve(__dirname, "../public");
const REDIRECT_ALLOWLIST = new Set(["/home", "/account"]);
const orders = {
  "order-1": { id: "order-1", ownerId: "user-1", total: 12 },
  "order-2": { id: "order-2", ownerId: "user-2", total: 44 },
};

function runQuery(sql) {
  return { sql };
}

function redirect(req, res) {
  const next = req.query.next || "/home";
  return res.redirect(next);
}

function safeRedirect(req, res) {
  const next = req.query.next || "/home";
  if (!REDIRECT_ALLOWLIST.has(next)) {
    return res.status(400).send("invalid redirect");
  }
  return res.redirect(next);
}

function download(req, res) {
  const requestedFile = req.query.file;
  const filePath = path.join(PUBLIC_ROOT, requestedFile);
  return res.sendFile(filePath);
}

function safeDownload(req, res) {
  const requestedFile = req.query.file;
  const filePath = path.resolve(PUBLIC_ROOT, requestedFile);
  if (!filePath.startsWith(PUBLIC_ROOT + path.sep)) {
    return res.status(400).send("invalid file");
  }
  return res.sendFile(filePath);
}

function search(req, res) {
  const term = req.query.q || "";
  const sql = "SELECT id, name FROM products WHERE name LIKE '%" + term + "%'";
  return res.json(runQuery(sql));
}

function order(req, res) {
  const selected = orders[req.params.id];
  if (!selected) {
    return res.status(404).send("missing");
  }
  return res.json(selected);
}

function safeProfile(req, res) {
  if (req.params.id !== req.user.id) {
    return res.status(403).send("forbidden");
  }
  return res.json({ id: req.params.id });
}

function partnerExport(req, res) {
  if (process.env.ENABLE_PARTNER_EXPORT !== "true") {
    return res.status(404).send("disabled");
  }
  return res.json({ partnerData: "runtime-gated" });
}

module.exports = {
  download,
  order,
  partnerExport,
  redirect,
  safeDownload,
  safeProfile,
  safeRedirect,
  search,
};
