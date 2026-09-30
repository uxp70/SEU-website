// SEU auth backend - zero dependencies (Node stdlib only).
// Env: SEU_PASSWORD_HASH (sha256 hex), SEU_SECRET, PORT, ALLOWED_ORIGINS
const http = require("http");
const https = require("https");
const crypto = require("crypto");

const PORT = Number(process.env.PORT || 3000);
const PASSWORD_HASH = (process.env.SEU_PASSWORD_HASH || "").trim().toLowerCase();
const SECRET = process.env.SEU_SECRET || "dev-secret-change-me";
const ORIGINS = (process.env.ALLOWED_ORIGINS || "").split(",").map(s => s.trim()).filter(Boolean);

// In-memory sessions: token -> expiry timestamp. Single-instance only.
const sessions = new Map();
const SESSION_TTL_MS = 12 * 60 * 60 * 1000;

if (!PASSWORD_HASH) console.warn("WARN: SEU_PASSWORD_HASH is not set - all logins will fail.");

function send(res, status, obj, headers = {}) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { "Content-Type": "application/json", ...headers });
  res.end(body);
}

function parseCookies(req) {
  const out = {};
  const header = req.headers.cookie || "";
  for (const part of header.split(";")) {
    const i = part.indexOf("=");
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", c => { data += c; if (data.length > 1e6) req.destroy(); });
    req.on("end", () => resolve(data));
    req.on("error", reject);
  });
}

function sha256Hex(text) {
  return crypto.createHash("sha256").update(text, "utf8").digest("hex");
}

function timingSafeEqualHex(a, b) {
  try {
    const ba = Buffer.from(a, "hex");
    const bb = Buffer.from(b, "hex");
    return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
  } catch { return false; }
}

function newSession() {
  const token = crypto.randomBytes(32).toString("hex");
  sessions.set(token, Date.now() + SESSION_TTL_MS);
  return token;
}

function sessionCookie(token, req) {
  // Production (Render) terminates TLS: cross-site frontend needs SameSite=None; Secure.
  // Local http dev keeps Lax.
  const secure = req.headers["x-forwarded-proto"] === "https";
  const maxAge = token ? 43200 : 0;
  const attrs = `HttpOnly; Path=/; Max-Age=${maxAge}; ${secure ? "SameSite=None; Secure" : "SameSite=Lax"}`;
  return token ? `seu_session=${token}; ${attrs}` : `seu_session=; ${attrs}`;
}

function fetchUpstream(url) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { timeout: 20000 }, (res) => {
      let data = "";
      res.on("data", c => { data += c; if (data.length > 5e6) req.destroy(); });
      res.on("end", () => resolve({ status: res.statusCode || 0, body: data }));
    });
    req.on("timeout", () => { req.destroy(); reject(new Error("upstream timeout")); });
    req.on("error", reject);
  });
}

const RFW_OWNER = process.env.RFW_OWNER || "uxp70";
const RFW_REPO = process.env.RFW_REPO || "raw-file-website";
const RFW_BRANCH = process.env.RFW_BRANCH || "main";

const SEU_REPO_JSON = "https://raw.githubusercontent.com/DatOneFlareon/The-SEU-app-repo-for-the-gangalang/main/SEU.json";
const SEU_REPO_URL = "https://github.com/DatOneFlareon/The-SEU-app-repo-for-the-gangalang";
const SEU_REPO_PREVIEW = "https://raw.githubusercontent.com/DatOneFlareon/The-SEU-app-repo-for-the-gangalang/main/Ipa%20file/IMG_1508.jpeg";

function fetchGitHub(path) {
  return new Promise((resolve, reject) => {
    const headers = { "User-Agent": "seu-backend", "Accept": "application/vnd.github+json" };
    if (process.env.SEU_GITHUB_TOKEN) headers.Authorization = "Bearer " + process.env.SEU_GITHUB_TOKEN;
    const req = https.get("https://api.github.com" + path, { timeout: 15000, headers }, (res) => {
      let data = "";
      res.on("data", c => { data += c; if (data.length > 5e6) req.destroy(); });
      res.on("end", () => resolve({ status: res.statusCode || 0, body: data }));
    });
    req.on("timeout", () => { req.destroy(); reject(new Error("github timeout")); });
    req.on("error", reject);
  });
}

function validSession(token) {
  if (!token) return false;
  const exp = sessions.get(token);
  if (!exp) return false;
  if (exp < Date.now()) { sessions.delete(token); return false; }
  return true;
}

setInterval(() => {
  const now = Date.now();
  for (const [t, exp] of sessions) if (exp < now) sessions.delete(t);
}, 15 * 60 * 1000).unref();

function cors(req, res) {
  const origin = req.headers.origin;
  if (origin && (ORIGINS.length === 0 || ORIGINS.includes(origin))) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Credentials", "true");
    res.setHeader("Vary", "Origin");
  }
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
}

const server = http.createServer(async (req, res) => {
  cors(req, res);
  if (req.method === "OPTIONS") { res.writeHead(204); return res.end(); }
  const url = new URL(req.url, "http://localhost");

  if (req.method === "POST" && url.pathname === "/api/login") {
    let password = "";
    try { password = JSON.parse(await readBody(req)).password || ""; }
    catch { return send(res, 400, { ok: false, error: "bad json" }); }
    if (PASSWORD_HASH && timingSafeEqualHex(sha256Hex(password), PASSWORD_HASH)) {
      const token = newSession();
      return send(res, 200, { ok: true }, { "Set-Cookie": sessionCookie(token, req) });
    }
    return send(res, 401, { ok: false, error: "wrong password" });
  }

  if (req.method === "GET" && url.pathname === "/api/me") {
    const ok = validSession(parseCookies(req).seu_session);
    return send(res, 200, { ok });
  }

  if (req.method === "POST" && url.pathname === "/api/logout") {
    const t = parseCookies(req).seu_session;
    if (t) sessions.delete(t);
    res.setHeader("Set-Cookie", sessionCookie(null, req));
    return send(res, 200, { ok: true });
  }

  // Gated site content: only returned with a valid session.
  // Nothing protected lives in the frontend HTML/JS - inspect shows an empty shell.
  if (req.method === "GET" && url.pathname === "/api/home") {
    if (!validSession(parseCookies(req).seu_session)) {
      return send(res, 401, { ok: false, error: "unauthorized" });
    }
    return send(res, 200, {
      ok: true,
      title: "SEU website",
      welcome: "Welcome to HQ",
      cards: [
        { title: "Certificates", text: "Browse and download signing certs.", goto: "certs" },
        { title: "Raw File Storage", text: "Files you upload, with raw links.", goto: "files" },
        { title: "Projects", text: "SEU builds and experiments.", goto: "projects" },
        { title: "Status", text: "All systems normal." }
      ],
      projects: [
        { title: "SEU website", text: "This site - password-gated HQ homescreen." },
        { title: "Project two", text: "Describe your next build here." },
        { title: "Project three", text: "Describe another build here." }
      ],
      links: [
        { title: "GitHub - uxp70", url: "https://github.com/uxp70" },
        { title: "Site repo", url: "https://github.com/uxp70/SEU-website" }
      ],
      resources: [
        { title: "GitHub Pages docs", url: "https://docs.github.com/en/pages" },
        { title: "Render docs", url: "https://render.com/docs" }
      ]
    });
  }

  if (req.method === "GET" && url.pathname === "/api/health") {
    return send(res, 200, { ok: true });
  }

  // Raw file storage listing (uxp70/raw-file-website uploads folder). Gated.
  if (req.method === "GET" && url.pathname === "/api/files") {
    if (!validSession(parseCookies(req).seu_session)) {
      return send(res, 401, { ok: false, error: "unauthorized" });
    }
    try {
      const up = await fetchGitHub(`/repos/${RFW_OWNER}/${RFW_REPO}/contents/uploads?ref=${encodeURIComponent(RFW_BRANCH)}`);
      if (up.status !== 200) return send(res, 502, { ok: false, error: "storage unreachable" });
      const items = JSON.parse(up.body);
      const files = (Array.isArray(items) ? items : [])
        .filter(x => x.type === "file" && !/\.part\d+$/.test(x.name) && x.name !== "files-index.json" && !x.name.endsWith(".manifest.json"))
        .map(x => ({ name: x.name, size: x.size, raw: x.download_url, path: x.path }));
      res.writeHead(200, { "Content-Type": "application/json", "Cache-Control": "no-store" });
      return res.end(JSON.stringify(files));
    } catch {
      return send(res, 502, { ok: false, error: "storage unreachable" });
    }
  }

  // SEU app repository summary (AltStore source). Gated: requires a valid session.
  if (req.method === "GET" && url.pathname === "/api/repo") {
    if (!validSession(parseCookies(req).seu_session)) {
      return send(res, 401, { ok: false, error: "unauthorized" });
    }
    try {
      const up = await fetchUpstream(SEU_REPO_JSON);
      if (up.status !== 200) return send(res, 502, { ok: false, error: "repo unreachable" });
      const src = JSON.parse(up.body);
      const apps = (Array.isArray(src.apps) ? src.apps : []).map(a => ({
        name: a.name, subtitle: a.subtitle, version: a.version,
        iconURL: a.iconURL, size: a.size, downloadURL: a.downloadURL
      }));
      const news = (Array.isArray(src.news) ? src.news : []).map(n => ({
        title: n.title, caption: n.caption, date: n.date, url: n.url, imageURL: n.imageURL
      }));
      return send(res, 200, {
        ok: true,
        name: src.name, description: src.description, subtitle: src.subtitle,
        iconURL: src.iconURL, tintColor: src.tintColor,
        repoUrl: SEU_REPO_URL, rawJsonUrl: SEU_REPO_JSON, previewImage: SEU_REPO_PREVIEW,
        appCount: apps.length, apps, news
      });
    } catch {
      return send(res, 502, { ok: false, error: "repo unreachable" });
    }
  }

  // Cert list proxy (sideloading.net NexCerts). Gated: requires a valid session.
  if (req.method === "GET" && url.pathname === "/api/certs") {
    if (!validSession(parseCookies(req).seu_session)) {
      return send(res, 401, { ok: false, error: "unauthorized" });
    }
    const filter = url.searchParams.get("status") || "signed";
    if (!["all", "signed", "revoked", "missingP12"].includes(filter)) {
      return send(res, 400, { ok: false, error: "bad status" });
    }
    const amount = Math.min(200, Math.max(1, parseInt(url.searchParams.get("amount") || "50", 10) || 50));
    try {
      const up = await fetchUpstream(`https://sideloading.net/api/certificates/list/${filter}/${amount}`);
      if (up.status !== 200) return send(res, 502, { ok: false, error: "cert provider error" });
      JSON.parse(up.body); // validate JSON before relaying
      res.writeHead(200, { "Content-Type": "application/json" });
      return res.end(up.body);
    } catch {
      return send(res, 502, { ok: false, error: "cert provider unreachable" });
    }
  }

  return send(res, 404, { ok: false, error: "not found" });
});

server.listen(PORT, () => console.log(`seu-backend listening on :${PORT}`));
