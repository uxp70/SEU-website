// SEU auth backend - zero dependencies (Node stdlib only).
// Env: SEU_PASSWORD_HASH (sha256 hex), SEU_SECRET, PORT, ALLOWED_ORIGINS
const http = require("http");
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
        { title: "Projects", text: "SEU builds and experiments live here." },
        { title: "Links", text: "Add quick links here next." },
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

  return send(res, 404, { ok: false, error: "not found" });
});

server.listen(PORT, () => console.log(`seu-backend listening on :${PORT}`));
