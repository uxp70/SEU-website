// SEU auth backend - zero dependencies (Node stdlib only).
// Env: SEU_PASSWORD_HASH (sha256 hex), SEU_SECRET, PORT, ALLOWED_ORIGINS
const http = require("http");
const https = require("https");
const crypto = require("crypto");
const { execFile } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

const PORT = Number(process.env.PORT || 3000);
const PASSWORD_HASH = (process.env.SEU_PASSWORD_HASH || "").trim().toLowerCase();
const SECRET = process.env.SEU_SECRET || "dev-secret-change-me";
const ORIGINS = (process.env.ALLOWED_ORIGINS || "").split(",").map(s => s.trim()).filter(Boolean);

// Site content lives OUTSIDE the repo (Render env SEU_CONTENT_JSON), so the
// public repository contains code only - no text, names, or lists to inspect.
let SITE_CONTENT = null;
try {
  const parsed = JSON.parse(process.env.SEU_CONTENT_JSON || "");
  if (parsed && typeof parsed === "object") SITE_CONTENT = parsed;
} catch { /* fallback below */ }

const DEFAULT_CONTENT = {
  title: "SEU website",
  welcome: "Welcome",
  cards: [{ title: "Status", text: "Content not configured.", lines: ["Backend: online"] }],
  projects: [],
  future: [],
  links: [],
  resources: [],
  featured: []
};

function siteContent() {
  return SITE_CONTENT || DEFAULT_CONTENT;
}

// Login brute-force guard: 15 attempts per 10 minutes per IP.
const loginAttempts = new Map();
function loginAllowed(ip) {
  const now = Date.now();
  const e = loginAttempts.get(ip);
  if (!e || e.reset < now) { loginAttempts.set(ip, { count: 1, reset: now + 10 * 60 * 1000 }); return true; }
  e.count++;
  return e.count <= 15;
}
function clientIp(req) {
  const fwd = (req.headers["x-forwarded-for"] || "").split(",")[0].trim();
  return fwd || (req.socket && req.socket.remoteAddress) || "unknown";
}

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
const FILES_TTL_MS = 60 * 1000;
const FILES_STALE_MS = 10 * 60 * 1000;
let filesCache = { at: 0, data: [] };
let filesFetching = null;

const SEU_REPO_JSON = "https://raw.githubusercontent.com/DatOneFlareon/The-SEU-app-repo-for-the-gangalang/main/SEU.json";
const SEU_REPO_URL = "https://github.com/DatOneFlareon/The-SEU-app-repo-for-the-gangalang";
const SEU_REPO_PREVIEW = "https://raw.githubusercontent.com/DatOneFlareon/The-SEU-app-repo-for-the-gangalang/main/Ipa%20file/IMG_1508.jpeg";

const IPA_SOURCES = [
  { id: "fastsign", name: "Alan's Gigantic Repo", url: "https://fastsign.dev/repo.json" },
  { id: "apptesters", name: "AppTesters IPA Repo", url: "https://repository.apptesters.org" },
  { id: "cypwn", name: "CyPwn IPA Library", url: "https://ipa.cypwn.xyz/cypwn.json" },
  { id: "quantum", name: "Quantum Source", url: "https://quarksources.github.io/quantumsource.json" },
  { id: "sidestore", name: "SideStore Team Picks", url: "https://community-apps.sidestore.io/sidecommunity.json" },
  { id: "wuxu", name: "WuXu's Library", url: "https://wuxu1.github.io/wuxu-complete.json" }
];
const FEED_TTL_MS = 30 * 60 * 1000;
const feedCache = {};
const feedFetching = {};

function normApp(a) {
  const v = (Array.isArray(a.versions) && a.versions[0]) || {};
  return {
    name: a.name, bundleID: a.bundleIdentifier || a.bundleID,
    version: v.version || a.version, subtitle: a.subtitle,
    date: v.date || a.versionDate || null,
    size: v.size || a.size, iconURL: a.iconURL || a.icon,
    downloadURL: v.downloadURL || a.downloadURL
  };
}

async function getFeed(id) {
  const src = IPA_SOURCES.find(s => s.id === id);
  if (!src) throw new Error("bad source");
  const now = Date.now(), c = feedCache[id];
  if (c && c.apps.length && now - c.at < FEED_TTL_MS) return c;
  if (feedFetching[id]) return feedFetching[id];
  feedFetching[id] = (async () => {
    const up = await fetchBig(src.url, 40e6);
    if (up.status !== 200) throw new Error("feed error " + up.status);
    const d = JSON.parse(up.body);
    feedCache[id] = {
      at: Date.now(), name: d.name || src.name,
      apps: (Array.isArray(d.apps) ? d.apps : []).map(normApp).filter(a => a.name && a.downloadURL)
    };
    return feedCache[id];
  })();
  try { return await feedFetching[id]; }
  finally { feedFetching[id] = null; }
}

function allSourceSearch(q) {
  // Searches every cached feed; uncached feeds are skipped (open a source once to warm it).
  const out = [];
  for (const s of IPA_SOURCES) {
    const c = feedCache[s.id];
    if (!c || !c.apps.length) continue;
    for (const a of c.apps) {
      if ((a.name || "").toLowerCase().includes(q) || (a.bundleID || "").toLowerCase().includes(q)) {
        out.push({ ...a, source: c.name });
        if (out.length >= 200) return out;
      }
    }
  }
  return out;
}

async function getAllFeeds() {
  // Sequential: avoids parsing multiple giant feeds at once on small hosts.
  const feeds = [];
  for (const s of IPA_SOURCES) {
    try { feeds.push(await getFeed(s.id)); }
    catch { feeds.push(null); }
  }
  return feeds;
}

function runCmd(cmd, args, opts = {}) {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, { timeout: 600000, maxBuffer: 2e6, ...opts }, (err, stdout, stderr) => {
      if (err) { err.stdout = stdout; err.stderr = stderr; return reject(err); }
      resolve({ stdout, stderr });
    });
  });
}

function downloadFile(url, dest) {
  return new Promise((resolve, reject) => {
    const visit = (u) => {
      const mod = u.startsWith("https:") ? https : http;
      const req = mod.get(u, { timeout: 60000 }, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          res.resume();
          return visit(new URL(res.headers.location, u).toString());
        }
        if (res.statusCode !== 200) {
          res.resume();
          return reject(new Error("download " + res.statusCode));
        }
        const out = fs.createWriteStream(dest);
        res.pipe(out);
        out.on("finish", () => resolve());
        out.on("error", reject);
        res.on("error", reject);
      });
      req.on("timeout", () => { req.destroy(); reject(new Error("download timeout")); });
      req.on("error", reject);
    };
    visit(url);
  });
}

// zsign binary (static linux build), fetched once per instance into tmp.
const ZSIGN_URL = "https://github.com/zhlynn/zsign/releases/download/v1.1.2/zsign-linux-musl-static.tar.gz";
let zsignPath = null, zsignFetching = null;

async function getZsign() {
  if (zsignPath) return zsignPath;
  if (zsignFetching) return zsignFetching;
  zsignFetching = (async () => {
    const dir = path.join(os.tmpdir(), "seu-zsign");
    const bin = path.join(dir, "zsign-musl");
    try { fs.accessSync(bin, fs.constants.X_OK); zsignPath = bin; return bin; }
    catch { /* download below */ }
    fs.mkdirSync(dir, { recursive: true });
    const tgz = path.join(dir, "zsign.tar.gz");
    await downloadFile(ZSIGN_URL, tgz);
    await runCmd("tar", ["-xzf", tgz, "-C", dir]);
    fs.chmodSync(bin, 0o755);
    try { fs.unlinkSync(tgz); } catch {}
    zsignPath = bin;
    return bin;
  })();
  try { return await zsignFetching; }
  finally { zsignFetching = null; }
}

// Minimal streaming multipart parser: file parts go straight to disk.
// Buffered multipart parser (body capped during accumulation).
function parseMultipart(req, saveDir, limits) {
  return new Promise((resolve, reject) => {
    const ctype = req.headers["content-type"] || "";
    const m = ctype.match(/boundary=(?:"([^"]+)"|([^;]+))/)
    if (!m) return reject(Object.assign(new Error("not multipart"), { status: 400 }));
    const boundary = Buffer.from("--" + (m[1] || m[2]).trim());
    const CRLF = Buffer.from("\r\n");
    const chunks = [];
    let total = 0;
    req.on("data", c => {
      total += c.length;
      if (total > ((limits && limits.total) || 450e6)) {
        req.destroy();
        return reject(Object.assign(new Error("upload too large"), { status: 413 }));
      }
      chunks.push(c);
    });
    req.on("error", () => reject(Object.assign(new Error("upload error"), { status: 500 })));
    req.on("end", () => {
      try {
        resolve(splitParts(Buffer.concat(chunks), boundary, CRLF, saveDir, limits || {}));
      } catch (e) {
        reject(Object.assign(new Error(e.message || "bad upload"), { status: e.status || 400 }));
      }
    });
  });
}

function splitParts(body, boundary, CRLF, saveDir, limits) {
  const fields = {};
  const files = {};
  let pos = body.indexOf(boundary, 0);
  if (pos < 0) throw { status: 400, message: "bad upload" };
  pos += boundary.length;
  for (;;) {
    if (pos + 1 >= body.length) throw { status: 400, message: "truncated upload" };
    if (body[pos] === 45 && body[pos + 1] === 45) break; // closing delimiter
    pos += 2; // skip CRLF after boundary
    const hend = body.indexOf("\r\n\r\n", pos);
    if (hend < 0) throw { status: 400, message: "bad part headers" };
    const disp = body.slice(pos, hend).toString("utf8")
      .match(/name="([^"]*)"(?:;\s*filename="([^"]*)")?/);
    const fieldName = disp ? disp[1] : "";
    const fileName = disp && disp[2] ? disp[2] : "";
    pos = hend + 4;
    const next = body.indexOf(boundary, pos);
    if (next < 0) throw { status: 400, message: "truncated upload" };
    let content = body.slice(pos, next);
    if (content.length >= 2 && content[content.length - 2] === 13 && content[content.length - 1] === 10) {
      content = content.slice(0, -2);
    }
    if (fileName) {
      const lim = limits[fieldName] || 5e6;
      if (content.length > lim) throw { status: 413, message: "file too large" };
      const safe = path.basename(fileName).replace(/[^A-Za-z0-9._-]+/g, "_").slice(0, 100) || "upload";
      const filePath = path.join(saveDir, fieldName + "-" + Date.now() + "-" + safe);
      fs.writeFileSync(filePath, content);
      files[fieldName] = { path: filePath, name: fileName, size: content.length };
    } else {
      if (content.length > 1e6) throw { status: 400, message: "field too large" };
      fields[fieldName] = content.toString("utf8");
    }
    pos = next + boundary.length;
  }
  return { fields, files };
}
function fetchBig(url, maxBytes) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { timeout: 60000 }, (res) => {
      let data = "";
      res.on("data", c => {
        data += c;
        if (data.length > maxBytes) { req.destroy(); reject(new Error("feed too large")); }
      });
      res.on("end", () => resolve({ status: res.statusCode || 0, body: data }));
    });
    req.on("timeout", () => { req.destroy(); reject(new Error("feed timeout")); });
    req.on("error", reject);
  });
}

async function getIpaFeed() {
  return getFeed("fastsign");
}

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
  for (const [ip, e] of loginAttempts) if (e.reset < now) loginAttempts.delete(ip);
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

function statusLines() {
  const lines = ["Backend: online"];
  let total = 0, n = 0;
  for (const s of IPA_SOURCES) {
    const c = feedCache[s.id];
    if (c && c.apps.length) { n++; total += c.apps.length; }
  }
  lines.push(n
    ? `Libraries: ${n}/${IPA_SOURCES.length} loaded (${total.toLocaleString("en-US")} apps indexed)`
    : "Libraries: warming up - open the IPAs tab");
  if (filesCache.data.length) {
    lines.push(`Files: ${filesCache.data.length} stored (${filesCache.data.filter(f => f.big).length} big)`);
  } else {
    lines.push("Files: storage connected");
  }
  lines.push("Session: 12h, all sections gated");
  return lines;
}

function homePayload() {
  const c = siteContent();
  return {
    ok: true,
    title: c.title || "SEU website",
    welcome: c.welcome || "Welcome",
    cards: (c.cards && c.cards.length ? c.cards : DEFAULT_CONTENT.cards).map(card =>
      card.title === "Status" && !card.lines ? { ...card, lines: statusLines() } : card),
    projects: c.projects || [],
    future: c.future || [],
    links: c.links || [],
    resources: c.resources || []
  };
}

const server = http.createServer(async (req, res) => {
  cors(req, res);
  if (req.method === "OPTIONS") { res.writeHead(204); return res.end(); }
  const url = new URL(req.url, "http://localhost");

  if (req.method === "POST" && url.pathname === "/api/login") {
    let password = "";
    try { password = JSON.parse(await readBody(req)).password || ""; }
    catch { return send(res, 400, { ok: false, error: "bad json" }); }
    if (!loginAllowed(clientIp(req))) {
      return send(res, 429, { ok: false, error: "too many attempts" });
    }
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
    return send(res, 200, homePayload());
  }

  if (req.method === "GET" && url.pathname === "/api/health") {
    return send(res, 200, { ok: true });
  }

  // Raw file storage listing (uxp70/raw-file-website uploads folder). Gated.
  // Cached server-side: GitHub's anonymous API allows 60 req/hr per IP and
  // Render shares egress IPs, so never hit GitHub more than once a minute.
  async function getFiles() {
    const now = Date.now();
    if (filesCache.data.length && now - filesCache.at < FILES_TTL_MS) return filesCache.data;
    if (filesFetching) return filesFetching;
    filesFetching = (async () => {
      // Preferred: prebuilt public list (no GitHub API, no rate limits).
      try {
        const lr = await fetchUpstream(`https://raw.githubusercontent.com/${RFW_OWNER}/${RFW_REPO}/${RFW_BRANCH}/uploads/list.json?ts=${Date.now()}`);
        if (lr.status === 200) {
          const parsed = JSON.parse(lr.body);
          if (Array.isArray(parsed)) {
            filesCache = { at: Date.now(), data: parsed };
            return parsed;
          }
        }
      } catch { /* fall back to API listing below */ }
      const up = await fetchGitHub(`/repos/${RFW_OWNER}/${RFW_REPO}/contents/uploads?ref=${encodeURIComponent(RFW_BRANCH)}`);
      if (up.status !== 200) throw new Error("github " + up.status);
      const items = JSON.parse(up.body);
      const list = Array.isArray(items) ? items : [];
      let index = {};
      try {
        const ix = await fetchUpstream(`https://raw.githubusercontent.com/${RFW_OWNER}/${RFW_REPO}/${RFW_BRANCH}/uploads/files-index.json?ts=${Date.now()}`);
        if (ix.status === 200) index = JSON.parse(ix.body);
      } catch { /* index optional: big files show as cooking */ }
      const files = [];
      for (const x of list) {
        if (x.type !== "file" || /\.part\d+$/.test(x.name) || x.name === "files-index.json" || x.name === ".gitkeep") continue;
        if (x.name.endsWith(".manifest.json")) {
          let original = x.name, size = x.size;
          try {
            const m = JSON.parse((await fetchUpstream(x.download_url + `?ts=${Date.now()}`)).body);
            if (m && m.type === "bigfile") { original = m.original || original; size = m.size || size; }
          } catch { /* keep manifest defaults */ }
          const hit = index[x.path] || {};
          files.push({ name: original, size, raw: hit.url || null, path: x.path, big: true });
        } else {
          files.push({ name: x.name, size: x.size, raw: x.download_url, path: x.path });
        }
      }
      filesCache = { at: Date.now(), data: files };
      return files;
    })();
    try { return await filesFetching; }
    catch (e) {
      if (filesCache.data.length && Date.now() - filesCache.at < FILES_STALE_MS) return filesCache.data;
      throw e;
    }
    finally { filesFetching = null; }
  }

  if (req.method === "GET" && url.pathname === "/api/files") {
    if (!validSession(parseCookies(req).seu_session)) {
      return send(res, 401, { ok: false, error: "unauthorized" });
    }
    try {
      const files = await getFiles();
      res.writeHead(200, { "Content-Type": "application/json", "Cache-Control": "no-store" });
      return res.end(JSON.stringify(files));
    } catch {
      return send(res, 502, { ok: false, error: "storage unreachable" });
    }
  }

  // IPA library search (cached upstream AltStore sources). Gated.
  if (req.method === "GET" && url.pathname === "/api/ipas") {
    if (!validSession(parseCookies(req).seu_session)) {
      return send(res, 401, { ok: false, error: "unauthorized" });
    }
    const source = url.searchParams.get("source") || "fastsign";
    const q = (url.searchParams.get("q") || "").trim().toLowerCase();
    if (q.length < 2) return send(res, 400, { ok: false, error: "query too short" });
    const page = Math.max(0, parseInt(url.searchParams.get("page") || "0", 10) || 0);
    const limit = Math.min(50, Math.max(1, parseInt(url.searchParams.get("limit") || "25", 10) || 25));
    try {
      let hits, label;
      if (source === "all") {
        if (!IPA_SOURCES.some(s => feedCache[s.id] && feedCache[s.id].apps.length)) {
          await getAllFeeds();
        }
        hits = allSourceSearch(q);
        label = "All repos";
      } else {
        const feed = await getFeed(source);
        hits = feed.apps.filter(a =>
          (a.name || "").toLowerCase().includes(q) || (a.bundleID || "").toLowerCase().includes(q));
        label = feed.name;
      }
      res.writeHead(200, { "Content-Type": "application/json", "Cache-Control": "no-store" });
      return res.end(JSON.stringify({
        ok: true, source: label, updatedAt: Date.now(), total: hits.length, page,
        apps: hits.slice(page * limit, page * limit + limit)
      }));
    } catch {
      return send(res, 502, { ok: false, error: "ipa feed unreachable" });
    }
  }

  // Source list with cached app counts. Gated.
  if (req.method === "GET" && url.pathname === "/api/sources") {
    if (!validSession(parseCookies(req).seu_session)) {
      return send(res, 401, { ok: false, error: "unauthorized" });
    }
    return send(res, 200, IPA_SOURCES.map(s => ({
      id: s.id, name: (feedCache[s.id] && feedCache[s.id].name) || s.name,
      appCount: (feedCache[s.id] && feedCache[s.id].apps.length) || null,
      updatedAt: (feedCache[s.id] && feedCache[s.id].at) || null
    })));
  }

  // Recently added across all sources, newest first. Gated.
  if (req.method === "GET" && url.pathname === "/api/recent") {
    if (!validSession(parseCookies(req).seu_session)) {
      return send(res, 401, { ok: false, error: "unauthorized" });
    }
    const page = Math.max(0, parseInt(url.searchParams.get("page") || "0", 10) || 0);
    const limit = Math.min(50, Math.max(1, parseInt(url.searchParams.get("limit") || "25", 10) || 25));
    try {
      const feeds = await getAllFeeds();
      const all = [];
      for (let i = 0; i < feeds.length; i++) {
        if (!feeds[i]) continue;
        for (const a of feeds[i].apps) {
          const t = a.date ? Date.parse(a.date) : NaN;
          if (!isNaN(t)) all.push({ ...a, dateMs: t, source: feeds[i].name });
        }
      }
      all.sort((x, y) => y.dateMs - x.dateMs);
      res.writeHead(200, { "Content-Type": "application/json", "Cache-Control": "no-store" });
      return res.end(JSON.stringify({
        ok: true, total: all.length, page,
        apps: all.slice(page * limit, page * limit + limit)
      }));
    } catch {
      return send(res, 502, { ok: false, error: "ipa feed unreachable" });
    }
  }

  // Featured apps resolved live from the sources. Gated.
  if (req.method === "GET" && url.pathname === "/api/featured") {
    if (!validSession(parseCookies(req).seu_session)) {
      return send(res, 401, { ok: false, error: "unauthorized" });
    }
    try {
      const feeds = await getAllFeeds();
      const out = [];
      const wanted = (siteContent().featured && siteContent().featured.length)
        ? siteContent().featured
        : [];
      for (const name of wanted) {
        const want = name.toLowerCase();
        for (const f of feeds) {
          if (!f) continue;
          const hit = f.apps.find(a => (a.name || "").toLowerCase() === want);
          if (hit) { out.push({ ...hit, source: f.name }); break; }
        }
      }
      return send(res, 200, out);
    } catch {
      return send(res, 502, { ok: false, error: "ipa feed unreachable" });
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

  // Signing health: is zsign ready? Gated.
  if (req.method === "GET" && url.pathname === "/api/sign-health") {
    if (!validSession(parseCookies(req).seu_session)) {
      return send(res, 401, { ok: false, error: "unauthorized" });
    }
    try {
      const bin = await getZsign();
      const out = await runCmd(bin, []).catch(e => e);
      const text = ((out.stdout || "") + "\n" + (out.stderr || "")).split("\n").slice(0, 3).join(" ").slice(0, 200);
      return send(res, 200, { ok: true, zsign: text.trim() || "ready" });
    } catch (e) {
      return send(res, 502, { ok: false, error: "signer unavailable" });
    }
  }

  // IPA signing (zsign). Gated. Files are temp-only and deleted after.
  // Multipart fields: password, bundleId, appName, certSource ("upload" or
  // "sideload:<id>"). Files: ipa (required), p12 + mobileprovision (upload mode).
  if (req.method === "POST" && url.pathname === "/api/sign") {
    if (!validSession(parseCookies(req).seu_session)) {
      return send(res, 401, { ok: false, error: "unauthorized" });
    }
    const workDir = fs.mkdtempSync(path.join(os.tmpdir(), "seu-sign-"));
    const cleanup = () => fs.rm(workDir, { recursive: true, force: true }, () => {});
    try {
      const { fields, files } = await parseMultipart(req, workDir, {
        total: 450e6, ipa: 400e6, p12: 5e6, mobileprovision: 5e6
      }).catch(e => { throw { status: e.status || 400, message: e.message }; });

      if (!files.ipa || !files.ipa.size) throw { status: 400, message: "ipa file required" };
      const bundleId = (fields.bundleId || "").trim().slice(0, 120);
      const appName = (fields.appName || "").trim().slice(0, 120);
      const certSource = (fields.certSource || "upload").trim();

      let p12Path, provPath, p12Password = "";
      if (certSource.startsWith("sideload:")) {
        const certId = certSource.split(":")[1];
        if (!/^\d+$/.test(certId || "")) throw { status: 400, message: "bad cert choice" };
        const dl = "https://sideloading.net/api/certificates/download/" + certId;
        p12Path = path.join(workDir, "cert.p12");
        provPath = path.join(workDir, "cert.mobileprovision");
        await downloadFile(dl + "/cert.p12", p12Path).catch(() => {
          throw { status: 400, message: "chosen cert has no p12 (try another)" };
        });
        await downloadFile(dl + "/cert.mobileprovision", provPath).catch(() => {
          throw { status: 502, message: "could not fetch provision file" };
        });
        try {
          const pw = await fetchUpstream(dl + "/password");
          p12Password = pw.status === 200 ? pw.body.trim().slice(0, 200) : "";
        } catch { p12Password = ""; }
      } else {
        if (!files.p12 || !files.p12.size) throw { status: 400, message: "p12 file required" };
        if (!files.mobileprovision || !files.mobileprovision.size) {
          throw { status: 400, message: "mobileprovision file required" };
        }
        p12Path = files.p12.path;
        provPath = files.mobileprovision.path;
        p12Password = (fields.password || "").slice(0, 200);
      }

      const bin = await getZsign().catch(() => {
        throw { status: 502, message: "signer unavailable, try again" };
      });
      const outName = "signed-" + (files.ipa.name || "app.ipa").replace(/\.ipa$/i, "") + ".ipa";
      const outPath = path.join(workDir, outName);
      const args = ["-k", p12Path];
      if (p12Password) args.push("-p", p12Password);
      args.push("-m", provPath, "-o", outPath, "-z", "9");
      if (bundleId) args.push("-b", bundleId);
      if (appName) args.push("-n", appName);
      args.push(files.ipa.path);
      try {
        await runCmd(bin, args);
      } catch (e) {
        const detail = String((e.stderr || e.stdout || e.message || "")).split("\n").slice(0, 4).join(" ").slice(0, 300);
        throw { status: 502, message: "signing failed" + (detail ? ": " + detail : "") };
      }

      const st = fs.statSync(outPath);
      res.writeHead(200, {
        "Content-Type": "application/octet-stream",
        "Content-Length": st.size,
        "Content-Disposition": `attachment; filename="${outName.replace(/"/g, "")}"`
      });
      fs.createReadStream(outPath).on("close", cleanup).on("error", cleanup).pipe(res);
    } catch (e) {
      cleanup();
      const status = (e && e.status) || 500;
      return send(res, status, { ok: false, error: (e && e.message) || "sign failed" });
    }
    return;
  }

  return send(res, 404, { ok: false, error: "not found" });
});

server.listen(PORT, () => console.log(`seu-backend listening on :${PORT}`));
