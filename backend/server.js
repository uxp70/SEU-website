// SEU auth backend - zero dependencies (Node stdlib only).
// Env: SEU_PASSWORD_HASH (sha256 hex), SEU_SECRET, PORT, ALLOWED_ORIGINS
const http = require("http");
const https = require("https");
const crypto = require("crypto");
const { execFile } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");
const zlib = require("zlib");

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

// Stateless IP-bound sessions: HMAC-signed tokens, no server storage.
// Anyone with the password gets one; it survives restarts/redeploys and
// only works from the IP that logged in (auto-rejoin for 12h).
const SESSION_TTL_MS = 12 * 60 * 60 * 1000;

function signSession(expHex, ip) {
  return crypto.createHmac("sha256", SECRET).update(expHex + "." + ip, "utf8").digest("hex");
}

function newSession(ip) {
  const expHex = (Date.now() + SESSION_TTL_MS).toString(16);
  return expHex + "." + signSession(expHex, ip);
}

function validSession(token, ip) {
  if (!token || typeof token !== "string") return false;
  const parts = token.split(".");
  if (parts.length !== 2 || !/^[a-f0-9]+$/.test(parts[0]) || !/^[a-f0-9]{64}$/.test(parts[1])) {
    return false;
  }
  const exp = parseInt(parts[0], 16);
  if (!exp || exp < Date.now()) return false;
  try {
    const a = Buffer.from(parts[1], "hex");
    const b = Buffer.from(signSession(parts[0], ip), "hex");
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return false;
  } catch { return false; }
  if (loggedOut.has(token)) return false;
  return true;
}

// Tokens explicitly logged out before expiry. Small by design.
const loggedOut = new Map();

if (!PASSWORD_HASH) console.warn("WARN: SEU_PASSWORD_HASH is not set - all logins will fail.");
if (!process.env.SEU_SECRET) console.warn("WARN: SEU_SECRET is not set - sessions use an insecure default.");

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

// Minimal zip surgery (stdlib only): replace an IPA's app icons with new
// image bytes. Rebuilds local headers + central directory; preserves the
// entry order. Throws if the file is not a usable zip.
function crc32(buf) {
  let table = crc32.table;
  if (!table) {
    table = crc32.table = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
      table[n] = c >>> 0;
    }
  }
  let crc = 0xFFFFFFFF;
  for (let i = 0; i < buf.length; i++) crc = table[(crc ^ buf[i]) & 0xFF] ^ (crc >>> 8);
  return (crc ^ 0xFFFFFFFF) >>> 0;
}

function parseZipEntries(buf) {
  // locate end of central directory
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 22 - 65557); i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error("not a zip");
  const count = buf.readUInt16LE(eocd + 10);
  let off = buf.readUInt32LE(eocd + 16);
  const entries = [];
  for (let i = 0; i < count; i++) {
    if (buf.readUInt32LE(off) !== 0x02014b50) throw new Error("bad central directory");
    const method = buf.readUInt16LE(off + 10);
    const crc = buf.readUInt32LE(off + 16);
    const compSize = buf.readUInt32LE(off + 20);
    const uncompSize = buf.readUInt32LE(off + 24);
    const nameLen = buf.readUInt16LE(off + 28);
    const extraLen = buf.readUInt16LE(off + 30);
    const commentLen = buf.readUInt16LE(off + 32);
    const localOff = buf.readUInt32LE(off + 42);
    const name = buf.slice(off + 46, off + 46 + nameLen).toString("utf8");
    entries.push({ method, crc, compSize, uncompSize, localOff, name });
    off += 46 + nameLen + extraLen + commentLen;
  }
  return entries;
}

function replaceZipIcons(ipaPath, iconBytes) {
  const buf = fs.readFileSync(ipaPath);
  const entries = parseZipEntries(buf);
  const targets = entries.filter(e =>
    /\.app\/([^/]*)(AppIcon|Icon[^/]*)\.png$/i.test(e.name));
  if (!targets.length) throw new Error("no replaceable app icons found in this IPA");
  const deflated = zlib.deflateRawSync(iconBytes, { level: 9 });
  const crc = crc32(iconBytes);
  const out = [];
  let pos = 0;
  const newOffsets = new Map();
  const nameBuf = (s) => Buffer.from(s, "utf8");
  for (const e of entries) {
    const nb = nameBuf(e.name);
    const isTarget = targets.includes(e);
    const data = isTarget ? deflated : null;
    const rawData = isTarget ? null : (() => {
      const lh = buf.readUInt32LE(e.localOff);
      if (lh !== 0x04034b50) throw new Error("bad local header");
      const nl = buf.readUInt16LE(e.localOff + 26);
      const el = buf.readUInt16LE(e.localOff + 28);
      const lc = buf.readUInt32LE(e.localOff + 18);
      const start = e.localOff + 30 + nl + el;
      return buf.slice(start, start + (lc || e.compSize));
    })();
    const payload = isTarget ? data : rawData;
    const useCrc = isTarget ? crc : e.crc;
    const useUncomp = isTarget ? iconBytes.length : e.uncompSize;
    const lh = Buffer.alloc(30 + nb.length);
    lh.writeUInt32LE(0x04034b50, 0);
    lh.writeUInt16LE(20, 4);
    lh.writeUInt16LE(0x0800, 6);
    lh.writeUInt16LE(isTarget ? 8 : e.method, 8);
    lh.writeUInt32LE(0, 10);
    lh.writeUInt32LE(useCrc, 14);
    lh.writeUInt32LE(payload.length, 18);
    lh.writeUInt32LE(useUncomp, 22);
    lh.writeUInt16LE(nb.length, 26);
    lh.writeUInt16LE(0, 28);
    nb.copy(lh, 30);
    newOffsets.set(e, pos);
    out.push(lh, payload);
    pos += lh.length + payload.length;
  }
  const cdStart = pos;
  const cdParts = [];
  for (const e of entries) {
    const nb = nameBuf(e.name);
    const isTarget = targets.includes(e);
    const ch = Buffer.alloc(46 + nb.length);
    ch.writeUInt32LE(0x02014b50, 0);
    ch.writeUInt16LE(20, 4);
    ch.writeUInt16LE(20, 6);
    ch.writeUInt16LE(0x0800, 8);
    ch.writeUInt16LE(isTarget ? 8 : e.method, 10);
    ch.writeUInt32LE(0, 12);
    ch.writeUInt32LE(isTarget ? crc : e.crc, 16);
    ch.writeUInt32LE(isTarget ? deflated.length : e.compSize, 20);
    ch.writeUInt32LE(isTarget ? iconBytes.length : e.uncompSize, 24);
    ch.writeUInt16LE(nb.length, 28);
    ch.writeUInt16LE(0, 30);
    ch.writeUInt16LE(0, 32);
    ch.writeUInt16LE(0, 34);
    ch.writeUInt16LE(0, 36);
    ch.writeUInt32LE(0, 38);
    ch.writeUInt32LE(newOffsets.get(e), 42);
    nb.copy(ch, 46);
    cdParts.push(ch);
    pos += ch.length;
  }
  const cd = Buffer.concat(cdParts);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(cd.length, 12);
  end.writeUInt32LE(cdStart, 16);
  fs.writeFileSync(ipaPath, Buffer.concat([...out, cd, end]));
  return targets.length;
}

function parseBplist(buf) {
  if (buf.slice(0, 8).toString() !== "bplist00") throw new Error("not bplist");
  const topObject = Number(buf.readBigUInt64BE(buf.length - 32 + 16));
  const offTableOff = Number(buf.readBigUInt64BE(buf.length - 32 + 24));
  const offSize = buf[buf.length - 32 + 6];
  const refSize = buf[buf.length - 32 + 7];
  function offset(i) {
    if (offSize === 1) return buf[offTableOff + i];
    if (offSize === 2) return buf.readUInt16BE(offTableOff + i * 2);
    if (offSize === 4) return buf.readUInt32BE(offTableOff + i * 4);
    return Number(buf.readBigUInt64BE(offTableOff + i * 8));
  }
  function ref(b, i) {
    if (refSize === 1) return b[i];
    if (refSize === 2) return b.readUInt16BE(i * 2);
    if (refSize === 4) return b.readUInt32BE(i * 4);
    return Number(b.readBigUInt64BE(i * 8));
  }
  function readInt(b) {
    if (b.length === 1) return b[0];
    if (b.length === 2) return b.readUInt16BE(0);
    if (b.length === 4) return b.readUInt32BE(0);
    return Number(b.readBigUInt64BE(0));
  }
  function val(idx) {
    const o = offset(idx);
    const marker = buf[o];
    const type = marker >> 4, info = marker & 0x0F;
    const count = () => {
      if (info !== 0xF) return info;
      const nb = 1 << (buf[o + 1] & 0x0F);
      return readInt(buf.slice(o + 2, o + 2 + nb));
    };
    const h = () => o + 1 + (info === 0xF ? 1 + (1 << (buf[o + 1] & 0x0F)) : 0);
    switch (type) {
      case 0x0:
        if (info === 0x8) return false;
        if (info === 0x9) return true;
        return null;
      case 0x1: return readInt(buf.slice(o + 1, o + 1 + (1 << info)));
      case 0x2: return buf.readDoubleBE(o + 1);
      case 0x3: return new Date((978307200 + buf.readDoubleBE(o + 1)) * 1000);
      case 0x4: return buf.slice(h(), h() + count());
      case 0x5: return buf.slice(h(), h() + count()).toString("utf8");
      case 0x6: {
        const n = count(), s = buf.slice(h(), h() + n * 2);
        let out = "";
        for (let i = 0; i < n; i++) out += String.fromCharCode(s.readUInt16BE(i * 2));
        return out;
      }
      case 0x8: return ref(buf.slice(h(), h() + count() * refSize), 0);
      case 0xA: {
        const n = count(), hb = h(), out = [];
        for (let i = 0; i < n; i++) out.push(val(ref(buf.slice(hb, hb + n * refSize), i)));
        return out;
      }
      case 0xD: {
        const n = count(), hb = h(), out = {};
        for (let i = 0; i < n; i++) {
          out[val(ref(buf.slice(hb, hb + n * refSize), i))] =
            val(ref(buf.slice(hb + n * refSize, hb + 2 * n * refSize), i));
        }
        return out;
      }
      default: return null;
    }
  }
  return val(topObject);
}

function parsePlistMeta(buf) {
  if (buf.slice(0, 6).toString() === "bplist") {
    const d = parseBplist(buf) || {};
    return {
      bundleId: d.CFBundleIdentifier || null,
      version: d.CFBundleShortVersionString || d.CFBundleVersion || null,
      name: d.CFBundleDisplayName || d.CFBundleName || null
    };
  }
  const text = buf.toString("utf8");
  const get = (key) => {
    const m = text.match(new RegExp("<key>" + key + "</key>\\s*<string>([^<]*)</string>"));
    return m ? m[1] : null;
  };
  return {
    bundleId: get("CFBundleIdentifier"),
    version: get("CFBundleShortVersionString") || get("CFBundleVersion"),
    name: get("CFBundleDisplayName") || get("CFBundleName")
  };
}

// Read one zip entry's bytes (stored or deflated) by name pattern.
function readZipEntry(ipaPath, pattern) {
  const buf = fs.readFileSync(ipaPath);
  const entries = parseZipEntries(buf);
  const e = entries.find(x => pattern.test(x.name));
  if (!e) return null;
  const nl = buf.readUInt16LE(e.localOff + 26);
  const el = buf.readUInt16LE(e.localOff + 28);
  const lc = buf.readUInt32LE(e.localOff + 18);
  const start = e.localOff + 30 + nl + el;
  const raw = buf.slice(start, start + (lc || e.compSize));
  if (e.method === 0) return raw;
  if (e.method === 8) return zlib.inflateRawSync(raw);
  return null;
}

function appMetaFromIpa(ipaPath) {
  try {
    const plist = readZipEntry(ipaPath, /Payload\/[^/]+\.app\/Info\.plist$/);
    if (!plist) return {};
    const m = parsePlistMeta(plist);
    return { bundleId: m.bundleId, version: m.version, name: m.name };
  } catch { return {}; }
}

function escXml(s) {
  return String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

// Install hosting: unguessable per-sign links, auto-expire. The manifested
// IPA URL must be public (Apple's installer cannot log in), so the token
// itself is the only protection - 256 bits, 30 minutes, then deleted.
const dlStore = new Map();
const DL_TTL_MS = 30 * 60 * 1000;

function buildManifest(ipaUrl, bundleId, version, title) {
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>items</key>
  <array>
    <dict>
      <key>assets</key>
      <array>
        <dict>
          <key>kind</key>
          <string>software-package</string>
          <key>url</key>
          <string>${escXml(ipaUrl)}</string>
        </dict>
      </array>
      <key>metadata</key>
      <dict>
        <key>bundle-identifier</key>
        <string>${escXml(bundleId)}</string>
        <key>bundle-version</key>
        <string>${escXml(version)}</string>
        <key>kind</key>
        <string>software</string>
        <key>title</key>
        <string>${escXml(title)}</string>
      </dict>
    </dict>
  </array>
</dict>
</plist>
`;
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

setInterval(() => {
  const now = Date.now();
  for (const [t, exp] of loggedOut) if (exp < now) loggedOut.delete(t);
  for (const [ip, e] of loginAttempts) if (e.reset < now) loginAttempts.delete(ip);
  for (const [tok, e] of dlStore) {
    if (e.at + DL_TTL_MS < now) {
      dlStore.delete(tok);
      fs.rm(e.dir, { recursive: true, force: true }, () => {});
    }
  }
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
      const token = newSession(clientIp(req));
      return send(res, 200, { ok: true }, { "Set-Cookie": sessionCookie(token, req) });
    }
    return send(res, 401, { ok: false, error: "wrong password" });
  }

  if (req.method === "GET" && url.pathname === "/api/me") {
    const ok = validSession(parseCookies(req).seu_session, clientIp(req));
    return send(res, 200, { ok });
  }

  if (req.method === "POST" && url.pathname === "/api/logout") {
    const t = parseCookies(req).seu_session;
    if (t && typeof t === "string") loggedOut.set(t, Date.now() + SESSION_TTL_MS);
    res.setHeader("Set-Cookie", sessionCookie(null, req));
    return send(res, 200, { ok: true });
  }

  // Gated site content: only returned with a valid session.
  // Nothing protected lives in the frontend HTML/JS - inspect shows an empty shell.
  if (req.method === "GET" && url.pathname === "/api/home") {
    if (!validSession(parseCookies(req).seu_session, clientIp(req))) {
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
    if (!validSession(parseCookies(req).seu_session, clientIp(req))) {
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
    if (!validSession(parseCookies(req).seu_session, clientIp(req))) {
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
    if (!validSession(parseCookies(req).seu_session, clientIp(req))) {
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
    if (!validSession(parseCookies(req).seu_session, clientIp(req))) {
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
    if (!validSession(parseCookies(req).seu_session, clientIp(req))) {
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
    if (!validSession(parseCookies(req).seu_session, clientIp(req))) {
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
    if (!validSession(parseCookies(req).seu_session, clientIp(req))) {
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
    if (!validSession(parseCookies(req).seu_session, clientIp(req))) {
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
    if (!validSession(parseCookies(req).seu_session, clientIp(req))) {
      return send(res, 401, { ok: false, error: "unauthorized" });
    }
    const workDir = fs.mkdtempSync(path.join(os.tmpdir(), "seu-sign-"));
    const cleanup = () => fs.rm(workDir, { recursive: true, force: true }, () => {});
    try {
      const { fields, files } = await parseMultipart(req, workDir, {
        total: 450e6, ipa: 400e6, p12: 5e6, mobileprovision: 5e6, icon: 5e6
      }).catch(e => { throw { status: e.status || 400, message: e.message }; });

      if (!files.ipa || !files.ipa.size) throw { status: 400, message: "ipa file required" };
      let ipaPath = files.ipa.path;
      if (files.icon && files.icon.size) {
        const iconBytes = fs.readFileSync(files.icon.path);
        const isPng = iconBytes.length > 8 && iconBytes[0] === 0x89 && iconBytes[1] === 0x50;
        const isJpg = iconBytes.length > 3 && iconBytes[0] === 0xFF && iconBytes[1] === 0xD8;
        if (!isPng && !isJpg) throw { status: 400, message: "icon must be PNG or JPEG" };
        const modPath = path.join(workDir, "icon-" + files.ipa.name);
        fs.copyFileSync(ipaPath, modPath);
        try {
          replaceZipIcons(modPath, iconBytes);
        } catch (e) {
          throw { status: 400, message: "icon replace failed: " + (e.message || "") };
        }
        ipaPath = modPath;
      }
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
      args.push(ipaPath);
      try {
        await runCmd(bin, args);
      } catch (e) {
        const detail = String((e.stderr || e.stdout || e.message || "")).split("\n").slice(0, 4).join(" ").slice(0, 300);
        throw { status: 502, message: "signing failed" + (detail ? ": " + detail : "") };
      }

      const st = fs.statSync(outPath);
      const meta = appMetaFromIpa(files.ipa.path);
      const finalBundleId = bundleId || meta.bundleId || "";
      const finalVersion = meta.version || "1.0";
      const finalTitle = appName || meta.name || outName.replace(/\.ipa$/i, "");
      if (!finalBundleId) {
        throw { status: 400, message: "enter the app's bundle ID (needed for install)" };
      }
      const token = crypto.randomBytes(32).toString("hex");
      const dlDir = path.join(os.tmpdir(), "seu-dl", token);
      fs.mkdirSync(dlDir, { recursive: true });
      const hostedName = "app.ipa";
      fs.copyFileSync(outPath, path.join(dlDir, hostedName));
      const origin = "https://" + (req.headers.host || "").split(",")[0].trim();
      const ipaUrl = origin + "/dl/" + token + "/" + hostedName;
      fs.writeFileSync(path.join(dlDir, "manifest.plist"),
        buildManifest(ipaUrl, finalBundleId, finalVersion, finalTitle));
      dlStore.set(token, { dir: dlDir, at: Date.now() });
      cleanup();
      return send(res, 200, {
        ok: true, token, fileName: outName, size: st.size,
        bundleId: finalBundleId, version: finalVersion, title: finalTitle
      });
    } catch (e) {
      cleanup();
      const status = (e && e.status) || 500;
      return send(res, status, { ok: false, error: (e && e.message) || "sign failed" });
    }
    return;
  }

  // Gated re-download of a signed IPA (for the Download button).
  if (req.method === "GET" && url.pathname === "/api/signed") {
    if (!validSession(parseCookies(req).seu_session, clientIp(req))) {
      return send(res, 401, { ok: false, error: "unauthorized" });
    }
    const token = url.searchParams.get("token") || "";
    const entry = (/^[a-f0-9]{64}$/.test(token) && dlStore.get(token)) || null;
    if (!entry) return send(res, 404, { ok: false, error: "expired - sign again" });
    const fp = path.join(entry.dir, "app.ipa");
    if (!fs.existsSync(fp)) return send(res, 404, { ok: false, error: "expired - sign again" });
    const st = fs.statSync(fp);
    res.writeHead(200, {
      "Content-Type": "application/octet-stream",
      "Content-Length": st.size,
      "Content-Disposition": 'attachment; filename="signed-app.ipa"'
    });
    fs.createReadStream(fp).pipe(res);
    return;
  }

  // Public install files. No session (Apple's installer cannot log in);
  // the 256-bit token in the URL is the only protection, links expire.
  if (req.method === "GET" && url.pathname.startsWith("/dl/")) {
    const parts = url.pathname.split("/");
    const token = parts[2] || "";
    const file = parts[3] || "";
    const entry = (/^[a-f0-9]{64}$/.test(token) && dlStore.get(token)) || null;
    if (!entry || (file !== "app.ipa" && file !== "manifest.plist")) {
      return send(res, 404, { ok: false, error: "not found" });
    }
    const fp = path.join(entry.dir, file);
    if (!fs.existsSync(fp)) return send(res, 404, { ok: false, error: "not found" });
    const st = fs.statSync(fp);
    res.writeHead(200, {
      "Content-Type": file === "manifest.plist" ? "application/xml" : "application/octet-stream",
      "Content-Length": st.size
    });
    fs.createReadStream(fp).pipe(res);
    return;
  }

  return send(res, 404, { ok: false, error: "not found" });
});

server.listen(PORT, () => console.log(`seu-backend listening on :${PORT}`));
