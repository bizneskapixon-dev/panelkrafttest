const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const ROOT = __dirname;
const DB_PATH = path.join(ROOT, "brew-panel-db.json");
const PORT = Number(process.env.PORT || 3000);
const HOST = "0.0.0.0";
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const sessions = new Map();

function nowIso() {
  return new Date().toISOString();
}

function uid(prefix) {
  return `${prefix}_${crypto.randomBytes(8).toString("hex")}_${Date.now().toString(16)}`;
}

function sha256Hex(text) {
  return crypto.createHash("sha256").update(String(text)).digest("hex");
}

function defaultDb() {
  const createdAt = nowIso();
  return {
    version: 1,
    createdAt,
    users: [{
      id: uid("usr"),
      username: "admin",
      role: "admin",
      passwordHash: sha256Hex("admin123"),
      createdAt,
      updatedAt: createdAt
    }],
    tasks: [],
    inventory: [],
    tanks: [],
    products: [],
    reservations: [],
    chatMessages: [],
    session: { userId: null, createdAt: null }
  };
}

function readDb() {
  if (!fs.existsSync(DB_PATH)) {
    const db = defaultDb();
    fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
    return db;
  }
  const db = JSON.parse(fs.readFileSync(DB_PATH, "utf8"));
  if (!db.users || db.users.length === 0) {
    const seed = defaultDb();
    db.users = seed.users;
  }
  if (!db.session) db.session = { userId: null, createdAt: null };
  if (!Array.isArray(db.chatMessages)) db.chatMessages = [];
  return db;
}

function writeDb(db) {
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
}

function sanitizeUser(user) {
  return {
    id: user.id,
    username: user.username,
    role: user.role,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt
  };
}

function sanitizeDb(db) {
  return {
    version: db.version,
    createdAt: db.createdAt,
    users: db.users.map(sanitizeUser),
    tasks: db.tasks || [],
    inventory: db.inventory || [],
    tanks: db.tanks || [],
    products: db.products || [],
    reservations: db.reservations || [],
    chatMessages: (db.chatMessages || []).map((item) => ({
      id: item.id,
      userId: item.userId,
      username: item.username,
      text: item.text,
      createdAt: item.createdAt
    })),
    session: { userId: null, createdAt: null }
  };
}

function json(res, status, payload) {
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" });
  res.end(JSON.stringify(payload));
}

function text(res, status, payload) {
  res.writeHead(status, { "Content-Type": "text/plain; charset=utf-8" });
  res.end(payload);
}

function parseCookies(req) {
  const out = {};
  for (const part of String(req.headers.cookie || "").split(";")) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const idx = trimmed.indexOf("=");
    if (idx === -1) continue;
    out[trimmed.slice(0, idx)] = decodeURIComponent(trimmed.slice(idx + 1));
  }
  return out;
}

function setCookie(res, name, value, maxAge) {
  const parts = [`${name}=${encodeURIComponent(value)}`, "Path=/", "HttpOnly", "SameSite=Lax"];
  if (maxAge !== undefined) parts.push(`Max-Age=${maxAge}`);
  if (process.env.NODE_ENV === "production") parts.push("Secure");
  res.setHeader("Set-Cookie", parts.join("; "));
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let raw = "";
    req.on("data", (chunk) => {
      raw += chunk;
      if (raw.length > 2 * 1024 * 1024) {
        reject(new Error("Plik jest za duzy."));
        req.destroy();
      }
    });
    req.on("end", () => {
      try {
        resolve(raw ? JSON.parse(raw) : {});
      } catch (_) {
        reject(new Error("Niepoprawny JSON."));
      }
    });
    req.on("error", reject);
  });
}

function getCurrentUser(req, db) {
  const cookies = parseCookies(req);
  const token = cookies.brew_sid;
  if (!token || !sessions.has(token)) return null;
  const session = sessions.get(token);
  if (session.expiresAt < Date.now()) {
    sessions.delete(token);
    return null;
  }
  session.expiresAt = Date.now() + SESSION_TTL_MS;
  session.lastSeenAt = nowIso();
  return db.users.find((user) => user.id === session.userId) || null;
}

function listOnlineUsers(db) {
  const now = Date.now();
  const unique = new Map();
  for (const [token, session] of sessions.entries()) {
    if (session.expiresAt < now) {
      sessions.delete(token);
      continue;
    }
    const user = db.users.find((entry) => entry.id === session.userId);
    if (!user || unique.has(user.id)) continue;
    unique.set(user.id, {
      id: user.id,
      username: user.username,
      role: user.role,
      lastSeenAt: session.lastSeenAt || nowIso()
    });
  }
  return Array.from(unique.values()).sort((a, b) => (b.lastSeenAt || "").localeCompare(a.lastSeenAt || ""));
}

function requireAuth(req, res, db) {
  const user = getCurrentUser(req, db);
  if (!user) {
    json(res, 401, { error: "Sesja wygasla. Zaloguj sie ponownie." });
    return null;
  }
  return user;
}

function validateDbShape(db) {
  const keys = ["users", "tasks", "inventory", "tanks", "products", "reservations", "chatMessages"];
  if (!db || typeof db !== "object" || db.version !== 1) throw new Error("Niepoprawna baza danych.");
  for (const key of keys) {
    if (!Array.isArray(db[key])) throw new Error(`Pole ${key} musi byc tablica.`);
  }
}

function normalizeUsers(incomingUsers, existingUsers) {
  const existingById = new Map(existingUsers.map((user) => [user.id, user]));
  const usedNames = new Set();
  const users = incomingUsers.map((item) => {
    const username = String(item.username || "").trim();
    if (!username) throw new Error("Kazde konto musi miec login.");
    const key = username.toLowerCase();
    if (usedNames.has(key)) throw new Error("Loginy musza byc unikalne.");
    usedNames.add(key);
    const previous = existingById.get(item.id);
    return {
      id: item.id || uid("usr"),
      username,
      role: item.role === "admin" ? "admin" : "worker",
      passwordHash: item.passwordPlain ? sha256Hex(item.passwordPlain) : (previous ? previous.passwordHash : item.passwordHash),
      createdAt: previous ? previous.createdAt : (item.createdAt || nowIso()),
      updatedAt: nowIso()
    };
  });
  if (!users.every((user) => user.passwordHash)) throw new Error("Kazde konto musi miec haslo.");
  if (!users.some((user) => user.role === "admin")) throw new Error("Musi zostac przynajmniej jedno konto admin.");
  return users;
}

function normalizeDbForStorage(incomingDb, existingDb) {
  validateDbShape(incomingDb);
  return {
    version: 1,
    createdAt: existingDb.createdAt || incomingDb.createdAt || nowIso(),
    users: normalizeUsers(incomingDb.users, existingDb.users || []),
    tasks: incomingDb.tasks || [],
    inventory: incomingDb.inventory || [],
    tanks: incomingDb.tanks || [],
    products: incomingDb.products || [],
    reservations: incomingDb.reservations || [],
    chatMessages: incomingDb.chatMessages || [],
    session: { userId: null, createdAt: null }
  };
}

function normalizeImportDb(incomingDb) {
  validateDbShape(incomingDb);
  const users = incomingDb.users.map((item) => ({
    id: item.id || uid("usr"),
    username: String(item.username || "").trim(),
    role: item.role === "admin" ? "admin" : "worker",
    passwordHash: item.passwordHash || (item.passwordPlain ? sha256Hex(item.passwordPlain) : ""),
    createdAt: item.createdAt || nowIso(),
    updatedAt: item.updatedAt || nowIso()
  }));
  if (!users.every((user) => user.username && user.passwordHash)) throw new Error("Import uzytkownikow jest niepelny.");
  if (!users.some((user) => user.role === "admin")) throw new Error("Import musi miec konto admin.");
  return {
    version: 1,
    createdAt: incomingDb.createdAt || nowIso(),
    users,
    tasks: incomingDb.tasks || [],
    inventory: incomingDb.inventory || [],
    tanks: incomingDb.tanks || [],
    products: incomingDb.products || [],
    reservations: incomingDb.reservations || [],
    chatMessages: incomingDb.chatMessages || [],
    session: { userId: null, createdAt: null }
  };
}

function serveFile(res, fileName) {
  const full = path.join(ROOT, fileName);
  if (!fs.existsSync(full)) return text(res, 404, "Not found");
  const ext = path.extname(full);
  const types = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8"
  };
  res.writeHead(200, { "Content-Type": types[ext] || "application/octet-stream" });
  fs.createReadStream(full).pipe(res);
}

async function handleApi(req, res, db) {
  if (req.url === "/api/wake" && req.method === "GET") {
    return json(res, 200, {
      ok: true,
      service: "browar-panel",
      wokeAt: nowIso()
    });
  }

  if (req.url === "/api/login" && req.method === "POST") {
    const body = await readJsonBody(req);
    const user = db.users.find((item) => item.username.toLowerCase() === String(body.username || "").trim().toLowerCase());
    if (!user || user.passwordHash !== sha256Hex(body.password || "")) return json(res, 401, { error: "Nieprawidlowy login lub haslo." });
    const token = crypto.randomBytes(24).toString("hex");
    sessions.set(token, { userId: user.id, expiresAt: Date.now() + SESSION_TTL_MS, lastSeenAt: nowIso() });
    setCookie(res, "brew_sid", token, Math.floor(SESSION_TTL_MS / 1000));
    return json(res, 200, { ok: true, user: sanitizeUser(user) });
  }

  if (req.url === "/api/logout" && req.method === "POST") {
    const cookies = parseCookies(req);
    if (cookies.brew_sid) sessions.delete(cookies.brew_sid);
    setCookie(res, "brew_sid", "", 0);
    return json(res, 200, { ok: true });
  }

  if (req.url === "/api/data" && req.method === "GET") {
    const user = requireAuth(req, res, db);
    if (!user) return true;
    return json(res, 200, { db: sanitizeDb(db), currentUser: sanitizeUser(user) });
  }

  if (req.url === "/api/online" && req.method === "GET") {
    const user = requireAuth(req, res, db);
    if (!user) return true;
    return json(res, 200, { onlineUsers: listOnlineUsers(db) });
  }

  if (req.url === "/api/presence" && req.method === "POST") {
    const user = requireAuth(req, res, db);
    if (!user) return true;
    return json(res, 200, { ok: true, onlineUsers: listOnlineUsers(db) });
  }

  if (req.url === "/api/data" && req.method === "PUT") {
    const user = requireAuth(req, res, db);
    if (!user) return true;
    const body = await readJsonBody(req);
    const nextDb = normalizeDbForStorage(body.db, db);
    if (!nextDb.users.some((item) => item.id === user.id)) throw new Error("Nie mozna usunac aktywnego uzytkownika.");
    writeDb(nextDb);
    return json(res, 200, { ok: true });
  }

  if (req.url === "/api/export" && req.method === "GET") {
    const user = requireAuth(req, res, db);
    if (!user) return true;
    if (user.role !== "admin") return json(res, 403, { error: "Tylko admin moze eksportowac dane." });
    return json(res, 200, { db });
  }

  if (req.url === "/api/import" && req.method === "POST") {
    const user = requireAuth(req, res, db);
    if (!user) return true;
    if (user.role !== "admin") return json(res, 403, { error: "Tylko admin moze importowac dane." });
    const body = await readJsonBody(req);
    writeDb(normalizeImportDb(body.db));
    return json(res, 200, { ok: true });
  }

  if (req.url === "/api/change-password" && req.method === "POST") {
    const user = requireAuth(req, res, db);
    if (!user) return true;
    const body = await readJsonBody(req);
    if (user.passwordHash !== sha256Hex(body.oldPassword || "")) return json(res, 400, { error: "Stare haslo jest bledne." });
    if (String(body.newPassword || "").length < 6) return json(res, 400, { error: "Nowe haslo jest za krotkie (min. 6)." });
    user.passwordHash = sha256Hex(body.newPassword);
    user.updatedAt = nowIso();
    writeDb(db);
    return json(res, 200, { ok: true });
  }

  if (req.url === "/api/chat" && req.method === "GET") {
    const user = requireAuth(req, res, db);
    if (!user) return true;
    return json(res, 200, { messages: (db.chatMessages || []).slice(-100) });
  }

  if (req.url === "/api/chat" && req.method === "POST") {
    const user = requireAuth(req, res, db);
    if (!user) return true;
    const body = await readJsonBody(req);
    const textValue = String(body.text || "").trim();
    if (!textValue) return json(res, 400, { error: "Wiadomosc nie moze byc pusta." });
    const message = {
      id: uid("msg"),
      userId: user.id,
      username: user.username,
      text: textValue.slice(0, 500),
      createdAt: nowIso()
    };
    db.chatMessages = db.chatMessages || [];
    db.chatMessages.push(message);
    if (db.chatMessages.length > 200) db.chatMessages = db.chatMessages.slice(-200);
    writeDb(db);
    return json(res, 200, { ok: true, message });
  }

  return false;
}

const server = http.createServer(async (req, res) => {
  try {
    const db = readDb();
    if (req.url === "/wake" && req.method === "GET") {
      return text(res, 200, `awake ${nowIso()}`);
    }
    if (req.url.startsWith("/api/")) {
      const handled = await handleApi(req, res, db);
      if (handled === false) text(res, 404, "Not found");
      return;
    }
    const pathname = req.url.split("?")[0];
    if (pathname === "/" || pathname === "/index.html") return serveFile(res, "index.html");
    if (pathname === "/app.js") return serveFile(res, "app.js");
    if (pathname === "/styles.css") return serveFile(res, "styles.css");
    return serveFile(res, "index.html");
  } catch (error) {
    json(res, 400, { error: error.message || "Blad serwera." });
  }
});

server.listen(PORT, HOST, () => {
  console.log(`Browar Panel server listening on http://${HOST}:${PORT}`);
});
