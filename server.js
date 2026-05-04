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

function pdf(res, filename, contentBuffer) {
  res.writeHead(200, {
    "Content-Type": "application/pdf",
    "Content-Disposition": `attachment; filename="${filename}"`,
    "Cache-Control": "no-store",
    "Content-Length": contentBuffer.length
  });
  res.end(contentBuffer);
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

function fmtQty(value) {
  const num = Number(value || 0);
  if (!Number.isFinite(num)) return "-";
  return num.toLocaleString("pl-PL", { maximumFractionDigits: 3 });
}

function normalizeReservationItems(item) {
  if (Array.isArray(item?.items)) {
    return item.items
      .map((entry) => ({
        productId: entry.productId,
        qty: Number(entry.qty || 0)
      }))
      .filter((entry) => entry.productId && entry.qty > 0);
  }
  if (item?.productId) {
    return [{ productId: item.productId, qty: Number(item.qty || 0) }].filter((entry) => entry.qty > 0);
  }
  return [];
}

function normalizeReservationFulfillment(item) {
  return Array.isArray(item?.fulfillment) ? item.fulfillment : [];
}

function asciiPdfText(value) {
  return String(value || "")
    .replaceAll("ą", "a")
    .replaceAll("ć", "c")
    .replaceAll("ę", "e")
    .replaceAll("ł", "l")
    .replaceAll("ń", "n")
    .replaceAll("ó", "o")
    .replaceAll("ś", "s")
    .replaceAll("ż", "z")
    .replaceAll("ź", "z")
    .replaceAll("Ą", "A")
    .replaceAll("Ć", "C")
    .replaceAll("Ę", "E")
    .replaceAll("Ł", "L")
    .replaceAll("Ń", "N")
    .replaceAll("Ó", "O")
    .replaceAll("Ś", "S")
    .replaceAll("Ż", "Z")
    .replaceAll("Ź", "Z")
    .replace(/[^\x20-\x7E]/g, " ");
}

function pdfEscape(value) {
  return asciiPdfText(value)
    .replaceAll("\\", "\\\\")
    .replaceAll("(", "\\(")
    .replaceAll(")", "\\)");
}

function wrapPdfLine(textValue, maxChars = 88) {
  const text = asciiPdfText(textValue).trim();
  if (!text) return [""];
  const words = text.split(/\s+/);
  const lines = [];
  let current = "";
  for (const word of words) {
    const next = current ? `${current} ${word}` : word;
    if (next.length > maxChars && current) {
      lines.push(current);
      current = word;
    } else {
      current = next;
    }
  }
  if (current) lines.push(current);
  return lines;
}

function reservationMatchesDay(item, dateValue) {
  const pickupBy = String(item.pickupBy || "").trim();
  return pickupBy.slice(0, 10) === dateValue;
}

function buildDailyReservationReport(db, dateValue) {
  const productById = new Map((db.products || []).map((item) => [item.id, item]));
  const reservations = (db.reservations || []).filter((item) => item.status !== "cancelled" && reservationMatchesDay(item, dateValue));

  const inventoryGroups = [];
  const tankGroups = [];

  for (const reservation of reservations) {
    const items = normalizeReservationItems(reservation);
    const itemsById = new Map(items.map((entry) => [entry.productId, entry]));
    const fulfillment = normalizeReservationFulfillment(reservation);

    const inventoryLines = [];
    const tankLines = [];

    for (const entry of fulfillment) {
      const product = productById.get(entry.productId);
      const unit = asciiPdfText(product?.unit || "szt");
      const productName = asciiPdfText(entry.productName || product?.name || "Produkt");
      if (Number(entry.fromProductQty || 0) > 0) {
        inventoryLines.push(`- ${productName}: ${fmtQty(entry.fromProductQty)} ${unit}`);
      }
      if (Number(entry.fromTankQty || 0) > 0) {
        const tanks = (entry.tankAllocations || [])
          .map((tank) => `${asciiPdfText(tank.tankName || "tank")} ${fmtQty(tank.quantityHl)} hl`)
          .join(", ");
        tankLines.push(`- ${productName}: ${fmtQty(entry.fromTankQty)} ${unit}; tanki: ${tanks}`);
      }
    }

    if (fulfillment.length === 0) {
      for (const entry of items) {
        const product = productById.get(entry.productId);
        const unit = asciiPdfText(product?.unit || "szt");
        inventoryLines.push(`- ${asciiPdfText(product?.name || "Produkt")}: ${fmtQty(entry.qty)} ${unit}`);
      }
    }

    const customerLine = `Klient: ${asciiPdfText(reservation.customerName || "-")} | Kontakt: ${asciiPdfText(reservation.customerContact || "-")} | Odbior: ${asciiPdfText(reservation.pickupBy || "-")}`;
    const notesLine = reservation.notes ? `Uwagi: ${asciiPdfText(reservation.notes)}` : "";

    if (inventoryLines.length > 0) {
      inventoryGroups.push({
        header: customerLine,
        notes: notesLine,
        lines: inventoryLines
      });
    }

    if (tankLines.length > 0) {
      tankGroups.push({
        header: customerLine,
        notes: notesLine,
        lines: tankLines
      });
    }
  }

  const lines = [
    "Lista rezerwacji dla magazyniera",
    `Dzien odbioru: ${dateValue}`,
    `Liczba rezerwacji: ${reservations.length}`,
    ""
  ];

  lines.push("1. Zamowienie - rzeczy, ktore sa w magazynie");
  if (inventoryGroups.length === 0) {
    lines.push("Brak pozycji magazynowych.");
  } else {
    for (const group of inventoryGroups) {
      lines.push(group.header);
      if (group.notes) lines.push(group.notes);
      for (const line of group.lines) lines.push(line);
      lines.push("");
    }
  }

  lines.push("");
  lines.push("2. Rzeczy, ktore trzeba wziac z tanka");
  if (tankGroups.length === 0) {
    lines.push("Brak pobran z tankow.");
  } else {
    for (const group of tankGroups) {
      lines.push(group.header);
      if (group.notes) lines.push(group.notes);
      for (const line of group.lines) lines.push(line);
      lines.push("");
    }
  }

  return { reservations, lines };
}

function buildSimplePdfBuffer(lines) {
  const pageWidth = 595;
  const pageHeight = 842;
  const marginX = 40;
  const startY = 800;
  const lineHeight = 15;
  const maxLinesPerPage = 48;
  const wrappedLines = lines.flatMap((line) => wrapPdfLine(line, 88));
  const pages = [];
  for (let i = 0; i < wrappedLines.length; i += maxLinesPerPage) {
    pages.push(wrappedLines.slice(i, i + maxLinesPerPage));
  }
  if (pages.length === 0) pages.push(["Brak danych."]);

  const objects = [];
  objects.push("<< /Type /Catalog /Pages 2 0 R >>");

  const pageObjectIds = [];
  const contentObjectIds = [];
  let nextId = 3;
  for (let i = 0; i < pages.length; i += 1) {
    pageObjectIds.push(nextId++);
    contentObjectIds.push(nextId++);
  }
  const fontObjectId = nextId++;
  objects.push(`<< /Type /Pages /Count ${pages.length} /Kids [${pageObjectIds.map((id) => `${id} 0 R`).join(" ")}] >>`);

  for (let pageIndex = 0; pageIndex < pages.length; pageIndex += 1) {
    const pageId = pageObjectIds[pageIndex];
    const contentId = contentObjectIds[pageIndex];
    objects[pageId - 1] = `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${pageWidth} ${pageHeight}] /Resources << /Font << /F1 ${fontObjectId} 0 R >> >> /Contents ${contentId} 0 R >>`;

    const commands = ["BT", "/F1 11 Tf"];
    let y = startY;
    for (const line of pages[pageIndex]) {
      commands.push(`1 0 0 1 ${marginX} ${y} Tm (${pdfEscape(line)}) Tj`);
      y -= lineHeight;
    }
    commands.push("ET");
    const stream = commands.join("\n");
    objects[contentId - 1] = `<< /Length ${Buffer.byteLength(stream, "latin1")} >>\nstream\n${stream}\nendstream`;
  }

  objects[fontObjectId - 1] = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>";

  let pdfText = "%PDF-1.4\n";
  const offsets = [0];
  for (let i = 0; i < objects.length; i += 1) {
    offsets.push(Buffer.byteLength(pdfText, "latin1"));
    pdfText += `${i + 1} 0 obj\n${objects[i]}\nendobj\n`;
  }
  const xrefOffset = Buffer.byteLength(pdfText, "latin1");
  pdfText += `xref\n0 ${objects.length + 1}\n`;
  pdfText += "0000000000 65535 f \n";
  for (let i = 1; i < offsets.length; i += 1) {
    pdfText += `${String(offsets[i]).padStart(10, "0")} 00000 n \n`;
  }
  pdfText += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xrefOffset}\n%%EOF`;
  return Buffer.from(pdfText, "latin1");
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
  const requestUrl = new URL(req.url, "http://localhost");

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

  if (requestUrl.pathname === "/api/reservations/daily-pdf" && req.method === "GET") {
    const user = requireAuth(req, res, db);
    if (!user) return true;
    const dateValue = String(requestUrl.searchParams.get("date") || "").trim();
    if (!/^\d{4}-\d{2}-\d{2}$/.test(dateValue)) return json(res, 400, { error: "Podaj date w formacie RRRR-MM-DD." });
    const report = buildDailyReservationReport(db, dateValue);
    const pdfBuffer = buildSimplePdfBuffer(report.lines);
    return pdf(res, `rezerwacje-${dateValue}.pdf`, pdfBuffer);
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
