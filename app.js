(function () {
  "use strict";

  const state = {
    db: null,
    currentUser: null,
    bootstrapped: false,
    onlineUsers: [],
    chatMessages: [],
    presenceTimer: null,
    chatTimer: null
  };

  function nowIso() {
    return new Date().toISOString();
  }

  function uid(prefix) {
    return `${prefix}_${Math.random().toString(16).slice(2)}_${Date.now().toString(16)}`;
  }

  function clone(value) {
    return JSON.parse(JSON.stringify(value));
  }

  function emptyDb() {
    return {
      version: 1,
      createdAt: nowIso(),
      users: [],
      tasks: [],
      inventory: [],
      tanks: [],
      products: [],
      reservations: [],
      chatMessages: [],
      session: { userId: null, createdAt: null }
    };
  }

  async function api(path, options = {}) {
    const headers = new Headers(options.headers || {});
    const hasBody = options.body !== undefined;
    if (hasBody && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
    const response = await fetch(path, {
      method: options.method || "GET",
      headers,
      body: hasBody ? JSON.stringify(options.body) : undefined,
      credentials: "same-origin"
    });
    const contentType = response.headers.get("content-type") || "";
    const payload = contentType.includes("application/json") ? await response.json() : await response.text();
    if (!response.ok) {
      const message = payload && payload.error ? payload.error : "Operacja nie powiodla sie.";
      const error = new Error(message);
      error.status = response.status;
      throw error;
    }
    return payload;
  }

  async function refreshState() {
    try {
      const payload = await api("/api/data");
      state.db = payload.db;
      state.currentUser = payload.currentUser;
    } catch (error) {
      if (error.status === 401) {
        state.db = emptyDb();
        state.currentUser = null;
      } else {
        throw error;
      }
    }
    state.bootstrapped = true;
  }

  async function refreshOnlineUsers() {
    try {
      const payload = await api("/api/online");
      state.onlineUsers = payload.onlineUsers || [];
    } catch (error) {
      if (error.status === 401) {
        state.onlineUsers = [];
      } else {
        throw error;
      }
    }
  }

  async function sendPresencePing() {
    try {
      await api("/api/presence", { method: "POST", body: {} });
    } catch (error) {
      if (error.status === 401) state.currentUser = null;
    }
  }

  async function refreshChatMessages() {
    try {
      const payload = await api("/api/chat");
      state.chatMessages = payload.messages || [];
    } catch (error) {
      if (error.status === 401) {
        state.chatMessages = [];
      } else {
        throw error;
      }
    }
  }

  function getCurrentDb() {
    return state.db ? clone(state.db) : emptyDb();
  }

  async function saveDb(db) {
    await api("/api/data", { method: "PUT", body: { db } });
    await refreshState();
  }

  function setPageTitle(title, crumb) {
    document.getElementById("uiPageTitle").textContent = title;
    document.getElementById("uiPageCrumb").textContent = crumb || "";
  }

  function setActiveNav(route) {
    document.querySelectorAll(".nav-link").forEach((node) => {
      node.classList.toggle("active", node.dataset.route === route);
    });
  }

  function setUserPill(user) {
    document.getElementById("uiUserName").textContent = user ? user.username : "-";
    document.getElementById("uiUserRole").textContent = user ? user.role : "-";
  }

  function pickRoute() {
    const match = (location.hash || "#/dashboard").match(/^#\/([a-z-]+)/i);
    return match ? match[1] : "dashboard";
  }

  function requireAuth() {
    if (!state.currentUser) {
      showLogin();
      return null;
    }
    return state.currentUser;
  }

  function escapeHtml(text) {
    return String(text || "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll("\"", "&quot;")
      .replaceAll("'", "&#039;");
  }

  function fmtQty(value) {
    const num = Number(value || 0);
    return Number.isNaN(num) ? "-" : num.toLocaleString("pl-PL", { maximumFractionDigits: 3 });
  }

  function render(html) {
    document.getElementById("viewRoot").innerHTML = html;
  }

  function badgeForQty(item) {
    const qty = Number(item.quantity || 0);
    const min = Number(item.minQuantity || 0);
    if (qty <= 0) return '<span class="pill bad">Brak</span>';
    if (min > 0 && qty < min) return '<span class="pill warn">Nisko</span>';
    return '<span class="pill ok">OK</span>';
  }

  function badgeForTask(item) {
    if (item.status === "done") return '<span class="pill ok">Zrobione</span>';
    if (item.status === "blocked") return '<span class="pill bad">Zablok.</span>';
    return '<span class="pill">Otwarte</span>';
  }

  function badgeForReservation(item) {
    if (item.status === "picked_up") return '<span class="pill ok">Odebrane</span>';
    if (item.status === "cancelled") return '<span class="pill bad">Anul.</span>';
    return '<span class="pill warn">Zarezerw.</span>';
  }

  function badgeForTankStage(item) {
    if (item.stage === "gotowe") return '<span class="pill ok">Gotowe</span>';
    if (item.stage === "fermentacja") return '<span class="pill warn">Fermentacja</span>';
    if (item.stage === "lezak") return '<span class="pill">Lezak</span>';
    return `<span class="pill">${escapeHtml(item.stage || "-")}</span>`;
  }

  function onlineUserNames() {
    if (!state.onlineUsers || state.onlineUsers.length === 0) return "Nikt";
    return state.onlineUsers.map((item) => item.username).join(", ");
  }

  function renderOnlineList() {
    if (!state.onlineUsers || state.onlineUsers.length === 0) {
      return '<div class="callout">Brak aktywnych uzytkownikow online.</div>';
    }
    return `
      <table class="table">
        <thead><tr><th>Uzytkownik</th><th>Rola</th><th>Ostatnia aktywnosc</th></tr></thead>
        <tbody>
          ${state.onlineUsers.map((item) => `
            <tr>
              <td>${escapeHtml(item.username)}</td>
              <td>${escapeHtml(item.role)}</td>
              <td>${escapeHtml((item.lastSeenAt || "").replace("T", " ").slice(0, 16))}</td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    `;
  }

  function normalizeReservationItems(item) {
    if (!item) return [];
    if (Array.isArray(item.items)) {
      return item.items
        .map((entry) => ({
          productId: entry.productId,
          qty: Number(entry.qty || 0)
        }))
        .filter((entry) => entry.productId && entry.qty > 0);
    }
    if (item.productId) {
      return [{
        productId: item.productId,
        qty: Number(item.qty || 0)
      }].filter((entry) => entry.qty > 0);
    }
    return [];
  }

  function findProduct(db, productId) {
    return db.products.find((item) => item.id === productId) || null;
  }

  function findTank(db, tankId) {
    return db.tanks.find((item) => item.id === tankId) || null;
  }

  function normalizeReservationFulfillment(item) {
    return Array.isArray(item?.fulfillment) ? item.fulfillment : [];
  }

  function revertReservationFulfillment(db, item) {
    if (!item || item.status === "cancelled") return;

    const fulfillment = normalizeReservationFulfillment(item);
    if (fulfillment.length > 0) {
      for (const entry of fulfillment) {
        const product = findProduct(db, entry.productId);
        if (product) {
          product.availableQty = Number(product.availableQty || 0) + Number(entry.fromProductQty || 0);
        }
        for (const allocation of entry.tankAllocations || []) {
          const tank = findTank(db, allocation.tankId);
          if (tank) {
            tank.quantityHl = Number(tank.quantityHl || 0) + Number(allocation.quantityHl || 0);
          }
        }
      }
      return;
    }

    for (const entry of normalizeReservationItems(item)) {
      const product = findProduct(db, entry.productId);
      if (product) product.availableQty = Number(product.availableQty || 0) + Number(entry.qty || 0);
    }
  }

  function allocateFromReadyTanks(db, product, neededUnits) {
    const hlPerUnit = Number(product.hlPerUnit || 0);
    const linkedBeerName = String(product.linkedBeerName || "").trim();

    if (!hlPerUnit || hlPerUnit <= 0) {
      throw new Error(`Produkt ${product.name} nie ma ustawionego przelicznika szt na hl.`);
    }
    if (!linkedBeerName) {
      throw new Error(`Produkt ${product.name} nie ma ustawionego powiazanego piwa w tanku.`);
    }

    let neededHl = neededUnits * hlPerUnit;
    const readyTanks = db.tanks
      .filter((tank) => tank.stage === "gotowe" && String(tank.beerName || "").trim().toLowerCase() === linkedBeerName.toLowerCase())
      .sort((a, b) => (a.tankName || "").localeCompare(b.tankName || ""));

    const allocations = [];
    for (const tank of readyTanks) {
      if (neededHl <= 0) break;
      const availableHl = Number(tank.quantityHl || 0);
      if (availableHl <= 0) continue;
      const takeHl = Math.min(availableHl, neededHl);
      tank.quantityHl = availableHl - takeHl;
      neededHl -= takeHl;
      allocations.push({
        tankId: tank.id,
        tankName: tank.tankName,
        beerName: tank.beerName,
        quantityHl: takeHl
      });
    }

    if (neededHl > 0.000001) {
      throw new Error(`Brak wystarczajacej ilosci gotowego piwa ${linkedBeerName} w tankach.`);
    }

    return allocations;
  }

  function applyReservationStockChange(db, previousItem, nextItem) {
    revertReservationFulfillment(db, previousItem);

    if (!nextItem || nextItem.status === "cancelled") {
      if (nextItem) nextItem.fulfillment = [];
      return;
    }

    const items = normalizeReservationItems(nextItem);
    const fulfillment = [];

    for (const entry of items) {
      const product = findProduct(db, entry.productId);
      if (!product) throw new Error("Powiazany produkt nie istnieje.");

      const requestedQty = Number(entry.qty || 0);
      const availableQty = Number(product.availableQty || 0);
      const fromProductQty = Math.min(availableQty, requestedQty);
      const shortageQty = requestedQty - fromProductQty;

      product.availableQty = availableQty - fromProductQty;

      const tankAllocations = shortageQty > 0 ? allocateFromReadyTanks(db, product, shortageQty) : [];
      fulfillment.push({
        productId: product.id,
        productName: product.name,
        requestedQty,
        fromProductQty,
        fromTankQty: shortageQty,
        tankAllocations
      });
    }

    nextItem.fulfillment = fulfillment;
  }

  function reservationItemsSummary(item, byId) {
    return normalizeReservationItems(item)
      .map((entry) => {
        const product = byId.get(entry.productId);
        const productName = product ? product.name : "(usuniety produkt)";
        return `${productName} x ${fmtQty(entry.qty)}`;
      })
      .join(", ");
  }

  function reservationFulfillmentSummary(item) {
    const fulfillment = normalizeReservationFulfillment(item);
    if (fulfillment.length === 0) return "-";
    return fulfillment
      .map((entry) => {
        const chunks = [];
        if (Number(entry.fromProductQty || 0) > 0) chunks.push(`mag:${fmtQty(entry.fromProductQty)}`);
        if (Number(entry.fromTankQty || 0) > 0) {
          const tanks = (entry.tankAllocations || []).map((tank) => `${tank.tankName} ${fmtQty(tank.quantityHl)} hl`).join(", ");
          chunks.push(`tank:${fmtQty(entry.fromTankQty)} (${tanks})`);
        }
        return `${entry.productName}: ${chunks.join(" + ")}`;
      })
      .join(" | ");
  }

  function downloadJson(filename, value) {
    const blob = new Blob([JSON.stringify(value, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  }

  function normalizeImport(obj) {
    const required = ["users", "tasks", "inventory", "tanks", "products", "reservations", "chatMessages", "session"];
    if (!obj || typeof obj !== "object" || obj.version !== 1) return { ok: false, error: "Niepoprawny plik JSON." };
    for (const key of required) {
      if (!(key in obj)) return { ok: false, error: `Brakuje pola: ${key}` };
    }
    return { ok: true, value: obj };
  }

  function modal() {
    const dialog = document.getElementById("modalDialog");
    const overlay = document.getElementById("overlay");
    const title = document.getElementById("modalTitle");
    const subtitle = document.getElementById("modalSubtitle");
    const content = document.getElementById("modalContent");
    const okButton = document.getElementById("modalOk");
    const cancelButton = document.getElementById("modalCancel");
    const closeButton = document.getElementById("modalClose");
    const errorNode = document.getElementById("modalError");

    function open(config) {
      title.textContent = config.titleText || "-";
      subtitle.textContent = config.subtitleText || "";
      content.innerHTML = config.contentHtml || "";
      okButton.textContent = config.okText || "Zapisz";
      errorNode.textContent = "";
      errorNode.classList.add("hidden");
      overlay.classList.remove("hidden");
      if (!dialog.open) dialog.showModal();
      if (config.initialFocusId) {
        setTimeout(() => {
          const focusNode = document.getElementById(config.initialFocusId);
          if (focusNode) focusNode.focus();
        }, 0);
      }
    }

    function close() {
      if (dialog.open) dialog.close();
      overlay.classList.add("hidden");
    }

    function setError(message) {
      errorNode.textContent = message;
      errorNode.classList.remove("hidden");
    }

    function values(form) {
      const out = {};
      for (const [key, value] of new FormData(form).entries()) out[key] = String(value);
      return out;
    }

    cancelButton.addEventListener("click", close);
    closeButton.addEventListener("click", close);
    overlay.addEventListener("click", close);
    dialog.addEventListener("cancel", (event) => {
      event.preventDefault();
      close();
    });
    dialog.addEventListener("close", () => {
      overlay.classList.add("hidden");
    });

    return { open, close, setError, values };
  }

  const uiModal = modal();

  function renderInventoryTable(db, compact, onlyRisks) {
    const rows = db.inventory.filter((item) => {
      if (!onlyRisks) return true;
      const qty = Number(item.quantity || 0);
      const min = Number(item.minQuantity || 0);
      return qty <= 0 || (min > 0 && qty < min);
    });
    if (rows.length === 0) return '<div class="callout">Brak pozycji do wyswietlenia.</div>';
    return `
      <table class="table">
        <thead>
          <tr>
            <th>Typ</th>
            <th>Nazwa</th>
            <th class="right">Ilosc</th>
            <th>Jedn.</th>
            <th class="right">Min</th>
            <th>Status</th>
            ${compact ? "" : '<th class="actions">Akcje</th>'}
          </tr>
        </thead>
        <tbody>
          ${rows.map((item) => `
            <tr>
              <td>${escapeHtml(item.type === "beer" ? "Piwo" : "Surowiec")}</td>
              <td>${escapeHtml(item.name)}</td>
              <td class="right">${fmtQty(item.quantity)}</td>
              <td>${escapeHtml(item.unit)}</td>
              <td class="right">${fmtQty(item.minQuantity)}</td>
              <td>${badgeForQty(item)}</td>
              ${compact ? "" : `<td class="actions">
                <button class="btn btn-secondary" type="button" data-kind="inventory" data-action="edit" data-id="${item.id}">Edytuj</button>
                <button class="btn btn-ghost" type="button" data-kind="inventory" data-action="delete" data-id="${item.id}">Usun</button>
              </td>`}
            </tr>
          `).join("")}
        </tbody>
      </table>
    `;
  }

  function renderDashboard(db) {
    const user = requireAuth();
    if (!user) return;
    setPageTitle("Pulpit", "Podsumowanie");
    setActiveNav("dashboard");
    const low = db.inventory.filter((item) => Number(item.minQuantity || 0) > 0 && Number(item.quantity || 0) < Number(item.minQuantity || 0)).length;
    const out = db.inventory.filter((item) => Number(item.quantity || 0) <= 0).length;
    const openTasks = db.tasks.filter((item) => item.status !== "done").length;
    const activeReservations = db.reservations.filter((item) => item.status === "reserved").length;
    const activeTanks = db.tanks.filter((item) => item.stage === "fermentacja" || item.stage === "lezak").length;
    render(`
      <div class="kpis">
        <div class="kpi"><div class="kpi-label">Niskie stany</div><div class="kpi-value">${low}</div></div>
        <div class="kpi"><div class="kpi-label">Braki</div><div class="kpi-value">${out}</div></div>
        <div class="kpi"><div class="kpi-label">Otwarte zadania</div><div class="kpi-value">${openTasks}</div></div>
        <div class="kpi"><div class="kpi-label">Rezerwacje aktywne</div><div class="kpi-value">${activeReservations}</div></div>
        <div class="kpi"><div class="kpi-label">Aktywne tanki</div><div class="kpi-value">${activeTanks}</div></div>
        <div class="kpi"><div class="kpi-label">Online teraz</div><div class="kpi-value">${state.onlineUsers.length}</div></div>
      </div>
      <div class="card">
        <div class="card-head"><div class="card-title">Do sprawdzenia</div></div>
        <div class="card-body">${renderInventoryTable(db, true, true)}</div>
      </div>
      <div class="card">
        <div class="card-head"><div class="card-title">Kto jest online</div><div class="muted small">${escapeHtml(onlineUserNames())}</div></div>
        <div class="card-body">${renderOnlineList()}</div>
      </div>
    `);
  }

  function renderLists(db) {
    if (!requireAuth()) return;
    setPageTitle("Listy", "Zadania");
    setActiveNav("lists");
    render(`
      <div class="card">
        <div class="card-head">
          <div class="card-title">Zadania</div>
          <button class="btn" id="btnAddTask" type="button">Dodaj</button>
        </div>
        <div class="card-body">
          ${db.tasks.length === 0 ? '<div class="callout">Brak zadan.</div>' : `
            <table class="table">
              <thead><tr><th>Tytul</th><th>Priorytet</th><th>Status</th><th>Opis</th><th class="actions">Akcje</th></tr></thead>
              <tbody>
                ${db.tasks.map((item) => `
                  <tr>
                    <td>${escapeHtml(item.title)}</td>
                    <td>${escapeHtml(item.priority || "normal")}</td>
                    <td>${badgeForTask(item)}</td>
                    <td>${escapeHtml(item.notes || "")}</td>
                    <td class="actions">
                      <button class="btn btn-secondary" type="button" data-kind="tasks" data-action="edit" data-id="${item.id}">Edytuj</button>
                      <button class="btn btn-ghost" type="button" data-kind="tasks" data-action="delete" data-id="${item.id}">Usun</button>
                    </td>
                  </tr>
                `).join("")}
              </tbody>
            </table>
          `}
        </div>
      </div>
    `);
    document.getElementById("btnAddTask").addEventListener("click", () => openTaskModal(getCurrentDb(), null));
    bindRowActions();
  }

  function renderInventory(db) {
    if (!requireAuth()) return;
    setPageTitle("Magazyn", "Piwo i surowce");
    setActiveNav("inventory");
    render(`
      <div class="card">
        <div class="card-head">
          <div class="card-title">Pozycje magazynu</div>
          <button class="btn" id="btnAddInventory" type="button">Dodaj</button>
        </div>
        <div class="card-body">${renderInventoryTable(db, false, false)}</div>
      </div>
    `);
    document.getElementById("btnAddInventory").addEventListener("click", () => openInventoryModal(getCurrentDb(), null));
    bindRowActions();
  }

  function renderTanks(db) {
    if (!requireAuth()) return;
    setPageTitle("Piwo w tankach", "Fermentacja, lezak, gotowe");
    setActiveNav("tanks");
    render(`
      <div class="card">
        <div class="card-head">
          <div class="card-title">Tanki</div>
          <button class="btn" id="btnAddTank" type="button">Dodaj</button>
        </div>
        <div class="card-body">
          ${db.tanks.length === 0 ? '<div class="callout">Brak wpisow o tankach.</div>' : `
            <table class="table">
              <thead><tr><th>Piwo</th><th>Tank</th><th class="right">Ilosc (hl)</th><th>Etap</th><th>Uwagi</th><th class="actions">Akcje</th></tr></thead>
              <tbody>
                ${db.tanks.map((item) => `
                  <tr>
                    <td>${escapeHtml(item.beerName || "")}</td>
                    <td>${escapeHtml(item.tankName || "")}</td>
                    <td class="right">${fmtQty(item.quantityHl)}</td>
                    <td>${badgeForTankStage(item)}</td>
                    <td>${escapeHtml(item.notes || "")}</td>
                    <td class="actions">
                      <button class="btn btn-secondary" type="button" data-kind="tanks" data-action="edit" data-id="${item.id}">Edytuj</button>
                      <button class="btn btn-ghost" type="button" data-kind="tanks" data-action="delete" data-id="${item.id}">Usun</button>
                    </td>
                  </tr>
                `).join("")}
              </tbody>
            </table>
          `}
        </div>
      </div>
    `);
    document.getElementById("btnAddTank").addEventListener("click", () => openTankModal(getCurrentDb(), null));
    bindRowActions();
  }

  function renderProducts(db) {
    if (!requireAuth()) return;
    setPageTitle("Produkty", "Katalog i dostepnosc");
    setActiveNav("products");
    render(`
      <div class="card">
        <div class="card-head">
          <div class="card-title">Produkty</div>
          <button class="btn" id="btnAddProduct" type="button">Dodaj</button>
        </div>
        <div class="card-body">
          ${db.products.length === 0 ? '<div class="callout">Brak produktow.</div>' : `
            <table class="table">
              <thead><tr><th>Nazwa</th><th class="right">Dostepne</th><th>Jedn.</th><th>Piwo z tanku</th><th class="right">1 szt = hl</th><th class="right">Cena</th><th>SKU</th><th class="actions">Akcje</th></tr></thead>
              <tbody>
                ${db.products.map((item) => `
                  <tr>
                    <td>${escapeHtml(item.name)}</td>
                    <td class="right">${fmtQty(item.availableQty)}</td>
                    <td>${escapeHtml(item.unit || "szt")}</td>
                    <td>${escapeHtml(item.linkedBeerName || "-")}</td>
                    <td class="right">${fmtQty(item.hlPerUnit)}</td>
                    <td class="right">${fmtQty(item.pricePln)} PLN</td>
                    <td>${escapeHtml(item.sku || "")}</td>
                    <td class="actions">
                      <button class="btn btn-secondary" type="button" data-kind="products" data-action="edit" data-id="${item.id}">Edytuj</button>
                      <button class="btn btn-ghost" type="button" data-kind="products" data-action="delete" data-id="${item.id}">Usun</button>
                    </td>
                  </tr>
                `).join("")}
              </tbody>
            </table>
          `}
        </div>
      </div>
    `);
    document.getElementById("btnAddProduct").addEventListener("click", () => openProductModal(getCurrentDb(), null));
    bindRowActions();
  }

  function renderReservations(db) {
    if (!requireAuth()) return;
    setPageTitle("Rezerwacje", "Rezerwacja produktow");
    setActiveNav("reservations");
    const byId = new Map(db.products.map((item) => [item.id, item]));
    render(`
      <div class="card">
        <div class="card-head">
          <div class="card-title">Rezerwacje</div>
          <button class="btn" id="btnAddReservation" type="button">Nowa</button>
        </div>
        <div class="card-body">
          ${db.reservations.length === 0 ? '<div class="callout">Brak rezerwacji.</div>' : `
            <table class="table">
              <thead><tr><th>Produkty</th><th>Klient</th><th class="right">Suma</th><th>Pobranie</th><th>Status</th><th>Odbior do</th><th class="actions">Akcje</th></tr></thead>
              <tbody>
                ${db.reservations.map((item) => `
                  <tr>
                    <td>${escapeHtml(reservationItemsSummary(item, byId))}</td>
                    <td>${escapeHtml(item.customerName)}<div class="muted small">${escapeHtml(item.customerContact || "")}</div></td>
                    <td class="right">${fmtQty(normalizeReservationItems(item).reduce((sum, entry) => sum + Number(entry.qty || 0), 0))}</td>
                    <td class="muted small">${escapeHtml(reservationFulfillmentSummary(item))}</td>
                    <td>${badgeForReservation(item)}</td>
                    <td>${escapeHtml(item.pickupBy || "")}</td>
                    <td class="actions">
                      <button class="btn btn-secondary" type="button" data-kind="reservations" data-action="edit" data-id="${item.id}">Edytuj</button>
                      <button class="btn btn-ghost" type="button" data-kind="reservations" data-action="delete" data-id="${item.id}">Usun</button>
                    </td>
                  </tr>
                `).join("")}
              </tbody>
            </table>
          `}
        </div>
      </div>
    `);
    document.getElementById("btnAddReservation").addEventListener("click", () => openReservationModal(getCurrentDb(), null));
    bindRowActions();
  }

  function renderUsers(db) {
    const user = requireAuth();
    if (!user) return;
    setPageTitle("Uzytkownicy", "Role i logowanie");
    setActiveNav("users");
    if (user.role !== "admin") {
      render('<div class="callout">Brak dostepu.</div>');
      return;
    }
    render(`
      <div class="card">
        <div class="card-head">
          <div class="card-title">Konta</div>
          <button class="btn" id="btnAddUser" type="button">Dodaj</button>
        </div>
        <div class="card-body">
          <table class="table">
            <thead><tr><th>Login</th><th>Rola</th><th>Utworzono</th><th class="actions">Akcje</th></tr></thead>
            <tbody>
              ${db.users.map((item) => `
                <tr>
                  <td>${escapeHtml(item.username)}</td>
                  <td>${escapeHtml(item.role)}</td>
                  <td>${escapeHtml((item.createdAt || "").slice(0, 10))}</td>
                  <td class="actions">
                    <button class="btn btn-secondary" type="button" data-kind="users" data-action="edit" data-id="${item.id}">Edytuj</button>
                    <button class="btn btn-ghost" type="button" data-kind="users" data-action="delete" data-id="${item.id}">Usun</button>
                  </td>
                </tr>
              `).join("")}
            </tbody>
          </table>
        </div>
      </div>
      <div class="card">
        <div class="card-head"><div class="card-title">Moje konto</div></div>
        <div class="card-body"><button class="btn btn-secondary" id="btnChangePw" type="button">Zmien haslo</button></div>
      </div>
      <div class="card">
        <div class="card-head"><div class="card-title">Aktualnie online</div></div>
        <div class="card-body">${renderOnlineList()}</div>
      </div>
    `);
    document.getElementById("btnAddUser").addEventListener("click", () => openUserModal(getCurrentDb(), null));
    document.getElementById("btnChangePw").addEventListener("click", () => openChangePasswordModal(user));
    bindRowActions();
  }

  function renderChat(db) {
    if (!requireAuth()) return;
    setPageTitle("Czat", "Wspolny pokoj browaru");
    setActiveNav("chat");
    const onlineCount = state.onlineUsers.length;
    render(`
      <div class="chat-shell card">
        <div class="chat-header">
          <div class="chat-header__main">
            <div class="chat-avatar">CZ</div>
            <div>
              <div class="card-title">Czat zespolu</div>
              <div class="muted small">${onlineCount} online: ${escapeHtml(onlineUserNames())}</div>
            </div>
          </div>
          <div class="chat-status-dot" title="Aktywny pokoj"></div>
        </div>
        <div class="chat-body" id="chatBody">
          ${state.chatMessages.length === 0 ? `
            <div class="chat-empty">
              <div class="chat-empty__icon">...</div>
              <div class="chat-empty__title">Brak wiadomosci</div>
              <div class="muted small">Napisz pierwsza wiadomosc do zespolu.</div>
            </div>
          ` : `
            <div class="chat-thread">
              ${state.chatMessages.map((item) => {
                const mine = state.currentUser && item.userId === state.currentUser.id;
                return `
                  <div class="chat-row ${mine ? "mine" : "theirs"}">
                    <div class="chat-bubble">
                      <div class="chat-bubble__meta">
                        <span class="chat-bubble__author">${escapeHtml(item.username)}</span>
                        <span class="chat-bubble__time">${escapeHtml((item.createdAt || "").replace("T", " ").slice(11, 16))}</span>
                      </div>
                      <div class="chat-bubble__text">${escapeHtml(item.text)}</div>
                    </div>
                  </div>
                `;
              }).join("")}
            </div>
          `}
        </div>
        <div class="chat-composer">
          <form id="chatForm" class="chat-composer__form">
            <input id="chatInput" class="chat-composer__input" placeholder="Napisz wiadomosc..." maxlength="500" />
            <button class="btn chat-composer__send" type="submit">Wyslij</button>
          </form>
        </div>
      </div>
    `);

    const body = document.getElementById("chatBody");
    if (body) body.scrollTop = body.scrollHeight;

    document.getElementById("chatForm").addEventListener("submit", async (event) => {
      event.preventDefault();
      const input = document.getElementById("chatInput");
      const text = input.value.trim();
      if (!text) return;
      try {
        await api("/api/chat", { method: "POST", body: { text } });
        input.value = "";
        await refreshChatMessages();
        renderChat(getCurrentDb());
      } catch (error) {
        alert(error.message);
      }
    });
  }

  async function deleteItem(kind, id) {
    const db = getCurrentDb();
    if (kind === "inventory") db.inventory = db.inventory.filter((item) => item.id !== id);
    if (kind === "tanks") db.tanks = db.tanks.filter((item) => item.id !== id);
    if (kind === "tasks") db.tasks = db.tasks.filter((item) => item.id !== id);
    if (kind === "products") db.products = db.products.filter((item) => item.id !== id);
    if (kind === "users") db.users = db.users.filter((item) => item.id !== id);
    if (kind === "reservations") {
      const reservation = db.reservations.find((item) => item.id === id);
      applyReservationStockChange(db, reservation, null);
      db.reservations = db.reservations.filter((item) => item.id !== id);
    }
    await saveDb(db);
    await route();
  }

  function bindRowActions() {
    document.querySelectorAll("[data-action='edit']").forEach((node) => {
      node.addEventListener("click", () => {
        const kind = node.dataset.kind;
        const id = node.dataset.id;
        const db = getCurrentDb();
        if (kind === "inventory") openInventoryModal(db, id);
        if (kind === "tanks") openTankModal(db, id);
        if (kind === "tasks") openTaskModal(db, id);
        if (kind === "products") openProductModal(db, id);
        if (kind === "reservations") openReservationModal(db, id);
        if (kind === "users") openUserModal(db, id);
      });
    });

    document.querySelectorAll("[data-action='delete']").forEach((node) => {
      node.addEventListener("click", async () => {
        if (!confirm("Na pewno usunac?")) return;
        try {
          await deleteItem(node.dataset.kind, node.dataset.id);
        } catch (error) {
          alert(error.message);
        }
      });
    });
  }

  function attachModalSubmit(handler) {
    const form = document.getElementById("modalForm");
    const wrapped = async (event) => {
      event.preventDefault();
      await handler(form, wrapped);
    };
    form.addEventListener("submit", wrapped);
  }

  function buildReservationItemRow(db, selectedProductId, qty) {
    const options = db.products.map((item) => {
      const selected = selectedProductId === item.id ? " selected" : "";
      return `<option value="${item.id}"${selected}>${escapeHtml(item.name)} (${fmtQty(item.availableQty)} ${escapeHtml(item.unit || "szt")})</option>`;
    }).join("");
    return `
      <div class="reservation-item-row row wrap" data-reservation-row>
        <div style="flex:2; min-width:220px;">
          <select data-reservation-product>
            <option value="">Wybierz produkt</option>
            ${options}
          </select>
        </div>
        <div style="width:120px;">
          <input data-reservation-qty inputmode="decimal" value="${escapeHtml(qty ?? "1")}" />
        </div>
        <button class="btn btn-ghost" type="button" data-remove-reservation-row>Usun</button>
      </div>
    `;
  }

  function bindReservationRows(db, initialItems) {
    const container = document.getElementById("reservationItems");
    const addButton = document.getElementById("btnAddReservationItem");

    function attachRemoveHandlers() {
      container.querySelectorAll("[data-remove-reservation-row]").forEach((button) => {
        button.onclick = () => {
          const rows = container.querySelectorAll("[data-reservation-row]");
          if (rows.length <= 1) return;
          button.closest("[data-reservation-row]").remove();
        };
      });
    }

    function addRow(selectedProductId, qty) {
      container.insertAdjacentHTML("beforeend", buildReservationItemRow(db, selectedProductId, qty));
      attachRemoveHandlers();
    }

    container.innerHTML = "";
    const seedItems = initialItems.length > 0 ? initialItems : [{ productId: "", qty: 1 }];
    seedItems.forEach((entry) => addRow(entry.productId, entry.qty));
    addButton.onclick = () => addRow("", 1);
  }

  function readReservationItemsFromModal() {
    const rows = Array.from(document.querySelectorAll("[data-reservation-row]"));
    return rows.map((row) => {
      return {
        productId: row.querySelector("[data-reservation-product]").value,
        qty: Number((row.querySelector("[data-reservation-qty]").value || "0").replace(",", "."))
      };
    });
  }

  function openInventoryModal(db, id) {
    const existing = id ? db.inventory.find((item) => item.id === id) : null;
    uiModal.open({
      titleText: existing ? "Edytuj pozycje" : "Nowa pozycja",
      subtitleText: "Magazyn piwa i surowcow",
      okText: existing ? "Zapisz" : "Dodaj",
      initialFocusId: "invName",
      contentHtml: `
        <div class="form-grid">
          <label class="field"><div class="label">Typ</div><select name="type"><option value="beer"${existing && existing.type === "beer" ? " selected" : ""}>Piwo</option><option value="raw"${existing && existing.type === "raw" ? " selected" : ""}>Surowiec</option></select></label>
          <label class="field"><div class="label">Jednostka</div><input name="unit" value="${escapeHtml(existing?.unit || "")}" /></label>
          <label class="field"><div class="label">Nazwa</div><input id="invName" name="name" value="${escapeHtml(existing?.name || "")}" required /></label>
          <label class="field"><div class="label">Ilosc</div><input name="quantity" value="${escapeHtml(existing?.quantity ?? "")}" /></label>
          <label class="field"><div class="label">Stan minimalny</div><input name="minQuantity" value="${escapeHtml(existing?.minQuantity ?? "")}" /></label>
        </div>
      `
    });

    attachModalSubmit(async (form, wrapped) => {
      const values = uiModal.values(form);
      const quantity = Number((values.quantity || "0").replace(",", "."));
      const minQuantity = Number((values.minQuantity || "0").replace(",", "."));
      if (!values.name) return uiModal.setError("Wpisz nazwe.");
      if (Number.isNaN(quantity) || Number.isNaN(minQuantity)) return uiModal.setError("Ilosc i minimum musza byc liczbami.");
      const nextDb = getCurrentDb();
      const item = existing ? nextDb.inventory.find((entry) => entry.id === existing.id) : { id: uid("inv"), createdAt: nowIso() };
      item.type = values.type;
      item.unit = values.unit || "";
      item.name = values.name.trim();
      item.quantity = quantity;
      item.minQuantity = minQuantity;
      item.updatedAt = nowIso();
      if (!existing) nextDb.inventory.push(item);
      try {
        await saveDb(nextDb);
        form.removeEventListener("submit", wrapped);
        uiModal.close();
        await route();
      } catch (error) {
        uiModal.setError(error.message);
      }
    });
  }

  function openTankModal(db, id) {
    const existing = id ? db.tanks.find((item) => item.id === id) : null;
    uiModal.open({
      titleText: existing ? "Edytuj tank" : "Nowy wpis w tankach",
      subtitleText: "Piwo w tankach i etap procesu",
      okText: existing ? "Zapisz" : "Dodaj",
      initialFocusId: "tankBeerName",
      contentHtml: `
        <div class="form-grid">
          <label class="field"><div class="label">Nazwa piwa</div><input id="tankBeerName" name="beerName" value="${escapeHtml(existing?.beerName || "")}" required /></label>
          <label class="field"><div class="label">Tank</div><input name="tankName" value="${escapeHtml(existing?.tankName || "")}" placeholder="np. CKT-01" required /></label>
          <label class="field"><div class="label">Ilosc (hl)</div><input name="quantityHl" value="${escapeHtml(existing?.quantityHl ?? "")}" inputmode="decimal" required /></label>
          <label class="field"><div class="label">Etap</div><select name="stage"><option value="fermentacja"${existing?.stage === "fermentacja" || !existing ? " selected" : ""}>fermentacja</option><option value="lezak"${existing?.stage === "lezak" ? " selected" : ""}>lezak</option><option value="gotowe"${existing?.stage === "gotowe" ? " selected" : ""}>gotowe</option></select></label>
        </div>
        <label class="field"><div class="label">Uwagi</div><textarea name="notes">${escapeHtml(existing?.notes || "")}</textarea></label>
      `
    });

    attachModalSubmit(async (form, wrapped) => {
      const values = uiModal.values(form);
      const quantityHl = Number((values.quantityHl || "0").replace(",", "."));
      if (!values.beerName || !values.tankName) return uiModal.setError("Wpisz nazwe piwa i tank.");
      if (Number.isNaN(quantityHl) || quantityHl < 0) return uiModal.setError("Ilosc w hl musi byc liczba.");
      const nextDb = getCurrentDb();
      const item = existing ? nextDb.tanks.find((entry) => entry.id === existing.id) : { id: uid("tnk"), createdAt: nowIso() };
      item.beerName = values.beerName.trim();
      item.tankName = values.tankName.trim();
      item.quantityHl = quantityHl;
      item.stage = values.stage || "fermentacja";
      item.notes = values.notes || "";
      item.updatedAt = nowIso();
      if (!existing) nextDb.tanks.push(item);
      try {
        await saveDb(nextDb);
        form.removeEventListener("submit", wrapped);
        uiModal.close();
        await route();
      } catch (error) {
        uiModal.setError(error.message);
      }
    });
  }

  function openTaskModal(db, id) {
    const existing = id ? db.tasks.find((item) => item.id === id) : null;
    uiModal.open({
      titleText: existing ? "Edytuj zadanie" : "Nowe zadanie",
      subtitleText: "Lista do zrobienia",
      okText: existing ? "Zapisz" : "Dodaj",
      initialFocusId: "taskTitle",
      contentHtml: `
        <div class="form-grid one">
          <label class="field"><div class="label">Tytul</div><input id="taskTitle" name="title" value="${escapeHtml(existing?.title || "")}" required /></label>
        </div>
        <div class="form-grid">
          <label class="field"><div class="label">Priorytet</div><select name="priority"><option value="low"${existing?.priority === "low" ? " selected" : ""}>low</option><option value="normal"${!existing || existing.priority === "normal" ? " selected" : ""}>normal</option><option value="high"${existing?.priority === "high" ? " selected" : ""}>high</option></select></label>
          <label class="field"><div class="label">Status</div><select name="status"><option value="open"${!existing || existing.status === "open" ? " selected" : ""}>open</option><option value="blocked"${existing?.status === "blocked" ? " selected" : ""}>blocked</option><option value="done"${existing?.status === "done" ? " selected" : ""}>done</option></select></label>
        </div>
        <label class="field"><div class="label">Opis</div><textarea name="notes">${escapeHtml(existing?.notes || "")}</textarea></label>
      `
    });
    attachModalSubmit(async (form, wrapped) => {
      const values = uiModal.values(form);
      if (!values.title) return uiModal.setError("Wpisz tytul.");
      const nextDb = getCurrentDb();
      const item = existing ? nextDb.tasks.find((entry) => entry.id === existing.id) : { id: uid("tsk"), createdAt: nowIso() };
      item.title = values.title.trim();
      item.priority = values.priority || "normal";
      item.status = values.status || "open";
      item.notes = values.notes || "";
      item.updatedAt = nowIso();
      if (!existing) nextDb.tasks.push(item);
      try {
        await saveDb(nextDb);
        form.removeEventListener("submit", wrapped);
        uiModal.close();
        await route();
      } catch (error) {
        uiModal.setError(error.message);
      }
    });
  }

  function openProductModal(db, id) {
    const existing = id ? db.products.find((item) => item.id === id) : null;
    uiModal.open({
      titleText: existing ? "Edytuj produkt" : "Nowy produkt",
      subtitleText: "Katalog produktow",
      okText: existing ? "Zapisz" : "Dodaj",
      initialFocusId: "prodName",
      contentHtml: `
        <div class="form-grid">
          <label class="field"><div class="label">Nazwa</div><input id="prodName" name="name" value="${escapeHtml(existing?.name || "")}" required /></label>
          <label class="field"><div class="label">SKU</div><input name="sku" value="${escapeHtml(existing?.sku || "")}" /></label>
          <label class="field"><div class="label">Dostepne</div><input name="availableQty" value="${escapeHtml(existing?.availableQty ?? "")}" /></label>
          <label class="field"><div class="label">Jednostka</div><input name="unit" value="${escapeHtml(existing?.unit || "szt")}" /></label>
          <label class="field"><div class="label">Piwo z tanku</div><input name="linkedBeerName" value="${escapeHtml(existing?.linkedBeerName || "")}" placeholder="np. Pils" /></label>
          <label class="field"><div class="label">1 szt = hl</div><input name="hlPerUnit" value="${escapeHtml(existing?.hlPerUnit ?? "")}" placeholder="np. 0.3 dla kega 30l" /></label>
          <label class="field"><div class="label">Cena (PLN)</div><input name="pricePln" value="${escapeHtml(existing?.pricePln ?? "")}" /></label>
        </div>
        <label class="field"><div class="label">Opis</div><textarea name="description">${escapeHtml(existing?.description || "")}</textarea></label>
      `
    });
    attachModalSubmit(async (form, wrapped) => {
      const values = uiModal.values(form);
      const availableQty = Number((values.availableQty || "0").replace(",", "."));
      const pricePln = Number((values.pricePln || "0").replace(",", "."));
      const hlPerUnit = values.hlPerUnit === "" ? 0 : Number((values.hlPerUnit || "0").replace(",", "."));
      if (!values.name) return uiModal.setError("Wpisz nazwe produktu.");
      if (Number.isNaN(availableQty) || Number.isNaN(pricePln) || Number.isNaN(hlPerUnit)) return uiModal.setError("Ilosc, cena i przelicznik musza byc liczbami.");
      const nextDb = getCurrentDb();
      const item = existing ? nextDb.products.find((entry) => entry.id === existing.id) : { id: uid("prd"), createdAt: nowIso() };
      item.name = values.name.trim();
      item.sku = values.sku || "";
      item.availableQty = availableQty;
      item.unit = values.unit || "szt";
      item.linkedBeerName = (values.linkedBeerName || "").trim();
      item.hlPerUnit = hlPerUnit;
      item.pricePln = pricePln;
      item.description = values.description || "";
      item.updatedAt = nowIso();
      if (!existing) nextDb.products.push(item);
      try {
        await saveDb(nextDb);
        form.removeEventListener("submit", wrapped);
        uiModal.close();
        await route();
      } catch (error) {
        uiModal.setError(error.message);
      }
    });
  }

  function openReservationModal(db, id) {
    const existing = id ? db.reservations.find((item) => item.id === id) : null;
    const initialItems = normalizeReservationItems(existing);
    uiModal.open({
      titleText: existing ? "Edytuj rezerwacje" : "Nowa rezerwacja",
      subtitleText: "Rezerwacja od razu zmniejsza stan produktu",
      okText: existing ? "Zapisz" : "Dodaj",
      initialFocusId: "resCustomer",
      contentHtml: `
        <div class="form-grid one">
          <div class="field">
            <div class="label">Produkty w rezerwacji</div>
            <div id="reservationItems"></div>
            <div class="row" style="margin-top:8px;">
              <button class="btn btn-secondary" id="btnAddReservationItem" type="button">Dodaj produkt</button>
            </div>
          </div>
        </div>
        <div class="form-grid">
          <label class="field"><div class="label">Klient</div><input id="resCustomer" name="customerName" value="${escapeHtml(existing?.customerName || "")}" required /></label>
          <label class="field"><div class="label">Kontakt</div><input name="customerContact" value="${escapeHtml(existing?.customerContact || "")}" /></label>
          <label class="field"><div class="label">Odbior do</div><input name="pickupBy" value="${escapeHtml(existing?.pickupBy || "")}" /></label>
          <label class="field"><div class="label">Status</div><select name="status"><option value="reserved"${!existing || existing.status === "reserved" ? " selected" : ""}>reserved</option><option value="picked_up"${existing?.status === "picked_up" ? " selected" : ""}>picked_up</option><option value="cancelled"${existing?.status === "cancelled" ? " selected" : ""}>cancelled</option></select></label>
        </div>
        <label class="field"><div class="label">Notatki</div><textarea name="notes">${escapeHtml(existing?.notes || "")}</textarea></label>
        <div class="callout">Status reserved i picked_up zdejmuja towar ze stanu. Gdy brakuje produktu, system moze dobrac brak tylko z tankow gotowe na podstawie pola "Piwo z tanku" i przelicznika hl w produkcie.</div>
      `
    });
    bindReservationRows(db, initialItems);
    attachModalSubmit(async (form, wrapped) => {
      const values = uiModal.values(form);
      if (db.products.length === 0) return uiModal.setError("Brak produktow.");
      if (!values.customerName) return uiModal.setError("Wpisz klienta.");
      const items = readReservationItemsFromModal();
      if (items.length === 0) return uiModal.setError("Dodaj przynajmniej jeden produkt.");
      for (const item of items) {
        if (!item.productId) return uiModal.setError("Kazda pozycja musi miec produkt.");
        if (Number.isNaN(item.qty) || item.qty <= 0) return uiModal.setError("Kazda pozycja musi miec dodatnia ilosc.");
      }

      const nextDb = getCurrentDb();
      const previousItem = existing ? nextDb.reservations.find((entry) => entry.id === existing.id) : null;
      const nextItem = previousItem || { id: uid("res"), createdAt: nowIso(), reservedAt: nowIso() };
      nextItem.items = items;
      delete nextItem.productId;
      delete nextItem.qty;
      nextItem.customerName = values.customerName.trim();
      nextItem.customerContact = values.customerContact || "";
      nextItem.pickupBy = values.pickupBy || "";
      nextItem.status = values.status || "reserved";
      nextItem.notes = values.notes || "";
      nextItem.updatedAt = nowIso();

      try {
        applyReservationStockChange(nextDb, previousItem ? clone(previousItem) : null, nextItem);
        if (!previousItem) nextDb.reservations.push(nextItem);
        await saveDb(nextDb);
        form.removeEventListener("submit", wrapped);
        uiModal.close();
        await route();
      } catch (error) {
        uiModal.setError(error.message);
      }
    });
  }

  function openUserModal(db, id) {
    const currentUser = state.currentUser;
    if (!currentUser || currentUser.role !== "admin") return;
    const existing = id ? db.users.find((item) => item.id === id) : null;
    const isSelf = existing && existing.id === currentUser.id;
    uiModal.open({
      titleText: existing ? "Edytuj konto" : "Nowe konto",
      subtitleText: "Role i logowanie",
      okText: existing ? "Zapisz" : "Dodaj",
      initialFocusId: "usrName",
      contentHtml: `
        <div class="form-grid">
          <label class="field"><div class="label">Login</div><input id="usrName" name="username" value="${escapeHtml(existing?.username || "")}" ${existing ? "readonly" : ""} required /></label>
          <label class="field"><div class="label">Rola</div><select name="role" ${isSelf ? "disabled" : ""}><option value="admin"${existing?.role === "admin" ? " selected" : ""}>admin</option><option value="worker"${!existing || existing.role === "worker" ? " selected" : ""}>worker</option></select></label>
        </div>
        <label class="field"><div class="label">${existing ? "Nowe haslo (opcjonalnie)" : "Haslo"}</div><input name="password" type="password" ${existing ? "" : "required"} /></label>
      `
    });
    attachModalSubmit(async (form, wrapped) => {
      const values = uiModal.values(form);
      if (!values.username) return uiModal.setError("Wpisz login.");
      const nextDb = getCurrentDb();
      if (!existing && nextDb.users.some((item) => item.username.toLowerCase() === values.username.toLowerCase())) {
        return uiModal.setError("Taki login juz istnieje.");
      }
      if (!existing && !values.password) return uiModal.setError("Ustaw haslo.");
      const item = existing ? nextDb.users.find((entry) => entry.id === existing.id) : { id: uid("usr"), createdAt: nowIso() };
      item.username = values.username.trim();
      item.role = isSelf ? existing.role : values.role || "worker";
      if (values.password) item.passwordPlain = values.password;
      item.updatedAt = nowIso();
      if (!existing) nextDb.users.push(item);
      try {
        await saveDb(nextDb);
        form.removeEventListener("submit", wrapped);
        uiModal.close();
        await route();
      } catch (error) {
        uiModal.setError(error.message);
      }
    });
  }

  function openChangePasswordModal(user) {
    uiModal.open({
      titleText: "Zmiana hasla",
      subtitleText: user.username,
      okText: "Zmien",
      initialFocusId: "pwOld",
      contentHtml: `
        <div class="form-grid one">
          <label class="field"><div class="label">Stare haslo</div><input id="pwOld" name="oldPassword" type="password" required /></label>
          <label class="field"><div class="label">Nowe haslo</div><input name="newPassword" type="password" required /></label>
        </div>
      `
    });
    attachModalSubmit(async (form, wrapped) => {
      const values = uiModal.values(form);
      if (!values.newPassword || values.newPassword.length < 6) return uiModal.setError("Nowe haslo za krotkie.");
      try {
        await api("/api/change-password", {
          method: "POST",
          body: { oldPassword: values.oldPassword || "", newPassword: values.newPassword || "" }
        });
        form.removeEventListener("submit", wrapped);
        uiModal.close();
      } catch (error) {
        uiModal.setError(error.message);
      }
    });
  }

  function showLogin() {
    const dialog = document.getElementById("loginDialog");
    document.getElementById("loginError").classList.add("hidden");
    if (!dialog.open) dialog.showModal();
    setTimeout(() => document.getElementById("loginUsername").focus(), 0);
  }

  function hideLogin() {
    const dialog = document.getElementById("loginDialog");
    if (dialog.open) dialog.close();
  }

  function bindLogin() {
    document.getElementById("loginForm").addEventListener("submit", async (event) => {
      event.preventDefault();
      const errorNode = document.getElementById("loginError");
      errorNode.classList.add("hidden");
      try {
        await api("/api/login", {
          method: "POST",
          body: {
            username: document.getElementById("loginUsername").value.trim(),
            password: document.getElementById("loginPassword").value
          }
        });
        await refreshState();
        hideLogin();
        await route();
      } catch (error) {
        errorNode.textContent = error.message;
        errorNode.classList.remove("hidden");
      }
    });
  }

  function bindGlobal() {
    document.getElementById("btnLogout").addEventListener("click", async () => {
      try {
        await api("/api/logout", { method: "POST", body: {} });
      } catch (_) {}
      state.currentUser = null;
      state.onlineUsers = [];
      state.chatMessages = [];
      setUserPill(null);
      showLogin();
    });

    document.getElementById("btnExport").addEventListener("click", async () => {
      try {
        const payload = await api("/api/export");
        downloadJson(`brew-panel-export-${new Date().toISOString().slice(0, 10)}.json`, payload.db);
      } catch (error) {
        alert(error.message);
      }
    });

    document.getElementById("fileImport").addEventListener("change", async (event) => {
      const file = event.target.files && event.target.files[0];
      event.target.value = "";
      if (!file) return;
      const parsed = JSON.parse(await file.text());
      const normalized = normalizeImport(parsed);
      if (!normalized.ok) return alert(normalized.error);
      try {
        await api("/api/import", { method: "POST", body: { db: normalized.value } });
        await refreshState();
        await route();
      } catch (error) {
        alert(error.message);
      }
    });
  }

  async function route() {
    if (!state.bootstrapped) await refreshState();
    if (state.currentUser) {
      await Promise.all([refreshOnlineUsers(), refreshChatMessages()]);
    }
    const db = getCurrentDb();
    setUserPill(state.currentUser);
    const routeKey = pickRoute();
    if (!state.currentUser) {
      setPageTitle("Logowanie", "");
      setActiveNav(routeKey);
      showLogin();
      return;
    }
    hideLogin();
    if (routeKey === "dashboard") return renderDashboard(db);
    if (routeKey === "lists") return renderLists(db);
    if (routeKey === "inventory") return renderInventory(db);
    if (routeKey === "tanks") return renderTanks(db);
    if (routeKey === "products") return renderProducts(db);
    if (routeKey === "reservations") return renderReservations(db);
    if (routeKey === "chat") return renderChat(db);
    if (routeKey === "users") return renderUsers(db);
    location.hash = "#/dashboard";
  }

  function startRealtimeLoops() {
    if (state.presenceTimer) clearInterval(state.presenceTimer);
    if (state.chatTimer) clearInterval(state.chatTimer);

    state.presenceTimer = setInterval(async () => {
      if (!state.currentUser) return;
      await sendPresencePing();
      await refreshOnlineUsers();
      const routeKey = pickRoute();
      if (routeKey === "dashboard" || routeKey === "users" || routeKey === "chat") {
        await route();
      }
    }, 20000);

    state.chatTimer = setInterval(async () => {
      if (!state.currentUser) return;
      await refreshChatMessages();
      if (pickRoute() === "chat") {
        renderChat(getCurrentDb());
      }
    }, 5000);
  }

  async function main() {
    bindLogin();
    bindGlobal();
    window.addEventListener("hashchange", () => { route().catch((error) => alert(error.message)); });
    await refreshState();
    startRealtimeLoops();
    await route();
  }

  main().catch((error) => {
    alert(error.message || "Blad aplikacji.");
  });
})();
