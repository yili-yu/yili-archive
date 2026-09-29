(() => {
  "use strict";

  const STORAGE_KEY = "yili.archive.encrypted.v1";
  const FORMAT = "yili-archive-v1";
  const ITERATIONS = 250000;
  const enc = new TextEncoder();
  const dec = new TextDecoder();

  const state = {
    envelope: null,
    vault: null,
    password: "",
    view: "home",
    query: "",
    groupFilter: "",
    typeFilter: "all",
    gateMode: "unlock",
  };

  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
  const gate = $("#gate");
  const app = $("#app");
  const view = $("#view");
  const recordDialog = $("#record-dialog");
  const groupDialog = $("#group-dialog");

  function bytesToBase64(bytes) {
    let binary = "";
    const chunk = 0x8000;
    for (let i = 0; i < bytes.length; i += chunk) {
      binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
    }
    return btoa(binary);
  }

  function base64ToBytes(value) {
    const binary = atob(value);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }

  async function deriveKey(password, salt, iterations = ITERATIONS) {
    const material = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
      material,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }

  async function encryptVault(vault, password) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKey(password, salt);
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(JSON.stringify(vault)));
    return {
      format: FORMAT,
      encrypted: true,
      kdf: "PBKDF2-SHA256",
      iterations: ITERATIONS,
      cipher: "AES-256-GCM",
      salt: bytesToBase64(salt),
      iv: bytesToBase64(iv),
      ciphertext: bytesToBase64(new Uint8Array(ciphertext)),
      updatedAt: new Date().toISOString(),
    };
  }

  async function decryptVault(envelope, password) {
    if (!envelope || envelope.format !== FORMAT || !envelope.encrypted) throw new Error("密库格式不正确");
    const salt = base64ToBytes(envelope.salt);
    const iv = base64ToBytes(envelope.iv);
    const key = await deriveKey(password, salt, Number(envelope.iterations) || ITERATIONS);
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, base64ToBytes(envelope.ciphertext));
    return normalizeVault(JSON.parse(dec.decode(plain)));
  }

  function defaultVault() {
    const now = new Date().toISOString();
    return { version: 1, profile: { title: "yili archive" }, groups: [], records: [], createdAt: now, updatedAt: now };
  }

  function normalizeVault(vault) {
    return {
      version: 1,
      profile: vault.profile || { title: "yili archive" },
      groups: Array.isArray(vault.groups) ? vault.groups : [],
      records: Array.isArray(vault.records) ? vault.records : [],
      createdAt: vault.createdAt || new Date().toISOString(),
      updatedAt: vault.updatedAt || new Date().toISOString(),
    };
  }

  async function discoverEnvelope() {
    const local = localStorage.getItem(STORAGE_KEY);
    if (local) {
      try { return JSON.parse(local); } catch { localStorage.removeItem(STORAGE_KEY); }
    }
    try {
      const response = await fetch("/data/vault.json", { cache: "no-store" });
      if (response.ok) {
        const remote = await response.json();
        if (remote?.encrypted && remote?.format === FORMAT) return remote;
      }
    } catch { /* Local file previews may not permit fetch. */ }
    return null;
  }

  async function persist() {
    state.vault.updatedAt = new Date().toISOString();
    state.envelope = await encryptVault(state.vault, state.password);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state.envelope));
  }

  function setupGate(hasVault) {
    state.gateMode = hasVault ? "unlock" : "setup";
    $("#gate-form").hidden = false;
    $("#confirm-row").hidden = hasVault;
    $("#gate-confirm").required = !hasVault;
    $("#gate-title").textContent = hasVault ? "私人档案" : "建立私人档案";
    $("#gate-copy").textContent = hasVault
      ? "输入密码，在此浏览器中解锁加密密库。"
      : "第一次使用。设置一个不少于八位的密码，建立空白加密密库。";
    $("#gate-submit").textContent = hasVault ? "解锁" : "建立并进入";
    $("#gate-password").autocomplete = hasVault ? "current-password" : "new-password";
    setTimeout(() => $("#gate-password").focus(), 0);
  }

  async function enterApp(vault, password) {
    state.vault = normalizeVault(vault);
    state.password = password;
    gate.hidden = true;
    app.hidden = false;
    render();
  }

  function lock() {
    state.vault = null;
    state.password = "";
    state.query = "";
    app.hidden = true;
    gate.hidden = false;
    $("#gate-form").reset();
    $("#gate-error").textContent = "";
    setupGate(true);
  }

  function escapeHtml(value = "") {
    return String(value).replace(/[&<>'"]/g, char => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" })[char]);
  }

  function safeHref(value = "") {
    const v = String(value).trim();
    if (/^https?:\/\//i.test(v) || v.startsWith("/") || v.startsWith("./")) return escapeHtml(v);
    return "";
  }

  function localDateInput(date = new Date()) {
    const d = new Date(date);
    const pad = n => String(n).padStart(2, "0");
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
  }

  function formatDate(value, withTime = true) {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "日期不明";
    return new Intl.DateTimeFormat("zh-CN", {
      year: "numeric", month: "2-digit", day: "2-digit",
      ...(withTime ? { hour: "2-digit", minute: "2-digit", hour12: false } : {}),
    }).format(date);
  }

  function typeLabel(type) {
    return ({ chat: "AI 会话", diary: "日记说明", document: "资料文件", note: "研究札记", other: "其他" })[type] || "其他";
  }

  function groupById(id) { return state.vault.groups.find(group => group.id === id); }
  function recordById(id) { return state.vault.records.find(record => record.id === id); }

  function recordGroups(record) {
    return (record.groups || []).map(groupById).filter(Boolean);
  }

  function visibleRecords() {
    const query = state.query.trim().toLocaleLowerCase("zh-CN");
    return [...state.vault.records]
      .filter(record => !state.groupFilter || (record.groups || []).includes(state.groupFilter))
      .filter(record => state.typeFilter === "all" || record.type === state.typeFilter)
      .filter(record => {
        if (!query) return true;
        const groups = recordGroups(record).map(group => group.name).join(" ");
        const haystack = [record.title, record.summary, record.body, record.localPath, record.fileName, groups].join(" ").toLocaleLowerCase("zh-CN");
        return haystack.includes(query);
      })
      .sort((a, b) => new Date(b.occurredAt) - new Date(a.occurredAt));
  }

  function recordCard(record, expanded = false) {
    const groups = recordGroups(record);
    const href = safeHref(record.fileUrl);
    const related = (record.related || []).map(recordById).filter(Boolean);
    return `<article class="record-card" data-record-id="${escapeHtml(record.id)}">
      <div class="record-card-head">
        <div>
          <p class="record-meta"><span class="type-badge">${typeLabel(record.type)}</span>　${formatDate(record.occurredAt)}</p>
          <h3>${escapeHtml(record.title)}</h3>
        </div>
        <div class="record-actions">
          <button type="button" data-action="edit-record" data-id="${escapeHtml(record.id)}" aria-label="编辑">编辑</button>
          <button type="button" data-action="delete-record" data-id="${escapeHtml(record.id)}" aria-label="删除">删除</button>
        </div>
      </div>
      ${record.summary ? `<p class="record-summary">${escapeHtml(record.summary)}</p>` : ""}
      ${expanded && record.body ? `<div class="record-body">${escapeHtml(record.body)}</div>` : ""}
      ${groups.length ? `<div class="chip-row">${groups.map(group => `<button class="chip" type="button" data-action="filter-group" data-id="${escapeHtml(group.id)}"><span style="color:${escapeHtml(group.color || "#456f61")}">●</span>${escapeHtml(group.name)}</button>`).join("")}</div>` : ""}
      ${(href || record.localPath) ? `<div class="attachment-row">
        ${href ? `<a class="file-link" href="${href}" target="_blank" rel="noreferrer">↗ ${escapeHtml(record.fileName || "打开在线文件")}</a>` : ""}
        ${record.localPath ? `<span class="path-box" title="${escapeHtml(record.localPath)}"><code>${escapeHtml(record.localPath)}</code><button class="copy-path" type="button" data-action="copy-path" data-path="${escapeHtml(record.localPath)}">复制</button></span>` : ""}
      </div>` : ""}
      ${expanded && related.length ? `<div class="chip-row"><span class="record-meta">关联：</span>${related.map(item => `<span class="chip">${escapeHtml(item.title)}</span>`).join("")}</div>` : ""}
    </article>`;
  }

  function emptyState(title, copy) {
    return `<div class="empty"><strong>${escapeHtml(title)}</strong>${escapeHtml(copy)}</div>`;
  }

  function renderHome() {
    const records = [...state.vault.records].sort((a, b) => new Date(b.occurredAt) - new Date(a.occurredAt));
    const counts = {
      all: records.length,
      chat: records.filter(r => r.type === "chat").length,
      document: records.filter(r => r.type === "document").length,
      groups: state.vault.groups.length,
    };
    const recent = records.slice(0, 5);
    const activeGroups = state.vault.groups.map(group => ({ ...group, count: records.filter(r => (r.groups || []).includes(group.id)).length })).sort((a, b) => b.count - a.count).slice(0, 6);
    view.innerHTML = `<header class="view-head"><div><p class="eyebrow">Private archive</p><h1>档案总览</h1><p>让会话、日记和资料沿时间排列，再由问题组横向连接。</p></div><div class="view-actions"><button class="quiet-button" type="button" data-action="new-group">＋ 问题组</button></div></header>
      <section class="metric-grid" aria-label="档案统计">
        <div class="metric"><span>全部记录</span><strong>${counts.all}</strong></div><div class="metric"><span>AI 会话</span><strong>${counts.chat}</strong></div><div class="metric"><span>资料文件</span><strong>${counts.document}</strong></div><div class="metric"><span>问题组</span><strong>${counts.groups}</strong></div>
      </section>
      <div class="dashboard-grid">
        <section class="panel"><div class="panel-head"><h2>最近记录</h2><button class="text-button" type="button" data-action="go-records">查看全部</button></div>${recent.length ? `<div class="record-list">${recent.map(r => recordCard(r)).join("")}</div>` : emptyState("还没有记录", "从一段会话、一则日记或一份资料开始。")}</section>
        <section class="panel"><div class="panel-head"><h2>活跃问题组</h2><button class="text-button" type="button" data-action="new-group">新建</button></div>${activeGroups.length ? `<div class="record-list">${activeGroups.map(g => `<button class="nav-item" type="button" data-action="filter-group" data-id="${escapeHtml(g.id)}"><span style="color:${escapeHtml(g.color || "#456f61")}">●</span>${escapeHtml(g.name)}<small style="margin-left:auto">${g.count}</small></button>`).join("")}</div>` : emptyState("尚无问题组", "问题组可以跨越时间和记录类型。")}</section>
      </div>`;
  }

  function renderTimeline() {
    const records = visibleRecords();
    const months = new Map();
    records.forEach(record => {
      const date = new Date(record.occurredAt);
      const key = Number.isNaN(date.getTime()) ? "日期不明" : `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}`;
      if (!months.has(key)) months.set(key, []);
      months.get(key).push(record);
    });
    view.innerHTML = `<header class="view-head"><div><p class="eyebrow">Chronology</p><h1>时间线</h1><p>所有材料按实际发生或形成时间排列。</p></div></header>${filterBar(records.length)}
      <div class="timeline">${records.length ? [...months.entries()].map(([month, items]) => `<section class="month-block"><h2 class="month-title">${escapeHtml(month)}<small>${items.length} 条记录</small></h2><div class="record-list">${items.map(r => recordCard(r, true)).join("")}</div></section>`).join("") : emptyState("没有符合条件的记录", "可以调整筛选，或新建一条记录。")}</div>`;
  }

  function filterBar(count) {
    return `<div class="filter-bar"><select id="type-filter" aria-label="按类型筛选"><option value="all">全部类型</option>${["chat","diary","document","note","other"].map(type => `<option value="${type}" ${state.typeFilter === type ? "selected" : ""}>${typeLabel(type)}</option>`).join("")}</select>
      ${state.groupFilter ? `<button class="quiet-button" type="button" data-action="clear-group">问题组：${escapeHtml(groupById(state.groupFilter)?.name || "未知")}　×</button>` : ""}<span class="result-count">${count} 条</span></div>`;
  }

  function renderRecords() {
    const records = visibleRecords();
    view.innerHTML = `<header class="view-head"><div><p class="eyebrow">All records</p><h1>全部记录</h1><p>会话、日记、资料与札记使用同一套时间和问题组索引。</p></div></header>${filterBar(records.length)}
      ${records.length ? `<div class="record-list">${records.map(r => recordCard(r, true)).join("")}</div>` : emptyState("没有符合条件的记录", "新建记录，或清除当前筛选。")}`;
  }

  function renderGroups() {
    const groups = state.vault.groups;
    view.innerHTML = `<header class="view-head"><div><p class="eyebrow">Problem groups</p><h1>问题组</h1><p>问题组不是文件夹。同一条记录可以同时参与多个问题。</p></div><div class="view-actions"><button class="primary-button" type="button" data-action="new-group">＋ 新建问题组</button></div></header>
      ${groups.length ? `<div class="group-grid">${groups.map(group => { const count = state.vault.records.filter(r => (r.groups || []).includes(group.id)).length; return `<article class="group-card" data-action="filter-group" data-id="${escapeHtml(group.id)}"><div class="group-line" style="background:${escapeHtml(group.color || "#456f61")}"></div><h2>${escapeHtml(group.name)}</h2><p>${escapeHtml(group.description || "尚未填写说明。")}</p><footer><span>${count} 条记录</span><button class="group-edit" type="button" data-action="edit-group" data-id="${escapeHtml(group.id)}">编辑</button></footer></article>`; }).join("")}</div>` : emptyState("还没有问题组", "建立一个问题组，再把不同时间和类型的记录连接起来。")}`;
  }

  function renderSettings() {
    view.innerHTML = `<header class="view-head"><div><p class="eyebrow">Vault settings</p><h1>设置</h1><p>密库默认只保存在这个浏览器中。你可以导出密文备份，并自行决定是否随网站上传。</p></div></header>
      <div class="settings-grid">
        <section class="setting-card"><h2>加密备份</h2><p>导出的 JSON 已经加密。可在其他设备导入，或替换站点的 <code>data/vault.json</code>。</p><div class="view-actions"><button class="primary-button" type="button" data-action="export-vault">导出密库</button><button class="quiet-button" type="button" data-action="import-vault">导入密库</button></div></section>
        <section class="setting-card"><h2>修改密码</h2><p>用新密码重新加密当前全部记录。忘记密码后无法恢复。</p><form id="password-form" class="stack"><label><span>新密码</span><input id="new-password" type="password" minlength="8" required autocomplete="new-password"></label><label><span>确认新密码</span><input id="new-password-confirm" type="password" minlength="8" required autocomplete="new-password"></label><button class="quiet-button" type="submit">重新加密</button></form></section>
        <section class="setting-card"><h2>可选文件上传</h2><p>文件是否上传由每条记录决定。只留在电脑上的文件填写本地路径；已经上传的文件填写在线链接。</p><div class="code-note">本地：E:\资料\文件.docx<br>在线：/files/文件.pdf</div></section>
        <section class="setting-card warning-card"><h2>清空此浏览器</h2><p>删除这个浏览器内保存的密库。请先导出备份；已经部署在服务器上的密库不会被删除。</p><button class="danger-button" type="button" data-action="reset-vault">删除本地密库</button></section>
      </div>`;
  }

  function render() {
    $$(".nav-item[data-view]").forEach(button => button.classList.toggle("is-active", button.dataset.view === state.view));
    if (state.view === "home") renderHome();
    if (state.view === "timeline") renderTimeline();
    if (state.view === "records") renderRecords();
    if (state.view === "groups") renderGroups();
    if (state.view === "settings") renderSettings();
    view.focus({ preventScroll: true });
  }

  function openRecord(record = null) {
    $("#record-form").reset();
    $("#record-id").value = record?.id || "";
    $("#record-dialog-title").textContent = record ? "编辑记录" : "新建记录";
    $("#record-title").value = record?.title || "";
    $("#record-type").value = record?.type || "chat";
    $("#record-date").value = localDateInput(record?.occurredAt || new Date());
    $("#record-summary").value = record?.summary || "";
    $("#record-body").value = record?.body || "";
    $("#record-url").value = record?.fileUrl || "";
    $("#record-file-name").value = record?.fileName || "";
    $("#record-local-path").value = record?.localPath || "";
    $("#record-related").value = (record?.related || []).join(", ");
    $("#record-groups").innerHTML = state.vault.groups.length
      ? state.vault.groups.map(group => `<label class="check-item"><input type="checkbox" value="${escapeHtml(group.id)}" ${(record?.groups || []).includes(group.id) ? "checked" : ""}><span>${escapeHtml(group.name)}</span></label>`).join("")
      : `<span class="record-meta">尚无问题组；可以先保存记录，之后再编辑归类。</span>`;
    recordDialog.showModal();
    setTimeout(() => $("#record-title").focus(), 0);
  }

  function openGroup(group = null) {
    $("#group-form").reset();
    $("#group-id").value = group?.id || "";
    $("#group-dialog-title").textContent = group ? "编辑问题组" : "新建问题组";
    $("#group-name").value = group?.name || "";
    $("#group-description").value = group?.description || "";
    $("#group-color").value = group?.color || "#456f61";
    $("#delete-group-button").hidden = !group;
    groupDialog.showModal();
    setTimeout(() => $("#group-name").focus(), 0);
  }

  function makeId(prefix) {
    return `${prefix}-${new Date().toISOString().slice(0, 10)}-${crypto.randomUUID().slice(0, 8)}`;
  }

  function toast(message) {
    const element = $("#toast");
    element.textContent = message;
    element.classList.add("is-visible");
    clearTimeout(toast.timer);
    toast.timer = setTimeout(() => element.classList.remove("is-visible"), 2400);
  }

  async function exportVault() {
    await persist();
    const blob = new Blob([JSON.stringify(state.envelope, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `yili-archive-vault-${new Date().toISOString().slice(0, 10)}.json`;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    toast("已导出加密密库");
  }

  async function importEnvelopeFile(file) {
    const incoming = JSON.parse(await file.text());
    if (incoming?.format !== FORMAT || !incoming?.encrypted || !incoming?.ciphertext) throw new Error("不是有效的 yili 加密密库");
    localStorage.setItem(STORAGE_KEY, JSON.stringify(incoming));
    state.envelope = incoming;
    lock();
    toast("密库已导入，请输入它的密码");
  }

  $("#gate-form").addEventListener("submit", async event => {
    event.preventDefault();
    const password = $("#gate-password").value;
    const error = $("#gate-error");
    error.textContent = "";
    $("#gate-submit").disabled = true;
    try {
      if (state.gateMode === "setup") {
        if (password.length < 8) throw new Error("密码至少需要八位");
        if (password !== $("#gate-confirm").value) throw new Error("两次输入的密码不一致");
        const vault = defaultVault();
        state.vault = vault;
        state.password = password;
        await persist();
        await enterApp(vault, password);
      } else {
        const vault = await decryptVault(state.envelope, password);
        await enterApp(vault, password);
      }
    } catch (err) {
      error.textContent = state.gateMode === "unlock" ? "密码不正确，或密库文件已经损坏。" : err.message;
    } finally {
      $("#gate-submit").disabled = false;
    }
  });

  $("#gate-import").addEventListener("click", () => $("#vault-file-input").click());
  $("#vault-file-input").addEventListener("change", async event => {
    const file = event.target.files?.[0];
    if (!file) return;
    try { await importEnvelopeFile(file); } catch (err) { $("#gate-error").textContent = err.message; }
    event.target.value = "";
  });

  $("#lock-button").addEventListener("click", lock);
  $("#menu-button").addEventListener("click", () => document.body.classList.toggle("menu-open"));
  $("#new-record-button").addEventListener("click", () => openRecord());
  $("#global-search").addEventListener("input", event => {
    state.query = event.target.value;
    if (state.query && !["records", "timeline"].includes(state.view)) state.view = "records";
    render();
  });

  $$(".nav-item[data-view]").forEach(button => button.addEventListener("click", () => {
    state.view = button.dataset.view;
    document.body.classList.remove("menu-open");
    render();
  }));

  view.addEventListener("change", event => {
    if (event.target.id === "type-filter") { state.typeFilter = event.target.value; render(); }
  });

  view.addEventListener("submit", async event => {
    if (event.target.id !== "password-form") return;
    event.preventDefault();
    const first = $("#new-password").value;
    const second = $("#new-password-confirm").value;
    if (first.length < 8) return toast("新密码至少需要八位");
    if (first !== second) return toast("两次输入的新密码不一致");
    state.password = first;
    await persist();
    event.target.reset();
    toast("密码已修改，密库已经重新加密");
  });

  view.addEventListener("click", async event => {
    const target = event.target.closest("[data-action]");
    if (!target) return;
    const action = target.dataset.action;
    const id = target.dataset.id;
    if (action === "new-group") openGroup();
    if (action === "go-records") { state.view = "records"; render(); }
    if (action === "filter-group") { state.groupFilter = id; state.view = "records"; render(); }
    if (action === "clear-group") { state.groupFilter = ""; render(); }
    if (action === "edit-record") openRecord(recordById(id));
    if (action === "delete-record" && confirm("删除这条记录？此操作会立即写入当前密库。")) {
      state.vault.records = state.vault.records.filter(record => record.id !== id);
      state.vault.records.forEach(record => { record.related = (record.related || []).filter(item => item !== id); });
      await persist(); render(); toast("记录已删除");
    }
    if (action === "edit-group") { event.stopPropagation(); openGroup(groupById(id)); }
    if (action === "copy-path") { await navigator.clipboard.writeText(target.dataset.path); toast("路径已复制"); }
    if (action === "export-vault") exportVault();
    if (action === "import-vault") $("#vault-file-input").click();
    if (action === "reset-vault" && confirm("确定删除这个浏览器中的全部档案吗？请确认已经导出备份。")) {
      localStorage.removeItem(STORAGE_KEY); location.reload();
    }
  });

  $("#record-form").addEventListener("submit", async event => {
    event.preventDefault();
    const id = $("#record-id").value || makeId($("#record-type").value);
    const existing = recordById(id);
    const record = {
      id,
      title: $("#record-title").value.trim(),
      type: $("#record-type").value,
      occurredAt: new Date($("#record-date").value).toISOString(),
      summary: $("#record-summary").value.trim(),
      body: $("#record-body").value.trim(),
      groups: $$("#record-groups input:checked").map(input => input.value),
      fileUrl: $("#record-url").value.trim(),
      fileName: $("#record-file-name").value.trim(),
      localPath: $("#record-local-path").value.trim(),
      related: $("#record-related").value.split(",").map(item => item.trim()).filter(Boolean),
      createdAt: existing?.createdAt || new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
    if (existing) Object.assign(existing, record); else state.vault.records.push(record);
    await persist();
    recordDialog.close();
    render();
    toast(existing ? "记录已更新" : "记录已建立");
  });

  $("#group-form").addEventListener("submit", async event => {
    event.preventDefault();
    const id = $("#group-id").value || makeId("problem");
    const existing = groupById(id);
    const group = { id, name: $("#group-name").value.trim(), description: $("#group-description").value.trim(), color: $("#group-color").value, createdAt: existing?.createdAt || new Date().toISOString(), updatedAt: new Date().toISOString() };
    if (existing) Object.assign(existing, group); else state.vault.groups.push(group);
    await persist();
    groupDialog.close();
    render();
    toast(existing ? "问题组已更新" : "问题组已建立");
  });

  $("#delete-group-button").addEventListener("click", async () => {
    const id = $("#group-id").value;
    if (!id || !confirm("删除这个问题组？所属记录本身不会删除。")) return;
    state.vault.groups = state.vault.groups.filter(group => group.id !== id);
    state.vault.records.forEach(record => { record.groups = (record.groups || []).filter(groupId => groupId !== id); });
    if (state.groupFilter === id) state.groupFilter = "";
    await persist();
    groupDialog.close();
    render();
    toast("问题组已删除");
  });

  [recordDialog, groupDialog].forEach(dialog => dialog.addEventListener("click", event => {
    if (event.target === dialog) dialog.close();
  }));

  window.addEventListener("keydown", event => {
    if (event.key === "Escape") document.body.classList.remove("menu-open");
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k" && !app.hidden) {
      event.preventDefault(); $("#global-search").focus();
    }
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "n" && !app.hidden) {
      event.preventDefault(); openRecord();
    }
  });

  (async function boot() {
    if (!window.crypto?.subtle) {
      $("#gate-copy").textContent = "当前浏览器不支持所需的加密功能，请使用新版浏览器或通过 HTTPS 访问。";
      return;
    }
    state.envelope = await discoverEnvelope();
    setupGate(Boolean(state.envelope));
  })();
})();
