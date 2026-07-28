"use strict";

(() => {
  const API_BASE = "/api/v1";
  const MUTATING_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);
  const SENSITIVE_KEY = /(password|passwd|secret|token|uuid|csrf|auth|credential|api_?key|private_?key|client_?secret|short_?id|node_?link|share_?link|uri)$/i;
  const state = {
    csrf: "",
    activeTab: "overview",
    sessionExpiresAt: 0,
    exits: [],
    groups: [],
    exitOrder: [],
    exitTargets: [],
    ruleTargets: [],
    runtimeLoading: false
  };

  class ApiError extends Error {
    constructor(status, code, message) {
      super(message || "请求失败");
      this.name = "ApiError";
      this.status = status;
      this.code = code || "request_failed";
    }
  }

  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

  function node(tag, className, text) {
    const item = document.createElement(tag);
    if (className) item.className = className;
    if (text !== undefined && text !== null) item.textContent = String(text);
    return item;
  }

  function empty(target) {
    target.replaceChildren();
  }

  function redactSensitiveText(value) {
    let text = String(value ?? "");
    text = text.replace(
      /\b(?:ss|vmess|trojan|vless|hysteria|hysteria2|hy2|tuic|anytls|shadowtls|socks5?):\/\/[^\s<>"']+/gi,
      "[节点链接已遮盖]"
    );
    text = text.replace(
      /^[^\r\n=]{1,80}\s*=\s*ss\s*,[^\r\n]+$/gim,
      "[Surge 节点行已遮盖]"
    );
    text = text.replace(
      /\bhttps?:\/\/[^\s/@:<>"']+:[^\s/@<>"']+@[^\s<>"']+/gi,
      "[含凭据地址已遮盖]"
    );
    text = text.replace(/\b\d{6,12}:[A-Za-z0-9_-]{20,}\b/g, "[Bot Token 已遮盖]");
    text = text.replace(
      /\b(password|passwd|secret|token|uuid|auth|credential|api_?key|private_?key|client_?secret|short_?id)\s*[:=]\s*[^\s,;]+/gi,
      "$1=[已遮盖]"
    );
    return text;
  }

  function safeString(value, maxLength = 4000) {
    const text = redactSensitiveText(value);
    return text.length > maxLength ? `${text.slice(0, maxLength)}…` : text;
  }

  function safeObject(value, parentKey = "", depth = 0) {
    if (SENSITIVE_KEY.test(parentKey)) return undefined;
    if (depth > 4) return "…";
    if (value === null || value === undefined) return value;
    if (typeof value === "string") return safeString(value, 2000);
    if (typeof value === "number" || typeof value === "boolean") return value;
    if (Array.isArray(value)) {
      return value.slice(0, 100).map((item) => safeObject(item, "", depth + 1))
        .filter((item) => item !== undefined);
    }
    if (typeof value === "object") {
      const result = {};
      Object.entries(value).slice(0, 100).forEach(([key, item]) => {
        const clean = safeObject(item, key, depth + 1);
        if (clean !== undefined) result[key] = clean;
      });
      return result;
    }
    return safeString(value);
  }

  function readableValue(value) {
    if (value === null || value === undefined || value === "") return "—";
    if (typeof value === "boolean") return value ? "开启" : "关闭";
    if (typeof value === "number") return String(value);
    if (typeof value === "string") return safeString(value, 2000);
    try {
      return JSON.stringify(safeObject(value));
    } catch (_error) {
      return "无法显示";
    }
  }

  function formatLabel(key) {
    const labels = {
      active: "运行状态",
      status: "状态",
      service: "服务",
      services: "服务",
      connections: "连接数",
      connection_count: "连接数",
      upload: "上传",
      download: "下载",
      upload_total: "累计上传",
      download_total: "累计下载",
      today: "今日",
      month: "本月",
      total: "累计",
      uptime: "运行时间",
      backend: "流量内核",
      core: "流量内核",
      platform: "手机平台",
      dot_domain: "DoT 域名",
      default: "默认出口",
      default_exit: "默认出口",
      tfo: "TCP Fast Open",
      hijack_mode: "DNS 劫持模式",
      quic_mode: "QUIC 模式",
      firewall_mode: "防火墙模式",
      version: "版本"
    };
    return labels[key] || String(key).replaceAll("_", " ");
  }

  function renderKeyValues(target, data, emptyText = "暂无数据") {
    empty(target);
    if (data === null || data === undefined || data === "") {
      target.append(node("div", "empty-state", emptyText));
      return;
    }
    if (typeof data !== "object" || Array.isArray(data)) {
      const prose = node("div", "prose", readableValue(data));
      target.append(prose);
      return;
    }
    const clean = safeObject(data);
    const entries = Object.entries(clean || {});
    if (!entries.length) {
      target.append(node("div", "empty-state", emptyText));
      return;
    }
    entries.forEach(([key, value]) => {
      const row = node("div", "kv-row");
      row.append(node("span", "kv-key", formatLabel(key)));
      row.append(node("span", "kv-value", readableValue(value)));
      target.append(row);
    });
  }

  function normalizePath(path) {
    return path.startsWith("/") ? path : `/${path}`;
  }

  async function api(path, options = {}) {
    const method = String(options.method || "GET").toUpperCase();
    const headers = new Headers({ Accept: "application/json" });
    if (options.body !== undefined) headers.set("Content-Type", "application/json");
    if (MUTATING_METHODS.has(method)) {
      if (!state.csrf) throw new ApiError(403, "csrf_missing", "安全令牌缺失，请重新登录");
      headers.set("X-CSRF-Token", state.csrf);
    }

    let response;
    try {
      response = await fetch(`${API_BASE}${normalizePath(path)}`, {
        method,
        headers,
        credentials: "same-origin",
        cache: "no-store",
        body: options.body === undefined ? undefined : JSON.stringify(options.body)
      });
    } catch (_error) {
      throw new ApiError(0, "network_error", "无法连接网关，请检查当前网络");
    }

    let envelope;
    try {
      envelope = await response.json();
    } catch (_error) {
      envelope = null;
    }

    if (response.status === 401) {
      if (path !== "/login") {
        showAuthenticated(false, "登录已过期，请重新登录");
        if (path !== "/session") window.setTimeout(loadSession, 0);
      }
      throw new ApiError(401, envelope?.error?.code, "登录已过期，请重新登录");
    }

    if (!response.ok || !envelope || envelope.ok !== true) {
      const code = envelope?.error?.code || `http_${response.status}`;
      const serverMessage = envelope?.error?.message;
      if (response.status === 403 && /csrf/i.test(code) && path !== "/login") {
        window.setTimeout(loadSession, 0);
      }
      throw new ApiError(response.status, code, serverMessage || defaultErrorMessage(response.status));
    }

    if (envelope.data && typeof envelope.data.csrf === "string") {
      state.csrf = envelope.data.csrf;
    }
    return { data: envelope.data, message: envelope.message || "" };
  }

  function defaultErrorMessage(status) {
    if (status === 400) return "请求格式不正确";
    if (status === 401) return "登录已过期";
    if (status === 403) return "安全校验失败，请刷新会话后重试";
    if (status === 404) return "请求的资源不存在";
    if (status === 409) return "配置正在被修改或已发生冲突，请刷新后重试";
    if (status === 422) return "输入内容未通过校验";
    if (status === 429) return "操作过于频繁，请稍后再试";
    if (status >= 500) return "网关内部出错，请稍后重试或查看终端日志";
    return "请求失败，请稍后重试";
  }

  function errorMessage(error, sensitiveLabel = "") {
    if (!(error instanceof ApiError)) return "操作未完成，请稍后重试";
    const category = defaultErrorMessage(error.status);
    if (sensitiveLabel) {
      if (error.status === 400 || error.status === 422) {
        return `${sensitiveLabel}未能添加：地址格式不受支持或内容校验未通过，原始内容已清除`;
      }
      return category;
    }
    const safe = safeString(error.message, 500);
    return safe && safe !== "请求失败" ? safe : category;
  }

  function loginErrorMessage(error) {
    if (!(error instanceof ApiError)) return "登录未完成，请检查当前网络";
    if (error.status === 401) return "管理密码不正确";
    if (error.status === 403) return "登录安全令牌已失效，请刷新页面后重试";
    if (error.status === 429) return "尝试次数过多，请稍后再试";
    return defaultErrorMessage(error.status);
  }

  function toast(message, tone = "neutral") {
    const region = $("#toast-region");
    const item = node("div", `toast ${tone}`, safeString(message, 600));
    region.append(item);
    window.setTimeout(() => item.remove(), tone === "bad" ? 7000 : 4200);
  }

  function setButtonBusy(button, busy, busyText = "处理中…") {
    if (!button) return;
    if (busy) {
      button.dataset.label = button.textContent;
      button.textContent = busyText;
      button.disabled = true;
      button.setAttribute("aria-busy", "true");
    } else {
      button.textContent = button.dataset.label || button.textContent;
      delete button.dataset.label;
      button.disabled = false;
      button.removeAttribute("aria-busy");
    }
  }

  function showAuthenticated(authenticated, message = "") {
    $("#login-view").hidden = authenticated;
    $("#app-view").hidden = !authenticated;
    if (!authenticated) {
      state.csrf = "";
      state.sessionExpiresAt = 0;
      $("#login-submit").disabled = true;
      $("#login-submit").textContent = "正在建立安全会话…";
      $("#login-message").textContent = message;
      window.setTimeout(() => $("#login-password").focus(), 0);
    }
  }

  function updateSessionLabel() {
    const label = $("#session-state");
    if (!state.sessionExpiresAt) {
      label.textContent = "已连接";
      return;
    }
    const remaining = Math.max(0, state.sessionExpiresAt - Math.floor(Date.now() / 1000));
    if (!remaining) {
      label.textContent = "会话待续";
      return;
    }
    label.textContent = remaining < 3600 ? `会话 ${Math.ceil(remaining / 60)} 分钟` : "已连接";
  }

  async function loadSession() {
    try {
      const { data } = await api("/session");
      if (data?.authenticated) {
        state.csrf = typeof data.csrf === "string" ? data.csrf : "";
        state.sessionExpiresAt = Number(data.expires_at || 0);
        showAuthenticated(true);
        updateSessionLabel();
        await loadTab("overview");
      } else {
        showAuthenticated(false);
        state.csrf = typeof data?.csrf === "string" ? data.csrf : "";
        $("#login-submit").disabled = !state.csrf;
        $("#login-submit").textContent = state.csrf ? "登录" : "安全会话不可用";
      }
    } catch (error) {
      if (error.status !== 401) showAuthenticated(false, errorMessage(error));
    }
  }

  async function login(event) {
    event.preventDefault();
    const input = $("#login-password");
    let password = input.value;
    input.value = "";
    $("#login-message").textContent = "";
    const button = $("#login-submit");
    setButtonBusy(button, true, "正在登录…");
    try {
      const { data } = await api("/login", { method: "POST", body: { password } });
      password = "";
      state.csrf = typeof data?.csrf === "string" ? data.csrf : "";
      state.sessionExpiresAt = Number(data?.expires_at || 0);
      if (!data?.authenticated) throw new ApiError(401, "login_failed", "密码不正确");
      showAuthenticated(true);
      updateSessionLabel();
      await loadTab("overview");
    } catch (error) {
      password = "";
      $("#login-message").textContent = loginErrorMessage(error);
      if (error instanceof ApiError && error.status === 403) {
        state.csrf = "";
        window.setTimeout(loadSession, 0);
      }
    } finally {
      setButtonBusy(button, false);
      if (!$("#login-view").hidden && !state.csrf) {
        button.disabled = true;
        button.textContent = "正在更新安全会话…";
      }
    }
  }

  async function logout() {
    const button = $("#logout-button");
    setButtonBusy(button, true, "退出中…");
    try {
      await api("/logout", { method: "POST", body: {} });
    } catch (error) {
      if (error.status !== 401) toast(errorMessage(error), "bad");
    } finally {
      setButtonBusy(button, false);
      showAuthenticated(false, "已安全退出");
      loadSession();
    }
  }

  async function confirmAction(title, message, confirmLabel = "确认", tone = "danger") {
    const dialog = $("#confirm-dialog");
    if (typeof dialog.showModal !== "function") {
      return window.confirm(`${title}\n\n${message}`);
    }
    $("#confirm-title").textContent = title;
    $("#confirm-message").textContent = message;
    const accept = $("#confirm-accept");
    accept.textContent = confirmLabel;
    accept.className = `button ${tone}`;
    dialog.returnValue = "cancel";
    dialog.showModal();
    return new Promise((resolve) => {
      dialog.addEventListener("close", () => resolve(dialog.returnValue === "confirm"), { once: true });
    });
  }

  function activateTab(name, focus = false) {
    if (!$("#panel-" + name)) return;
    state.activeTab = name;
    $$(".tab").forEach((tab) => {
      const active = tab.dataset.tab === name;
      tab.classList.toggle("active", active);
      tab.setAttribute("aria-selected", String(active));
      tab.tabIndex = active ? 0 : -1;
      if (active && focus) tab.focus();
    });
    $$(".panel").forEach((panel) => {
      panel.hidden = panel.id !== `panel-${name}`;
    });
    const reducedMotion = window.matchMedia?.("(prefers-reduced-motion: reduce)")?.matches;
    window.scrollTo({ top: 0, behavior: reducedMotion ? "auto" : "smooth" });
    loadTab(name);
  }

  async function loadTab(name) {
    try {
      if (name === "overview") await loadOverview();
      if (name === "exits") await loadExits();
      if (name === "rules") await loadRules();
      if (name === "dns") await loadDns();
      if (name === "runtime") await loadRuntime();
      if (name === "ops") await loadSettings();
    } catch (error) {
      toast(errorMessage(error), "bad");
    }
  }

  function overviewHealth(status, doctor) {
    if (status === null || status === undefined || status === "") return "warn";
    const flattened = JSON.stringify(safeObject({ status, doctor }) || {}).toLowerCase();
    if (/(fail|failed|inactive|error|critical|失败|异常)/.test(flattened)) return "bad";
    if (/(warn|warning|degraded|unknown|警告|未知)/.test(flattened)) return "warn";
    return "good";
  }

  function overviewStatusSummary(status) {
    if (typeof status === "string") return safeString(status, 80);
    if (Array.isArray(status)) return `${status.length} 项状态`;
    if (status && typeof status === "object") {
      const active = Object.values(status).filter((value) =>
        value === true || String(value).toLowerCase() === "active" || String(value).toLowerCase() === "ok"
      ).length;
      return `${active}/${Object.keys(status).length} 正常`;
    }
    return "状态未知";
  }

  function doctorSummaryText(doctor) {
    if (typeof doctor === "string") return safeString(doctor, 3000);
    if (Array.isArray(doctor)) {
      const failures = doctor.filter((item) =>
        String(item?.level || item?.status).toLowerCase() === "fail"
      );
      const warnings = doctor.filter((item) =>
        String(item?.level || item?.status).toLowerCase() === "warn"
      );
      const lines = doctor.slice(0, 12).map((item) => {
        if (typeof item === "string") return safeString(item, 240);
        const title = item.check || item.name || item.title || "检查项";
        const detail = item.detail || item.message || item.status || "";
        return `${title}：${safeString(detail, 240)}`;
      });
      return `${failures.length} 项失败，${warnings.length} 项警告\n${lines.join("\n")}`;
    }
    return readableValue(doctor);
  }

  function serviceEntries(status) {
    if (Array.isArray(status)) {
      return status.slice(0, 30).map((item, index) => {
        if (typeof item === "string") return { name: `状态 ${index + 1}`, value: item };
        return {
          name: item.name || item.service || item.title || `状态 ${index + 1}`,
          value: item.state ?? item.status ?? item.active ?? "未知"
        };
      });
    }
    if (status && typeof status === "object") {
      return Object.entries(safeObject(status) || {}).slice(0, 30)
        .map(([name, value]) => ({ name, value }));
    }
    return [{ name: "网关", value: status || "未知" }];
  }

  function appendMetric(target, label, value, detail) {
    const card = node("article", "metric-card");
    card.append(node("span", "metric-label", label));
    card.append(node("span", "metric-value", value));
    card.append(node("span", "metric-detail", detail));
    target.append(card);
  }

  async function loadOverview() {
    const { data } = await api("/overview");
    const info = data || {};
    $("#overview-version").textContent = safeString(info.version || "版本未知", 80);
    const cards = $("#overview-cards");
    empty(cards);
    appendMetric(cards, "手机平台", info.platform === "ios" ? "iOS" : info.platform === "android" ? "Android" : readableValue(info.platform), "当前网关属性");
    appendMetric(cards, "DoT 域名", safeString(info.dot_domain || "未配置", 120), "手机私密 DNS");
    appendMetric(cards, "网关状态", overviewStatusSummary(info.status), "Mihomo · MosDNS");
    const health = overviewHealth(info.status, info.doctor);
    appendMetric(cards, "自检结论", health === "good" ? "正常" : health === "warn" ? "有警告" : "需处理", "共享 doctor 检查");

    const healthPill = $("#overview-health");
    healthPill.className = `status-pill ${health}`;
    healthPill.textContent = health === "good" ? "全部正常" : health === "warn" ? "有警告" : "需处理";

    const services = $("#service-list");
    empty(services);
    serviceEntries(info.status).forEach((item) => {
      const value = readableValue(item.value);
      const lower = value.toLowerCase();
      const tone = /(active|ok|true|正常|运行)/.test(lower)
        ? "good"
        : /(warn|degraded|警告)/.test(lower) ? "warn" : "bad";
      const row = node("div", "status-row");
      row.append(node("span", `status-dot ${tone}`));
      row.append(node("span", "status-name", formatLabel(item.name)));
      row.append(node("span", "status-value", value));
      services.append(row);
    });
    $("#doctor-summary").textContent = doctorSummaryText(info.doctor);
  }

  function makeActionButton(label, action, tone = "") {
    const button = node("button", `mini-button ${tone}`.trim(), label);
    button.type = "button";
    button.dataset.action = action;
    return button;
  }

  function renderExitList() {
    const target = $("#exit-list");
    empty(target);
    $("#exit-count").textContent = `${state.exits.length} 个出口`;
    if (!state.exits.length) {
      target.append(node("div", "empty-state", "暂无出口，请先安全添加节点链接"));
      return;
    }
    state.exits.forEach((item) => {
      const card = node("article", "list-card");
      card.dataset.tag = item.tag;
      const main = node("div", "list-card-main");
      const title = node("div", "list-card-title");
      title.append(node("b", "", item.tag));
      title.append(node("span", "type-badge", item.type || "unknown"));
      main.append(title);
      const endpoint = item.server
        ? `${safeString(item.server, 180)}${item.server_port ? `:${item.server_port}` : ""}`
        : Array.isArray(item.members) ? item.members.join(" › ") : "由服务器管理";
      main.append(node("span", "list-card-detail", endpoint));
      card.append(main);

      const actions = node("div", "list-actions");
      const locked = item.type === "direct" || item.tag === "direct";
      const rename = makeActionButton("改名", "rename");
      rename.disabled = locked;
      if (locked) rename.title = "内建直连出口不能改名";
      actions.append(rename);
      const remove = makeActionButton("删除", "delete", "danger");
      remove.disabled = locked;
      if (locked) remove.title = "内建直连出口不能删除";
      actions.append(remove);
      card.append(actions);
      target.append(card);
    });
  }

  function normalizeExitOrder(order) {
    const tags = state.exits.map((item) => item.tag);
    const valid = (Array.isArray(order) ? order : []).filter((tag, index, all) =>
      tags.includes(tag) && all.indexOf(tag) === index
    );
    tags.forEach((tag) => {
      if (!valid.includes(tag)) valid.push(tag);
    });
    return valid;
  }

  function renderExitOrder() {
    const target = $("#exit-order");
    empty(target);
    if (!state.exitOrder.length) {
      target.append(node("li", "loading-state", "暂无可排序出口"));
      return;
    }
    state.exitOrder.forEach((tag, index) => {
      const row = node("li");
      row.dataset.index = String(index);
      row.append(node("span", "order-name", tag));
      const actions = node("span", "order-actions");
      const up = node("button", "", "↑");
      up.type = "button";
      up.dataset.direction = "up";
      up.disabled = index === 0;
      up.setAttribute("aria-label", `上移 ${tag}`);
      const down = node("button", "", "↓");
      down.type = "button";
      down.dataset.direction = "down";
      down.disabled = index === state.exitOrder.length - 1;
      down.setAttribute("aria-label", `下移 ${tag}`);
      actions.append(up, down);
      row.append(actions);
      target.append(row);
    });
  }

  function populateSelect(
    select,
    values,
    selected = "",
    includeDirect = false,
    directLabel = "VPS 本机直出（流量先到 VPS）"
  ) {
    empty(select);
    const unique = [];
    if (includeDirect) unique.push("direct");
    (Array.isArray(values) ? values : []).forEach((value) => {
      if (value && !unique.includes(value)) unique.push(value);
    });
    if (!unique.length) {
      const option = node("option", "", "暂无可选目标");
      option.value = "";
      select.append(option);
      select.disabled = true;
      return;
    }
    select.disabled = false;
    unique.forEach((value) => {
      const label = value === "direct" ? directLabel : value;
      const option = node("option", "", label);
      option.value = value;
      option.selected = value === selected;
      select.append(option);
    });
  }

  function renderGroups() {
    const target = $("#group-list");
    empty(target);
    if (!state.groups.length) {
      target.append(node("div", "empty-state", "暂无故障切换组"));
      return;
    }
    state.groups.forEach((group) => {
      const card = node("article", "list-card");
      card.dataset.tag = group.tag;
      const main = node("div", "list-card-main");
      const title = node("div", "list-card-title");
      title.append(node("b", "", group.tag));
      title.append(node("span", "type-badge", "FAILOVER"));
      main.append(title);
      main.append(node("span", "list-card-detail", (group.members || []).join(" › ") || "无成员"));
      const actions = node("div", "list-actions");
      actions.append(makeActionButton("改成员", "edit-group"));
      actions.append(makeActionButton("删除", "delete-group", "danger"));
      card.append(main, actions);
      target.append(card);
    });
  }

  async function loadExits() {
    const [exitResponse, groupResponse] = await Promise.all([api("/exits"), api("/groups")]);
    const exitData = exitResponse.data || {};
    const groupData = groupResponse.data || {};
    state.exits = Array.isArray(exitData.items) ? exitData.items.map((item) => ({
      tag: safeString(item.tag, 80),
      type: safeString(item.type, 40),
      server: item.server ? safeString(item.server, 200) : "",
      server_port: item.server_port,
      members: Array.isArray(item.members) ? item.members.map((member) => safeString(member, 80)) : []
    })) : [];
    state.groups = Array.isArray(groupData.items) ? groupData.items.map((item) => ({
      tag: safeString(item.tag, 80),
      members: Array.isArray(item.members) ? item.members.map((member) => safeString(member, 80)) : []
    })) : [];
    state.exitTargets = Array.isArray(exitData.targets) ? exitData.targets.map(String) : state.exits.map((item) => item.tag);
    state.exitOrder = normalizeExitOrder(exitData.order);
    renderExitList();
    renderExitOrder();
    renderGroups();
    populateSelect($("#default-exit"), state.exitTargets, String(exitData.default || ""));
    $("#save-order").disabled = true;
  }

  async function addExit(event) {
    event.preventDefault();
    const input = $("#exit-link");
    let link = input.value.trim();
    input.value = "";
    event.currentTarget.reset();
    if (!link) return;
    const button = $("button[type='submit']", event.currentTarget);
    setButtonBusy(button, true, "正在校验…");
    try {
      const result = await api("/exits", { method: "POST", body: { link } });
      link = "";
      toast(result.message || "出口已添加，原始链接已从页面清除", "good");
      await loadExits();
    } catch (error) {
      link = "";
      toast(errorMessage(error, "节点"), "bad");
    } finally {
      link = "";
      setButtonBusy(button, false);
    }
  }

  async function handleExitAction(event) {
    const button = event.target.closest("button[data-action]");
    if (!button) return;
    const card = button.closest("[data-tag]");
    const tag = card?.dataset.tag;
    if (!tag) return;

    if (button.dataset.action === "rename") {
      const name = window.prompt(`把出口“${tag}”改名为：`, tag);
      if (!name || name === tag) return;
      try {
        const result = await api(`/exits/${encodeURIComponent(tag)}`, {
          method: "PATCH", body: { name: name.trim() }
        });
        toast(result.message || `出口已改名为 ${name.trim()}`, "good");
        await loadExits();
      } catch (error) {
        toast(errorMessage(error), "bad");
      }
    }

    if (button.dataset.action === "delete") {
      const confirmed = await confirmAction(
        "删除出口",
        `确认删除“${tag}”？引用它的默认出口、故障组或分流规则可能需要重新选择。`,
        "删除出口"
      );
      if (!confirmed) return;
      try {
        const result = await api(`/exits/${encodeURIComponent(tag)}`, { method: "DELETE" });
        toast(result.message || `已删除出口 ${tag}`, "good");
        await loadExits();
      } catch (error) {
        toast(errorMessage(error), "bad");
      }
    }
  }

  function moveExitOrder(event) {
    const button = event.target.closest("button[data-direction]");
    if (!button) return;
    const index = Number(button.closest("li")?.dataset.index);
    if (!Number.isInteger(index)) return;
    const targetIndex = button.dataset.direction === "up" ? index - 1 : index + 1;
    if (targetIndex < 0 || targetIndex >= state.exitOrder.length) return;
    [state.exitOrder[index], state.exitOrder[targetIndex]] =
      [state.exitOrder[targetIndex], state.exitOrder[index]];
    renderExitOrder();
    $("#save-order").disabled = false;
  }

  async function saveExitOrder() {
    const button = $("#save-order");
    let saved = false;
    setButtonBusy(button, true, "保存中…");
    try {
      const result = await api("/exits/order", {
        method: "PUT", body: { order: state.exitOrder.slice() }
      });
      saved = true;
      toast(result.message || "出口顺序已保存", "good");
      await loadExits();
    } catch (error) {
      toast(errorMessage(error), "bad");
    } finally {
      setButtonBusy(button, false);
      button.disabled = saved;
    }
  }

  async function saveDefaultExit(event) {
    event.preventDefault();
    const button = $("button[type='submit']", event.currentTarget);
    setButtonBusy(button, true, "保存中…");
    try {
      const tag = $("#default-exit").value;
      const result = await api("/default-exit", { method: "PUT", body: { tag } });
      toast(result.message || `默认出口已设为 ${tag}`, "good");
    } catch (error) {
      toast(errorMessage(error), "bad");
    } finally {
      setButtonBusy(button, false);
    }
  }

  async function addGroup(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const name = $("#group-name").value.trim();
    const members = $("#group-members").value.trim().split(/[\s,，]+/).filter(Boolean);
    if (members.length < 2 || new Set(members).size !== members.length) {
      toast("故障切换组至少需要两个不重复的成员", "bad");
      return;
    }
    const button = $("button[type='submit']", form);
    setButtonBusy(button, true, "创建中…");
    try {
      const result = await api("/groups", { method: "POST", body: { name, members } });
      form.reset();
      toast(result.message || `故障组 ${name} 已创建`, "good");
      await loadExits();
    } catch (error) {
      toast(errorMessage(error), "bad");
    } finally {
      setButtonBusy(button, false);
    }
  }

  async function handleGroupAction(event) {
    const button = event.target.closest("button[data-action]");
    if (!button) return;
    const tag = button.closest("[data-tag]")?.dataset.tag;
    const group = state.groups.find((item) => item.tag === tag);
    if (!tag || !group) return;
    if (button.dataset.action === "edit-group") {
      const value = window.prompt(`编辑“${tag}”成员（用空格分隔）：`, group.members.join(" "));
      if (!value) return;
      const members = value.trim().split(/[\s,，]+/).filter(Boolean);
      if (members.length < 2 || new Set(members).size !== members.length) {
        toast("故障切换组至少需要两个不重复的成员", "bad");
        return;
      }
      try {
        const result = await api(`/groups/${encodeURIComponent(tag)}`, {
          method: "PATCH", body: { members }
        });
        toast(result.message || `故障组 ${tag} 已更新`, "good");
        await loadExits();
      } catch (error) {
        toast(errorMessage(error), "bad");
      }
    }
    if (button.dataset.action === "delete-group") {
      const confirmed = await confirmAction(
        "删除故障切换组",
        `确认删除“${tag}”？使用该组的默认出口或分流规则需要重新选择。`,
        "删除组"
      );
      if (!confirmed) return;
      try {
        const result = await api(`/groups/${encodeURIComponent(tag)}`, { method: "DELETE" });
        toast(result.message || `已删除故障组 ${tag}`, "good");
        await loadExits();
      } catch (error) {
        toast(errorMessage(error), "bad");
      }
    }
  }

  function targetOptions(select, selected = "") {
    populateSelect(
      select,
      state.ruleTargets,
      selected,
      true,
      "手机直连（MosDNS 返回真实地址，不经过 VPS）"
    );
  }

  function renderRules(items) {
    const target = $("#rule-list");
    empty(target);
    $("#rule-count").textContent = `${items.length} 条规则`;
    if (!items.length) {
      target.append(node("div", "empty-state", "暂无自定义域名规则"));
      return;
    }
    items.forEach((item) => {
      const row = node("article", "table-row");
      row.dataset.domain = item.domain;
      const info = node("div");
      info.append(node("div", "table-primary", item.domain));
      info.append(node("div", "table-secondary", item.kind === "direct" || item.target === "direct"
        ? "DNS 返回真实地址，手机直接连接"
        : `经网关转发 · ${item.kind || "域名规则"}`));
      const controls = node("div", "table-controls");
      const select = node("select");
      select.setAttribute("aria-label", `${item.domain} 的目标`);
      targetOptions(select, item.target);
      controls.append(select);
      controls.append(makeActionButton("保存", "save-rule"));
      controls.append(makeActionButton("删除", "delete-rule", "danger"));
      row.append(info, controls);
      target.append(row);
    });
  }

  function renderRulesets(items) {
    const target = $("#ruleset-list");
    empty(target);
    if (!items.length) {
      target.append(node("div", "empty-state", "暂无外部规则集"));
      return;
    }
    items.forEach((item) => {
      const row = node("article", "table-row");
      row.dataset.name = item.name;
      const info = node("div");
      const targetLabel = item.target === "direct"
        ? "手机直连（不经 VPS）"
        : (item.target || "未指定");
      info.append(node("div", "table-primary", item.label || item.name));
      info.append(node("div", "table-secondary",
        `${safeString(item.url || "地址由服务器管理", 260)} · ${item.behavior || "自动"} → ${targetLabel}`));
      const controls = node("div", "table-controls");
      controls.append(makeActionButton("改名称", "label-ruleset"));
      controls.append(makeActionButton("删除", "delete-ruleset", "danger"));
      row.append(info, controls);
      target.append(row);
    });
  }

  async function loadRules() {
    const [rulesResponse, rulesetResponse] = await Promise.all([api("/rules"), api("/rulesets")]);
    const rulesData = rulesResponse.data || {};
    const rulesetData = rulesetResponse.data || {};
    state.ruleTargets = Array.isArray(rulesData.targets) ? rulesData.targets.map(String) : state.exitTargets.slice();
    targetOptions($("#rule-target"));
    targetOptions($("#ruleset-target"));
    const rules = Array.isArray(rulesData.items) ? rulesData.items.map((item) => ({
      domain: safeString(item.domain, 260),
      target: safeString(item.target, 80),
      kind: safeString(item.kind, 60)
    })) : [];
    const rulesets = Array.isArray(rulesetData.items) ? rulesetData.items.map((item) => ({
      name: safeString(item.name, 100),
      label: safeString(item.label || "", 100),
      url: safeString(item.url || "", 400),
      target: safeString(item.target || "", 80),
      behavior: safeString(item.behavior || "", 40)
    })) : [];
    renderRules(rules);
    renderRulesets(rulesets);
  }

  async function addRule(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const domain = $("#rule-domain").value.trim().toLowerCase();
    const target = $("#rule-target").value;
    const button = $("button[type='submit']", form);
    setButtonBusy(button, true, "添加中…");
    try {
      const result = await api("/rules", { method: "POST", body: { domain, target } });
      form.reset();
      toast(result.message || `已添加 ${domain} → ${target === "direct" ? "手机直连" : target}`, "good");
      await loadRules();
    } catch (error) {
      toast(errorMessage(error), "bad");
    } finally {
      setButtonBusy(button, false);
    }
  }

  async function handleRuleAction(event) {
    const button = event.target.closest("button[data-action]");
    if (!button) return;
    const row = button.closest("[data-domain]");
    const domain = row?.dataset.domain;
    if (!domain) return;
    if (button.dataset.action === "save-rule") {
      const target = $("select", row).value;
      try {
        const result = await api(`/rules/${encodeURIComponent(domain)}`, {
          method: "PATCH", body: { target }
        });
        toast(result.message || `${domain} 已改为 ${target === "direct" ? "手机直连" : target}`, "good");
        await loadRules();
      } catch (error) {
        toast(errorMessage(error), "bad");
      }
    }
    if (button.dataset.action === "delete-rule") {
      const confirmed = await confirmAction(
        "删除域名规则",
        `确认删除“${domain}”的自定义分流？之后它会重新按系统规则判定。`,
        "删除规则"
      );
      if (!confirmed) return;
      try {
        const result = await api(`/rules/${encodeURIComponent(domain)}`, { method: "DELETE" });
        toast(result.message || `已删除 ${domain} 的规则`, "good");
        await loadRules();
      } catch (error) {
        toast(errorMessage(error), "bad");
      }
    }
  }

  async function addRuleset(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const urlInput = $("#ruleset-url");
    let submittedUrl = urlInput.value.trim();
    urlInput.value = "";
    const body = {
      url: submittedUrl,
      target: $("#ruleset-target").value
    };
    submittedUrl = "";
    const label = $("#ruleset-label").value.trim();
    const behavior = $("#ruleset-behavior").value;
    if (label) body.label = label;
    if (behavior) body.behavior = behavior;
    const button = $("button[type='submit']", form);
    setButtonBusy(button, true, "下载校验中…");
    try {
      const result = await api("/rulesets", { method: "POST", body });
      submittedUrl = "";
      body.url = "";
      form.reset();
      toast(result.message || "规则集已添加", "good");
      await loadRules();
    } catch (error) {
      submittedUrl = "";
      body.url = "";
      toast(errorMessage(error, "规则集"), "bad");
    } finally {
      submittedUrl = "";
      body.url = "";
      setButtonBusy(button, false);
    }
  }

  async function handleRulesetAction(event) {
    const button = event.target.closest("button[data-action]");
    if (!button) return;
    const row = button.closest("[data-name]");
    const name = row?.dataset.name;
    if (!name) return;
    if (button.dataset.action === "label-ruleset") {
      const label = window.prompt(`规则集“${name}”的新显示名称（留空清除）：`, "");
      if (label === null) return;
      try {
        const result = await api(`/rulesets/${encodeURIComponent(name)}`, {
          method: "PATCH", body: { label: label.trim() }
        });
        toast(result.message || "规则集名称已更新", "good");
        await loadRules();
      } catch (error) {
        toast(errorMessage(error), "bad");
      }
    }
    if (button.dataset.action === "delete-ruleset") {
      const confirmed = await confirmAction(
        "删除规则集",
        `确认删除“${name}”及其分流引用？本机缓存的受管规则文件也可能被清理。`,
        "删除规则集"
      );
      if (!confirmed) return;
      try {
        const result = await api(`/rulesets/${encodeURIComponent(name)}`, { method: "DELETE" });
        toast(result.message || `已删除规则集 ${name}`, "good");
        await loadRules();
      } catch (error) {
        toast(errorMessage(error), "bad");
      }
    }
  }

  function splitAddresses(text) {
    return text.split(/[\n\r,，]+/).map((item) => item.trim()).filter(Boolean);
  }

  function renderCurrentDns(target, values) {
    empty(target);
    const items = Array.isArray(values) ? values : [];
    if (!items.length) {
      target.append(node("span", "dns-current-empty", "服务器未返回可展示的安全摘要"));
      return;
    }
    items.forEach((value) => {
      const endpoint = node("div", "dns-current-endpoint", safeString(value, 600));
      endpoint.setAttribute("role", "listitem");
      target.append(endpoint);
    });
  }

  async function loadDns() {
    const { data } = await api("/dns");
    renderCurrentDns($("#dns-current-remote"), data?.remote);
    renderCurrentDns($("#dns-current-local"), data?.local);
    $("#dns-remote").value = "";
    $("#dns-local").value = "";
  }

  async function saveDns(event, kind) {
    event.preventDefault();
    const textarea = kind === "remote" ? $("#dns-remote") : $("#dns-local");
    const addresses = splitAddresses(textarea.value);
    textarea.value = "";
    if (!addresses.length) {
      toast("请手动输入至少一个完整 DNS 上游地址；留空不会修改当前配置", "bad");
      return;
    }
    if (addresses.length > 8) {
      toast("一次最多可配置 8 个 DNS 上游地址", "bad");
      return;
    }
    const body = { addresses };
    const button = $("button[type='submit']", event.currentTarget);
    setButtonBusy(button, true, "校验应用中…");
    try {
      const result = await api(`/dns/${kind}`, { method: "PUT", body });
      body.addresses = [];
      toast(result.message || `${kind === "remote" ? "国际" : "国内"} DNS 上游已更新`, "good");
      await loadDns();
    } catch (error) {
      body.addresses = [];
      toast(errorMessage(error, "DNS 上游"), "bad");
    } finally {
      body.addresses = [];
      setButtonBusy(button, false);
    }
  }

  async function loadRuntime() {
    if (state.runtimeLoading) return;
    state.runtimeLoading = true;
    const logLines = Math.min(200, Math.max(10, Number($("#log-lines").value) || 100));
    try {
      const results = await Promise.allSettled([
        api("/runtime"),
        api("/traffic"),
        api(`/logs?lines=${logLines}`)
      ]);
      const [runtime, traffic, logs] = results;
      if (runtime.status === "fulfilled") {
        renderKeyValues($("#runtime-summary"), runtime.value.data, "暂无运行摘要");
      } else {
        renderKeyValues($("#runtime-summary"), errorMessage(runtime.reason));
      }
      if (traffic.status === "fulfilled") {
        renderKeyValues($("#traffic-summary"), traffic.value.data, "暂无流量数据");
      } else {
        renderKeyValues($("#traffic-summary"), errorMessage(traffic.reason));
      }
      if (logs.status === "fulfilled") {
        const lines = Array.isArray(logs.value.data?.lines) ? logs.value.data.lines : [];
        $("#runtime-logs").textContent = lines.length
          ? lines.map((line) => safeString(line, 4000)).join("\n")
          : "暂无日志";
      } else {
        $("#runtime-logs").textContent = errorMessage(logs.reason);
      }
    } finally {
      state.runtimeLoading = false;
    }
  }

  async function loadSettings() {
    const { data } = await api("/settings");
    const settings = data || {};
    renderKeyValues($("#settings-summary"), {
      hijack_mode: settings.hijack_mode,
      quic_mode: settings.quic_mode,
      firewall_mode: settings.firewall_mode
    });
    $("#tfo-enabled").checked = Boolean(settings.tfo);
  }

  async function saveTfo(event) {
    event.preventDefault();
    const button = $("button[type='submit']", event.currentTarget);
    const enabled = $("#tfo-enabled").checked;
    setButtonBusy(button, true, "应用中…");
    try {
      const result = await api("/settings/tfo", { method: "PUT", body: { enabled } });
      toast(result.message || `TCP Fast Open 已${enabled ? "开启" : "关闭"}`, "good");
      await loadSettings();
    } catch (error) {
      toast(errorMessage(error), "bad");
    } finally {
      setButtonBusy(button, false);
    }
  }

  const operationDetails = {
    restart: {
      title: "重启网关服务",
      message: "重启期间 DNS 与代理流量可能短暂中断。确认继续？",
      label: "确认重启",
      tone: "danger",
      pending: "正在重启并检查服务…"
    },
    "rules-update": {
      title: "更新规则库",
      message: "将下载并校验 geosite 与订阅规则集；失败时继续使用上一份有效规则。确认开始？",
      label: "开始更新",
      tone: "warning",
      pending: "正在更新规则库…"
    }
  };

  function showOperationResult(message, good = true) {
    const target = $("#operation-result");
    target.className = `operation-result ${good ? "good" : "bad"}`;
    target.textContent = safeString(message, 1000);
  }

  async function runOperation(name, body = {}, sourceButton = null, skipConfirmation = false) {
    const details = operationDetails[name];
    if (details && !skipConfirmation) {
      const confirmed = await confirmAction(details.title, details.message, details.label, details.tone);
      if (!confirmed) return;
    }
    setButtonBusy(sourceButton, true, details?.pending || "处理中…");
    showOperationResult(details?.pending || "正在执行操作…", true);
    try {
      const result = await api(`/actions/${name}`, { method: "POST", body });
      showOperationResult(result.message || "操作已提交并完成", true);
      toast(result.message || "操作已完成", "good");
      if (name === "restart" || name === "rules-update") await loadOverview();
    } catch (error) {
      const message = errorMessage(error);
      showOperationResult(message, false);
      toast(message, "bad");
    } finally {
      setButtonBusy(sourceButton, false);
    }
  }

  async function handleOperationButton(event) {
    const button = event.target.closest("[data-operation]");
    if (!button) return;
    const operation = button.dataset.operation;
    if (operation === "snapshot") {
      await runOperation("snapshot", {}, button, true);
      return;
    }
    await runOperation(operation, {}, button);
  }

  async function rollback(event) {
    event.preventDefault();
    const index = Number($("#rollback-index").value);
    if (!Number.isInteger(index) || index < 0) {
      toast("快照序号必须是大于或等于 0 的整数", "bad");
      return;
    }
    const confirmed = await confirmAction(
      "回滚本机快照",
      `即将回滚到序号 ${index} 的快照，当前受管配置和服务状态会被覆盖，连接可能中断。`,
      "确认回滚",
      "danger"
    );
    if (!confirmed) return;
    const button = $("button[type='submit']", event.currentTarget);
    setButtonBusy(button, true, "正在回滚…");
    showOperationResult(`正在回滚快照 ${index}…`, true);
    try {
      await api("/actions/rollback", { method: "POST", body: { index } });
      const message = "回滚任务已启动，连接可能中断";
      showOperationResult(message, true);
      toast(message, "good");
    } catch (error) {
      const message = errorMessage(error);
      showOperationResult(message, false);
      toast(message, "bad");
    } finally {
      setButtonBusy(button, false);
    }
  }

  async function softwareUpdate() {
    const confirmed = await confirmAction(
      "升级 PDG 软件",
      "升级会安装最新发布版本和指定内核，期间网关与本页面可能短暂断开。服务器会先创建快照，健康门失败时自动回滚。",
      "确认开始升级",
      "warning"
    );
    if (!confirmed) return;
    const button = $("#software-update");
    setButtonBusy(button, true, "正在启动升级…");
    showOperationResult("正在检查可用发布版本并启动升级…", true);
    try {
      await api("/actions/software-update", {
        method: "POST", body: { confirm: true }
      });
      const message = "升级任务已启动，连接可能中断；请稍后重新登录核验";
      showOperationResult(message, true);
      toast(message, "good");
    } catch (error) {
      const message = errorMessage(error);
      showOperationResult(message, false);
      toast(message, "bad");
      setButtonBusy(button, false);
    }
  }

  function bindEvents() {
    $("#login-form").addEventListener("submit", login);
    $("#logout-button").addEventListener("click", logout);
    $("#toggle-password").addEventListener("click", () => {
      const input = $("#login-password");
      const visible = input.type === "text";
      input.type = visible ? "password" : "text";
      $("#toggle-password").textContent = visible ? "显示" : "隐藏";
      $("#toggle-password").setAttribute("aria-label", visible ? "显示密码" : "隐藏密码");
      $("#toggle-password").setAttribute("aria-pressed", String(!visible));
    });

    $$(".tab").forEach((tab) => {
      tab.addEventListener("click", () => activateTab(tab.dataset.tab));
      tab.addEventListener("keydown", (event) => {
        if (!["ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown", "Home", "End"].includes(event.key)) return;
        event.preventDefault();
        const tabs = $$(".tab");
        const current = tabs.indexOf(event.currentTarget);
        let next = current;
        if (event.key === "Home") next = 0;
        if (event.key === "End") next = tabs.length - 1;
        if (event.key === "ArrowLeft" || event.key === "ArrowUp") next = (current - 1 + tabs.length) % tabs.length;
        if (event.key === "ArrowRight" || event.key === "ArrowDown") next = (current + 1) % tabs.length;
        activateTab(tabs[next].dataset.tab, true);
      });
    });

    $$("[data-go-tab]").forEach((button) => {
      button.addEventListener("click", () => activateTab(button.dataset.goTab, true));
    });
    $("#refresh-button").addEventListener("click", () => loadTab(state.activeTab));
    $("#exit-form").addEventListener("submit", addExit);
    $("#exit-list").addEventListener("click", handleExitAction);
    $("#exit-order").addEventListener("click", moveExitOrder);
    $("#save-order").addEventListener("click", saveExitOrder);
    $("#default-exit-form").addEventListener("submit", saveDefaultExit);
    $("#group-form").addEventListener("submit", addGroup);
    $("#group-list").addEventListener("click", handleGroupAction);
    $("#rule-form").addEventListener("submit", addRule);
    $("#rule-list").addEventListener("click", handleRuleAction);
    $("#ruleset-form").addEventListener("submit", addRuleset);
    $("#ruleset-list").addEventListener("click", handleRulesetAction);
    $("#dns-remote-form").addEventListener("submit", (event) => saveDns(event, "remote"));
    $("#dns-local-form").addEventListener("submit", (event) => saveDns(event, "local"));
    $("#runtime-refresh").addEventListener("click", loadRuntime);
    $("#log-lines").addEventListener("change", loadRuntime);
    $("#tfo-form").addEventListener("submit", saveTfo);
    $("#panel-ops").addEventListener("click", handleOperationButton);
    $("#rollback-form").addEventListener("submit", rollback);
    $("#software-update").addEventListener("click", softwareUpdate);

    document.addEventListener("visibilitychange", () => {
      if (!document.hidden && state.activeTab === "runtime") loadRuntime();
    });
    window.setInterval(() => {
      updateSessionLabel();
      if (!document.hidden && state.activeTab === "runtime" && !$("#app-view").hidden) loadRuntime();
    }, 15000);
  }

  bindEvents();
  loadSession();
})();
