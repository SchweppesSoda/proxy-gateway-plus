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
    groupProviders: [],
    groupRevision: "",
    editingGroupRevision: "",
    editingGroup: "",
    groupMembers: [],
    groupProviderSelection: [],
    groupPicker: null,
    textEntryResolve: null,
    exitOrder: [],
    exitTargets: [],
    ruleTargets: [],
    runtimeLoading: false,
    exitDiagnostics: new Map(),
    exitDiagnosticsTesting: false,
    replaceExitTag: "",
    snapshots: [],
    maintenanceJobs: [],
    trackedMaintenanceJobs: new Set(),
    maintenancePollTimer: 0,
    maintenancePollDisconnected: false,
    importPreview: null,
    exportKind: "",
    mobileMoreRestoreFocus: false
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
  const mobileNavigationQuery = window.matchMedia("(max-width: 759px)");

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
      available: "接口状态",
      active: "运行状态",
      status: "状态",
      service: "服务",
      services: "服务",
      connections: "连接数",
      connection_count: "连接数",
      upload: "上传",
      download: "下载",
      uploadTotal: "累计上传",
      downloadTotal: "累计下载",
      upload_total: "累计上传",
      download_total: "累计下载",
      byExit: "按出口统计",
      memory: "内存占用",
      memory_usage: "内存占用",
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
      hijack_mode: "DNS 劫持范围",
      quic_mode: "QUIC 处理方式",
      firewall_mode: "入站访问控制",
      version: "内核版本",
      outbounds: "出口总数",
      rules: "分流规则",
      managedFiles: "受管文件",
      bundleMosdns: "包含 MosDNS 配置",
      bundleRulesets: "包含规则集元数据",
      proxies: "代理节点",
      proxyProviders: "代理提供器（Provider）",
      proxyGroups: "代理策略组",
      ruleProviders: "规则提供器（Provider）",
      plugins: "MosDNS 插件",
      mode: "应用方式"
    };
    return labels[key] || String(key).replace(/([a-z])([A-Z])/g, "$1 $2").replaceAll("_", " ");
  }

  function formatSummaryValue(key, value) {
    const enumLabels = {
      hijack_mode: {
        all: "代理所有中国大陆以外域名",
        gfw: "仅代理规则列表中的域名",
        unknown: "配置状态未知"
      },
      quic_mode: {
        tproxy: "透明代理 QUIC（TProxy）",
        reject: "阻断 QUIC，并回落到 TCP",
        unknown: "配置状态未知"
      },
      firewall_mode: {
        managed: "由 PDG 管理",
        external: "由外部防火墙管理",
        unknown: "配置状态未知"
      },
      mode: { replace: "完整替换", merge: "合并现有配置" }
    };
    if (enumLabels[key]?.[value]) return enumLabels[key][value];
    if (["upload", "download", "uploadTotal", "downloadTotal",
      "upload_total", "download_total", "memory", "memory_usage"].includes(key)) {
      return formatBytes(value);
    }
    if (["outbounds", "rules", "managedFiles", "proxies", "proxyProviders",
      "proxyGroups", "ruleProviders", "plugins"].includes(key)
        && Number.isFinite(Number(value))) {
      return `${new Intl.NumberFormat("zh-CN").format(Number(value))} 项`;
    }
    if (key === "available" && typeof value === "boolean") {
      return value ? "正常" : "暂不可用";
    }
    if (["bundleMosdns", "bundleRulesets"].includes(key) && typeof value === "boolean") {
      return value ? "是" : "否";
    }
    return readableValue(value);
  }

  function formatExitName(tag) {
    const value = String(tag ?? "");
    return value === "jp" ? "JP" : value;
  }

  function exitByTag(tag) {
    return state.exits.find((item) => item.tag === tag);
  }

  function isProbeableExit(item) {
    return Boolean(item && item.tag !== "direct" && item.type !== "urltest");
  }

  function isReplaceableProxy(item) {
    return Boolean(item && item.tag !== "direct" && !["direct", "urltest"].includes(item.type));
  }

  function ruleTargetLabel(tag, phoneDirectLabel = "手机直连（不经 VPS）") {
    if (tag === "direct") return phoneDirectLabel;
    const item = exitByTag(tag);
    if (item?.type === "direct") return `${formatExitName(tag)}（VPS 本机直出）`;
    return formatExitName(tag) || "未指定";
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
      row.append(node("span", "kv-value", formatSummaryValue(key, value)));
      target.append(row);
    });
  }

  const UNSAFE_NAME_CODEPOINTS = new Set([
    0x00ad, 0x034f, 0x061c, 0x115f, 0x1160, 0x17b4, 0x17b5,
    0x180e, 0x200b, 0x200e, 0x200f, 0x202a, 0x202b, 0x202c,
    0x202d, 0x202e, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064,
    0x2066, 0x2067, 0x2068, 0x2069, 0x206a, 0x206b, 0x206c,
    0x206d, 0x206e, 0x206f, 0x3164, 0xfeff, 0xffa0
  ]);
  const FORMAT_CONTROL_RE = /\p{Cf}/u;

  function normalizeIdentifierName(value) {
    if (typeof value !== "string") throw new Error("名称必须是文本");
    const canonical = value.normalize("NFC");
    const invalid = Array.from(canonical).some((character) => {
      const codepoint = character.codePointAt(0);
      return codepoint < 0x20 || (codepoint >= 0x7f && codepoint <= 0x9f)
        || (codepoint >= 0xd800 && codepoint <= 0xdfff)
        || codepoint === 0x2028 || codepoint === 0x2029
        || (FORMAT_CONTROL_RE.test(character) && codepoint !== 0x200d)
        || UNSAFE_NAME_CODEPOINTS.has(codepoint);
    });
    const name = canonical.trim();
    const points = Array.from(name);
    const bytes = new TextEncoder().encode(name);
    if (!name || points.length > 64 || bytes.length > 256 || invalid) {
      throw new Error("名称需为 1–64 个字符，且不能包含控制字符或危险隐形字符");
    }
    return name;
  }

  function safeIdentifierName(value) {
    try { return normalizeIdentifierName(value); }
    catch (_error) { return ""; }
  }

  function identifierPath(value) {
    const bytes = new TextEncoder().encode(normalizeIdentifierName(value));
    let binary = "";
    bytes.forEach((byte) => { binary += String.fromCharCode(byte); });
    return `~${btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "")}`;
  }

  function groupTypeLabel(type) {
    return ({
      select: "手动选择",
      "url-test": "自动测速",
      fallback: "故障切换",
      "load-balance": "负载均衡"
    })[type] || type;
  }

  function updateThemeButton() {
    const button = $("#theme-toggle");
    if (!button || !window.PDGTheme) return;
    const labels = { system: "跟随系统", light: "浅色", dark: "深色" };
    const icons = { system: "◐", light: "☀", dark: "☾" };
    const mode = window.PDGTheme.mode;
    const label = labels[mode] || labels.system;
    $("#theme-toggle-icon").textContent = icons[mode] || icons.system;
    button.title = `界面主题：${label}`;
    button.setAttribute("aria-label", `选择界面主题，当前${label}`);
    $$("#theme-dialog [data-theme-mode]").forEach((option) => {
      const selected = option.dataset.themeMode === mode;
      option.classList.toggle("selected", selected);
      option.setAttribute("aria-pressed", String(selected));
    });
  }

  function closeThemeDialog(restoreFocus = true) {
    const dialog = $("#theme-dialog");
    $("#theme-toggle").setAttribute("aria-expanded", "false");
    if (dialog.open) dialog.close();
    if (restoreFocus) $("#theme-toggle").focus();
  }

  function openThemeDialog() {
    const dialog = $("#theme-dialog");
    if (typeof dialog.showModal !== "function") {
      window.PDGTheme?.set(window.PDGTheme.resolved === "dark" ? "light" : "dark");
      updateThemeButton();
      return;
    }
    updateThemeButton();
    $("#theme-toggle").setAttribute("aria-expanded", "true");
    if (!dialog.open) dialog.showModal();
    window.requestAnimationFrame(() => {
      $("[data-theme-mode][aria-pressed='true']", dialog)?.focus();
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

  async function binaryApi(path, bytes, contentType) {
    const headers = new Headers({
      Accept: "application/json",
      "Content-Type": contentType || "application/octet-stream",
      "X-CSRF-Token": state.csrf
    });
    if (!state.csrf) throw new ApiError(403, "csrf_missing", "安全令牌缺失，请重新登录");
    let response;
    try {
      response = await fetch(`${API_BASE}${normalizePath(path)}`, {
        method: "POST", headers, credentials: "same-origin", cache: "no-store", body: bytes
      });
    } catch (_error) {
      throw new ApiError(0, "network_error", "无法连接网关，请检查当前网络");
    }
    let envelope = null;
    try { envelope = await response.json(); } catch (_error) { envelope = null; }
    if (response.status === 401) {
      showAuthenticated(false, "登录已过期，请重新登录");
      window.setTimeout(loadSession, 0);
      throw new ApiError(401, envelope?.error?.code, "登录已过期，请重新登录");
    }
    if (!response.ok || envelope?.ok !== true) {
      throw new ApiError(
        response.status, envelope?.error?.code,
        envelope?.error?.message || defaultErrorMessage(response.status)
      );
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
      closeThemeDialog(false);
      closeMobileMore(false);
      stopMaintenancePolling();
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
        await loadMaintenanceJobs({ silent: true });
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
      await loadMaintenanceJobs({ silent: true });
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

  function requestTextEntry({ title, message = "", label = "名称", value = "",
    help = "", submitLabel = "保存", allowEmpty = false, maxLength = 64 }) {
    const dialog = $("#text-entry-dialog");
    if (typeof dialog.showModal !== "function") {
      toast("当前浏览器不支持站内编辑对话框，请升级浏览器后重试", "bad");
      return Promise.resolve(null);
    }
    if (state.textEntryResolve) settleTextEntry(null);
    $("#text-entry-title").textContent = title;
    $("#text-entry-message").textContent = message;
    $("#text-entry-label").textContent = label;
    $("#text-entry-help").textContent = help;
    $("#text-entry-submit").textContent = submitLabel;
    const input = $("#text-entry-value");
    input.value = value;
    input.required = !allowEmpty;
    input.maxLength = maxLength;
    dialog.showModal();
    window.setTimeout(() => { input.focus(); input.select(); }, 0);
    return new Promise((resolve) => { state.textEntryResolve = resolve; });
  }

  function settleTextEntry(value) {
    const resolve = state.textEntryResolve;
    state.textEntryResolve = null;
    const dialog = $("#text-entry-dialog");
    if (dialog.open) dialog.close(value === null ? "cancel" : "submit");
    if (resolve) resolve(value);
  }

  function mobileOverflowTabs() {
    return $$(".tab").filter((tab) => !tab.hasAttribute("data-mobile-primary"));
  }

  function mobileTabLabel(tab) {
    return tab.querySelector("span:last-child")?.textContent?.trim() || tab.dataset.tab;
  }

  function renderMobileMoreItems() {
    const items = $("#mobile-more-items");
    const fragment = document.createDocumentFragment();
    mobileOverflowTabs().forEach((tab) => {
      const button = node("button", "mobile-more-item");
      button.type = "button";
      button.dataset.moreTab = tab.dataset.tab;
      button.setAttribute("aria-controls", tab.getAttribute("aria-controls"));
      const icon = node(
        "span", "mobile-more-item-icon",
        tab.querySelector("span:first-child")?.textContent || "•"
      );
      icon.setAttribute("aria-hidden", "true");
      button.append(icon, node("span", "mobile-more-item-label", mobileTabLabel(tab)));
      fragment.append(button);
    });
    items.replaceChildren(fragment);
  }

  function syncMobileMoreState(name = state.activeTab) {
    const more = $("#mobile-more-button");
    const activeOverflow = mobileNavigationQuery.matches
      ? mobileOverflowTabs().find((tab) => tab.dataset.tab === name) : null;
    more.classList.toggle("active", Boolean(activeOverflow));
    if (activeOverflow) {
      more.setAttribute("aria-current", "page");
      more.setAttribute("aria-label", `更多功能，当前：${mobileTabLabel(activeOverflow)}`);
    } else {
      more.removeAttribute("aria-current");
      more.setAttribute("aria-label", "更多功能");
    }
    $$("[data-more-tab]", $("#mobile-more-items")).forEach((item) => {
      const active = item.dataset.moreTab === name;
      item.classList.toggle("active", active);
      if (active) item.setAttribute("aria-current", "page");
      else item.removeAttribute("aria-current");
    });
  }

  function openMobileMore() {
    if (!mobileNavigationQuery.matches || !mobileOverflowTabs().length) return;
    const dialog = $("#mobile-more-dialog");
    renderMobileMoreItems();
    syncMobileMoreState();
    $("#mobile-more-button").setAttribute("aria-expanded", "true");
    if (!dialog.open) dialog.showModal();
    window.requestAnimationFrame(() => {
      const items = $$("[data-more-tab]", $("#mobile-more-items"));
      const target = items.find((item) => item.dataset.moreTab === state.activeTab)
        || items[0] || $("#mobile-more-close");
      target.focus();
    });
  }

  function closeMobileMore(restoreFocus = true) {
    const dialog = $("#mobile-more-dialog");
    state.mobileMoreRestoreFocus = restoreFocus;
    if (dialog.open) dialog.close();
    else if (restoreFocus && mobileNavigationQuery.matches) $("#mobile-more-button").focus();
  }

  function mobileMoreKeydown(event) {
    if (!["ArrowUp", "ArrowDown", "Home", "End"].includes(event.key)) return;
    const items = $$("[data-more-tab]", $("#mobile-more-items"));
    const current = items.indexOf(event.target.closest("[data-more-tab]"));
    if (current < 0 || !items.length) return;
    event.preventDefault();
    let next = current;
    if (event.key === "Home") next = 0;
    if (event.key === "End") next = items.length - 1;
    if (event.key === "ArrowUp") next = (current - 1 + items.length) % items.length;
    if (event.key === "ArrowDown") next = (current + 1) % items.length;
    items[next].focus();
  }

  function syncNavigationSemantics(name = state.activeTab) {
    const mobile = mobileNavigationQuery.matches;
    const tabList = $("#canonical-tab-list");
    if (mobile) tabList.removeAttribute("role");
    else tabList.setAttribute("role", "tablist");
    $$(".tab").forEach((tab) => {
      const active = tab.dataset.tab === name;
      const primary = tab.hasAttribute("data-mobile-primary");
      const panel = $("#" + tab.getAttribute("aria-controls"));
      if (mobile) {
        tab.removeAttribute("role");
        tab.removeAttribute("aria-selected");
        tab.tabIndex = primary ? 0 : -1;
        if (primary) {
          tab.removeAttribute("aria-hidden");
          if (active) tab.setAttribute("aria-current", "page");
          else tab.removeAttribute("aria-current");
        } else {
          tab.setAttribute("aria-hidden", "true");
          tab.removeAttribute("aria-current");
        }
        panel.setAttribute("role", "region");
        panel.removeAttribute("aria-labelledby");
        panel.setAttribute("aria-label", mobileTabLabel(tab));
      } else {
        tab.setAttribute("role", "tab");
        tab.setAttribute("aria-selected", String(active));
        tab.removeAttribute("aria-current");
        tab.removeAttribute("aria-hidden");
        tab.tabIndex = active ? 0 : -1;
        panel.setAttribute("role", "tabpanel");
        panel.setAttribute("aria-labelledby", tab.id);
        panel.removeAttribute("aria-label");
      }
    });
  }

  function activateTab(name, focus = false) {
    if (!$("#panel-" + name)) return;
    state.activeTab = name;
    const reducedMotion = window.matchMedia?.("(prefers-reduced-motion: reduce)")?.matches;
    $$(".tab").forEach((tab) => {
      const active = tab.dataset.tab === name;
      tab.classList.toggle("active", active);
    });
    syncNavigationSemantics(name);
    syncMobileMoreState(name);
    const canonicalTab = $$(".tab").find((tab) => tab.dataset.tab === name);
    const navigationTarget = mobileNavigationQuery.matches
      && canonicalTab && !canonicalTab.hasAttribute("data-mobile-primary")
      ? $("#mobile-more-button") : canonicalTab;
    if (navigationTarget && focus) navigationTarget.focus();
    navigationTarget?.scrollIntoView({
      block: "nearest",
      inline: "nearest",
      behavior: reducedMotion ? "auto" : "smooth",
    });
    $$(".panel").forEach((panel) => {
      panel.hidden = panel.id !== `panel-${name}`;
    });
    window.scrollTo({ top: 0, behavior: reducedMotion ? "auto" : "smooth" });
    loadTab(name);
  }

  async function loadTab(name) {
    try {
      if (name === "overview") await loadOverview();
      if (name === "exits") await loadExits();
      if (name === "groups") await loadGroups();
      if (name === "rules") await loadRules();
      if (name === "dns") await loadDns();
      if (name === "runtime") await loadRuntime();
      if (name === "ops") await loadSettings();
    } catch (error) {
      toast(errorMessage(error), "bad");
    }
  }

  function serviceStateLevel(value) {
    if (value === true) return "good";
    if (value === false || value === null || value === undefined || value === "") return "bad";
    const stateValue = String(value).trim().toLowerCase();
    if (/^(active|ok|good|running|ready|true|正常|运行中)$/.test(stateValue)) return "good";
    if (/^(warn|warning|degraded|unknown|activating|警告|未知|启动中)$/.test(stateValue)) return "warn";
    return "bad";
  }

  function serviceStateLabel(value) {
    const level = serviceStateLevel(value);
    if (level === "good") return "运行中";
    if (level === "warn") return "状态待确认";
    return "未运行";
  }

  function serviceName(name) {
    return ({
      "pdg-quic-routing": "QUIC 路由",
      mosdns: "MosDNS",
      mihomo: "Mihomo",
      "pdg-bot": "Telegram Bot",
      "pdg-web": "Web 控制台",
      "pdg-probe81": "iOS 网络探测",
      "pdg-mitm": "定位服务插件"
    })[name] || formatLabel(name);
  }

  function overviewHealth(status, doctor) {
    if (status === null || status === undefined || status === "") return "warn";
    const serviceLevels = serviceEntries(status).map((item) => serviceStateLevel(item.value));
    const doctorLevels = doctorEntries(doctor).map((item) => item.level);
    if (serviceLevels.includes("bad") || doctorLevels.includes("fail")) return "bad";
    if (serviceLevels.includes("warn") || doctorLevels.includes("warn")) return "warn";
    return "good";
  }

  function overviewStatusSummary(status) {
    if (typeof status === "string") return safeString(status, 80);
    if (Array.isArray(status)) return `${status.length} 项状态`;
    if (status && typeof status === "object") {
      const values = Object.values(status);
      const active = values.filter((value) => serviceStateLevel(value) === "good").length;
      return `${active}/${values.length} 正常`;
    }
    return "状态未知";
  }

  function doctorLevel(item) {
    const level = String(item?.level || item?.status || "").toLowerCase();
    if (/(fail|failed|error|critical|失败|异常)/.test(level)) return "fail";
    if (/(warn|warning|degraded|unknown|警告|未知)/.test(level)) return "warn";
    if (/(info|notice|说明|提示)/.test(level)) return "info";
    if (/(ok|good|pass|passed|success|正常|通过)/.test(level)) return "ok";
    return "warn";
  }

  function doctorTitle(title) {
    const labels = {
      "平台": "客户端平台",
      "服务": "核心服务",
      "Bot 凭据": "Telegram Bot",
      "mihomo 版本": "Mihomo 内核",
      "MosDNS 修补版": "MosDNS 内核",
      "DoT A 记录": "DoT 域名解析",
      "DoT 域名一致性": "DoT 配置一致性",
      "内网卡段": "客户端网段",
      "透明数据面": "透明代理配置",
      "防火墙": "端口访问控制",
      "input 链冲突": "防火墙规则冲突",
      "代理入口": "透明代理入口",
      "GMS 推送": "Google 推送通道",
      "GMS 残留": "Google 推送残留",
      "限流": "DNS 请求保护",
      "内存模式": "DNS 缓存策略",
      "证书": "TLS 证书",
      "本机DNS": "DNS 服务响应",
      "mihomo 配置": "Mihomo 配置",
      "规则集": "分流规则集",
      "配置事务": "配置变更",
      "DoT 握手(853)": "DoT 加密连接",
      "DoT 会话恢复": "DoT 会话安全",
      "DNS 解析(国内)": "国内域名解析",
      "clash_api": "Mihomo 控制接口",
      "DNS 上游探测": "DNS 上游连通性",
      "代理劫持验证": "透明代理范围说明",
      "MITM结构": "定位服务接管配置",
      "MITM 插件": "定位服务插件",
      "iOS 探测(:81)": "iOS 网络探测"
    };
    return labels[title] || title;
  }

  function doctorDetail(title, detail, level) {
    let text = safeString(detail, 1200).trim();
    if (title === "平台" && /^(android|ios)$/i.test(text)) {
      return text.toLowerCase() === "android" ? "Android" : "iOS";
    }
    if (title === "服务" && (/ 都在$/u.test(text) || text.startsWith("核心服务均运行正常："))) {
      const services = text.startsWith("核心服务均运行正常：")
        ? text.slice("核心服务均运行正常：".length).split("、").filter(Boolean)
        : text.replace(/ 都在$/u, "").split("/").filter(Boolean);
      return `${services.length} 项核心服务均在运行：${services.map(serviceName).join("、")}`;
    }
    if (title === "Bot 凭据" && text.includes("token + 允许 id 均已配置")) {
      return "凭据与授权用户均已配置，Bot 服务运行正常";
    }
    if (title === "mihomo 版本") {
      const version = text.match(/v?([0-9]+(?:\.[0-9]+){2})/u)?.[1];
      if (version && level === "ok") return `版本 v${version}，由当前 PDG 发布统一维护`;
    }
    if (title === "MosDNS 修补版" && level === "ok") {
      const build = text.match(/^([^ ]+) \(([^)]+)\)/u);
      if (build) return `版本 ${build[1]}，${build[2]} 架构，构建来源校验通过`;
    }
    if (title === "DoT A 记录" && level === "ok") {
      const address = text.replaceAll("✓", "").trim().match(/^(.+?)\s*→\s*([^ ]+)$/u);
      if (address) return `加密 DNS 域名 ${address[1]} 已正确解析到本机地址 ${address[2]}`;
    }
    if (title === "DoT 域名一致性" && level === "ok") {
      return `证书与运行配置使用同一加密 DNS 域名：${text.replaceAll("✓", "").trim()}`;
    }
    if (title === "内网卡段" && level === "ok") {
      return `透明代理仅接收来自客户端网段 ${text} 的流量`;
    }
    if (title === "透明数据面" && level === "ok") {
      const match = text.match(/^mode=([^;]+); QUIC=([^;]+); TLS=([^;]+); HTTP=([^;]+);/u);
      if (match) {
        const firewall = match[1] === "external" ? "外部防火墙" : "PDG 受管防火墙";
        const quic = match[2] === "tproxy" ? "TProxy" : "阻断并回落 TCP";
        return `${firewall}模式；QUIC 使用 ${quic}；透明接管端口：TLS ${match[3]}，HTTP ${match[4]}。持久配置与运行状态一致`;
      }
    }
    if (title === "防火墙" && text.includes("external 模式：PDG 未管理 input 暴露面")) {
      return "PDG 未接管主机入站访问控制；端口开放范围由外部防火墙负责";
    }
    if (title === "input 链冲突" && text.includes("external 模式：PDG 无 input hook")) {
      return "未发现与 PDG 冲突的主机入站规则；端口开放范围由外部防火墙负责";
    }
    if (title === "代理入口" && level === "ok") {
      const ports = text.match(/TCP 端口 ([0-9,]+)/u)?.[1];
      const target = text.match(/mihomo :(\d+)/iu)?.[1];
      if (ports && target) return `来自客户端网段的 TCP ${ports} 已转交 Mihomo 端口 ${target}`;
    }
    if (title === "GMS 推送" && level === "ok") {
      return "Android 推送端口 5228–5230 已接入 Mihomo 透明代理";
    }
    if (title === "限流" && level === "ok") {
      return "已启用单客户端 DNS 请求保护：持续 200 次/秒，允许短时突发 400 次";
    }
    if (title === "内存模式" && level === "ok") {
      const match = text.match(/^(低内存|标准|未知).*?cache=(\d+|\?)/iu);
      if (match) return `${match[1]}配置，DNS 缓存容量 ${match[2] === "?" ? "未知" : new Intl.NumberFormat("zh-CN").format(Number(match[2])) + " 条"}`;
    }
    if (title === "证书" && level === "ok") return "证书有效期超过 14 天";
    if (title === "本机DNS" && level === "ok") return "MosDNS 正常响应本机查询";
    if (title === "mihomo 配置" && level === "ok") return "配置语法校验通过";
    if (title === "规则集" && level === "ok") {
      const count = text.match(/(\d+) 个/u)?.[1];
      if (count) return `${count} 个规则集均可由 Mihomo 正常加载`;
    }
    if (title === "配置事务" && level === "ok") {
      const operationLabels = { rulesets_refresh: "规则集刷新", snapshot: "快照创建", update: "软件升级" };
      const recent = text.match(/最近一笔:\s*([^ )]+)\s+([^ )]+)/u);
      if (recent) {
        const operation = operationLabels[recent[1]] || recent[1];
        const status = recent[2] === "COMMITTED" ? "已提交" : recent[2];
        return `当前没有未完成的配置变更；最近一次${operation}${status}`;
      }
      return "当前没有未完成的配置变更";
    }
    if (title === "DoT 握手(853)" && level === "ok") {
      const match = text.match(/\((TLSv[^,]+), SNI=([^)]+)\)/u);
      if (match) return `证书链和域名校验通过；协议 ${match[1]}，服务域名 ${match[2]}`;
    }
    if (title === "DoT 会话恢复" && level === "ok") {
      const tls = text.match(/TLS=(TLSv[^,)]+)/u)?.[1];
      return `两次加密 DNS 连接均成功，且未复用 TLS 会话${tls ? `；协议 ${tls}` : ""}`;
    }
    if (title === "DNS 解析(国内)" && level === "ok") {
      return text.replace(/→/gu, "解析为").replace(/\(直连\)$/u, "，按直连处理");
    }
    if (title === "clash_api" && level === "ok") {
      const count = text.match(/,\s*(\d+) 个出站\/组/u)?.[1];
      return `控制接口仅在本机可访问${count ? `，已加载 ${count} 个代理节点或策略组` : ""}`;
    }
    if (title === "DNS 上游探测" && level === "ok") {
      return text.replace("国际remote", "国际 DNS")
        .replace("国内local", "国内 DNS")
        .replace(/\s*;\s*/gu, "；")
        .replace(/(\d+)\/(\d+) 最慢/gu, "$1/$2 可用，最慢");
    }
    if (title === "代理劫持验证" && level === "info") {
      const cidr = text.match(/来源 ([^ ]+) 生效/u)?.[1];
      return `${cidr ? `透明代理仅对客户端网段 ${cidr} 生效。` : ""}本机查询不经过透明代理；如需端到端验证，请使用连接该网段的手机测试`;
    }
    return text.replaceAll("✓", "").replace(/, /gu, "，").replace(/; /gu, "；");
  }

  function doctorEntries(doctor) {
    if (Array.isArray(doctor)) {
      return doctor.slice(0, 50).map((item, index) => {
        if (typeof item === "string") {
          return {
            level: "warn",
            title: `检查项 ${index + 1}`,
            detail: safeString(item, 1200)
          };
        }
        const clean = safeObject(item) || {};
        const level = doctorLevel(clean);
        const rawTitle = safeString(clean.check || clean.name || clean.title || `检查项 ${index + 1}`, 80);
        return {
          level,
          title: doctorTitle(rawTitle),
          detail: doctorDetail(rawTitle, clean.detail || clean.message || clean.status || "未提供说明", level)
        };
      });
    }
    if (doctor !== null && doctor !== undefined && doctor !== "") {
      return [{
        level: "warn",
        title: "原始自检输出",
        detail: safeString(readableValue(doctor), 3000)
      }];
    }
    return [];
  }

  function doctorGroup(title) {
    const groups = [
      { key: "runtime", label: "核心服务", match: /(平台|核心服务|telegram|mihomo(?: 内核| 配置| 控制接口)|mosdns 内核)/i },
      { key: "dns", label: "加密 DNS", match: /(dot|dns|域名解析|tls 证书|会话安全)/i },
      { key: "dataplane", label: "代理与网络", match: /(客户端网段|透明代理|google 推送|quic|路由|出口)/i },
      { key: "security", label: "访问安全", match: /(防火墙|访问控制|请求保护|端口冲突)/i },
      { key: "transactions", label: "配置与维护", match: /(配置变更|规则集|更新|升级|回滚|快照|残留)/i }
    ];
    return groups.find((group) => group.match.test(title)) || { key: "other", label: "其他检查" };
  }

  function doctorTone(level) {
    return level === "fail" ? "bad" : level === "warn" ? "warn" : level === "info" ? "info" : "good";
  }

  function renderDoctorSummary(target, doctor) {
    empty(target);
    const entries = doctorEntries(doctor);
    const healthPill = $("#doctor-health");
    if (!entries.length) {
      healthPill.className = "status-pill warn";
      healthPill.textContent = "结果不可用";
      target.append(node("div", "empty-state", "暂时没有可显示的自检结果"));
      return;
    }

    const counts = entries.reduce((result, item) => {
      result[item.level] += 1;
      return result;
    }, { ok: 0, warn: 0, fail: 0, info: 0 });
    const tone = counts.fail ? "bad" : counts.warn ? "warn" : "good";
    healthPill.className = `status-pill ${tone}`;
    healthPill.textContent = counts.fail
      ? `${counts.fail} 项失败`
      : counts.warn ? `${counts.warn} 项警告` : "运行正常";

    const result = node("div", `doctor-result ${tone}`);
    const resultIcon = node("span", "doctor-result-icon", tone === "good" ? "✓" : tone === "warn" ? "!" : "×");
    resultIcon.setAttribute("aria-hidden", "true");
    const resultCopy = node("div", "doctor-result-copy");
    resultCopy.append(node("strong", "", tone === "good"
      ? "系统运行正常"
      : tone === "warn" ? "存在需要关注的项目" : "发现需要处理的问题"));
    const total = counts.ok + counts.warn + counts.fail + counts.info;
    const explanation = [`共检查 ${total} 项`, `${counts.ok} 项正常`];
    if (counts.info) explanation.push(`${counts.info} 项说明`);
    if (counts.warn) explanation.push(`${counts.warn} 项警告`);
    if (counts.fail) explanation.push(`${counts.fail} 项失败`);
    resultCopy.append(node("span", "", explanation.join(" · ")));
    result.append(resultIcon, resultCopy);

    const stats = node("div", "doctor-stats");
    [
      { key: "fail", label: "失败" },
      { key: "warn", label: "警告" },
      { key: "ok", label: "正常" },
      { key: "info", label: "说明" }
    ].filter((item) => counts[item.key] > 0).forEach((item) => {
      const stat = node("div", `doctor-stat ${item.key}`);
      stat.append(node("strong", "", counts[item.key]));
      stat.append(node("span", "", item.label));
      stats.append(stat);
    });
    result.append(stats);
    target.append(result);

    const grouped = new Map();
    entries.forEach((entry) => {
      const group = doctorGroup(entry.title);
      if (!grouped.has(group.key)) grouped.set(group.key, { label: group.label, items: [] });
      grouped.get(group.key).items.push(entry);
    });

    const groups = node("div", "doctor-groups");
    grouped.forEach((group) => {
      const section = node("details", "doctor-group");
      const groupCounts = group.items.reduce((result, item) => {
        result[item.level] += 1;
        return result;
      }, { ok: 0, warn: 0, fail: 0, info: 0 });
      section.open = groupCounts.fail > 0 || groupCounts.warn > 0;
      const heading = node("summary", "doctor-group-heading");
      heading.append(node("h3", "", group.label));
      const groupState = groupCounts.fail
        ? `${groupCounts.fail} 项失败`
        : groupCounts.warn ? `${groupCounts.warn} 项警告`
          : groupCounts.info ? `${groupCounts.ok} 项正常 · ${groupCounts.info} 项说明`
            : `${groupCounts.ok} 项正常`;
      heading.append(node("span", "", groupState));
      section.append(heading);
      const list = node("div", "doctor-check-list");
      group.items.forEach((entry) => {
        const item = node("article", `doctor-check ${doctorTone(entry.level)}`);
        const marker = node("span", "doctor-check-marker", entry.level === "ok" ? "✓" : entry.level === "warn" ? "!" : entry.level === "info" ? "i" : "×");
        marker.setAttribute("aria-hidden", "true");
        const copy = node("div", "doctor-check-copy");
        copy.append(node("strong", "", entry.title));
        copy.append(node("span", "", entry.detail));
        const stateLabel = entry.level === "ok" ? "正常" : entry.level === "warn" ? "警告" : entry.level === "info" ? "说明" : "失败";
        item.append(marker, copy, node("span", `doctor-check-state ${doctorTone(entry.level)}`, stateLabel));
        list.append(item);
      });
      section.append(list);
      groups.append(section);
    });
    target.append(groups);
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
    appendMetric(cards, "客户端平台", info.platform === "ios" ? "iOS" : info.platform === "android" ? "Android" : readableValue(info.platform), "当前服务对象");
    appendMetric(cards, "加密 DNS 域名", safeString(info.dot_domain || "未配置", 120), "Android 私有 DNS / iOS 加密 DNS");
    appendMetric(cards, "核心服务", overviewStatusSummary(info.status), "核心服务运行状态");
    const health = overviewHealth(info.status, info.doctor);
    const checkCount = doctorEntries(info.doctor).length;
    appendMetric(cards, "系统检查", health === "good" ? "运行正常" : health === "warn" ? "需要关注" : "需要处理", checkCount ? `共 ${checkCount} 项检查` : "检查结果不可用");

    const healthPill = $("#overview-health");
    healthPill.className = `status-pill ${health}`;
    healthPill.textContent = health === "good" ? "全部正常" : health === "warn" ? "有警告" : "需处理";

    const services = $("#service-list");
    empty(services);
    serviceEntries(info.status).forEach((item) => {
      const tone = serviceStateLevel(item.value);
      const row = node("div", "status-row");
      row.append(node("span", `status-dot ${tone}`));
      row.append(node("span", "status-name", serviceName(item.name)));
      row.append(node("span", "status-value", serviceStateLabel(item.value)));
      services.append(row);
    });
    renderDoctorSummary($("#doctor-summary"), info.doctor);
  }

  function makeActionButton(label, action, tone = "") {
    const button = node("button", `mini-button ${tone}`.trim(), label);
    button.type = "button";
    button.dataset.action = action;
    return button;
  }

  function exitDiagnosticBadge(item) {
    const badge = node("span", "latency-badge neutral", "未测速");
    if (item.type === "urltest") {
      badge.textContent = "故障切换代理策略组本轮不单测";
      return badge;
    }
    if (!isProbeableExit(item)) {
      badge.textContent = "无需测速";
      return badge;
    }
    if (state.exitDiagnosticsTesting) {
      badge.className = "latency-badge testing";
      badge.textContent = "测试中…";
      return badge;
    }
    const result = state.exitDiagnostics.get(item.tag);
    if (!result) return badge;
    const status = String(result.status || "").toLowerCase();
    if (status === "ok" && Number.isFinite(result.delayMs) && result.delayMs >= 0) {
      badge.className = "latency-badge good";
      badge.textContent = `${Math.round(result.delayMs)} ms`;
      return badge;
    }
    if (status === "ok") {
      badge.className = "latency-badge good";
      badge.textContent = "可用";
      return badge;
    }
    if (["timeout", "unreachable"].includes(status)) {
      badge.className = "latency-badge bad";
      badge.textContent = status === "timeout" ? "超时" : "不可达";
      return badge;
    }
    if (["skipped", "unsupported"].includes(status)) {
      badge.className = "latency-badge neutral";
      badge.textContent = status === "skipped" ? "已跳过" : "不支持测速";
      return badge;
    }
    if (status === "unavailable") {
      badge.className = "latency-badge bad";
      badge.textContent = "Mihomo API 不可用";
      return badge;
    }
    badge.className = "latency-badge bad";
    badge.textContent = "测速失败";
    return badge;
  }

  function renderExitList() {
    const target = $("#exit-list");
    empty(target);
    $("#exit-count").textContent = `${state.exits.length} 个出口`;
    if (!state.exits.length) {
      target.append(node("div", "empty-state", "暂无代理节点，请先添加节点链接"));
      return;
    }
    state.exits.forEach((item) => {
      const card = node("article", "list-card");
      card.dataset.tag = item.tag;
      const main = node("div", "list-card-main");
      const title = node("div", "list-card-title");
      title.append(node("b", "", formatExitName(item.tag)));
      title.append(node("span", "type-badge", item.type || "unknown"));
      title.append(exitDiagnosticBadge(item));
      main.append(title);
      const endpoint = item.server
        ? `${safeString(item.server, 180)}${item.server_port ? `:${item.server_port}` : ""}`
        : Array.isArray(item.members) ? item.members.map(formatExitName).join(" › ") : "由服务器管理";
      main.append(node("span", "list-card-detail", endpoint));
      card.append(main);

      const actions = node("div", "list-actions");
      const locked = item.type === "direct" || item.tag === "direct";
      if (isReplaceableProxy(item)) {
        actions.append(makeActionButton("更新连接", "replace"));
      }
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
      row.append(node("span", "order-name", formatExitName(tag)));
      const actions = node("span", "order-actions");
      const up = node("button", "", "↑");
      up.type = "button";
      up.dataset.direction = "up";
      up.disabled = index === 0;
      up.setAttribute("aria-label", `上移 ${formatExitName(tag)}`);
      const down = node("button", "", "↓");
      down.type = "button";
      down.dataset.direction = "down";
      down.disabled = index === state.exitOrder.length - 1;
      down.setAttribute("aria-label", `下移 ${formatExitName(tag)}`);
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
      const label = value === "direct" ? directLabel : formatExitName(value);
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
      target.append(node("div", "empty-state", "暂无代理策略组"));
      return;
    }
    state.groups.forEach((group) => {
      const card = node("article", "list-card");
      card.dataset.tag = group.name;
      const main = node("div", "list-card-main");
      const title = node("div", "list-card-title");
      title.append(node("b", "", group.name));
      title.append(node("span", "type-badge", `${groupTypeLabel(group.type)} · ${group.type}`));
      main.append(title);
      main.append(node("span", "list-card-detail",
        (group.proxies || []).map(formatExitName).join(" › ") || "仅使用代理提供器"));
      if (group.use.length) {
        main.append(node("span", "list-card-detail", `代理提供器：${group.use.join(", ")}`));
      }
      const options = [];
      if (group.url) options.push(`探测地址：${group.url}`);
      if (group.interval) options.push(`间隔：${group.interval} 秒`);
      if (Number.isInteger(group.tolerance)) options.push(`容差：${group.tolerance} ms`);
      if (group.strategy) options.push(`负载策略：${group.strategy}`);
      if (group.lazy) options.push("按需测速");
      if (group.disableUdp) options.push("禁用 UDP");
      if (group.hidden) options.push("隐藏组");
      if (options.length) main.append(node("span", "list-card-detail", options.join(" · ")));
      if (group.type === "select") {
        main.append(node("span", "list-card-detail",
          `临时运行态: ${group.runtimeSelected ? formatExitName(group.runtimeSelected) : "不可用"}`));
      }
      const actions = node("div", "list-actions");
      actions.append(makeActionButton("编辑", "edit-group"));
      if (group.type === "select") actions.append(makeActionButton("临时切换", "select-runtime"));
      actions.append(makeActionButton("删除", "delete-group", "danger"));
      card.append(main, actions);
      target.append(card);
    });
  }

  function renderSelectionChips(target, values, kind) {
    empty(target);
    if (!values.length) {
      target.append(node("div", "selection-empty",
        kind === "member" ? "尚未选择组成员" : "未选择代理提供器"));
      return;
    }
    values.forEach((value, index) => {
      const chip = node("div", "selection-chip");
      chip.setAttribute("role", "listitem");
      chip.append(node("span", "selection-chip-name", value));
      const actions = node("span", "selection-chip-actions");
      if (kind === "member") {
        const up = node("button", "selection-chip-button", "↑");
        up.type = "button";
        up.dataset.selectionAction = "up";
        up.disabled = index === 0;
        up.setAttribute("aria-label", `上移 ${value}`);
        const down = node("button", "selection-chip-button", "↓");
        down.type = "button";
        down.dataset.selectionAction = "down";
        down.disabled = index === values.length - 1;
        down.setAttribute("aria-label", `下移 ${value}`);
        actions.append(up, down);
      }
      const remove = node("button", "selection-chip-button danger-text", "×");
      remove.type = "button";
      remove.dataset.selectionAction = "remove";
      remove.setAttribute("aria-label", `移除 ${value}`);
      actions.append(remove);
      chip.dataset.selectionKind = kind;
      chip.dataset.index = String(index);
      chip.append(actions);
      target.append(chip);
    });
  }

  function renderGroupSelections() {
    renderSelectionChips($("#group-member-chips"), state.groupMembers, "member");
    renderSelectionChips(
      $("#group-provider-chips"), state.groupProviderSelection, "provider");
  }

  function groupPickerSections(kind, runtimeCandidates = []) {
    if (kind === "provider") {
      return [{ title: "代理提供器", items: state.groupProviders.map((value) => ({
        value, label: value
      })) }];
    }
    if (kind === "runtime") {
      return [{ title: "当前可用成员", items: runtimeCandidates.map((value) => ({
        value, label: ruleTargetLabel(value, "手机直连")
      })) }];
    }
    const groups = new Set(state.groups.map((item) => item.name));
    if (state.editingGroup) groups.delete(state.editingGroup);
    const exitKinds = new Map(state.exits.map((item) => [item.tag, item.type]));
    const targets = Array.from(new Set([...state.exitTargets, ...exitKinds.keys()]))
      .filter(Boolean);
    const builtins = [];
    const proxies = [];
    const nested = [];
    targets.forEach((value) => {
      if (groups.has(value)) nested.push({ value, label: value });
      else if (exitKinds.get(value) === "direct") {
        builtins.push({ value, label: `${formatExitName(value)}（VPS 本机直出）` });
      } else proxies.push({ value, label: formatExitName(value) });
    });
    builtins.push({ value: "REJECT", label: "REJECT（拒绝连接）" });
    return [
      { title: "代理节点", items: proxies },
      { title: "代理策略组", items: nested },
      { title: "内建动作", items: builtins }
    ];
  }

  function renderGroupPickerOptions() {
    const picker = state.groupPicker;
    const target = $("#group-picker-options");
    empty(target);
    if (!picker) return;
    const query = $("#group-picker-search").value.trim().toLocaleLowerCase();
    const selected = new Set(picker.kind === "member" ? state.groupMembers
      : picker.kind === "provider" ? state.groupProviderSelection : []);
    picker.sections.forEach((section) => {
      const matching = section.items.filter((item) => !query
        || item.label.toLocaleLowerCase().includes(query)
        || item.value.toLocaleLowerCase().includes(query));
      if (!matching.length) return;
      target.append(node("h3", "picker-section-title", section.title));
      matching.forEach((item) => {
        const button = node("button", "picker-option");
        button.type = "button";
        button.dataset.pickerValue = item.value;
        button.setAttribute("role", "option");
        button.setAttribute("aria-selected", String(selected.has(item.value)));
        button.disabled = selected.has(item.value);
        button.append(node("span", "picker-option-label", item.label));
        button.append(node("span", "picker-option-action",
          selected.has(item.value) ? "已添加" : "添加"));
        target.append(button);
      });
    });
    if (!target.childElementCount) target.append(node("div", "empty-state", "没有匹配项目"));
  }

  function openGroupPicker(kind, runtimeCandidates = []) {
    const dialog = $("#group-picker-dialog");
    if (typeof dialog.showModal !== "function") {
      toast("当前浏览器不支持成员选择器，请升级浏览器后重试", "bad");
      return Promise.resolve(null);
    }
    if (state.groupPicker) closeGroupPicker(null);
    const sections = groupPickerSections(kind, runtimeCandidates);
    $("#group-picker-title").textContent = kind === "member" ? "添加组成员"
      : kind === "provider" ? "添加代理提供器" : "临时切换运行成员";
    $("#group-picker-help").textContent = kind === "runtime"
      ? "仅修改当前 Mihomo 运行态，不写入配置。" : "已添加项目会自动禁用，避免重复。";
    $("#group-picker-search").value = "";
    dialog.showModal();
    if (kind === "runtime") {
      return new Promise((resolve) => {
        state.groupPicker = { kind, sections, resolve };
        renderGroupPickerOptions();
        window.setTimeout(() => $("#group-picker-search").focus(), 0);
      });
    }
    state.groupPicker = { kind, sections, resolve: null };
    renderGroupPickerOptions();
    window.setTimeout(() => $("#group-picker-search").focus(), 0);
    return Promise.resolve(null);
  }

  function closeGroupPicker(value = null) {
    const picker = state.groupPicker;
    state.groupPicker = null;
    const dialog = $("#group-picker-dialog");
    if (dialog.open) dialog.close();
    if (picker?.resolve) picker.resolve(value);
  }

  function chooseGroupPickerOption(event) {
    const button = event.target.closest("button[data-picker-value]");
    const picker = state.groupPicker;
    if (!button || !picker) return;
    const value = button.dataset.pickerValue;
    if (picker.kind === "runtime") {
      closeGroupPicker(value);
      return;
    }
    const values = picker.kind === "member"
      ? state.groupMembers : state.groupProviderSelection;
    if (!values.includes(value)) values.push(value);
    renderGroupSelections();
    renderGroupPickerOptions();
  }

  function editGroupSelection(event) {
    const button = event.target.closest("button[data-selection-action]");
    const chip = button?.closest("[data-selection-kind][data-index]");
    if (!button || !chip) return;
    const values = chip.dataset.selectionKind === "member"
      ? state.groupMembers : state.groupProviderSelection;
    const index = Number(chip.dataset.index);
    if (!Number.isInteger(index) || index < 0 || index >= values.length) return;
    if (button.dataset.selectionAction === "remove") values.splice(index, 1);
    if (button.dataset.selectionAction === "up" && index > 0) {
      [values[index - 1], values[index]] = [values[index], values[index - 1]];
    }
    if (button.dataset.selectionAction === "down" && index < values.length - 1) {
      [values[index + 1], values[index]] = [values[index], values[index + 1]];
    }
    renderGroupSelections();
  }

  function normalizeGroups(items) {
    return Array.isArray(items) ? items.map((item) => ({
      name: safeIdentifierName(item.name || item.tag),
      tag: safeIdentifierName(item.name || item.tag),
      type: safeString(item.type, 32),
      proxies: Array.isArray(item.proxies || item.members)
        ? (item.proxies || item.members).map(safeIdentifierName).filter(Boolean) : [],
      use: Array.isArray(item.use) ? item.use.map(safeIdentifierName).filter(Boolean) : [],
      url: item.url ? safeString(item.url, 8192) : "",
      interval: Number(item.interval) || 0,
      tolerance: Number.isInteger(item.tolerance) ? item.tolerance : undefined,
      strategy: item.strategy ? safeString(item.strategy, 40) : "",
      lazy: item.lazy === true,
      disableUdp: item["disable-udp"] === true,
      hidden: item.hidden === true,
      runtimeSelected: item.runtimeSelected ? safeIdentifierName(item.runtimeSelected) : "",
      runtimeCandidates: Array.isArray(item.runtimeCandidates)
        ? item.runtimeCandidates.map(safeIdentifierName).filter(Boolean) : []
    })) : [];
  }

  async function loadGroups() {
    const [{ data }, { data: exitData }] = await Promise.all([
      api("/policy-groups"), api("/exits")
    ]);
    state.groups = normalizeGroups(data?.items);
    state.exits = normalizeExitItems(exitData?.items);
    state.groupRevision = typeof data?.revision === "string" ? data.revision : "";
    state.groupProviders = Array.isArray(data?.providers)
      ? data.providers.map(safeIdentifierName).filter(Boolean) : [];
    state.exitTargets = Array.isArray(data?.targets)
      ? data.targets.map(safeIdentifierName).filter(Boolean)
      : Array.isArray(exitData?.targets)
        ? exitData.targets.map(safeIdentifierName).filter(Boolean) : state.exitTargets;
    renderGroups();
    $("#group-count").textContent = `${state.groups.length} 个代理策略组`;
    renderGroupSelections();
  }

  function normalizeExitItems(items) {
    return Array.isArray(items) ? items.map((item) => ({
      tag: safeIdentifierName(item.tag),
      type: safeString(item.type, 40),
      server: item.server ? safeString(item.server, 200) : "",
      server_port: item.server_port,
      members: Array.isArray(item.members)
        ? item.members.map(safeIdentifierName).filter(Boolean)
        : []
    })) : [];
  }

  async function loadExits() {
    const [exitResponse, groupResponse] = await Promise.all([api("/exits"), api("/groups")]);
    const exitData = exitResponse.data || {};
    const groupData = groupResponse.data || {};
    state.exits = normalizeExitItems(
      Array.isArray(exitData.items) ? exitData.items : []
    );
    // Legacy compact endpoint remains a compatibility read; the independent
    // policy-groups page always reloads the full schema from /policy-groups.
    if (!state.groups.length && Array.isArray(groupData.items)) {
      state.groups = normalizeGroups(groupData.items);
    }
    state.exitTargets = Array.isArray(exitData.targets)
      ? exitData.targets.map(safeIdentifierName).filter(Boolean)
      : state.exits.map((item) => item.tag);
    const currentTags = new Set(state.exits.map((item) => item.tag));
    Array.from(state.exitDiagnostics.keys()).forEach((tag) => {
      if (!currentTags.has(tag)) state.exitDiagnostics.delete(tag);
    });
    state.exitOrder = normalizeExitOrder(exitData.order);
    renderExitList();
    renderExitOrder();
    populateSelect($("#default-exit"), state.exitTargets, String(exitData.default || ""));
    $("#save-order").disabled = true;
  }

  async function testExits() {
    const button = $("#test-exits");
    state.exitDiagnosticsTesting = true;
    setButtonBusy(button, true, "测速中…");
    renderExitList();
    try {
      const { data, message } = await api("/diagnostics/exits", {
        method: "POST",
        body: {}
      });
      const items = Array.isArray(data?.items) ? data.items : [];
      const results = new Map();
      items.slice(0, 256).forEach((item) => {
        const tag = safeIdentifierName(item?.tag || "");
        if (!tag || !exitByTag(tag)) return;
        const delay = Number(item?.delayMs);
        results.set(tag, {
          status: safeString(item?.status || "error", 32),
          delayMs: Number.isFinite(delay) && delay >= 0 ? delay : undefined
        });
      });
      state.exitDiagnostics = results;
      if (data?.available !== true) {
        state.exits.filter(isProbeableExit).forEach((item) => {
          if (!state.exitDiagnostics.has(item.tag)) {
            state.exitDiagnostics.set(item.tag, {
              status: "unavailable",
              delayMs: undefined
            });
          }
        });
        toast("Mihomo API unavailable（出口测速不可用）", "bad");
      } else {
        toast(message || `已完成 ${results.size} 个出口的结构化测速`, "good");
      }
    } catch (error) {
      toast(errorMessage(error), "bad");
    } finally {
      state.exitDiagnosticsTesting = false;
      setButtonBusy(button, false);
      renderExitList();
    }
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

  function clearReplaceExitDialog() {
    $("#replace-exit-link").value = "";
    state.replaceExitTag = "";
  }

  function openReplaceExitDialog(tag) {
    const dialog = $("#replace-exit-dialog");
    clearReplaceExitDialog();
    state.replaceExitTag = tag;
    $("#replace-exit-message").textContent =
      `正在更新“${formatExitName(tag)}”的连接参数；出口 tag 将由服务器强制保持不变。`;
    if (typeof dialog.showModal !== "function") {
      toast("当前浏览器不支持安全节点更新对话框，请升级浏览器后再试", "bad");
      clearReplaceExitDialog();
      return;
    }
    dialog.showModal();
    window.setTimeout(() => $("#replace-exit-link").focus(), 0);
  }

  function cancelReplaceExit() {
    const dialog = $("#replace-exit-dialog");
    clearReplaceExitDialog();
    if (dialog.open) dialog.close("cancel");
  }

  async function replaceExit(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const dialog = $("#replace-exit-dialog");
    const tag = state.replaceExitTag;
    const input = $("#replace-exit-link");
    let link = input.value.trim();
    input.value = "";
    if (dialog.open) dialog.close("submitted");
    state.replaceExitTag = "";
    if (!tag || !link) {
      link = "";
      return;
    }
    const confirmed = await confirmAction(
      "确认更新节点连接",
      `确认替换“${formatExitName(tag)}”的连接参数？出口 tag 与现有分流引用将保持不变。`,
      "确认更新",
      "warning"
    );
    if (!confirmed) {
      link = "";
      return;
    }
    const button = $("button[type='submit']", form);
    setButtonBusy(button, true, "校验更新中…");
    const body = { link };
    try {
      const result = await api(`/exits/${identifierPath(tag)}`, {
        method: "PUT",
        body
      });
      link = "";
      body.link = "";
      toast(result.message || `出口 ${formatExitName(tag)} 的连接已安全更新`, "good");
      await loadExits();
    } catch (error) {
      link = "";
      body.link = "";
      toast(errorMessage(error, "节点"), "bad");
    } finally {
      link = "";
      body.link = "";
      input.value = "";
      setButtonBusy(button, false);
    }
  }

  async function handleExitAction(event) {
    const button = event.target.closest("button[data-action]");
    if (!button) return;
    const card = button.closest("[data-tag]");
    const tag = card?.dataset.tag;
    if (!tag) return;

    if (button.dataset.action === "replace") {
      openReplaceExitDialog(tag);
      return;
    }

    if (button.dataset.action === "rename") {
      const entered = await requestTextEntry({
        title: "重命名出口",
        message: `把“${formatExitName(tag)}”改为新的显示名称。分流和代理策略组引用会同步更新。`,
        label: "新名称",
        value: tag,
        help: "支持中文、空格、emoji 和常见符号，最多 64 个字符。",
        submitLabel: "保存名称",
        maxLength: 64
      });
      if (entered === null) return;
      let name;
      try { name = normalizeIdentifierName(entered); }
      catch (error) { toast(error.message || "名称无效", "bad"); return; }
      if (name === tag) return;
      try {
        const result = await api(`/exits/${identifierPath(tag)}`, {
          method: "PATCH", body: { name }
        });
        toast(result.message || `出口已改名为 ${name}`, "good");
        await loadExits();
      } catch (error) {
        toast(errorMessage(error), "bad");
      }
    }

    if (button.dataset.action === "delete") {
      const confirmed = await confirmAction(
        "删除出口",
        `确认删除“${tag}”？引用它的默认出口、代理策略组或分流规则可能需要重新选择。`,
        "删除出口"
      );
      if (!confirmed) return;
      try {
        const result = await api(`/exits/${identifierPath(tag)}`, { method: "DELETE" });
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
    let name;
    try {
      name = normalizeIdentifierName($("#group-name").value);
    } catch (error) {
      toast(error.message || "代理策略组名称无效", "bad");
      $("#group-name").focus();
      return;
    }
    const type = $("#group-type").value;
    const proxies = state.groupMembers.slice();
    const use = state.groupProviderSelection.slice();
    if ((!proxies.length && !use.length) || new Set(proxies).size !== proxies.length || new Set(use).size !== use.length) {
      toast("代理策略组至少需要一个成员或代理提供器，且不能重复", "bad");
      return;
    }
    const body = {
      revision: state.editingGroup ? state.editingGroupRevision : state.groupRevision,
      name, type, proxies, use
    };
    body.lazy = $("#group-lazy").checked;
    body["disable-udp"] = $("#group-disable-udp").checked;
    body.hidden = $("#group-hidden").checked;
    if (["url-test", "fallback", "load-balance"].includes(type)) {
      body.url = $("#group-url").value.trim();
      body.interval = Number($("#group-interval").value);
    }
    if (type === "url-test") body.tolerance = Number($("#group-tolerance").value);
    if (type === "load-balance") body.strategy = $("#group-strategy").value;
    const button = $("button[type='submit']", form);
    setButtonBusy(button, true, state.editingGroup ? "保存中…" : "创建中…");
    try {
      const editing = state.editingGroup;
      const result = await api(editing ? `/policy-groups/${identifierPath(editing)}` : "/policy-groups", {
        method: editing ? "PATCH" : "POST", body
      });
      resetGroupEditor();
      toast(result.message || `代理策略组 ${name} 已${editing ? "保存" : "创建"}`, "good");
      await loadGroups();
    } catch (error) {
      toast(errorMessage(error), "bad");
    } finally {
      setButtonBusy(button, false);
    }
  }

  function updateGroupOptions() {
    const type = $("#group-type").value;
    $("#group-probe-options").hidden = type === "select";
    $("#group-tolerance-wrap").hidden = type !== "url-test";
    $("#group-strategy-wrap").hidden = type !== "load-balance";
  }

  function resetGroupEditor() {
    state.editingGroup = "";
    state.editingGroupRevision = "";
    state.groupMembers = [];
    state.groupProviderSelection = [];
    $("#group-form").reset();
    $("#group-url").value = "https://www.gstatic.com/generate_204";
    $("#group-interval").value = "180";
    $("#group-tolerance").value = "50";
    $("#group-lazy").checked = false;
    $("#group-disable-udp").checked = false;
    $("#group-hidden").checked = false;
    $("#group-editor-title").textContent = "创建代理策略组";
    $("#group-submit").textContent = "创建代理策略组";
    $("#group-cancel-edit").hidden = true;
    renderGroupSelections();
    updateGroupOptions();
  }

  function editGroup(group) {
    state.editingGroup = group.name;
    state.editingGroupRevision = state.groupRevision;
    $("#group-name").value = group.name;
    $("#group-type").value = group.type;
    state.groupMembers = group.proxies.slice();
    state.groupProviderSelection = group.use.slice();
    $("#group-url").value = group.url || "https://www.gstatic.com/generate_204";
    $("#group-interval").value = String(group.interval || 180);
    $("#group-tolerance").value = String(group.tolerance ?? 50);
    $("#group-strategy").value = group.strategy || "consistent-hashing";
    $("#group-lazy").checked = group.lazy;
    $("#group-disable-udp").checked = group.disableUdp;
    $("#group-hidden").checked = group.hidden;
    $("#group-editor-title").textContent = `编辑代理策略组 ${group.name}`;
    $("#group-submit").textContent = "保存配置变更";
    $("#group-cancel-edit").hidden = false;
    renderGroupSelections();
    updateGroupOptions();
    $("#group-name").focus();
  }

  async function handleGroupAction(event) {
    const button = event.target.closest("button[data-action]");
    if (!button) return;
    const tag = button.closest("[data-tag]")?.dataset.tag;
    const group = state.groups.find((item) => item.name === tag);
    if (!tag || !group) return;
    if (button.dataset.action === "edit-group") {
      editGroup(group);
    }
    if (button.dataset.action === "select-runtime") {
      const member = await openGroupPicker("runtime", group.runtimeCandidates);
      if (!member) return;
      try {
        const result = await api(`/policy-groups/${identifierPath(tag)}/runtime`, {
          method: "PUT", body: { member }
        });
        toast(result.message || `已临时切换到 ${member}（未写入配置）`, "good");
        await loadGroups();
      } catch (error) {
        toast(errorMessage(error), "bad");
      }
    }
    if (button.dataset.action === "delete-group") {
      const confirmed = await confirmAction(
        "删除代理策略组",
        `确认删除“${tag}”？嵌套引用会安全级联，路由目标会切换到可用回退项。`,
        "删除代理策略组"
      );
      if (!confirmed) return;
      try {
        const result = await api(`/policy-groups/${identifierPath(tag)}`, {
          method: "DELETE", body: { revision: state.groupRevision }
        });
        toast(result.message || `已删除代理策略组 ${tag}`, "good");
        resetGroupEditor();
        await loadGroups();
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
      "手机直连"
    );
    Array.from(select.options).forEach((option) => {
      if (option.value && option.value !== "direct") {
        option.textContent = ruleTargetLabel(option.value);
      }
    });
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
        : ruleTargetLabel(item.target);
      info.append(node("div", "table-primary", item.label || item.name));
      info.append(node("div", "table-secondary",
        `${safeString(item.url || "地址由服务器管理", 260)} · ${item.behavior || "自动"} → ${targetLabel}`));
      const controls = node("div", "table-controls");
      const select = node("select");
      select.setAttribute("aria-label", `${item.label || item.name} 的出口目标`);
      targetOptions(select, item.target);
      controls.append(select);
      controls.append(makeActionButton("保存出口", "target-ruleset"));
      controls.append(makeActionButton("改名称", "label-ruleset"));
      controls.append(makeActionButton("删除", "delete-ruleset", "danger"));
      row.append(info, controls);
      target.append(row);
    });
  }

  async function loadRules() {
    const [rulesResponse, rulesetResponse, exitResponse] = await Promise.all([
      api("/rules"),
      api("/rulesets"),
      api("/exits")
    ]);
    const rulesData = rulesResponse.data || {};
    const rulesetData = rulesetResponse.data || {};
    const exitData = exitResponse.data || {};
    state.exits = normalizeExitItems(exitData.items);
    state.exitTargets = Array.isArray(exitData.targets)
      ? exitData.targets.map(String)
      : state.exits.map((item) => item.tag);
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
    let label = $("#ruleset-label").value.trim();
    const behavior = $("#ruleset-behavior").value;
    if (label) {
      try { label = normalizeIdentifierName(label); }
      catch (error) {
        submittedUrl = "";
        body.url = "";
        toast(error.message || "规则集显示名称无效", "bad");
        return;
      }
      body.label = label;
    }
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
    if (button.dataset.action === "target-ruleset") {
      const target = $("select", row)?.value;
      if (!target) return;
      setButtonBusy(button, true, "保存中…");
      try {
        const result = await api(`/rulesets/${identifierPath(name)}/target`, {
          method: "PUT",
          body: { target }
        });
        toast(result.message || `规则集出口已改为 ${ruleTargetLabel(target)}`, "good");
        await loadRules();
      } catch (error) {
        toast(errorMessage(error), "bad");
      } finally {
        setButtonBusy(button, false);
      }
      return;
    }
    if (button.dataset.action === "label-ruleset") {
      const label = await requestTextEntry({
        title: "修改规则集显示名称",
        message: `设置“${name}”在控制台中的显示名称。留空可清除自定义名称。`,
        label: "显示名称",
        value: "",
        help: "仅改变显示名称，不改变规则集内部标识。",
        submitLabel: "保存",
        allowEmpty: true,
        maxLength: 64
      });
      if (label === null) return;
      let normalizedLabel = "";
      try {
        normalizedLabel = label.trim() ? normalizeIdentifierName(label) : "";
      } catch (error) {
        toast(error.message || "规则集显示名称无效", "bad");
        return;
      }
      try {
        const result = await api(`/rulesets/${identifierPath(name)}`, {
          method: "PATCH", body: { label: normalizedLabel }
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
        const result = await api(`/rulesets/${identifierPath(name)}`, { method: "DELETE" });
        toast(result.message || `已删除规则集 ${name}`, "good");
        await loadRules();
      } catch (error) {
        toast(errorMessage(error), "bad");
      }
    }
  }

  function diagnosticEvidence(result) {
    const path = String(result?.path || "unknown").toLowerCase();
    const reason = String(result?.reason || "").toLowerCase();
    const dnsVerified = result?.dnsVerified === true;
    const routeConfidence = String(result?.routeConfidence || "unknown").toLowerCase();
    if (reason === "config_changed") {
      return {
        label: "配置已变化",
        tone: "neutral",
        detail: "诊断期间配置发生变化，本次结果已作废，请重新诊断"
      };
    }
    if (reason === "probe_busy") {
      return {
        label: "诊断繁忙",
        tone: "neutral",
        detail: "本次尚未执行诊断，请稍后重试"
      };
    }
    if (reason === "dns_no_answer") {
      return {
        label: "DNS 无应答",
        tone: "neutral",
        detail: "没有取得 DNS 答案，无法判断手机连接路径"
      };
    }
    if (path === "direct" && dnsVerified) {
      return {
        label: "DNS 实测直连",
        tone: "good",
        detail: "DNS 已返回真实地址；验证的是 DNS 直连路径"
      };
    }
    if (path === "gateway" && dnsVerified) {
      return {
        label: "DNS 入口实测 + 出口规则推演",
        tone: "warn",
        detail: "DNS 已确认连接进入 VPS；具体出口依据规则推演，未进行出口连接实测"
      };
    }
    if (routeConfidence === "simulated") {
      return {
        label: "规则推演",
        tone: "warn",
        detail: "依据当前配置推演，未进行网络路径实测"
      };
    }
    return { label: "不确定", tone: "neutral", detail: "现有信息不足，无法确认实际路径" };
  }

  function diagnosticPathLabel(path) {
    const labels = {
      direct: "手机直连",
      gateway: "经 VPS 网关",
      unknown: "路径未知"
    };
    return labels[String(path || "unknown").toLowerCase()] || "路径未知";
  }

  function diagnosticReasonLabel(reason) {
    const labels = {
      dns_real: "DNS 返回真实地址",
      explicit_domain: "命中显式域名规则",
      keyword: "命中域名关键词规则",
      ruleset: "命中规则集",
      default: "采用默认出口",
      dns_no_answer: "DNS 无应答",
      probe_busy: "诊断繁忙，本次未执行",
      probe_unavailable: "诊断服务不可用",
      config_changed: "诊断期间配置发生变化，结果作废"
    };
    return labels[String(reason || "").toLowerCase()] || "服务器未提供明确理由";
  }

  function diagnosticDnsEvidence(result) {
    const reason = String(result?.reason || "").toLowerCase();
    const path = String(result?.path || "unknown").toLowerCase();
    if (reason === "config_changed") return "配置发生变化；没有可采信的 DNS 证据";
    if (reason === "probe_busy") return "诊断尚未执行；没有 DNS 实测证据";
    if (reason === "dns_no_answer") return "DNS 无应答；路径无法验证";
    if (reason === "probe_unavailable") return "诊断服务不可用；没有 DNS 实测证据";
    if (result?.dnsVerified === true && path === "direct") {
      return "已实测：DNS 返回真实地址，手机可直接连接";
    }
    if (result?.dnsVerified === true && path === "gateway") {
      return "已实测：DNS 返回网关地址，连接入口为 VPS";
    }
    return "未取得可验证的 DNS 路径证据";
  }

  function diagnosticRouteConfidence(result) {
    const path = String(result?.path || "unknown").toLowerCase();
    const confidence = String(result?.routeConfidence || "unknown").toLowerCase();
    if (path === "gateway") {
      return confidence === "unknown"
        ? "不确定（无法确认具体出口）"
        : "规则推演（未实测具体出口）";
    }
    const labels = {
      verified: "已验证 DNS 路径；不表示代理出口测速",
      simulated: "规则推演（未进行网络实测）",
      unknown: "不确定"
    };
    return labels[confidence] || labels.unknown;
  }

  function renderRouteDiagnostic(result) {
    const target = $("#route-diagnostic-result");
    empty(target);
    const evidence = diagnosticEvidence(result);
    const card = node("article", `diagnostic-card ${evidence.tone}`);
    const heading = node("div", "diagnostic-heading");
    heading.append(node("strong", "", safeString(result?.domain || "域名诊断", 253)));
    heading.append(node("span", `status-pill ${evidence.tone}`, evidence.label));
    card.append(heading);
    card.append(node("p", "diagnostic-evidence", evidence.detail));

    const details = node("dl", "diagnostic-details");
    const rows = [
      ["目标出口", result?.target ? ruleTargetLabel(String(result.target)) : "无法确定"],
      ["判定路径", diagnosticPathLabel(result?.path)],
      ["DNS 路径证据", diagnosticDnsEvidence(result)],
      ["出口判定置信度", diagnosticRouteConfidence(result)],
      ["判定理由", diagnosticReasonLabel(result?.reason)],
      ["匹配规则", safeString(result?.ruleLabel || "未标明", 300)],
    ];
    rows.forEach(([label, value]) => {
      details.append(node("dt", "", label));
      details.append(node("dd", "", value));
    });
    card.append(details);
    target.append(card);
  }

  async function diagnoseDomain(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const domain = $("#route-diagnostic-domain").value.trim().toLowerCase();
    const resultTarget = $("#route-diagnostic-result");
    if (!domain) return;
    empty(resultTarget);
    resultTarget.append(node("div", "loading-state", "正在诊断，尚未得出结论…"));
    const button = $("button[type='submit']", form);
    setButtonBusy(button, true, "诊断中…");
    try {
      const { data } = await api("/diagnostics/domain", {
        method: "POST",
        body: { domain }
      });
      renderRouteDiagnostic(data || { domain });
    } catch (error) {
      empty(resultTarget);
      const failure = node("div", "diagnostic-unavailable");
      failure.append(node("strong", "", "不确定"));
      failure.append(node("span", "", errorMessage(error)));
      resultTarget.append(failure);
    } finally {
      setButtonBusy(button, false);
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

  function appendSummaryMetric(target, label, value, detail = "", tone = "") {
    const card = node("article", `summary-metric ${tone}`.trim());
    card.append(node("span", "summary-metric-label", label));
    card.append(node("strong", "summary-metric-value", value));
    if (detail) card.append(node("span", "summary-metric-detail", detail));
    target.append(card);
  }

  function renderRuntimeSummary(target, data) {
    empty(target);
    const runtime = safeObject(data) || {};
    if (!runtime || typeof runtime !== "object" || Array.isArray(runtime)) {
      target.append(node("div", "empty-state", "暂时无法读取内核运行信息"));
      return;
    }
    const metrics = node("div", "summary-metric-grid");
    appendSummaryMetric(
      metrics,
      "流量内核",
      String(runtime.backend || "").toLowerCase() === "mihomo" ? "Mihomo" : readableValue(runtime.backend),
      "负责透明代理与分流"
    );
    appendSummaryMetric(metrics, "内核版本", safeString(runtime.version || "未返回", 80), "当前运行版本");
    appendSummaryMetric(metrics, "内存占用", formatBytes(runtime.memory), "Mihomo 当前使用量");
    target.append(metrics);

    const services = runtime.services && typeof runtime.services === "object"
      && !Array.isArray(runtime.services) ? runtime.services : {};
    const entries = serviceEntries(services);
    if (entries.length) {
      target.append(node("h3", "summary-subheading", "相关服务"));
      const list = node("div", "status-list compact-status-list");
      entries.forEach((item) => {
        const tone = serviceStateLevel(item.value);
        const row = node("div", "status-row");
        row.append(node("span", `status-dot ${tone}`));
        row.append(node("span", "status-name", serviceName(item.name)));
        row.append(node("span", "status-value", serviceStateLabel(item.value)));
        list.append(row);
      });
      target.append(list);
    }
  }

  function renderTrafficSummary(target, data) {
    empty(target);
    const traffic = safeObject(data) || {};
    if (!traffic || typeof traffic !== "object" || Array.isArray(traffic)) {
      target.append(node("div", "empty-state", "暂时无法读取连接与流量数据"));
      return;
    }
    if (traffic.available !== true) {
      target.append(node("div", "summary-notice warn", "Mihomo 控制接口暂不可用，以下数值可能不完整。"));
    }
    const connectionCount = Number.isFinite(Number(traffic.connections))
      ? Number(traffic.connections) : 0;
    const metrics = node("div", "summary-metric-grid traffic-metrics");
    appendSummaryMetric(
      metrics,
      "活动连接",
      new Intl.NumberFormat("zh-CN").format(connectionCount),
      "当前正在传输的连接"
    );
    appendSummaryMetric(metrics, "累计上传", formatBytes(traffic.uploadTotal), "本次内核运行期间");
    appendSummaryMetric(metrics, "累计下载", formatBytes(traffic.downloadTotal), "本次内核运行期间");
    target.append(metrics);

    target.append(node("h3", "summary-subheading", "按出口统计"));
    const exits = Array.isArray(traffic.byExit) ? traffic.byExit.slice(0, 128) : [];
    if (!exits.length) {
      target.append(node("div", "empty-state compact-empty", "当前没有活动连接"));
      return;
    }
    const list = node("div", "traffic-exit-list");
    exits.forEach((item) => {
      if (!item || typeof item !== "object") return;
      const row = node("div", "traffic-exit-row");
      const copy = node("div", "traffic-exit-copy");
      const name = item.tag === "unknown" ? "未识别出口" : formatExitName(item.tag || "未命名出口");
      const count = Number.isFinite(Number(item.connections)) ? Number(item.connections) : 0;
      copy.append(node("strong", "", name));
      copy.append(node("span", "", `${new Intl.NumberFormat("zh-CN").format(count)} 个活动连接`));
      row.append(copy, node("span", "traffic-exit-bytes", `上传 ${formatBytes(item.upload)} · 下载 ${formatBytes(item.download)}`));
      list.append(row);
    });
    target.append(list);
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
        renderRuntimeSummary($("#runtime-summary"), runtime.value.data);
      } else {
        empty($("#runtime-summary"));
        $("#runtime-summary").append(node("div", "empty-state", errorMessage(runtime.reason)));
      }
      if (traffic.status === "fulfilled") {
        renderTrafficSummary($("#traffic-summary"), traffic.value.data);
      } else {
        empty($("#traffic-summary"));
        $("#traffic-summary").append(node("div", "empty-state", errorMessage(traffic.reason)));
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

  function formatDateTime(value) {
    if (value === null || value === undefined || value === "") return "时间未知";
    let date;
    if (typeof value === "number") {
      date = new Date(value < 1e12 ? value * 1000 : value);
    } else {
      date = new Date(String(value));
    }
    if (Number.isNaN(date.getTime())) return safeString(value, 80);
    return new Intl.DateTimeFormat("zh-CN", {
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false
    }).format(date);
  }

  function formatBytes(value) {
    const bytes = Number(value);
    if (!Number.isFinite(bytes) || bytes < 0) return "—";
    if (bytes < 1024) return `${Math.round(bytes)} B`;
    const units = ["KiB", "MiB", "GiB", "TiB", "PiB"];
    let amount = bytes;
    let unit = -1;
    do {
      amount /= 1024;
      unit += 1;
    } while (amount >= 1024 && unit < units.length - 1);
    return `${new Intl.NumberFormat("zh-CN", {
      maximumFractionDigits: amount >= 100 ? 0 : amount >= 10 ? 1 : 2
    }).format(amount)} ${units[unit]}`;
  }

  function normalizeSnapshot(item) {
    const id = safeString(item?.id || "", 96);
    if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,95}$/.test(id)) return null;
    return {
      id,
      createdAt: item?.createdAt,
      size: Number(item?.size),
      legacy: item?.legacy === true
    };
  }

  function selectedSnapshot() {
    const id = $("#rollback-snapshot").value;
    return state.snapshots.find((item) => item.id === id);
  }

  function updateSnapshotDetail() {
    const detail = $("#rollback-snapshot-detail");
    const snapshot = selectedSnapshot();
    if (!snapshot) {
      detail.textContent = state.snapshots.length
        ? "请选择一份精确快照。"
        : "没有可回滚的本机快照。";
      return;
    }
    detail.textContent = `${formatDateTime(snapshot.createdAt)} · ${formatBytes(snapshot.size)}${
      snapshot.legacy ? " · 旧版快照" : ""
    } · 稳定 ID：${snapshot.id}`;
  }

  function renderSnapshots(message = "") {
    const select = $("#rollback-snapshot");
    empty(select);
    if (!state.snapshots.length) {
      const option = node("option", "", message || "没有可用快照");
      option.value = "";
      select.append(option);
      select.disabled = true;
      updateSnapshotDetail();
      setMaintenanceControls();
      return;
    }
    state.snapshots.forEach((snapshot, index) => {
      const option = node("option", "", `${formatDateTime(snapshot.createdAt)} · ${
        formatBytes(snapshot.size)
      }${snapshot.legacy ? " · 旧版" : ""}`);
      option.value = snapshot.id;
      option.selected = index === 0;
      select.append(option);
    });
    select.disabled = false;
    updateSnapshotDetail();
    setMaintenanceControls();
  }

  async function loadSnapshots() {
    const { data } = await api("/snapshots");
    state.snapshots = (Array.isArray(data?.items) ? data.items : [])
      .slice(0, 100)
      .map(normalizeSnapshot)
      .filter(Boolean);
    renderSnapshots();
  }

  function normalizeMaintenanceStatus(value) {
    const status = String(value || "").toLowerCase();
    if (["queued", "pending", "accepted", "waiting"].includes(status)) return "queued";
    if (["running", "active", "activating", "started"].includes(status)) return "running";
    if (["succeeded", "success", "completed", "complete", "done"].includes(status)) {
      return "succeeded";
    }
    if (["failed", "failure", "error"].includes(status)) return "failed";
    if (["interrupted", "cancelled", "canceled", "aborted"].includes(status)) {
      return "interrupted";
    }
    return "unknown";
  }

  function normalizeMaintenanceJob(item, fallbackOperation = "") {
    const id = safeString(item?.id || "", 64);
    if (!/^[0-9]{8}[Tt][0-9]{6}[Zz]-[a-f0-9]{12}$/.test(id)) return null;
    return {
      id,
      operation: safeString(
        item?.operation || item?.action || item?.kind || fallbackOperation || "maintenance",
        40
      ),
      status: normalizeMaintenanceStatus(item?.status || item?.state),
      requestedAt: item?.requestedAt ?? item?.createdAt,
      startedAt: item?.startedAt,
      finishedAt: item?.finishedAt,
      snapshotId: safeString(item?.snapshotId || "", 96),
      target: safeString(item?.target || "", 96)
    };
  }

  function maintenanceOperationLabel(operation) {
    const labels = {
      rollback: "回滚快照",
      "software-update": "软件升级",
      update: "软件升级",
      snapshot: "创建快照",
      "config-import": "导入受管配置"
    };
    return labels[operation] || "维护操作";
  }

  function maintenanceStatusView(status) {
    const views = {
      queued: { label: "已排队", tone: "neutral", detail: "任务尚未完成" },
      running: { label: "执行中", tone: "warn", detail: "服务或本页面可能短暂断开" },
      succeeded: { label: "成功", tone: "good", detail: "任务已由后台确认完成" },
      failed: { label: "失败", tone: "bad", detail: "任务未成功；请运行自检后再处理" },
      interrupted: { label: "已中断", tone: "bad", detail: "任务状态未能完整收尾；请运行自检" },
      unknown: { label: "待确认", tone: "neutral", detail: "服务器尚未提供可确认的最终状态" }
    };
    return views[status] || views.unknown;
  }

  function hasActiveMaintenanceJob() {
    return state.maintenanceJobs.some((job) => ["queued", "running"].includes(job.status));
  }

  function setMaintenanceControls() {
    const unavailable = state.maintenancePollDisconnected || hasActiveMaintenanceJob();
    $$("[data-operation], [data-maintenance-control], [data-config-maintenance-control]").forEach((control) => {
      control.disabled = unavailable;
      if (unavailable) {
        control.title = state.maintenancePollDisconnected
          ? "维护任务状态暂时无法确认"
          : "已有维护任务正在执行";
      } else {
        control.removeAttribute("title");
      }
    });
    const select = $("#rollback-snapshot");
    select.disabled = unavailable || !state.snapshots.length;
    const rollbackButton = $("button[type='submit']", $("#rollback-form"));
    rollbackButton.disabled = unavailable || !selectedSnapshot();
  }

  function renderMaintenanceJobs() {
    const target = $("#maintenance-job-list");
    const health = $("#maintenance-job-health");
    empty(target);
    if (state.maintenancePollDisconnected) {
      health.className = "status-pill warn";
      health.textContent = "状态待确认";
      const note = node("div", "job-connection-note");
      note.append(node("strong", "", "暂时无法刷新任务"));
      note.append(node("span", "", "网络恢复或重新登录后会继续查询；现有任务不会被误判为失败。"));
      target.append(note);
    } else if (hasActiveMaintenanceJob()) {
      health.className = "status-pill warn";
      health.textContent = "任务执行中";
    } else {
      health.className = "status-pill good";
      health.textContent = "无活动任务";
    }
    if (!state.maintenanceJobs.length) {
      target.append(node("div", "empty-state", "暂无维护任务记录"));
      setMaintenanceControls();
      return;
    }
    state.maintenanceJobs.slice(0, 20).forEach((job) => {
      const view = maintenanceStatusView(job.status);
      const card = node("article", "job-card");
      card.dataset.jobId = job.id;
      const heading = node("div", "job-card-heading");
      heading.append(node("strong", "", maintenanceOperationLabel(job.operation)));
      heading.append(node("span", `status-pill ${view.tone}`, view.label));
      card.append(heading);
      const targetText = job.snapshotId
        ? `快照 ${job.snapshotId}`
        : (job.target ? `目标 ${job.target}` : `任务 ${job.id}`);
      card.append(node("span", "job-card-target", targetText));
      card.append(node("span", "job-card-detail", view.detail));
      const times = node("span", "job-card-time", `提交：${formatDateTime(job.requestedAt)}`);
      if (job.finishedAt) {
        times.textContent += ` · 完成：${formatDateTime(job.finishedAt)}`;
      } else if (job.startedAt) {
        times.textContent += ` · 开始：${formatDateTime(job.startedAt)}`;
      }
      card.append(times);
      target.append(card);
    });
    setMaintenanceControls();
  }

  function mergeMaintenanceJob(job) {
    const index = state.maintenanceJobs.findIndex((item) => item.id === job.id);
    if (index >= 0) {
      state.maintenanceJobs[index] = job;
    } else {
      state.maintenanceJobs.unshift(job);
    }
    state.maintenanceJobs = state.maintenanceJobs.slice(0, 20);
  }

  function announceMaintenanceResult(job) {
    if (!state.trackedMaintenanceJobs.has(job.id)) return;
    if (!["succeeded", "failed", "interrupted"].includes(job.status)) return;
    state.trackedMaintenanceJobs.delete(job.id);
    const label = maintenanceOperationLabel(job.operation);
    if (job.status === "succeeded") {
      const message = `${label}已由后台确认成功`;
      showOperationResult(message, true);
      toast(message, "good");
      if (job.operation === "rollback") loadSnapshots().catch(() => {});
      return;
    }
    const message = job.status === "interrupted"
      ? `${label}被中断，结果不确定；请运行自检`
      : `${label}未成功；请运行自检后再处理`;
    showOperationResult(message, false);
    toast(message, "bad");
  }

  function stopMaintenancePolling() {
    if (state.maintenancePollTimer) window.clearTimeout(state.maintenancePollTimer);
    state.maintenancePollTimer = 0;
  }

  function scheduleMaintenancePolling(delay = 3500) {
    stopMaintenancePolling();
    if ($("#app-view").hidden) return;
    if (!hasActiveMaintenanceJob() && !state.maintenancePollDisconnected) return;
    state.maintenancePollTimer = window.setTimeout(pollMaintenanceJobs, delay);
  }

  async function pollMaintenanceJobs() {
    state.maintenancePollTimer = 0;
    if ($("#app-view").hidden) return;
    const active = state.maintenanceJobs.filter((job) =>
      ["queued", "running"].includes(job.status)
    );
    if (!active.length) {
      await loadMaintenanceJobs({ silent: true });
      return;
    }
    const results = await Promise.allSettled(active.map((job) =>
      api(`/jobs/${encodeURIComponent(job.id)}`)
    ));
    let disconnected = false;
    results.forEach((result, index) => {
      if (result.status !== "fulfilled") {
        disconnected = true;
        return;
      }
      const job = normalizeMaintenanceJob(
        result.value.data,
        active[index].operation
      );
      if (!job) {
        disconnected = true;
        return;
      }
      mergeMaintenanceJob(job);
      announceMaintenanceResult(job);
    });
    state.maintenancePollDisconnected = disconnected;
    renderMaintenanceJobs();
    scheduleMaintenancePolling(disconnected ? 8000 : 3500);
  }

  async function loadMaintenanceJobs(options = {}) {
    try {
      const { data } = await api("/jobs");
      const jobs = (Array.isArray(data?.items) ? data.items : [])
        .slice(0, 20)
        .map((item) => normalizeMaintenanceJob(item))
        .filter(Boolean);
      state.maintenanceJobs = jobs;
      jobs.filter((job) => ["queued", "running"].includes(job.status))
        .forEach((job) => state.trackedMaintenanceJobs.add(job.id));
      state.maintenancePollDisconnected = false;
      renderMaintenanceJobs();
      scheduleMaintenancePolling();
    } catch (error) {
      state.maintenancePollDisconnected = true;
      renderMaintenanceJobs();
      scheduleMaintenancePolling(8000);
      if (!options.silent && !(error instanceof ApiError && error.status === 401)) {
        toast(errorMessage(error), "bad");
      }
    }
  }

  function registerMaintenanceJob(item, fallbackOperation) {
    const job = normalizeMaintenanceJob(item, fallbackOperation);
    if (!job) {
      loadMaintenanceJobs({ silent: true });
      return null;
    }
    mergeMaintenanceJob(job);
    if (["queued", "running"].includes(job.status)) {
      state.trackedMaintenanceJobs.add(job.id);
    }
    state.maintenancePollDisconnected = false;
    renderMaintenanceJobs();
    scheduleMaintenancePolling(1500);
    return job;
  }

  async function loadSettings() {
    const [settingsResult, snapshotResult] = await Promise.allSettled([
      api("/settings"),
      loadSnapshots()
    ]);
    if (settingsResult.status !== "fulfilled") throw settingsResult.reason;
    if (snapshotResult.status !== "fulfilled") {
      state.snapshots = [];
      renderSnapshots("快照清单暂时不可用");
    }
    await loadMaintenanceJobs({ silent: true });
    const settings = settingsResult.value.data || {};
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

  function resetImportPreview(message = "") {
    state.importPreview = null;
    const target = $("#config-import-result");
    target.hidden = !message;
    empty(target);
    if (message) target.append(node("div", "empty-state", message));
  }

  function renderImportPreview(preview) {
    const target = $("#config-import-result");
    empty(target);
    target.hidden = false;
    target.append(node("h3", "", "预览已完成，生产配置尚未修改"));
    target.append(node("h4", "import-section-title", "导入内容概览"));
    const summary = node("div", "kv-list import-summary");
    renderKeyValues(summary, preview.summary || {}, "没有可显示的配置变更");
    target.append(summary);
    const warnings = Array.isArray(preview.warnings) ? preview.warnings.slice(0, 20) : [];
    if (warnings.length) {
      const box = node("div", "import-warnings");
      box.append(node("strong", "", "导入提醒"));
      const list = node("ul");
      warnings.forEach((warning) => list.append(node("li", "", safeString(warning, 300))));
      box.append(list);
      target.append(box);
    }
    const controls = node("div", "import-apply-controls");
    const modeWrap = node("div", "grow");
    const modeLabel = node("label", "", "应用方式");
    modeLabel.htmlFor = "config-import-mode";
    const mode = node("select");
    mode.id = "config-import-mode";
    (Array.isArray(preview.modes) ? preview.modes : ["merge"]).forEach((value) => {
      const option = node("option", "", value === "replace" ? "替换受管配置" : "合并（推荐）");
      option.value = value;
      mode.append(option);
    });
    modeWrap.append(modeLabel, mode);
    controls.append(modeWrap);
    target.append(controls);
    const conflicts = Array.isArray(preview.conflicts) ? preview.conflicts.slice(0, 200) : [];
    if (conflicts.length) {
      const conflictBox = node("div", "import-conflicts");
      conflictBox.append(node("strong", "", "同名项目处理"));
      conflicts.forEach((conflict) => {
        const row = node("label", "import-conflict-row");
        const kind = ({
          name: "节点或策略组",
          "proxy-provider": "代理提供器",
          "rule-provider": "规则提供器"
        })[conflict.kind] || "配置项目";
        row.append(node("span", "", `${kind}：${safeString(conflict.name, 80)}`));
        const select = node("select");
        select.dataset.importConflict = safeString(conflict.conflictId, 64);
        const incoming = node("option", "", "使用导入内容");
        incoming.value = "incoming";
        const existing = node("option", "", "保留现有内容");
        existing.value = "existing";
        if (conflict.default === "existing") existing.selected = true;
        select.append(incoming, existing);
        row.append(select);
        conflictBox.append(row);
      });
      target.append(conflictBox);
      const syncConflictMode = () => {
        const replace = mode.value === "replace";
        $$('[data-import-conflict]', conflictBox).forEach((select) => {
          if (replace) select.value = "incoming";
          select.disabled = replace;
        });
      };
      mode.addEventListener("change", syncConflictMode);
      syncConflictMode();
    }
    const apply = node("button", "button warning", "确认并创建导入任务");
    apply.type = "button";
    apply.id = "config-import-apply";
    apply.dataset.configMaintenanceControl = "";
    const cancel = node("button", "button ghost", "取消预览并清理暂存");
    cancel.type = "button";
    cancel.id = "config-import-cancel";
    cancel.dataset.configMaintenanceControl = "";
    target.append(apply, cancel);
    setMaintenanceControls();
  }

  function importContentType(file, kind) {
    const name = String(file.name || "").toLowerCase();
    if (name.endsWith(".zip")) return "application/zip";
    if (name.endsWith(".gz") || name.endsWith(".tgz")) return "application/gzip";
    if (kind === "pdg" && name.endsWith(".json")) return "application/json";
    return "application/yaml";
  }

  async function previewConfigImport(event) {
    event.preventDefault();
    const kind = $("#config-import-kind").value;
    const input = $("#config-import-file");
    let file = input.files?.[0];
    const maximumMiB = kind === "pdg" ? 68 : 36;
    if (!file || file.size <= 0 || file.size > maximumMiB * 1024 * 1024) {
      toast(`请选择不超过 ${maximumMiB} MiB 的非空配置文件`, "bad");
      return;
    }
    const button = $("#config-import-preview");
    setButtonBusy(button, true, "正在安全解析…");
    resetImportPreview("正在上传并验证；此阶段不会修改生产配置…");
    try {
      const contentType = importContentType(file, kind);
      const bytes = await file.arrayBuffer();
      // Release the File object/input immediately after the bounded copy; the
      // upload and parser may take time and must not retain the local handle.
      input.value = "";
      file = null;
      const result = await binaryApi(
        `/imports/${encodeURIComponent(kind)}/preview`, bytes, contentType
      );
      state.importPreview = result.data || null;
      if (!state.importPreview?.importId) throw new ApiError(500, "invalid_preview", "预览结果无效");
      renderImportPreview(state.importPreview);
      toast("导入预览已完成，尚未修改生产配置", "good");
    } catch (error) {
      resetImportPreview(errorMessage(error));
      toast(errorMessage(error), "bad");
    } finally {
      input.value = "";
      file = null;
      setButtonBusy(button, false);
      setMaintenanceControls();
    }
  }

  async function applyConfigImport() {
    const preview = state.importPreview;
    if (!preview?.importId) return;
    const confirmed = await confirmAction(
      "应用受管配置导入",
      "服务器会再次核对暂存文件和预览基线，然后通过 PDG 配置事务校验、提交并观察服务；失败会自动回滚。",
      "确认应用", "warning"
    );
    if (!confirmed) return;
    const conflicts = {};
    $$('[data-import-conflict]', $("#config-import-result")).forEach((select) => {
      conflicts[select.dataset.importConflict] = select.value;
    });
    const button = $("#config-import-apply");
    setButtonBusy(button, true, "正在创建任务…");
    try {
      const result = await api(`/imports/${encodeURIComponent(preview.importId)}/apply`, {
        method: "POST",
        body: { confirm: true, mode: $("#config-import-mode").value, conflicts }
      });
      const job = registerMaintenanceJob(result.data?.job, "config-import");
      resetImportPreview(job ? "导入任务已提交，请在最近维护任务中查看结果。" : "导入请求已接受。");
      $("#config-import-file").value = "";
      toast("配置导入任务已提交，尚未确认完成", "good");
    } catch (error) {
      toast(errorMessage(error), "bad");
    } finally {
      setButtonBusy(button, false);
      setMaintenanceControls();
    }
  }

  async function cancelConfigImport() {
    const preview = state.importPreview;
    if (!preview?.importId) return;
    const button = $("#config-import-cancel");
    setButtonBusy(button, true, "正在清理…");
    try {
      await api(`/imports/${encodeURIComponent(preview.importId)}`, { method: "DELETE" });
      resetImportPreview("预览已取消，暂存上传已立即清理；生产配置未修改。");
      toast("导入预览已取消", "good");
    } catch (error) {
      toast(errorMessage(error), "bad");
    } finally {
      setButtonBusy(button, false);
      setMaintenanceControls();
    }
  }

  function openConfigExport(kind) {
    state.exportKind = kind;
    const dialog = $("#export-config-dialog");
    $("#export-config-password").value = "";
    dialog.returnValue = "cancel";
    dialog.showModal();
    window.setTimeout(() => $("#export-config-password").focus(), 0);
  }

  async function submitConfigExport(event) {
    event.preventDefault();
    const kind = state.exportKind;
    const input = $("#export-config-password");
    let password = input.value;
    input.value = "";
    const button = $("#export-config-submit");
    setButtonBusy(button, true, "正在验证…");
    try {
      const response = await fetch(`${API_BASE}/exports/${encodeURIComponent(kind)}`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": state.csrf },
        credentials: "same-origin", cache: "no-store", body: JSON.stringify({ password })
      });
      password = "";
      if (!response.ok) {
        let envelope = null;
        try { envelope = await response.json(); } catch (_error) { envelope = null; }
        throw new ApiError(
          response.status, envelope?.error?.code,
          response.status === 401 ? "管理密码不正确" : envelope?.error?.message
        );
      }
      const disposition = response.headers.get("Content-Disposition") || "";
      const match = /filename="([A-Za-z0-9_.-]{1,64})"/.exec(disposition);
      if (!match) throw new ApiError(500, "invalid_attachment", "导出附件无效");
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = match[1];
      link.click();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
      $("#export-config-dialog").close("complete");
      toast("配置已导出到本机下载目录", "good");
    } catch (error) {
      password = "";
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
      const job = result.data?.job
        ? registerMaintenanceJob(result.data.job, name)
        : null;
      if (job && ["queued", "running", "unknown"].includes(job.status)) {
        const message = `${maintenanceOperationLabel(job.operation)}任务已提交，尚未确认完成`;
        showOperationResult(message, true);
        toast(message, "good");
      } else {
        showOperationResult(result.message || "操作已提交并完成", true);
        toast(result.message || "操作已完成", "good");
      }
      if (name === "restart" || name === "rules-update") await loadOverview();
      if (name === "snapshot" && !job) await loadSnapshots();
    } catch (error) {
      const message = errorMessage(error);
      showOperationResult(message, false);
      toast(message, "bad");
    } finally {
      setButtonBusy(sourceButton, false);
      setMaintenanceControls();
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
    const snapshot = selectedSnapshot();
    if (!snapshot) {
      toast("请选择清单中的一份精确快照", "bad");
      return;
    }
    const confirmed = await confirmAction(
      "回滚本机快照",
      `即将回滚到 ${formatDateTime(snapshot.createdAt)} 的快照（稳定 ID：${snapshot.id}）。当前受管配置和服务状态会被覆盖，连接可能中断。`,
      "确认回滚",
      "danger"
    );
    if (!confirmed) return;
    const button = $("button[type='submit']", event.currentTarget);
    setButtonBusy(button, true, "正在启动…");
    showOperationResult(`正在提交快照 ${snapshot.id} 的精确回滚任务…`, true);
    try {
      const result = await api("/actions/rollback", {
        method: "POST",
        body: { snapshotId: snapshot.id, confirm: true }
      });
      const job = registerMaintenanceJob(result.data?.job, "rollback");
      const message = job
        ? "回滚任务已提交，尚未确认完成；连接可能中断"
        : "回滚启动请求已接受，正在查询后台任务状态";
      showOperationResult(message, true);
      toast(message, "good");
      if (!job) await loadMaintenanceJobs({ silent: true });
    } catch (error) {
      if (error instanceof ApiError && error.code === "network_error") {
        const message = "连接在启动响应前中断，回滚是否开始尚待确认；正在查询最近任务";
        showOperationResult(message, true);
        toast(message, "neutral");
        await loadMaintenanceJobs({ silent: true });
      } else {
        const message = errorMessage(error);
        showOperationResult(message, false);
        toast(message, "bad");
      }
    } finally {
      setButtonBusy(button, false);
      setMaintenanceControls();
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
      const result = await api("/actions/software-update", {
        method: "POST", body: { confirm: true }
      });
      const job = registerMaintenanceJob(result.data?.job, "software-update");
      const message = job
        ? "升级任务已提交，尚未确认完成；连接中断后请重新登录查看任务"
        : "升级启动请求已接受，正在查询后台任务状态";
      showOperationResult(message, true);
      toast(message, "good");
      if (!job) await loadMaintenanceJobs({ silent: true });
    } catch (error) {
      if (error instanceof ApiError && error.code === "network_error") {
        const message = "连接在启动响应前中断，升级是否开始尚待确认；重新登录后会继续查询";
        showOperationResult(message, true);
        toast(message, "neutral");
        await loadMaintenanceJobs({ silent: true });
      } else {
        const message = errorMessage(error);
        showOperationResult(message, false);
        toast(message, "bad");
      }
    } finally {
      setButtonBusy(button, false);
      setMaintenanceControls();
    }
  }

  function bindEvents() {
    $("#login-form").addEventListener("submit", login);
    $("#logout-button").addEventListener("click", logout);
    updateThemeButton();
    $("#theme-toggle").addEventListener("click", openThemeDialog);
    $("#theme-dialog-close").addEventListener("click", () => closeThemeDialog(true));
    $("#theme-dialog").addEventListener("cancel", (event) => {
      event.preventDefault();
      closeThemeDialog(true);
    });
    $("#theme-dialog").addEventListener("click", (event) => {
      if (event.target === event.currentTarget) closeThemeDialog(true);
    });
    $("#theme-dialog").addEventListener("close", () => {
      $("#theme-toggle").setAttribute("aria-expanded", "false");
    });
    $$("#theme-dialog [data-theme-mode]").forEach((option) => {
      option.addEventListener("click", () => {
        window.PDGTheme?.set(option.dataset.themeMode);
        updateThemeButton();
        closeThemeDialog(true);
      });
    });
    window.addEventListener("pdg-theme-change", updateThemeButton);
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
        if (mobileNavigationQuery.matches) return;
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

    renderMobileMoreItems();
    syncNavigationSemantics();
    syncMobileMoreState();
    $("#mobile-more-button").addEventListener("click", openMobileMore);
    $("#mobile-more-button").addEventListener("keydown", (event) => {
      if (!["ArrowUp", "ArrowDown"].includes(event.key)) return;
      event.preventDefault();
      openMobileMore();
    });
    $("#mobile-more-close").addEventListener("click", () => closeMobileMore(true));
    $("#mobile-more-items").addEventListener("click", (event) => {
      const item = event.target.closest("[data-more-tab]");
      if (!item) return;
      activateTab(item.dataset.moreTab);
      closeMobileMore(true);
    });
    $("#mobile-more-items").addEventListener("keydown", mobileMoreKeydown);
    $("#mobile-more-dialog").addEventListener("cancel", (event) => {
      event.preventDefault();
      closeMobileMore(true);
    });
    $("#mobile-more-dialog").addEventListener("click", (event) => {
      if (event.target === event.currentTarget) closeMobileMore(true);
    });
    $("#mobile-more-dialog").addEventListener("close", () => {
      $("#mobile-more-button").setAttribute("aria-expanded", "false");
      if (state.mobileMoreRestoreFocus && mobileNavigationQuery.matches) {
        $("#mobile-more-button").focus();
      }
      state.mobileMoreRestoreFocus = false;
    });
    const mobileNavigationChanged = () => {
      const focusedTab = document.activeElement?.closest?.(".tab");
      const focusWasInMore = document.activeElement === $("#mobile-more-button")
        || $("#mobile-more-dialog").contains(document.activeElement);
      const focusWasInMobileNavigation = Boolean(focusedTab) || focusWasInMore;
      if (!mobileNavigationQuery.matches) closeMobileMore(false);
      renderMobileMoreItems();
      syncNavigationSemantics();
      syncMobileMoreState();
      if (mobileNavigationQuery.matches && focusedTab
          && !focusedTab.hasAttribute("data-mobile-primary")) {
        $("#mobile-more-button").focus();
      } else if (!mobileNavigationQuery.matches && focusWasInMobileNavigation) {
        $$(".tab").find((tab) => tab.dataset.tab === state.activeTab)?.focus();
      }
    };
    if (typeof mobileNavigationQuery.addEventListener === "function") {
      mobileNavigationQuery.addEventListener("change", mobileNavigationChanged);
    } else {
      mobileNavigationQuery.addListener(mobileNavigationChanged);
    }

    $$("[data-go-tab]").forEach((button) => {
      button.addEventListener("click", () => activateTab(button.dataset.goTab, true));
    });
    $("#refresh-button").addEventListener("click", () => loadTab(state.activeTab));
    $("#exit-form").addEventListener("submit", addExit);
    $("#test-exits").addEventListener("click", testExits);
    $("#exit-list").addEventListener("click", handleExitAction);
    $("#replace-exit-form").addEventListener("submit", replaceExit);
    $("[data-action='cancel-replace-exit']").addEventListener("click", cancelReplaceExit);
    $("#replace-exit-dialog").addEventListener("close", () => {
      $("#replace-exit-link").value = "";
      state.replaceExitTag = "";
    });
    $("#exit-order").addEventListener("click", moveExitOrder);
    $("#save-order").addEventListener("click", saveExitOrder);
    $("#default-exit-form").addEventListener("submit", saveDefaultExit);
    $("#group-form").addEventListener("submit", addGroup);
    $("#group-list").addEventListener("click", handleGroupAction);
    $("#group-type").addEventListener("change", updateGroupOptions);
    $("#group-cancel-edit").addEventListener("click", resetGroupEditor);
    $("#group-add-member").addEventListener("click", () => openGroupPicker("member"));
    $("#group-add-provider").addEventListener("click", () => openGroupPicker("provider"));
    $("#group-member-chips").addEventListener("click", editGroupSelection);
    $("#group-provider-chips").addEventListener("click", editGroupSelection);
    $("#group-picker-search").addEventListener("input", renderGroupPickerOptions);
    $("#group-picker-options").addEventListener("click", chooseGroupPickerOption);
    $("#group-picker-close").addEventListener("click", () => closeGroupPicker(null));
    $("#group-picker-dialog").addEventListener("cancel", (event) => {
      event.preventDefault();
      closeGroupPicker(null);
    });
    $("#group-picker-dialog").addEventListener("click", (event) => {
      if (event.target === event.currentTarget) closeGroupPicker(null);
    });
    $("#group-picker-dialog").addEventListener("close", () => {
      if (!state.groupPicker) return;
      const resolve = state.groupPicker.resolve;
      state.groupPicker = null;
      if (resolve) resolve(null);
    });
    $("#text-entry-form").addEventListener("submit", (event) => {
      event.preventDefault();
      const input = $("#text-entry-value");
      if (input.required && !input.value.trim()) return;
      settleTextEntry(input.value.trim());
    });
    $("[data-text-entry-cancel]").addEventListener("click", () => settleTextEntry(null));
    $("#text-entry-dialog").addEventListener("cancel", (event) => {
      event.preventDefault();
      settleTextEntry(null);
    });
    $("#text-entry-dialog").addEventListener("close", () => {
      if (!state.textEntryResolve) return;
      const resolve = state.textEntryResolve;
      state.textEntryResolve = null;
      resolve(null);
    });
    $("#rule-form").addEventListener("submit", addRule);
    $("#rule-list").addEventListener("click", handleRuleAction);
    $("#ruleset-form").addEventListener("submit", addRuleset);
    $("#ruleset-list").addEventListener("click", handleRulesetAction);
    $("#route-diagnostic-form").addEventListener("submit", diagnoseDomain);
    $("#dns-remote-form").addEventListener("submit", (event) => saveDns(event, "remote"));
    $("#dns-local-form").addEventListener("submit", (event) => saveDns(event, "local"));
    $("#runtime-refresh").addEventListener("click", loadRuntime);
    $("#log-lines").addEventListener("change", loadRuntime);
    $("#tfo-form").addEventListener("submit", saveTfo);
    $("#panel-ops").addEventListener("click", handleOperationButton);
    $("#rollback-snapshot").addEventListener("change", () => {
      updateSnapshotDetail();
      setMaintenanceControls();
    });
    $("#rollback-form").addEventListener("submit", rollback);
    $("#software-update").addEventListener("click", softwareUpdate);
    $("#config-import-form").addEventListener("submit", previewConfigImport);
    const discardSupersededPreview = () => {
      if (state.importPreview?.importId) cancelConfigImport();
      else resetImportPreview();
    };
    $("#config-import-kind").addEventListener("change", discardSupersededPreview);
    $("#config-import-file").addEventListener("change", discardSupersededPreview);
    $("#config-import-result").addEventListener("click", (event) => {
      if (event.target.closest("#config-import-apply")) applyConfigImport();
      if (event.target.closest("#config-import-cancel")) cancelConfigImport();
    });
    $$("[data-export-kind]").forEach((button) => {
      button.addEventListener("click", () => openConfigExport(button.dataset.exportKind));
    });
    $("#export-config-form").addEventListener("submit", submitConfigExport);
    $("[data-export-cancel]").addEventListener("click", () => {
      $("#export-config-password").value = "";
      state.exportKind = "";
      $("#export-config-dialog").close("cancel");
    });
    $("#export-config-dialog").addEventListener("close", () => {
      $("#export-config-password").value = "";
      state.exportKind = "";
    });

    document.addEventListener("visibilitychange", () => {
      if (!document.hidden && state.activeTab === "runtime") loadRuntime();
      if (!document.hidden && hasActiveMaintenanceJob()) scheduleMaintenancePolling(250);
    });
    window.setInterval(() => {
      updateSessionLabel();
      if (!document.hidden && state.activeTab === "runtime" && !$("#app-view").hidden) loadRuntime();
    }, 15000);
  }

  bindEvents();
  updateGroupOptions();
  loadSession();
})();
