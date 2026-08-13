#!/usr/bin/env python3
"""Static/DOM regressions for the native PDG Web frontend."""
from __future__ import annotations

from html.parser import HTMLParser
import json
from pathlib import Path
import re
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "deploy/web/static"
INDEX_SOURCE = (STATIC / "index.html").read_text(encoding="utf-8")
APP_SOURCE = (STATIC / "app.js").read_text(encoding="utf-8")
STYLE_SOURCE = (STATIC / "style.css").read_text(encoding="utf-8")
MANIFEST = json.loads((STATIC / "manifest.webmanifest").read_text(encoding="utf-8"))


class FrontendParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.elements: dict[str, tuple[str, dict[str, str | None]]] = {}
        self.assets: list[str] = []
        self.inline_handlers: list[str] = []
        self.inline_styles: list[str] = []
        self.style_tags = 0
        self.scripts_without_src = 0

    def handle_starttag(self, tag: str, attrs) -> None:
        values = dict(attrs)
        element_id = values.get("id")
        if element_id:
            assert element_id not in self.elements, f"duplicate id: {element_id}"
            self.elements[element_id] = (tag, values)
        for name, value in attrs:
            if name.lower().startswith("on"):
                self.inline_handlers.append(name)
            if name.lower() == "style":
                self.inline_styles.append(value or "")
        if tag == "style":
            self.style_tags += 1
        if tag == "script":
            if not values.get("src"):
                self.scripts_without_src += 1
            else:
                self.assets.append(values["src"])
        if tag == "link" and values.get("href"):
            self.assets.append(values["href"])
        if tag in {"img", "source"} and values.get("src"):
            self.assets.append(values["src"])


def function_source(name: str) -> str:
    start_match = re.search(
        rf"(?m)^  (?:async )?function {re.escape(name)}\([^)]*\) \{{", APP_SOURCE
    )
    assert start_match, f"missing JS function: {name}"
    next_match = re.search(
        r"(?m)^  (?:async )?function [A-Za-z0-9_]+\(",
        APP_SOURCE[start_match.end():],
    )
    end = len(APP_SOURCE) if next_match is None else start_match.end() + next_match.start()
    return APP_SOURCE[start_match.start():end]


parser = FrontendParser()
parser.feed(INDEX_SOURCE)

# CSP-compatible, same-origin static shell with no query-bearing asset requests.
assert parser.style_tags == 0
assert parser.scripts_without_src == 0
assert not parser.inline_handlers
assert not parser.inline_styles
for asset in parser.assets:
    parsed = urlsplit(asset)
    assert not parsed.scheme and not parsed.netloc, f"external asset: {asset}"
    assert not parsed.query and not parsed.fragment, f"query-bearing asset: {asset}"
assert set(parser.assets) == {
    "./manifest.webmanifest", "./icon.svg", "./style.css", "./app.js",
}
for sink in (
    "innerHTML", "outerHTML", "insertAdjacentHTML", "document.write",
    "localStorage", "sessionStorage", "new Function", "eval(",
):
    assert sink not in APP_SOURCE, sink
assert "@import" not in STYLE_SOURCE
assert not re.search(r"url\s*\(\s*['\"]?https?://", STYLE_SOURCE, re.I)

# Browser-side password policy agrees with setup's minimum.
password_tag, password_attrs = parser.elements["login-password"]
assert password_tag == "input"
assert password_attrs.get("type") == "password"
assert password_attrs.get("minlength") == "12"
assert parser.elements["ruleset-label"][1].get("maxlength") == "40"

# The seven native tabs form one complete, ordered tab/panel relationship.
tab_ids = ("overview", "exits", "groups", "rules", "dns", "runtime", "ops")
for tab_id in tab_ids:
    tab_tag, tab_attrs = parser.elements[f"tab-{tab_id}"]
    assert tab_tag == "button"
    assert tab_attrs.get("role") == "tab"
    assert tab_attrs.get("data-tab") == tab_id
    assert tab_attrs.get("aria-controls") == f"panel-{tab_id}"
    panel_tag, panel_attrs = parser.elements[f"panel-{tab_id}"]
    assert panel_tag == "section"
    assert panel_attrs.get("role") == "tabpanel"
    assert panel_attrs.get("aria-labelledby") == f"tab-{tab_id}"
assert [INDEX_SOURCE.index(f'id="tab-{tab_id}"') for tab_id in tab_ids] == sorted(
    INDEX_SOURCE.index(f'id="tab-{tab_id}"') for tab_id in tab_ids
)

# Mobile keeps four explicitly primary canonical tabs plus an independent More
# button. Every current or future canonical tab without the primary marker is
# projected into the drawer; the More action is deliberately outside tablist.
primary_ids = ("overview", "exits", "groups", "rules")
assert all("data-mobile-primary" in parser.elements[f"tab-{tab_id}"][1]
           for tab_id in primary_ids)
assert all("data-mobile-primary" not in parser.elements[f"tab-{tab_id}"][1]
           for tab_id in set(tab_ids) - set(primary_ids))
tab_list_tag, tab_list_attrs = parser.elements["canonical-tab-list"]
assert tab_list_tag == "div" and tab_list_attrs.get("role") == "tablist"
more_tag, more_attrs = parser.elements["mobile-more-button"]
assert more_tag == "button" and more_attrs.get("role") != "tab"
assert more_attrs.get("aria-haspopup") == "dialog"
assert more_attrs.get("aria-expanded") == "false"
assert more_attrs.get("aria-controls") == "mobile-more-dialog"
tab_list_start = INDEX_SOURCE.index('id="canonical-tab-list"')
tab_list_end = INDEX_SOURCE.index("</div>", tab_list_start)
assert INDEX_SOURCE.index('id="mobile-more-button"') > tab_list_end
dialog_tag, dialog_attrs = parser.elements["mobile-more-dialog"]
assert dialog_tag == "dialog" and dialog_attrs.get("aria-labelledby") == "mobile-more-title"
assert dialog_attrs.get("aria-modal") == "true"
assert parser.elements["mobile-more-items"][0] == "nav"

# On 320–430px portrait screens, the five bottom targets stay on one row and
# keep a 2.75rem (44px at the root size) minimum touch width. Safe-area padding
# and overflow remain as a fallback, while desktop restores the canonical list.
mobile_style = STYLE_SOURCE[:STYLE_SOURCE.index("@media (min-width: 760px)")]
mobile_bar = re.search(r"(?ms)^\.tab-bar\s*\{(.*?)^\}", mobile_style).group(1)
mobile_list = re.search(r"(?ms)^\.tab-list\s*\{(.*?)^\}", mobile_style).group(1)
mobile_control = re.search(
    r"(?ms)^\.tab,\s*^\.mobile-more-button\s*\{(.*?)^\}", mobile_style
).group(1)
for declaration in (
    "display: grid", "grid-template-columns: repeat(5, minmax(2.75rem, 1fr))",
    "overflow-x: auto",
    "overflow-y: hidden", "scroll-snap-type: x proximity",
):
    assert declaration in mobile_bar
assert "grid-template-columns: repeat(4, minmax(2.75rem, 1fr))" in mobile_list
assert "grid-column: 1 / span 4" in mobile_list
assert ".tab:not([data-mobile-primary])" in mobile_style
assert "var(--safe-left)" in mobile_bar and "var(--safe-right)" in mobile_bar
assert "min-height: 3.4rem" in mobile_control
assert "min-width: 2.75rem" in mobile_control
assert "white-space: nowrap" in mobile_control
assert "var(--safe-bottom)" in mobile_style
sheet_style = re.search(r"(?ms)^\.mobile-more-sheet\s*\{(.*?)^\}", mobile_style).group(1)
for safe_edge in ("--safe-left", "--safe-right", "--safe-bottom"):
    assert safe_edge in sheet_style
app_shell_style = re.search(r"(?ms)^\.app-shell\s*\{(.*?)^\}", mobile_style).group(1)
assert "padding-bottom: calc(5.4rem + var(--safe-bottom))" in app_shell_style
desktop_style = STYLE_SOURCE[STYLE_SOURCE.index("@media (min-width: 760px)"):]
assert "flex-direction: column" in desktop_style
assert "overflow: visible" in desktop_style
assert ".mobile-more-button" in desktop_style and "display: none" in desktop_style
assert ".tab:not([data-mobile-primary])" in desktop_style

# Drawer behavior is DOM-derived and keeps canonical activate/load ownership:
# modal focus, Escape/click-outside close, selection close, focus restoration,
# keyboard reachability, active semantics and responsive teardown are all wired.
overflow_tabs = function_source("mobileOverflowTabs")
assert "data-mobile-primary" in overflow_tabs
for forbidden in ('"dns"', '"runtime"', '"ops"'):
    assert forbidden not in overflow_tabs
render_more = function_source("renderMobileMoreItems")
assert "mobileOverflowTabs()" in render_more
assert "document.createDocumentFragment()" in render_more
assert "items.replaceChildren(fragment)" in render_more
sync_more = function_source("syncMobileMoreState")
assert 'more.setAttribute("aria-current", "page")' in sync_more
assert 'item.setAttribute("aria-current", "page")' in sync_more
open_more = function_source("openMobileMore")
assert "dialog.showModal()" in open_more
assert "requestAnimationFrame" in open_more and "target.focus()" in open_more
close_more = function_source("closeMobileMore")
assert "dialog.close()" in close_more and '$("#mobile-more-button").focus()' in close_more
more_keys = function_source("mobileMoreKeydown")
for key in ("ArrowUp", "ArrowDown", "Home", "End"):
    assert key in more_keys
semantics = function_source("syncNavigationSemantics")
for contract in (
    'tabList.removeAttribute("role")',
    'tabList.setAttribute("role", "tablist")',
    'tab.removeAttribute("role")',
    'tab.removeAttribute("aria-selected")',
    'tab.tabIndex = primary ? 0 : -1',
    'tab.setAttribute("aria-hidden", "true")',
    'tab.setAttribute("aria-current", "page")',
    'panel.setAttribute("role", "region")',
    'panel.setAttribute("aria-label", mobileTabLabel(tab))',
    'tab.setAttribute("role", "tab")',
    'tab.setAttribute("aria-selected", String(active))',
    'tab.tabIndex = active ? 0 : -1',
    'panel.setAttribute("role", "tabpanel")',
    'panel.setAttribute("aria-labelledby", tab.id)',
    'panel.removeAttribute("aria-label")',
):
    assert contract in semantics
bind_events = function_source("bindEvents")
for event_name in ('"cancel"', '"click"', '"close"', '"change"'):
    assert event_name in bind_events
assert "event.target === event.currentTarget" in bind_events
assert "closeMobileMore(true)" in bind_events
assert "closeMobileMore(false)" in bind_events
assert "mobileNavigationQuery.matches" in bind_events
assert "syncNavigationSemantics()" in bind_events
assert "if (mobileNavigationQuery.matches) return" in bind_events
assert "focusWasInMore" in bind_events
assert "focusWasInMobileNavigation = Boolean(focusedTab) || focusWasInMore" in bind_events
assert "!mobileNavigationQuery.matches && focusWasInMobileNavigation" in bind_events
assert "tab.dataset.tab === state.activeTab)?.focus()" in bind_events
assert '!focusedTab.hasAttribute("data-mobile-primary")' in bind_events
assert '$("#mobile-more-button").addEventListener("keydown"' in bind_events
assert '["ArrowUp", "ArrowDown"]' in bind_events
show_authenticated = function_source("showAuthenticated")
assert "closeMobileMore(false)" in show_authenticated
activate_tab = function_source("activateTab")
assert "syncMobileMoreState(name)" in activate_tab
assert "syncNavigationSemantics(name)" in activate_tab
assert '$("#mobile-more-button")' in activate_tab
assert "navigationTarget?.scrollIntoView" in activate_tab
assert 'inline: "nearest"' in activate_tab
assert "loadTab(name)" in activate_tab

# Doctor results are rendered as a structured, live status panel rather than a
# preformatted text dump.
doctor_tag, doctor_attrs = parser.elements["doctor-summary"]
assert doctor_tag == "div"
assert doctor_attrs.get("aria-live") == "polite"
assert "doctor-panel" in (doctor_attrs.get("class") or "")
assert "doctor-health" in parser.elements
load_overview = function_source("loadOverview")
assert 'renderDoctorSummary($("#doctor-summary"), info.doctor);' in load_overview
assert "doctorSummaryText" not in APP_SOURCE
for selector in (
    ".doctor-result", ".doctor-stats", ".doctor-group",
    ".doctor-check", ".doctor-check-state",
):
    assert selector in STYLE_SOURCE

# Configuration migration keeps credentials/files out of long-lived DOM state,
# exposes only same-origin templates, and participates in the maintenance gate.
for template in (
    "/templates/mihomo-import.example.yaml",
    "/templates/mosdns-import.example.yaml",
):
    assert template in INDEX_SOURCE
for element_id in (
    "config-import-file", "config-import-preview", "config-import-result",
    "export-config-dialog", "export-config-password", "export-config-submit",
):
    assert element_id in parser.elements
preview_import = function_source("previewConfigImport")
assert "await file.arrayBuffer()" in preview_import
read_at = preview_import.index("await file.arrayBuffer()")
clear_at = preview_import.index('input.value = "";', read_at)
upload_at = preview_import.index("await binaryApi(", read_at)
release_at = preview_import.index("file = null;", read_at)
assert read_at < clear_at < release_at < upload_at
assert 'kind === "pdg" ? 68 : 36' in preview_import
assert "maximumMiB * 1024 * 1024" in preview_import
render_preview = function_source("renderImportPreview")
assert 'mode.value === "replace"' in render_preview
assert 'select.value = "incoming"' in render_preview
assert "select.disabled = replace" in render_preview
cancel_import = function_source("cancelConfigImport")
assert 'method: "DELETE"' in cancel_import
assert "暂存上传已立即清理" in cancel_import
submit_export = function_source("submitConfigExport")
assert 'input.value = "";' in submit_export
assert 'password = "";' in submit_export
assert "URL.revokeObjectURL(url)" in submit_export
maintenance_controls = function_source("setMaintenanceControls")
assert "data-config-maintenance-control" in maintenance_controls
assert "data-config-maintenance-control" in parser.elements["config-import-preview"][1]

# Canonical models now use JP; the formatter also normalizes legacy jp payloads
# so an older backup/server response is never shown with inconsistent casing.
format_exit_name = function_source("formatExitName")
assert 'return value === "jp" ? "JP" : value;' in format_exit_name
assert "formatExitName(item.tag)" in APP_SOURCE
assert 'formatExitName(value)' in function_source("populateSelect")

# Client reads and writes only the frozen API field names; no legacy aliases.
for legacy in (
    "csrfToken", "data.expiresAt", "data?.expiresAt", "item.outbound",
    "item.serverPort", "info.dotHost", "{ upstreams }",
):
    assert legacy not in APP_SOURCE, legacy
for snippet in (
    'state.csrf = typeof data.csrf === "string" ? data.csrf : "";',
    "Number(data.expires_at || 0)",
    "info.dot_domain",
    "Array.isArray(exitData.items)",
    "item.server_port",
    "Array.isArray(groupData.items)",
    "Array.isArray(rulesData.targets)",
    "item.target",
    "settings.hijack_mode",
    "settings.quic_mode",
    "settings.firewall_mode",
    'body: { name: name.trim() }',
    'const { data } = await api("/policy-groups");',
    'state.groupRevision = typeof data?.revision === "string" ? data.revision : "";',
    'runtimeCandidates: Array.isArray(item.runtimeCandidates)',
    'revision: state.editingGroup ? state.editingGroupRevision : state.groupRevision,',
    'body["disable-udp"] = $("#group-disable-udp").checked;',
    '$("#group-lazy").checked = group.lazy;',
    'method: editing ? "PATCH" : "POST", body',
    'method: "PUT", body: { member }',
    'method: "DELETE", body: { revision: state.groupRevision }',
    'body: { domain, target }',
    'method: "PATCH", body: { target }',
    "const body = { addresses };",
    'body: { snapshotId: snapshot.id, confirm: true }',
    'body: { confirm: true }',
):
    assert snippet in APP_SOURCE, snippet

# Safe DNS summaries are display-only DOM nodes; replacement controls start empty.
for kind in ("remote", "local"):
    current_tag, _ = parser.elements[f"dns-current-{kind}"]
    replacement_tag, replacement_attrs = parser.elements[f"dns-{kind}"]
    assert current_tag == "div"
    assert replacement_tag == "textarea"
    assert "value" not in replacement_attrs
assert "当前配置（只读安全摘要）" in INDEX_SOURCE
assert "展示值可能省略路径、查询参数或凭据" in INDEX_SOURCE

load_dns = function_source("loadDns")
assert 'renderCurrentDns($("#dns-current-remote"), data?.remote);' in load_dns
assert 'renderCurrentDns($("#dns-current-local"), data?.local);' in load_dns
assert '$("#dns-remote").value = "";' in load_dns
assert '$("#dns-local").value = "";' in load_dns
assert ".join(" not in load_dns

save_dns = function_source("saveDns")
clear_at = save_dns.index('textarea.value = "";')
request_at = save_dns.index("await api(")
assert clear_at < request_at
assert "if (!addresses.length)" in save_dns
assert "const body = { addresses };" in save_dns
assert 'errorMessage(error, "DNS 上游")' in save_dns

# Rules and rulesets both retain phone-direct semantics, clearly distinguished from
# the built-in VPS-local direct outbound used by default-exit controls.
target_options = function_source("targetOptions")
assert '"手机直连（MosDNS 返回真实地址，不经过 VPS）"' in target_options
load_rules = function_source("loadRules")
assert 'targetOptions($("#rule-target"));' in load_rules
assert 'targetOptions($("#ruleset-target"));' in load_rules
render_rulesets = function_source("renderRulesets")
assert 'item.target === "direct"' in render_rulesets
assert '"手机直连（不经 VPS）"' in render_rulesets
assert "规则集可选“手机直连”" in INDEX_SOURCE
assert "内建 direct 表示流量先到 VPS" in INDEX_SOURCE

# Existing rulesets expose an inline target selector.  Literal direct remains
# phone-direct while a direct-type tagged outbound is labelled as VPS-local.
assert "ruleTargetLabel(option.value)" in target_options
assert "（VPS 本机直出）" in function_source("ruleTargetLabel")
assert 'makeActionButton("保存出口", "target-ruleset")' in render_rulesets
ruleset_action = function_source("handleRulesetAction")
assert 'method: "PUT"' in ruleset_action
assert 'body: { target }' in ruleset_action
assert '/target`' in ruleset_action

# Concrete proxy connections are replaced in a dedicated secure dialog.  The
# selected tag is carried in UI state, never accepted from the pasted link, and
# the sensitive textarea is cleared before confirmation/network I/O.
replace_dialog = parser.elements["replace-exit-dialog"]
assert replace_dialog[0] == "dialog"
replace_link = parser.elements["replace-exit-link"]
assert replace_link[0] == "textarea"
assert replace_link[1].get("autocomplete") == "off"
render_exits = function_source("renderExitList")
assert 'makeActionButton("更新连接", "replace")' in render_exits
replace_exit = function_source("replaceExit")
clear_at = replace_exit.index('input.value = "";')
confirm_at = replace_exit.index("await confirmAction(")
request_at = replace_exit.index("await api(")
assert clear_at < confirm_at < request_at
assert 'method: "PUT"' in replace_exit
assert "body = { link }" in replace_exit
assert "body.link = \"\";" in replace_exit
assert "body: { link, tag" not in replace_exit

# Structured exit diagnostics are shown on exit cards.  A tagged direct-type
# anchor such as JP is probeable, while the literal phone-direct pseudo target
# is not a state exit.  Only concrete proxy protocols allow connection replace.
assert "test-exits" in parser.elements
test_exits = function_source("testExits")
assert 'api("/diagnostics/exits"' in test_exits
assert "data?.items" in test_exits
probeable = function_source("isProbeableExit")
assert 'item.tag !== "direct"' in probeable
assert 'item.type !== "urltest"' in probeable
assert 'item.type !== "direct"' not in probeable
replaceable = function_source("isReplaceableProxy")
assert '!["direct", "urltest"].includes(item.type)' in replaceable
assert "isReplaceableProxy(item)" in render_exits
diagnostic_badge = function_source("exitDiagnosticBadge")
assert '"故障组本轮不单测"' in diagnostic_badge
assert "isProbeableExit(item)" in diagnostic_badge
assert "result.delayMs" in diagnostic_badge
assert 'status === "unavailable"' in diagnostic_badge
assert '"Mihomo API 不可用"' in diagnostic_badge
assert "data?.available !== true" in test_exits
assert '"Mihomo API unavailable（出口测速不可用）", "bad"' in test_exits
assert ".latency-badge" in STYLE_SOURCE
assert "包括 VPS 直出锚点" in INDEX_SOURCE

# Domain diagnostics consume the split DNS/route evidence model.  A direct DNS
# answer may be called measured; a gateway result must always say that only the
# DNS entrance was measured and the concrete outbound remains a rule inference.
assert parser.elements["route-diagnostic-result"][1].get("aria-live") == "polite"
diagnose_domain = function_source("diagnoseDomain")
assert 'api("/diagnostics/domain"' in diagnose_domain
evidence = function_source("diagnosticEvidence")
for field in ("dnsVerified", "routeConfidence"):
    assert field in evidence
for legacy_field in ("result?.verified", "result?.confidence"):
    assert legacy_field not in evidence
for label in (
    "DNS 实测直连", "DNS 入口实测 + 出口规则推演",
    "配置已变化", "诊断繁忙", "DNS 无应答", "规则推演", "不确定",
):
    assert f'"{label}"' in evidence
assert "未进行出口连接实测" in evidence
dns_evidence = function_source("diagnosticDnsEvidence")
assert "result?.dnsVerified" in dns_evidence
assert "DNS 返回真实地址" in dns_evidence
route_confidence = function_source("diagnosticRouteConfidence")
assert "result?.routeConfidence" in route_confidence
assert "规则推演（未实测具体出口）" in route_confidence
reasons = function_source("diagnosticReasonLabel")
for reason in ("config_changed", "probe_busy", "dns_no_answer", "probe_unavailable"):
    assert reason in reasons
render_diagnostic = function_source("renderRouteDiagnostic")
assert 'node("dt"' in render_diagnostic
assert 'node("dd"' in render_diagnostic
assert '["DNS 路径证据", diagnosticDnsEvidence(result)]' in render_diagnostic
assert '["出口判定置信度", diagnosticRouteConfidence(result)]' in render_diagnostic

# Snapshot rollback uses an exact ID selected from the server-provided list;
# numeric indices must not return to the frontend.
assert "rollback-index" not in parser.elements
assert parser.elements["rollback-snapshot"][0] == "select"
load_snapshots = function_source("loadSnapshots")
assert 'api("/snapshots")' in load_snapshots
rollback = function_source("rollback")
assert "selectedSnapshot()" in rollback
assert "snapshot.id" in rollback
assert 'body: { snapshotId: snapshot.id, confirm: true }' in rollback
assert "index" not in rollback
assert "尚未确认完成" in rollback
assert "回滚成功" not in rollback
assert "loadOverview(" not in rollback

# Rollback/update acceptance registers a persistent background job.  Only a
# polled terminal state may produce a success claim; network loss stays unknown.
assert parser.elements["maintenance-job-list"][1].get("aria-live") == "polite"
assert "maintenance-job-health" in parser.elements
load_jobs = function_source("loadMaintenanceJobs")
assert 'api("/jobs")' in load_jobs
normalize_job = function_source("normalizeMaintenanceJob")
assert "[Tt]" in normalize_job and "[Zz]" in normalize_job
poll_jobs = function_source("pollMaintenanceJobs")
assert 'api(`/jobs/${encodeURIComponent(job.id)}`)' in poll_jobs
assert "Promise.allSettled" in poll_jobs
announce = function_source("announceMaintenanceResult")
assert 'job.status === "succeeded"' in announce
assert "已由后台确认成功" in announce
assert "state.trackedMaintenanceJobs.has(job.id)" in announce
render_jobs = function_source("renderMaintenanceJobs")
assert "maintenancePollDisconnected" in render_jobs
assert "不会被误判为失败" in render_jobs

software_update = function_source("softwareUpdate")
assert '"正在检查可用发布版本并启动升级…"' in software_update
assert "registerMaintenanceJob" in software_update
assert "尚未确认完成" in software_update
assert "升级成功" not in software_update
assert '"network_error"' in software_update

for selector in (
    ".diagnostic-card", ".diagnostic-details", ".job-card",
    ".job-connection-note", ".secure-entry-dialog",
):
    assert selector in STYLE_SOURCE

# The manifest is local and query-free as well.
assert MANIFEST["start_url"] == "/"
assert MANIFEST["scope"] == "/"
for icon in MANIFEST["icons"]:
    parsed = urlsplit(icon["src"])
    assert not parsed.scheme and not parsed.netloc and not parsed.query

print("[OK] Web frontend static/DOM regressions")
