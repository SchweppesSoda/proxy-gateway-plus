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

# The six frozen native tabs are present.
for tab_id in ("overview", "exits", "rules", "dns", "runtime", "ops"):
    assert f"tab-{tab_id}" in parser.elements
    assert f"panel-{tab_id}" in parser.elements

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
    'body: { name, members }',
    'method: "PATCH", body: { members }',
    'body: { domain, target }',
    'method: "PATCH", body: { target }',
    "const body = { addresses };",
    'body: { index }',
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

# Rollback/update responses are only transient-job acceptance.  The UI must not
# claim completion or immediately reload state while pdg-web may be restarting.
rollback = function_source("rollback")
assert '"回滚任务已启动，连接可能中断"' in rollback
assert "已回滚" not in rollback
assert "回滚完成" not in rollback
assert "loadOverview(" not in rollback
software_update = function_source("softwareUpdate")
assert '"正在检查可用发布版本并启动升级…"' in software_update
assert '"升级任务已启动，连接可能中断；请稍后重新登录核验"' in software_update
assert "升级已提交" not in software_update
assert "升级完成" not in software_update

# The manifest is local and query-free as well.
assert MANIFEST["start_url"] == "/"
assert MANIFEST["scope"] == "/"
for icon in MANIFEST["icons"]:
    parsed = urlsplit(icon["src"])
    assert not parsed.scheme and not parsed.netloc and not parsed.query

print("[OK] Web frontend static/DOM regressions")
