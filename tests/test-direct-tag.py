#!/usr/bin/env python3
"""本机 direct 锚点：v3 迁移、自定义、全引用闭包与生产接线回归。"""
import copy
import importlib.util
import json
import re
import sys
import types
from pathlib import Path

try:
    import fcntl  # noqa: F401
except ModuleNotFoundError:  # Windows 本地静态回归；生产与 CI 使用真实 fcntl。
    sys.modules["fcntl"] = types.SimpleNamespace(
        LOCK_EX=1, LOCK_NB=2, LOCK_UN=8, flock=lambda *_args: None)

ROOT = Path(__file__).resolve().parents[1]
BOT = ROOT / "deploy/bot/pdg-bot.py"
PDG = ROOT / "deploy/bot/pdg.sh"
TEMPLATE = ROOT / "deploy/singbox/config.json.tmpl"

spec = importlib.util.spec_from_file_location("pdg_bot_direct_tag", BOT)
bot = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(bot)
import sb2mihomo  # noqa: E402


def old_model():
    return {
        "outbounds": [
            {"type": "direct", "tag": "jp"},
            {"type": "shadowsocks", "tag": "hk"},
            {"type": "urltest", "tag": "auto", "outbounds": ["jp", "hk"]},
        ],
        "route": {
            "rules": [
                {"action": "reject"},
                {"domain_suffix": ["example.test"], "outbound": "jp"},
            ],
            "final": "jp",
        },
    }


cfg = old_model()
assert bot._normalize_default_direct_tag(cfg) is True
assert cfg["outbounds"][0]["tag"] == "JP"
assert cfg["_pdg"]["schema"] == 3
assert cfg["_pdg"]["policy-groups"][0]["proxies"] == ["JP", "hk"]
assert not any(item.get("type") in {"selector", "urltest"}
               for item in cfg["outbounds"])
assert cfg["route"]["rules"][1]["outbound"] == "JP"
assert cfg["route"]["final"] == "JP"
assert bot._direct_anchor_tag(cfg) == "JP"
assert bot._normalize_default_direct_tag(cfg) is False

meta = {
    "legacy": {"outbound": "jp"},
    "phone": {"outbound": "direct"},
    "proxy": {"outbound": "hk"},
}
assert bot._normalize_default_direct_meta(meta) is True
assert meta["legacy"]["outbound"] == "JP"
assert meta["phone"]["outbound"] == "direct"
assert meta["proxy"]["outbound"] == "hk"

custom = {"outbounds": [{"type": "direct", "tag": "LOCAL"}],
          "route": {"rules": [], "final": "LOCAL"}}
assert bot._normalize_default_direct_tag(custom) is True
assert custom["outbounds"][0]["tag"] == "LOCAL"
assert bot._normalize_default_direct_tag(custom) is False

collision = old_model()
collision["outbounds"].append({"type": "shadowsocks", "tag": "JP"})
try:
    bot._normalize_default_direct_tag(collision)
    raise AssertionError("JP tag collision must fail closed")
except ValueError:
    pass

for tag in ("jp", "JP", "LOCAL"):
    model = {
        "outbounds": [{"type": "direct", "tag": tag}],
        "route": {"rules": [{"rule_set": "unlock", "outbound": tag}]},
    }
    assert bot._wda_on(model) is True
    model["route"]["rules"][0]["outbound"] = "wrong"
    assert bot._wda_on(model) is False
ambiguous = {
    "outbounds": [
        {"type": "direct", "tag": "JP"},
        {"type": "direct", "tag": "LOCAL"},
    ],
    "route": {"rules": [{"rule_set": "unlock", "outbound": "JP"}]},
}
assert bot._direct_anchor_tag(ambiguous) is None
assert bot._wda_on(ambiguous) is False

# WDA 写入当前模型的真实 direct tag，而不是任何固定大小写字符串。
for tag in ("jp", "JP", "LOCAL"):
    current = {
        "outbounds": [{"type": "direct", "tag": tag}],
        "route": {"rules": [], "rule_set": []},
    }
    captured = {}
    bot.load = lambda c=current: copy.deepcopy(c)
    bot._wda_authorized = lambda: True
    bot._unlock_precheck = lambda _domains: (True, "")

    def fake_tx(_op, model_mod=None, **_kwargs):
        candidate = copy.deepcopy(current)
        model_mod(candidate)
        captured["candidate"] = candidate
        return True, ""

    bot.tx_apply = fake_tx
    ok, msg = bot.set_wda_mode(True)
    assert ok, msg
    unlock = next(
        rule for rule in captured["candidate"]["route"]["rules"]
        if rule.get("rule_set") == "unlock")
    assert unlock["outbound"] == tag

bot.load = lambda: copy.deepcopy(ambiguous)
ok, msg = bot.set_wda_mode(True)
assert not ok and "只能有一个" in msg

# 专用 direct-tag 操作在一次 CAS/pdgtx 调用中修改模型和 rulesets 元数据；
# Mihomo 的内建 DIRECT 保持字面量，不把机器自定义名泄漏成不存在的 proxy。
direct_model = bot.pdgmodel.migrate({
    "outbounds": [
        {"type": "direct", "tag": "JP"},
        {"type": "shadowsocks", "tag": "hk", "server": "127.0.0.1",
         "server_port": 8388, "method": "aes-128-gcm", "password": "x"},
    ],
    "route": {
        "rules": [
            {"domain_suffix": ["direct.example"], "outbound": "JP"},
            {"domain_suffix": ["group.example"], "outbound": "nested"},
        ],
        "final": "JP",
    },
    "_pdg": {"schema": 3, "policy-groups": [
        {"name": "choice", "type": "select", "proxies": ["JP", "hk"], "use": []},
        {"name": "nested", "type": "fallback", "proxies": ["choice", "JP"],
         "use": [], "url": "https://www.gstatic.com/generate_204", "interval": 180},
    ], "mihomo": {"proxy-providers": {}, "rule-providers": {},
                     "advanced": {}, "managed-files": {}}},
})
direct_meta = {
    "machine": {"outbound": "JP"},
    "phone": {"outbound": "direct"},
    "proxy": {"outbound": "hk"},
}
captured = {}
bot.load = lambda: copy.deepcopy(direct_model)
bot._model_snapshot = lambda: (copy.deepcopy(direct_model), "c" * 64)
bot._rs_meta_snapshot = lambda: (copy.deepcopy(direct_meta), "a" * 64)

def fake_direct_tx(op, model_mod=None, files=None, file_expects=None, **_kwargs):
    candidate = copy.deepcopy(direct_model)
    model_mod(candidate)
    captured.update(op=op, candidate=candidate, files=files,
                    file_expects=file_expects,
                    model_expect=_kwargs.get("model_expect"))
    return True, "committed"

bot.tx_apply = fake_direct_tx
ok, msg = bot.set_direct_tag("KFC_JP")
assert ok, msg
renamed = captured["candidate"]
assert captured["op"] == "direct_tag_set"
assert captured["file_expects"] == {"rs_meta": "a" * 64}
assert captured["model_expect"] == "c" * 64
renamed_meta = json.loads(captured["files"]["rs_meta"].decode())
assert renamed_meta["machine"]["outbound"] == "KFC_JP"
assert renamed_meta["phone"]["outbound"] == "direct"
assert renamed["outbounds"][0]["tag"] == "KFC_JP"
assert renamed["_pdg"]["policy-groups"][0]["proxies"] == ["KFC_JP", "hk"]
assert renamed["_pdg"]["policy-groups"][1]["proxies"] == ["choice", "KFC_JP"]
assert renamed["route"]["rules"][0]["outbound"] == "KFC_JP"
assert renamed["route"]["final"] == "KFC_JP"
rendered, _warnings = sb2mihomo.singbox_to_mihomo(renamed)
choice = next(group for group in rendered["proxy-groups"] if group["name"] == "choice")
assert choice["proxies"] == ["DIRECT", "hk"]

# Collision and transaction failure are fail-closed and cannot mutate the source model.
for bad in ("choice", "hk", "DIRECT", "DiReCt", "REJECT", "jp", "JP", "bad tag"):
    bot.load = lambda: copy.deepcopy(direct_model)
    bot._model_snapshot = lambda: (copy.deepcopy(direct_model), "c" * 64)
    ok, _msg = bot.set_direct_tag(bad)
    assert not ok, bad
unchanged = copy.deepcopy(direct_model)
bot.load = lambda: unchanged
bot._model_snapshot = lambda: (copy.deepcopy(unchanged), "d" * 64)
bot._rs_meta_snapshot = lambda: (copy.deepcopy(direct_meta), "b" * 64)
bot.tx_apply = lambda *_args, **_kwargs: (False, "rolled back")
ok, msg = bot.set_direct_tag("KFC_JP")
assert not ok and msg == "rolled back"
assert unchanged == direct_model

template = json.loads(TEMPLATE.read_text(encoding="utf-8"))
assert template["outbounds"] == [{"type": "direct", "tag": "JP"}]
assert template["route"]["final"] == "JP"

pdg_source = PDG.read_text(encoding="utf-8")
migration = re.search(
    r"(?ms)^migrate_default_direct_tag\(\)\{.*?^\}", pdg_source)
assert migration is not None
body = migration.group(0)
for required in (
    "_normalize_default_direct_tag",
    "_normalize_default_direct_meta",
    "candidate-model",
    "candidate-meta",
    "candidate-mihomo",
    "_pdg_atomic_restore_file",
    "_directtag_restore",
    "_core_kernel_stable",
):
    assert required in body, required
run_all = pdg_source[pdg_source.index("run_all_migrations(){"):]
assert "migrate_default_direct_tag || return 1" in run_all

print("direct-tag v3/custom regression OK")
