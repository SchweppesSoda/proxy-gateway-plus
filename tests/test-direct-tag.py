#!/usr/bin/env python3
"""默认 direct 锚点 JP：模型迁移、WDA 动态引用与生产接线回归。"""
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
assert cfg["outbounds"][2]["outbounds"] == ["JP", "hk"]
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

custom = {"outbounds": [{"type": "direct", "tag": "LOCAL"}], "route": {"rules": []}}
assert bot._normalize_default_direct_tag(custom) is False
assert custom["outbounds"][0]["tag"] == "LOCAL"

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

print("direct-tag JP regression OK")
