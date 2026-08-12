#!/usr/bin/env python3
"""Regression: rename_exit 真改名并级联更新所有引用(规则/故障组/final/TG/规则集元数据)."""
import copy
import json
import importlib.util
import sys
import types
from pathlib import Path

try:  # Production is Linux; permit the pure mutation regression on Windows.
    import fcntl  # noqa: F401
except ImportError:  # pragma: no cover - Windows developer workstation only
    fcntl_stub = types.ModuleType("fcntl")
    fcntl_stub.LOCK_EX = 2
    fcntl_stub.LOCK_NB = 4
    fcntl_stub.LOCK_UN = 8
    fcntl_stub.flock = lambda *_args, **_kwargs: None
    sys.modules["fcntl"] = fcntl_stub

ROOT = Path(__file__).resolve().parents[1]
BOT = ROOT / "deploy/bot/pdg-bot.py"

spec = importlib.util.spec_from_file_location("pdg_bot", BOT)
bot = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(bot)

cfg = {
    "outbounds": [
        {"type": "direct", "tag": "jp"},
        {"type": "shadowsocks", "tag": "hk", "server": "203.0.113.10", "server_port": 1},
        {"type": "shadowsocks", "tag": "tw", "server": "203.0.113.11", "server_port": 1},
        {"type": "urltest", "tag": "auto", "outbounds": ["hk", "tw"]},
    ],
    "route": {
        "rules": [
            {"action": "reject", "ip_cidr": ["203.0.113.1/32"]},
            {"inbound": ["tg-proxy"], "outbound": "hk"},
            {"rule_set": "rs_11111111", "outbound": "hk"},
            {"domain_suffix": ["x.com"], "outbound": "hk"},
            {"domain_suffix": ["y.com"], "outbound": "tw"},
            {"domain_suffix": ["z.com"], "outbound": "auto"},
        ],
        "final": "hk",
    },
}

bot.load = lambda: copy.deepcopy(cfg)
bot._model_snapshot = lambda: (copy.deepcopy(cfg), "a" * 64)

# 5.1: rename_exit 的 model 改动与 rulesets.json 级联现在是同一笔事务。按新契约打桩:
# model_mod 作用到内存里的 cfg, files 里的 rs_meta 直接落到 meta —— 断言的仍是级联是否完整。
def fake_tx(op, model_mod=None, files=None, **kw):
    if model_mod is not None:
        cc = copy.deepcopy(cfg)
        model_mod(cc)
        cfg.clear(); cfg.update(cc)
    for name, data in (files or {}).items():
        if name == "rs_meta":
            meta.clear(); meta.update(json.loads(data.decode()))
    return True, ""
bot.tx_apply = fake_tx
bot.apply_sb = lambda mod: fake_tx("apply_sb", model_mod=mod)

meta = {"rs_11111111": {"url": "http://example.com/x.list", "outbound": "hk", "label": "币安"}}
bot._rs_meta = lambda: copy.deepcopy(meta)
bot._rs_meta_snapshot = lambda: (copy.deepcopy(meta), "test-meta-sha256")
def fake_save(m):
    meta.clear(); meta.update(m)
bot._save_rs_meta = fake_save

# ── 改代理出口: hk → hk2, 所有引用级联 ──
ok, msg = bot.rename_exit("hk", "hk2")
assert ok, msg
tags = [o["tag"] for o in cfg["outbounds"]]
assert "hk2" in tags and "hk" not in tags
auto = next(o for o in cfg["outbounds"] if o["tag"] == "auto")
assert auto["outbounds"] == ["hk2", "tw"], auto              # 故障组成员
assert all(r.get("outbound") != "hk" for r in cfg["route"]["rules"])
tg = next(r for r in cfg["route"]["rules"] if r.get("inbound") == ["tg-proxy"])
assert tg["outbound"] == "hk2"                               # TG 出口规则
rs = next(r for r in cfg["route"]["rules"] if r.get("rule_set"))
assert rs["outbound"] == "hk2"                               # 规则集规则
assert cfg["route"]["final"] == "hk2"                        # 默认出口
assert meta["rs_11111111"]["outbound"] == "hk2"              # 规则集元数据
assert "hk2" in msg and "已改名" in msg

# ── 改故障组名: auto → main, 指向组的规则级联 ──
ok, msg = bot.rename_exit("auto", "main")
assert ok, msg
assert any(o["tag"] == "main" and o["type"] == "urltest" for o in cfg["outbounds"])
zr = next(r for r in cfg["route"]["rules"] if r.get("domain_suffix") == ["z.com"])
assert zr["outbound"] == "main"

# ── 拒绝分支 ──
ok, msg = bot.rename_exit("jp", "jp2")                       # direct 不可改(WDA 依赖)
assert not ok, msg
ok, msg = bot.rename_exit("nope", "x")                       # 不存在
assert not ok, msg
ok, msg = bot.rename_exit("tw", "main")                      # 与现有出口/组重名
assert not ok and "占用" in msg, msg
ok, msg = bot.rename_exit("tw", "tw")                        # 同名
assert not ok, msg
ok, msg = bot.rename_exit("tw", "中文名")                     # 非法字符(清洗后无字母数字)
assert not ok, msg
ok, msg = bot.rename_exit("tw", "direct")                    # 保留字
assert not ok, msg
snap = copy.deepcopy(cfg)

# ── 事务失败 → 原样返回错误, 元数据不动(同一笔事务, 不会只落一半) ──
bot.tx_apply = lambda op, **kw: (False, "boom")
ok, msg = bot.rename_exit("tw", "tw9")
assert not ok and msg == "boom"
assert meta["rs_11111111"]["outbound"] == "hk2"
assert cfg == snap

# ── Bot 旧 delx 路径: 删除代理后递归清空组，并在同一 CAS/pdgtx 内级联 rulesets ──
delete_cfg = bot.pdgmodel.migrate({
    "outbounds": [
        {"type": "direct", "tag": "KFC_JP"},
        {"type": "shadowsocks", "tag": "hk", "server": "203.0.113.20",
         "server_port": 443},
        {"type": "shadowsocks", "tag": "tw", "server": "203.0.113.21",
         "server_port": 443},
    ],
    "route": {
        "rules": [
            {"action": "reject", "ip_cidr": ["198.51.100.1/32"]},
            {"domain_suffix": ["leaf.example"], "outbound": "leaf"},
        ],
        "final": "hk",
    },
    "_pdg": {
        "schema": 3,
        "policy-groups": [
            {"name": "leaf", "type": "select", "proxies": ["hk"], "use": []},
            {"name": "root", "type": "select",
             "proxies": ["leaf", "KFC_JP"], "use": []},
        ],
        "mihomo": {"proxy-providers": {}, "rule-providers": {},
                   "advanced": {}, "managed-files": {}},
    },
})
delete_meta = {
    "rs_22222222": {"url": "https://example.com/leaf.list",
                     "outbound": "leaf", "label": "leaf"},
    "rs_33333333": {"url": "https://example.com/direct.list",
                     "outbound": "direct", "label": "direct"},
}
bot._model_snapshot = lambda: (copy.deepcopy(delete_cfg), "c" * 64)
bot._rs_meta_snapshot = lambda: (copy.deepcopy(delete_meta), "d" * 64)
delete_calls = []

def fake_delete_tx(op, model_mod=None, files=None, **kwargs):
    record = {"op": op, "files": dict(files or {}), **kwargs}
    candidate = copy.deepcopy(delete_cfg)
    model_mod(candidate)
    bot.pdgmodel.validate(candidate)
    delete_cfg.clear(); delete_cfg.update(candidate)
    if "rs_meta" in record["files"]:
        delete_meta.clear()
        delete_meta.update(json.loads(record["files"]["rs_meta"].decode()))
    delete_calls.append(record)
    return True, ""

bot.tx_apply = fake_delete_tx
ok, msg = bot.delete_exit("hk")
assert ok, msg
assert [item["tag"] for item in delete_cfg["outbounds"]] == ["KFC_JP", "tw"]
groups = delete_cfg["_pdg"]["policy-groups"]
assert [item["name"] for item in groups] == ["root"]
assert groups[0]["proxies"] == ["KFC_JP"]
assert delete_cfg["route"]["final"] == "KFC_JP"
assert delete_cfg["route"]["rules"][0] == {
    "action": "reject", "ip_cidr": ["198.51.100.1/32"]}
assert delete_cfg["route"]["rules"][1]["outbound"] == "KFC_JP"
assert delete_meta["rs_22222222"]["outbound"] == "KFC_JP"
assert delete_meta["rs_33333333"]["outbound"] == "direct"
assert len(delete_calls) == 1
assert delete_calls[0]["op"] == "exit_delete"
assert delete_calls[0]["model_expect"] == "c" * 64
assert delete_calls[0]["file_expects"] == {"rs_meta": "d" * 64}

# Failed transaction must leave both authoritative files untouched.
delete_before = copy.deepcopy(delete_cfg)
meta_before = copy.deepcopy(delete_meta)
bot._model_snapshot = lambda: (copy.deepcopy(delete_cfg), "e" * 64)
bot.tx_apply = lambda *_args, **_kwargs: (False, "PRECONDITION_FAILED")
ok, msg = bot.delete_exit("tw")
assert not ok and msg == "PRECONDITION_FAILED"
assert delete_cfg == delete_before and delete_meta == meta_before

print("exit-rename regression OK")
