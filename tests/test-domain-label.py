#!/usr/bin/env python3
"""Regression: domain test should show a renamed ruleset label, not rs_xxxx."""
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BOT = ROOT / "deploy/bot/pdg-bot.py"

spec = importlib.util.spec_from_file_location("pdg_bot", BOT)
bot = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(bot)

bot.load = lambda: {
    "route": {
        "rules": [{"rule_set": "rs_9d05f092", "outbound": "hk"}],
        "final": "direct",
    }
}
bot._rs_meta = lambda: {"rs_9d05f092": {"label": "line", "count": 24}}
bot._match_ruleset = lambda name, domain, suffixes: name == "rs_9d05f092" and domain == "line-apps.com"

tag, why = bot._singbox_route("line-apps.com")

assert tag == "hk"
assert why == "规则集 line"
assert "rs_9d05f092" not in why

# 删除规则集的结果消息也要用显示名, 不是 rs_xxxx
bot._rs_meta = lambda: {"rs_9d05f092": {"label": "line", "path": "/nonexistent.json"}}
# 5.1: del_ruleset 现在把 model / 规则集文件 / 元数据放进同一笔事务。本用例验的是**显示名**,
# 事务机制由 test-config-transaction*.py 覆盖 —— 这里按新契约打桩即可。
bot.tx_apply = lambda op, **kw: (True, "")
bot._save_rs_meta = lambda m: None
ok, msg = bot.del_ruleset("rs_9d05f092")
assert ok and "line" in msg and "rs_9d05f092" not in msg, msg
