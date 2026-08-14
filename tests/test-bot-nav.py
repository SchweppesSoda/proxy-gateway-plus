#!/usr/bin/env python3
"""Static regressions for Telegram bot navigation after operation results."""
import re
from pathlib import Path
import os
import sys
import types

ROOT = Path(__file__).resolve().parents[1]
bot = (ROOT / "deploy/bot/pdg-bot.py").read_text(encoding="utf-8")

assert "OPS_BACK" in bot, "ops result keyboard must be explicit, not the full first-level MENU"
assert '"callback_data": "nav:ops"' in bot, "ops result keyboard should return to the ops submenu"
assert 'set_tfo(data == "tfo:on"); edit(chat, mid, msg if ok else ("❌ " + msg), OPS_BACK)' in bot, (
    "TFO toggle result must not show the whole first-level menu"
)
# 「🔄 重启服务」的每条出口(内核失败 / mosdns 起不来 / 全部成功)都必须留在运维子菜单,
# 不许刷出一级菜单。这里按分支取代码段再逐条查, 而不是钉死某一行字面量 —— 那样文案一改
# 断言就废, 却又不是真的坏了。
_restart_branch = bot.split('if data == "restart":', 1)[1].split('if data == "updgeo":', 1)[0]
_edits = _restart_branch.count("edit(chat, mid")
assert _edits >= 3, "重启分支应当分别处理: 内核失败 / mosdns 起不来 / 全部成功"
# 每次编辑都配一个 OPS_BACK(消息可能跨行, 所以数总量而不是逐行看)
assert _restart_branch.count("OPS_BACK") >= _edits, "restart result must stay in ops navigation"
assert "MENU)" not in _restart_branch, "重启结果不该刷出一级菜单"
assert "mosdns 未能起来" in _restart_branch, (
    "mosdns 重启结果必须核实 —— 不能只看 apply_sb 成功就回「已重启」"
)
assert 'msg = f"✅ geosite 已更新; 规则集刷新 {n} 个"' in bot and "edit(chat, mid, msg, OPS_BACK)" in bot, (
    "rule-update result path should stay covered"
)
assert '), OPS_BACK); return' in bot, "rule-update result must use OPS_BACK"


def assert_near(marker: str, expected: str, message: str, window: int = 2000) -> None:
    start = bot.find(marker)
    assert start >= 0, f"missing marker: {marker}"
    assert expected in bot[start:start + window], message


assert "EXIT_BACK" in bot, "exit-management third-level screens should return to the exit submenu"
assert "RULE_BACK" in bot, "rule-management third-level screens should return to the rule submenu"
assert '"callback_data": "nav:exit"' in bot, "exit back keyboard should return to exit management"
assert '"callback_data": "nav:rule"' in bot, "rule back keyboard should return to rule management"
assert '"callback_data": "exit_list"' in bot, "exit submenu list should not reuse the main-level exits callback"
assert_near('if data == "exit_list":', "EXIT_BACK", "exit list should return to exit management")
assert_near('if data == "rules":', "RULE_BACK", "rule list should return to rule management")
assert_near('if data == "add_exit":', "EXIT_BACK", "add-exit prompt should return to exit management")
assert_near('if data == "add_grp":', "EXIT_BACK", "add-group prompt should return to exit management")
assert_near('if data == "order_exit":', "EXIT_BACK", "exit ordering prompt should return to exit management")
assert_near('if data.startswith("delx:"):', "EXIT_BACK", "exit deletion result should return to exit management")
assert_near('if data.startswith("fin:"):', "EXIT_BACK", "default-exit result should return to exit management")
assert_near('if data == "add_rule":', "RULE_BACK", "add-rule prompt should return to rule management")
assert_near('if data == "edit_rule":', "RULE_BACK", "edit-rule selector should return to rule management")
assert_near('if data.startswith("ero:"):', "RULE_BACK", "changing a rule outbound should return to rule management")
assert_near('if data == "del_rule":', "RULE_BACK", "delete-rule selector should return to rule management")
assert_near('if data == "ddel":', "RULE_BACK", "bulk domain deletion should return to rule management")
assert_near('if data == "testdom":', "RULE_BACK", "test-domain prompt should return to rule management")
assert_near('if data == "add_rs":', "RULE_BACK", "add-ruleset prompt should return to rule management")
assert_near('if data == "del_rs":', "RULE_BACK", "delete-ruleset selector should return to rule management")
assert_near('if data == "edit_rs":', "RULE_BACK", "rename-ruleset selector should return to rule management")
assert_near('if data.startswith("delrs:"):', "RULE_BACK", "ruleset deletion result should return to rule management")
assert_near('if data == "test":', 'edit(chat, mid, "测试中…", BACK)', (
    "exit latency test progress message should show only a back button, not the full first-level menu"
))
assert 'edit(chat, mid, "测试中…", None)' not in bot, (
    "passing None to edit() falls back to the full first-level MENU"
)
assert_near('if data == "upd_check":', 'edit(chat, mid, "🔄 检查更新中…", BACK)', (
    "update-check progress message should show only a back button, not the full first-level menu"
))
assert 'edit(chat, mid, "🔄 检查更新中…", None)' not in bot, (
    "passing None to edit() falls back to the full first-level MENU"
)
assert '"callback_data": "upd_apply:" + target' in bot, (
    "update confirmation must bind the exact origin release checked by the user"
)
assert 'start_update(target)' in bot and '"--target", target' in bot, (
    "background update must carry the confirmed exact target"
)
assert 'if data == "upd_apply":' in bot and "旧更新确认已失效" in bot, (
    "unbound legacy update buttons must be rejected"
)
none_progress_edits = re.findall(r"edit\(chat, mid, [^\n]+, None\)", bot)
assert not none_progress_edits, (
    "progress/result edits must pass an explicit keyboard; None falls back to the full first-level MENU: "
    + ", ".join(none_progress_edits)
)
assert_near('if data == "dnsup":', '"callback_data": "menu"', (
    "DNS upstream page should include a main-menu button"
), window=1600)
assert_near('if data == "tfo":', '"callback_data": "menu"', (
    "TFO page should include a main-menu button"
), window=900)

callback_block = bot[bot.find('elif "callback_query" in u:'):]
answer_pos = callback_block.find('answer_cb_async(q["id"])')
handle_pos = callback_block.find(
    'handle_cb(message["chat"]["id"], message["message_id"], q["data"])'
)
assert answer_pos >= 0 and handle_pos >= 0, "callback loop should answer and handle callback queries"
assert answer_pos < handle_pos, "answerCallbackQuery should be sent before slow callback handling"

# ── 动态回归: 返回主菜单/切子菜单必须清掉待输入状态和删除勾选 ──
# 否则: 点「iOS 描述文件」进入 ios_ssid 输入态 → 点返回 → 下一条随手发的文字被误当 SSID 名单生成描述文件。
import importlib.util

if os.name == "nt":
    sys.modules.setdefault("fcntl", types.SimpleNamespace(
        flock=lambda *_args: None, LOCK_EX=1, LOCK_NB=2, LOCK_UN=8))

spec = importlib.util.spec_from_file_location("pdg_bot", ROOT / "deploy/bot/pdg-bot.py")
mod = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(mod)

mod.edit = lambda chat, mid, text, kb=None: None   # 不出网
mod.status_text = lambda: "s"
mod._dot_host = lambda: "dot.test"                 # nav:client 标题会用到

for data in ("menu", "status", "nav:client", "nav:exit", "nav:rule", "nav:ops"):
    mod.state[1] = "ios_ssid"
    mod.del_sel[1] = {"x.com"}
    mod.handle_cb(1, 9, data)
    assert 1 not in mod.state, f"{data} 后待输入状态应被清掉"
    assert 1 not in mod.del_sel, f"{data} 后删除勾选应被清掉"

# Dynamic names never enter Telegram's 64-byte callback payload.  The digest is
# resolved against the current candidate set, so a deleted/renamed (stale)
# choice fails closed; pre-upgrade raw ASCII callbacks remain compatible.
unicode_name = "东京/Reality｜主用 % # ? < > & 👨\u200d👩\u200d👧\u200d👦"
callback = mod._callback_data("renx", unicode_name)
assert len(callback.encode("utf-8")) <= 64
assert unicode_name not in callback
assert callback.startswith("renx:~")
raw_token = callback.split(":", 1)[1]
assert mod._resolve_callback(raw_token, [unicode_name, "hk"]) == unicode_name
assert mod._resolve_callback(raw_token, ["hk"]) is None, "过期摘要令牌必须安全失效"
assert mod._resolve_callback("hk", ["hk", unicode_name]) == "hk"
assert mod._resolve_callback("missing", ["hk", unicode_name]) is None

keyboard = mod.kb_pick("delx", [unicode_name])
button = keyboard["inline_keyboard"][0][0]
assert button["text"] == unicode_name
assert unicode_name not in button["callback_data"]
assert len(button["callback_data"].encode("utf-8")) <= 64
assert mod._esc("<东京 & 香港>") == "&lt;东京 &amp; 香港&gt;"

# Ruleset display names follow the same Unicode contract: preserve the stored
# value exactly after NFC/outer-trim normalization, reject unsafe/long input
# instead of truncating, and escape the dynamic HTML confirmation.
ruleset_meta = {"rs_demo": {"url": "https://example.invalid/list.txt",
                            "outbound": "direct"}}
mod._rs_meta_snapshot = lambda: (ruleset_meta, "revision")
mod.tx_apply = lambda *_args, **_kwargs: (True, "ok")
ok, message = mod.set_ruleset_label("rs_demo", "  <东京 & 香港>  ")
assert ok
assert ruleset_meta["rs_demo"]["label"] == "<东京 & 香港>"
assert "&lt;东京 &amp; 香港&gt;" in message
ok, message = mod.set_ruleset_label("rs_demo", "敏" * 65)
assert not ok and "1–64" in message
assert ruleset_meta["rs_demo"]["label"] == "<东京 & 香港>"
ok, message = mod.set_ruleset_label("rs_demo", "bad\u202ename")
assert not ok and "危险隐形字符" in message

# Derived MosDNS comments are still part of the exported/rendered artifact: do
# not reintroduce the old ASCII replacement merely because the name is written
# after a comment marker.
ruleset_note_name = "东京/Reality｜主用 % # ? < > & 👨\u200d👩\u200d👧\u200d👦"
ruleset_notes = mod._ruleset_hijack_bytes(
    {
        ruleset_note_name: {
            "url": "https://example.invalid/domain.mrs",
            "outbound": "hk",
            "format": "mrs",
            "path": "/etc/sing-box/rs/u-unicode-note.mrs",
        }
    },
    {},
    {},
).decode("utf-8")
assert f"# {ruleset_note_name}: binary provider" in ruleset_notes
