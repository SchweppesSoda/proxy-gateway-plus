#!/usr/bin/env python3
"""文案必须与当前行为一致(历史记录不动, 但"现在怎么工作"不许说错)。

当前文案边界(WLOC 已退役，其拒绝行为另有回归):
  2. :81 探测端点: probe81.py 一直返回 **200**(iOS 的 URLStringProbe 只认 200), 而 unit
     描述和实战记录里写成 204 —— 有人照着去"修正"实现就把探测搞挂了。
  3. 端口清单: 写死一串全平台端口, 于是 iOS 机器上 doctor 声称 GMS 5228-5230 已就位
     (那段装机就剥掉了), Android 上又提 :81(它根本不装 pdg-probe81)。
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
pass_n = 0


def ok(m):
    global pass_n
    print("[OK]  ", m); pass_n += 1


def bad(m):
    print("[FAIL]", m); sys.exit(1)


def text(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


# WLOC behavior is retired; active boundary checks live in test-wloc-retirement.py.

# ── 2. :81 返回 200 ─────────────────────────────────────────────────────────
probe = text("deploy/ios/probe81.py")
if "send_response(200)" not in probe:
    bad("probe81.py 的实现不是返回 200(不要按文档去改实现!)")
if "send_response(204)" in probe:
    bad("probe81.py 改成 204 了 —— iOS 的 URLStringProbe 不认 204")
ok("实现仍返回 HTTP 200(iOS URLStringProbe 只认 200)")

unit = text("deploy/ios/pdg-probe81.service")
if "204" in unit:
    bad("pdg-probe81.service 的描述里仍写 204")
if "200" not in unit:
    bad("pdg-probe81.service 的描述没写明返回 200")
ok("pdg-probe81.service 描述已改为 HTTP 200")

notes = text("docs/production-notes.md")
for m in re.finditer(r"[^\n]*204[^\n]*", notes):
    line = m.group(0)
    if "generate_204" in line:
        continue          # Google 的 generate_204 探测地址, 与 :81 无关, 不能动
    if ":81" in line or "probe81" in line or "探测端点" in line:
        bad(f"production-notes 里 :81 相关说明仍写 204: {line.strip()[:70]}")
ok("production-notes 的 :81 说明已改为 200(generate_204 那些是 Google 地址, 原样保留)")

# ── 3. 端口按平台 ──────────────────────────────────────────────────────────
checks = text("deploy/bot/checks.py")
if "def platform_ports_text(" not in checks:
    bad("端口清单没有按平台生成的函数")
ok("doctor 的端口清单由 platform_ports_text() 按平台生成")

install_md = text("docs/INSTALL.md")
for port, tag in (("| 81 |", "仅 iOS"), ("| 5228-5230 |", "仅 Android")):
    row = next((ln for ln in install_md.splitlines() if ln.startswith(port)), "")
    if not row:
        bad(f"INSTALL.md 端口表里找不到 {port}")
    if tag not in row:
        bad(f"INSTALL.md 里 {port} 没标注「{tag}」: {row}")
ok("INSTALL.md 端口表标注了 :81 仅 iOS / 5228-5230 仅 Android")

# 8445 是两平台共用的 Telegram SOCKS5 —— 不许被标成某个平台专属
if "8445" not in checks:
    bad("checks 里没有 8445(Telegram SOCKS5)")
_pp = checks.split("def platform_ports_text(", 1)[1].split("\ndef ", 1)[0]
if "8445" not in _pp:
    bad("8445 没进端口清单")
if re.search(r'"8445[^"]*(仅 iOS|仅 Android)', _pp):
    bad("8445 被标成了某平台专属 —— 它是两平台共用的 Telegram SOCKS5")
ok("8445 仍是两平台共用的 Telegram SOCKS5")

print("\n通过 %d 项断言" % pass_n)
