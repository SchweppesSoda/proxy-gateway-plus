#!/usr/bin/env python3
"""规则集完整性回归(P0): 没进到实际运行配置的规则集, 一律不许当成功。

旧行为的三个洞:
  · bot 的 add_ruleset 接受 `.srs` 并回"已添加", 但 _mihomo_rulesets 会跳过 .srs
    (mihomo 消费不了 sing-box 的二进制规则集) → 渲染器把它记进 meta["dropped"];
  · _core_apply 与迁移只检查 meta["unknown_proxies"], **不看 dropped** → 规则集被静默
    丢弃, 配置照样应用, 用户以为分流生效了, 实际那条规则根本不存在;
  · `.mrs` 是 mihomo 原生格式(渲染层本来就支持), 却被 add_ruleset 以"sing-box 不支持"拒掉。

现在: dropped 非空即判失败并列出被丢弃的规则集; .mrs 放行; .srs 在入口就拒(并给出替换指引);
已有 .srs 的老机器迁移时会被拦下, 保留 sing-box 运行, 而不是迁过去悄悄少一条分流。
"""
import importlib.util
import json
import os
import sys
import tempfile
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy" / "bot"))
spec = importlib.util.spec_from_file_location("pdg_bot", ROOT / "deploy/bot/pdg-bot.py")
bot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bot)

import sb2mihomo

pass_n = 0


def ok(msg):
    global pass_n
    print("[OK]  ", msg)
    pass_n += 1


def bad(msg):
    print("[FAIL]", msg)
    sys.exit(1)


SAMPLE = {
    "experimental": {"clash_api": {"external_controller": "127.0.0.1:9090"}},
    "outbounds": [
        {"type": "shadowsocks", "tag": "hk", "server": "1.1.1.1", "server_port": 8388,
         "method": "aes-256-gcm", "password": "pw"},
        {"type": "direct", "tag": "jp"},
    ],
    "route": {"rules": [{"ip_cidr": ["127.0.0.0/8"], "action": "reject"}], "final": "jp"},
}


class FakeSh:
    def __init__(self):
        self.calls = []

    def __call__(self, cmd):
        self.calls.append(list(cmd))
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")


def setup(tmp):
    bot.SB = os.path.join(tmp, "config.json")
    bot.RS_DIR = os.path.join(tmp, "rs")
    bot.RS_META = os.path.join(tmp, "rulesets.json")
    bot.MIHOMO_DIR = os.path.join(tmp, "mihomo")
    bot.MIHOMO_CFG = os.path.join(bot.MIHOMO_DIR, "config.yaml")
    bot.BACKEND_MARKER = os.path.join(tmp, "backend")
    bot.LOCKFILE = os.path.join(tmp, "lock")
    os.makedirs(bot.RS_DIR, exist_ok=True)
    with open(bot.SB, "w") as f:
        json.dump(SAMPLE, f)
    with open(bot.BACKEND_MARKER, "w") as f:
        f.write("mihomo")
    fake = FakeSh()
    bot.sh = fake
    bot._svc_active = lambda unit, **k: True
    return fake


def main():
    # ── 1. 渲染层: 规则集没进 rule-providers 就必须记进 dropped ──
    model = json.loads(json.dumps(SAMPLE))
    model["route"]["rules"].append({"rule_set": "rs_deadbeef", "outbound": "hk"})
    _cfg, meta = sb2mihomo.singbox_to_mihomo(model, redir_port=7893, rulesets={})
    if not meta.get("dropped"):
        bad("规则集未进 rule-providers 却没被记进 dropped")
    ok("渲染层: 未能翻译的规则集被记进 meta['dropped']")

    # ── 2. _core_apply: dropped 非空必须判失败并点名(而不是静默应用) ──
    with tempfile.TemporaryDirectory() as tmp:
        setup(tmp)
        c = json.load(open(bot.SB))
        c["route"]["rules"].append({"rule_set": "rs_deadbeef", "outbound": "hk"})
        json.dump(c, open(bot.SB, "w"))
        okr, err, restarted = bot._core_apply()
        if okr:
            bad("dropped 非空却应用成功了(规则集被静默丢弃)")
        if "rs_deadbeef" not in err:
            bad(f"失败信息没点名被丢弃的规则集: {err}")
        if restarted:
            bad("校验没过却重启了内核")
        ok("_core_apply: dropped 非空 → 判失败 + 点名被丢弃的规则集 + 不重启")

    # ── 3. .srs 在入口就被拒(mihomo 消费不了), 且给出替换指引 ──
    with tempfile.TemporaryDirectory() as tmp:
        setup(tmp)
        okr, msg = bot.add_ruleset("https://example.com/list.srs", "hk")
        if okr:
            bad(".srs 仍被接受(它进不了 mihomo 运行配置)")
        if ".srs" not in msg or "mihomo" not in msg:
            bad(f".srs 拒绝文案不清楚: {msg}")
        ok(f".srs 入口即拒并说明原因: {msg[:48]}…")
        # 拒绝之后不得留下半截状态
        if os.path.exists(bot.RS_META) and "rs_" in open(bot.RS_META).read():
            bad(".srs 被拒却写进了规则集元数据")
        rules = json.load(open(bot.SB))["route"]["rules"]
        if any(r.get("rule_set") for r in rules):
            bad(".srs 被拒却把规则写进了 model")
        ok(".srs 被拒后不留半截状态(元数据与 model 都干净)")

    # ── 4. .mrs 是 mihomo 原生格式 → 必须放行(旧代码以"sing-box 不支持"拒掉) ──
    with tempfile.TemporaryDirectory() as tmp:
        setup(tmp)
        bot._fetch_bytes = lambda url: b"MRSbinary"
        okr, msg = bot.add_ruleset("https://example.com/geo.mrs", "hk")
        if not okr:
            bad(f".mrs 被拒了(mihomo 原生格式应当可用): {msg}")
        m = json.load(open(bot.RS_META))
        if not any(i.get("format") == "mrs" for i in m.values()):
            bad(f".mrs 未按 mrs 格式记录: {m}")
        ok(".mrs 放行并按 mihomo 原生格式记录")

    # ── 5. YAML provider 放行 ──
    with tempfile.TemporaryDirectory() as tmp:
        setup(tmp)
        bot._build_source = lambda url, path: (12, False)
        okr, msg = bot.add_ruleset("https://example.com/rules.yaml", "hk")
        if not okr:
            bad(f"YAML provider 被拒: {msg}")
        ok("YAML provider 放行")

    # ── 6. 应用失败后原后端仍可用: model 回到改前, 磁盘上不留坏渲染 ──
    with tempfile.TemporaryDirectory() as tmp:
        setup(tmp)
        before = open(bot.SB).read()
        # 直接往 model 里塞一条"进不了 rule-providers"的规则集规则 → apply 必失败
        okr, msg = bot.apply_sb(lambda c: c["route"]["rules"].append(
            {"rule_set": "rs_missing", "outbound": "hk"}))
        if okr:
            bad("dropped 非空却 apply 成功")
        if open(bot.SB).read() != before:
            bad("apply 失败后 model 没还原(原后端不再可用)")
        ok("应用失败 → model 完整还原, 原后端保持可用")

    # ── 7. 升级前就存在的 .srs(老机器现场): 必须挡住迁移, 而不是迁过去悄悄少一条分流 ──
    # 迁移侧(pdg.sh 的 _activate_mihomo_core)调的正是 bot._render_mihomo_file, 这里验同一判据。
    with tempfile.TemporaryDirectory() as tmp:
        setup(tmp)
        srs = os.path.join(bot.RS_DIR, "rs_legacy.srs")
        open(srs, "wb").write(b"SRSbinary")
        json.dump({"rs_legacy": {"url": "https://old.example/geo.srs", "outbound": "hk",
                                 "format": "binary", "path": srs, "count": None}},
                  open(bot.RS_META, "w"))
        c = json.load(open(bot.SB))
        c["route"].setdefault("rule_set", []).append(
            {"tag": "rs_legacy", "type": "local", "format": "binary", "path": srs})
        c["route"]["rules"].append({"rule_set": "rs_legacy", "outbound": "hk"})
        json.dump(c, open(bot.SB, "w"))
        meta = bot._render_mihomo_file()
        if not (meta or {}).get("dropped"):
            bad("老机器遗留 .srs 未被记进 dropped(迁移会静默丢掉这条分流)")
        okr, err, _ = bot._core_apply()
        if okr:
            bad("遗留 .srs 仍让配置照常应用")
        if "rs_legacy" not in err:
            bad(f"未点名遗留的 .srs 规则集: {err}")
        ok("老机器遗留 .srs → 判失败并点名(迁移据此中止, 保留 sing-box 运行)")

    # ── 8. 正常规则集(有 rule-provider)不受影响 ──
    with tempfile.TemporaryDirectory() as tmp:
        setup(tmp)
        bot._build_source = lambda url, path: (34, False)
        okr, msg = bot.add_ruleset("https://example.com/cn.list", "hk")
        if not okr:
            bad(f"正常 .list 规则集被误拒: {msg}")
        cfg = json.load(open(bot.MIHOMO_CFG))
        if not any(str(r).startswith("RULE-SET,") for r in cfg.get("rules", [])):
            bad("正常规则集没进 mihomo 运行配置")
        ok("正常 .list 规则集照常添加, 并真的进了 mihomo 运行配置")

    # ── 9. doctor 要提前预警遗留 .srs, 而不是等 update 被挡住才让用户回头查 ──
    import importlib.util as _il
    _s = _il.spec_from_file_location("checks", ROOT / "deploy/bot/checks.py")
    checks = _il.module_from_spec(_s)
    _s.loader.exec_module(checks)
    with tempfile.TemporaryDirectory() as tmp:
        checks.RS_META = os.path.join(tmp, "none.json")
        if checks.check_rulesets() is not None:
            bad("没有规则集时不该显示该检查项")
        checks.RS_META = os.path.join(tmp, "ok.json")
        json.dump({"rs_a": {"url": "https://x/a.list", "format": "source"}},
                  open(checks.RS_META, "w"))
        lv, _lab, _d = checks.check_rulesets()
        if lv != "ok":
            bad(f"正常规则集被判成 {lv}")
        checks.RS_META = os.path.join(tmp, "srs.json")
        json.dump({"rs_old": {"url": "https://x/geo.srs", "format": "binary", "label": "旧规则"}},
                  open(checks.RS_META, "w"))
        lv, _lab, detail = checks.check_rulesets()
        if lv != "fail" or "旧规则" not in detail:
            bad(f"遗留 .srs 未被 doctor 判 fail 并点名: {lv} {detail}")
        if "pdg update" not in detail or "分流管理" not in detail:
            bad(f"doctor 提示不具可操作性: {detail}")
        ok("doctor 提前预警遗留 .srs(点名 + 说明会挡住 update + 给出处理入口)")

    print(f"\n通过 {pass_n} 项断言")


if __name__ == "__main__":
    main()
