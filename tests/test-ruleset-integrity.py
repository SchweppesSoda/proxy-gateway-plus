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

# 真函数留底: 个别用例会打桩 _build_source/_fetch_bytes, 但那种桩**绝不能泄漏**到后面用
# 真实 fixture 的用例里(否则等于把被测逻辑 mock 掉了还以为在测)。setup() 每次都复原。
_REAL_BUILD_SOURCE = bot._build_source
_REAL_FETCH_BYTES = bot._fetch_bytes

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
    bot._build_source = _REAL_BUILD_SOURCE      # 复原, 防止上一个用例的桩泄漏进来
    bot._fetch_bytes = _REAL_FETCH_BYTES
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
        # .mrs 的 behavior 判不出来, 必须显式声明(见下方真实 fixture 用例里的"未声明即拒绝")
        okr, msg = bot.add_ruleset("https://example.com/geo.mrs", "hk", behavior="domain")
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

# ══════════════════════════════════════════════════════════════════════════════
# 真实规则集 fixture 走**本地 HTTP 服务** —— 不 mock _build_source, 完整跑
# 添加 → 刷新 → 渲染 → 内核校验。
# ══════════════════════════════════════════════════════════════════════════════
import http.server
import shutil
import subprocess
import threading

FIXTURES = ROOT / "tests" / "fixtures"

# 真实的 Clash YAML provider(mihomo/Clash 生态最常见的形态)
YAML_PROVIDER = b"""payload:
  - DOMAIN-SUFFIX,example.com
  - DOMAIN,api.example.com
  - 'DOMAIN-KEYWORD,exam'
  - IP-CIDR,1.2.3.0/24
"""
SURGE_LIST = b"""# comment
DOMAIN-SUFFIX,surge.example.com
DOMAIN,x.surge.example.com
"""


class _Serve(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a):     # 别把请求日志刷进测试输出
        pass


def serve_dir(d):
    """起一个本地 HTTP 服务伺服目录 d, 返回 (base_url, shutdown)。"""
    handler = lambda *a, **k: _Serve(*a, directory=d, **k)   # noqa: E731
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return "http://127.0.0.1:%d" % srv.server_address[1], srv.shutdown


def mihomo_bin():
    """有真 mihomo 就用它做内核校验; 没有则返回 None(该断言跳过并说明)。"""
    return shutil.which("mihomo")


def ruleset_main():
    mrs_fix = FIXTURES / "ruleset-domain.mrs"
    if not mrs_fix.exists():
        bad("缺少真实 MRS fixture: %s" % mrs_fix)
    mrs_bytes = mrs_fix.read_bytes()

    www = tempfile.mkdtemp(prefix="pdgwww")
    (Path(www) / "cn.yaml").write_bytes(YAML_PROVIDER)
    (Path(www) / "cn.list").write_bytes(SURGE_LIST)
    (Path(www) / "geo.mrs").write_bytes(mrs_bytes)
    base, shutdown = serve_dir(www)
    try:
        # ── 真实 YAML provider: 添加 → 解析出规则 → 刷新 → 渲染进运行配置 ──
        with tempfile.TemporaryDirectory() as tmp:
            setup(tmp)
            okr, msg = bot.add_ruleset(base + "/cn.yaml", "hk")
            if not okr:
                bad(f"真实 Clash YAML provider 添加失败: {msg}")
            m = json.load(open(bot.RS_META))
            info = next(iter(m.values()))
            local = json.load(open(info["path"]))
            rules = local["rules"][0]
            if "example.com" not in rules.get("domain_suffix", []):
                bad(f"YAML provider 的 DOMAIN-SUFFIX 没解析出来: {rules}")
            if "api.example.com" not in rules.get("domain", []):
                bad(f"YAML provider 的 DOMAIN 没解析出来: {rules}")
            if "1.2.3.0/24" not in rules.get("ip_cidr", []):
                bad(f"YAML provider 的 IP-CIDR 没解析出来: {rules}")
            ok("真实 Clash YAML provider(payload: 列表)被正确解析并添加")

            cfg = json.load(open(bot.MIHOMO_CFG))
            if not any(str(r).startswith("RULE-SET,") for r in cfg.get("rules", [])):
                bad("YAML provider 没进 mihomo 运行配置")
            ok("YAML provider 已渲染进 mihomo 运行配置(RULE-SET)")

            rr = bot.refresh_rulesets()
            if not (isinstance(rr, tuple) and len(rr) == 2):
                bad(f"refresh_rulesets 未返回 (成功数, 失败项) 二元组: {rr!r}")
            nok, failed = rr
            if failed or nok < 1:
                bad(f"刷新真实 YAML provider 失败: {rr!r}")
            ok("刷新真实 YAML provider 成功, 且返回明确状态 (成功数, 失败项)")

            mh = mihomo_bin()
            if mh:
                r = subprocess.run([mh, "-t", "-d", bot.MIHOMO_DIR, "-f", bot.MIHOMO_CFG],
                                   capture_output=True, text=True)
                if r.returncode != 0:
                    bad(f"真 mihomo -t 拒绝了含 YAML provider 的配置: {(r.stdout + r.stderr)[-300:]}")
                ok("真 mihomo -t 接受含 YAML provider 的运行配置")
            else:
                print("[SKIP] 本机无 mihomo, 跳过真内核校验(CI 的 e2e/functional job 会覆盖)")

        # ── .mrs: 必须按二进制下载, 不得进文本解析路径 ──
        with tempfile.TemporaryDirectory() as tmp:
            setup(tmp)
            okr, msg = bot.add_ruleset(base + "/geo.mrs", "hk", behavior="domain")
            if not okr:
                bad(f"真实 .mrs 添加失败: {msg}")
            m = json.load(open(bot.RS_META))
            info = next(iter(m.values()))
            got = open(info["path"], "rb").read()
            if got != mrs_bytes:
                bad(".mrs 落盘内容与源文件不一致(疑似走了文本解析路径)")
            if info.get("behavior") != "domain":
                bad(f".mrs 的 behavior 未按显式声明记录: {info}")
            ok("真实 .mrs 按二进制落盘, 内容逐字节一致, behavior 按显式声明记录")

            rr = bot.refresh_rulesets()
            nok, failed = rr
            if failed:
                bad(f".mrs 刷新失败: {rr!r}")
            if open(info["path"], "rb").read() != mrs_bytes:
                bad(".mrs 刷新后内容变了(文本解析把二进制毁了?)")
            ok("再次刷新 .mrs: 仍按二进制处理, 内容逐字节不变")

            # 源头变成坏档(空响应)→ 刷新必须失败并回滚到上一份好档
            (Path(www) / "geo.mrs").write_bytes(b"")
            rr = bot.refresh_rulesets()
            nok, failed = rr
            if not failed:
                bad("坏档(.mrs 空响应)却报刷新成功")
            if open(info["path"], "rb").read() != mrs_bytes:
                bad("坏档刷新后没回滚到上一份好档")
            ok("坏 .mrs → 刷新明确失败并回滚到上一份好档(不断网)")
            (Path(www) / "geo.mrs").write_bytes(mrs_bytes)

        # ── .mrs 未声明 behavior: 不得静默当成 domain ──
        with tempfile.TemporaryDirectory() as tmp:
            setup(tmp)
            okr, msg = bot.add_ruleset(base + "/geo.mrs", "hk")
            if okr:
                bad(".mrs 未声明 behavior 却被接受(静默按 domain 处理是错的)")
            if "behavior" not in msg and "类型" not in msg:
                bad(f".mrs 拒绝文案没说清要指定类型: {msg}")
            ok(".mrs 未声明 behavior → 拒绝并要求指定类型(不静默硬编码 domain)")

        # ── 刷新部分失败: 必须如实报出是哪一个 ──
        with tempfile.TemporaryDirectory() as tmp:
            setup(tmp)
            bot.add_ruleset(base + "/cn.list", "hk")
            m = json.load(open(bot.RS_META))
            name = next(iter(m))
            m[name]["url"] = base + "/does-not-exist.list"      # 让它刷新时 404
            json.dump(m, open(bot.RS_META, "w"))
            nok, failed = bot.refresh_rulesets()
            if not failed:
                bad("规则集 404 却报刷新成功")
            if not any(name in str(f) for f in failed):
                bad(f"失败项没点名是哪个规则集: {failed}")
            ok("刷新失败如实返回失败项并点名(不再只 print 却表现为成功)")
    finally:
        shutdown()
        shutil.rmtree(www, ignore_errors=True)

    print(f"通过 {pass_n} 项断言(含真实 fixture)")


if __name__ == "__main__":
    ruleset_main()

