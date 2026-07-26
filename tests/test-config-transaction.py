#!/usr/bin/env python3
"""统一配置事务核心(5.1)回归: 状态机 / 白名单 / 前置检查 / 原子落盘 / 观察 / 回滚 / 审计。

全部是**行为测试**: 在沙箱文件树(PDG_TX_FSROOT)里真跑一遍事务, 用假的 systemctl / nft /
mihomo 充当"外部世界"(桩会把每次调用记进日志, 也能按需装成失败), 断言的是磁盘与状态的真实
结果, 不是源码里有没有某个字符串。
"""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
pass_n = 0
fail_n = 0


def ok(m):
    global pass_n
    print("[OK]   %s" % m); pass_n += 1


def bad(m):
    global fail_n
    print("[FAIL] %s" % m); fail_n += 1


from txbox import Box, load_tx  # noqa: E402


MODEL = json.dumps({"outbounds": [{"type": "direct", "tag": "direct"}],
                    "route": {"rules": []}, "inbounds": []}).encode()


def main():
    # ── 1. 状态机(用一次性沙箱: 这里会故意把事务停在 APPLYING, 那是"待恢复"状态,
    #        它本身就应该挡住后续事务 —— 见第 13 段) ──
    box0 = Box(); tx = load_tx(box0.env)
    assert tx.PREPARING in tx._ALLOWED
    t = tx.Tx("test", "op1")
    t2 = tx.Tx("test", "op2")
    if t.txid == t2.txid:
        bad("两笔事务拿到同一个 txid")
    else:
        ok("transaction ID 唯一(同秒内也不同)")
    try:
        t._set_state(tx.COMMITTED)          # PREPARING → COMMITTED 非法
        bad("非法状态跳转没有被拒绝")
    except tx.TxError:
        ok("非法状态跳转(PREPARING→COMMITTED)被拒绝")
    t._set_state(tx.VALIDATED); t._set_state(tx.APPLYING)
    try:
        t._set_state(tx.ABORTED)            # APPLYING 不能直接 ABORTED(现网已被动过)
        bad("APPLYING→ABORTED 竟被允许")
    except tx.TxError:
        ok("APPLYING 不允许跳到 ABORTED(那会掩盖已改动的现网)")
    for st in (tx.APPLYING, tx.ROLLING_BACK, tx.ROLLBACK_FAILED):
        if st not in tx.NEEDS_RECOVERY:
            bad("%s 不在需要恢复的状态集合里" % st)
    ok("APPLYING / ROLLING_BACK / ROLLBACK_FAILED 都被认定为需要恢复")

    # ── 1b. 停在 APPLYING 的事务会挡住下一笔写 ──
    box0.put("/etc/sing-box/config.json", MODEL)
    box0.up("mihomo")
    t3 = tx.Tx("test", "blocked-by-pending")
    t3.stage("model", MODEL)
    try:
        t3.commit(); bad("上一笔停在 APPLYING, 新事务竟然照跑")
    except tx.TxRefused as e:
        if "recover" in str(e):
            ok("上一笔停在 APPLYING → 新的写事务被拒绝, 并指向 tx recover")
        else:
            bad("拒绝原因不对: %s" % e)
    box0.clean()

    # ── 2. 目标白名单 ──
    box = Box(); tx = load_tx(box.env)
    for bad_name in ("../../etc/shadow", "/etc/passwd", "model2", "mosdns_rule:../x.txt",
                     "mosdns_rule:x.yaml", "ruleset:../../a.json", "unit:evil.sh"):
        try:
            tx.resolve_target(bad_name)
            bad("白名单没挡住: %s" % bad_name)
        except tx.TxError:
            pass
    ok("白名单挡掉越界目标(绝对路径 / ../ / 非法后缀 / 未知名字)")
    p, mode, secret, val = tx.resolve_target("model")
    if p == box.path("/etc/sing-box/config.json") and secret and mode == 0o600:
        ok("合法目标解析出沙箱内的绝对路径 + 0600 + 标记含凭据")
    else:
        bad("model 解析结果不对: %s %s %s" % (p, oct(mode), secret))

    # ── 3. 候选校验失败 → 现网零改动 + ABORTED ──
    box.put("/etc/sing-box/config.json", MODEL)
    box.up("mihomo")
    before = box.read("/etc/sing-box/config.json")
    t = tx.Tx("test", "bad-model")
    t.stage("model", b"{not json")
    try:
        t.commit(); bad("坏候选竟然提交成功")
    except tx.TxRefused as e:
        if box.read("/etc/sing-box/config.json") == before and t.state == tx.ABORTED:
            ok("候选校验失败 → 现网零改动 + 状态 ABORTED")
        else:
            bad("校验失败后现网被改了或状态不对: %s" % t.state)

    # ── 4. 正常提交: 原子落盘 + 服务动作 + 观察 + 材料清理 ──
    newmodel = json.dumps({"outbounds": [{"type": "direct", "tag": "direct"}],
                           "route": {"rules": [{"domain_suffix": ["a.com"], "outbound": "direct"}]},
                           "inbounds": []}).encode()
    t = tx.Tx("test", "add-rule")
    t.stage("model", newmodel)
    t.stage("mosdns_rule:custom_hijack.txt", b"domain:a.com\n")
    t.service("restart:mihomo"); t.service("restart:mosdns")
    box.up("mosdns")
    res = t.commit()
    if res["state"] == tx.COMMITTED and box.read("/etc/sing-box/config.json") == newmodel \
            and box.read("/etc/mosdns/rules/custom_hijack.txt") == b"domain:a.com\n":
        ok("正常提交: 两个目标都落盘, 状态 COMMITTED")
    else:
        bad("提交结果不对: %s / %s" % (res["state"], res.get("error")))
    calls = open(box.calls).read()
    if "systemctl restart mihomo" in calls and "systemctl restart mosdns" in calls:
        ok("声明的服务动作真的执行了(两个 restart 都在调用日志里)")
    else:
        bad("服务动作没执行: %s" % calls[-200:])
    txd = os.path.join(box.env["PDG_TX_ROOT"], res["txid"])
    if not os.path.exists(os.path.join(txd, "candidate")) and \
            not os.path.exists(os.path.join(txd, "before")):
        ok("COMMITTED 后候选与 before 材料已删除(不把凭据留在盘上)")
    else:
        bad("提交后仍留着候选/before 材料")
    if os.path.exists(os.path.join(txd, "meta.json")) and os.path.exists(os.path.join(txd, "diff.txt")):
        ok("脱敏 meta.json 与 diff.txt 保留下来供审计")
    else:
        bad("meta/diff 没留下")

    # ── 5. 前置检查: 准备期间被别人改过 → 拒绝覆盖 ──
    t = tx.Tx("test", "stale")
    t.stage("model", MODEL)
    box.put("/etc/sing-box/config.json", json.dumps({"outbounds": [], "route": {}}).encode())
    try:
        t.commit(); bad("目标被改过仍然覆盖了")
    except tx.TxRefused:
        ok("目标在准备期间被改过 → 拒绝覆盖(expect_sha256 前置检查)")

    # ── 6. 观察期: 服务起来即崩 → 回滚 ──
    box2 = Box(restart_crash=True); tx2 = load_tx(box2.env)
    box2.put("/etc/sing-box/config.json", MODEL)
    box2.up("mihomo")
    crashy = json.dumps({"outbounds": [{"type": "direct", "tag": "CRASHME"}],
                         "route": {"rules": []}, "inbounds": []}).encode()
    t = tx2.Tx("test", "crashy")
    t.stage("model", crashy); t.service("restart:mihomo")
    res = t.commit()
    if res["state"] == tx2.ROLLED_BACK and box2.read("/etc/sing-box/config.json") == MODEL:
        ok("观察期 NRestarts 上涨(起来即崩)→ 回滚且内容逐字节还原")
    else:
        bad("崩溃循环没被判失败: %s" % res)
    if res.get("rollback_complete"):
        ok("回滚被验证为完整")
    else:
        bad("回滚完整性没被确认")
    box2.clean()

    # ── 7. 服务 restart 失败 → 回滚 ──
    box3 = Box(svc_fail=["mosdns"]); tx3 = load_tx(box3.env)
    box3.put("/etc/mosdns/rules/custom_direct.txt", b"domain:old.com\n", 0o644)
    box3.up("mosdns")
    t = tx3.Tx("test", "mosdns-fail")
    t.stage("mosdns_rule:custom_direct.txt", b"domain:new.com\n")
    t.service("restart:mosdns")
    res = t.commit()
    if res["state"] == tx3.ROLLED_BACK and box3.read("/etc/mosdns/rules/custom_direct.txt") == b"domain:old.com\n":
        ok("服务重启失败 → 文件回滚到操作前内容")
    else:
        bad("重启失败没回滚: %s / %r" % (res["state"], box3.read("/etc/mosdns/rules/custom_direct.txt")))
    box3.clean()

    # ── 8. 新建文件的回滚 = 删除 ──
    box4 = Box(svc_fail=["mosdns"]); tx4 = load_tx(box4.env)
    box4.up("mosdns")
    t = tx4.Tx("test", "create-then-fail")
    t.stage("mosdns_rule:brand_new.txt", b"domain:x.com\n")
    t.service("restart:mosdns")
    res = t.commit()
    if res["state"] == tx4.ROLLED_BACK and box4.read("/etc/mosdns/rules/brand_new.txt") is None:
        ok("原本不存在的目标: 回滚 = 删掉本次新建的文件(absent 标记生效)")
    else:
        bad("新建文件没被回滚删除")
    box4.clean()

    # ── 9. 基线门: 相关组件操作前就坏 → 普通事务拒绝开始; repair 模式放行 ──
    box5 = Box(healthy=False); tx5 = load_tx(box5.env)
    box5.put("/etc/sing-box/config.json", MODEL)          # mihomo 故意不 up, 探针也不起
    t = tx5.Tx("test", "normal-on-broken")
    t.stage("model", newmodel)
    try:
        t.commit(); bad("组件已坏仍允许普通变更")
    except tx5.TxRefused as e:
        ok("操作前硬门已坏 → 普通事务拒绝开始(%s)" % str(e)[:40])
    t = tx5.Tx("test", "repair-on-broken", mode="repair")
    t.stage("model", newmodel); t.service("restart:mihomo")
    res = t.commit()
    if res["state"] == tx5.COMMITTED:
        ok("修复模式允许在降级基线上运行")
    else:
        bad("修复模式被挡住了: %s" % res)
    box5.clean()

    # ── 10. 锁: 被别人占着 → TxBusy(不阻塞) ──
    import fcntl
    lf = open(box.env["PDG_LOCKFILE"], "w")
    fcntl.flock(lf, fcntl.LOCK_EX)
    t = tx.Tx("test", "busy"); t.stage("mosdns_rule:custom_direct.txt", b"domain:z.com\n")
    t0 = time.time()
    try:
        t.commit(); bad("锁被占着还是提交了")
    except tx.TxBusy:
        ok("锁被占用 → 立刻 TxBusy(耗时 %.1fs, 没有排队)" % (time.time() - t0))
    fcntl.flock(lf, fcntl.LOCK_UN); lf.close()

    # ── 11. 审计 ──
    audit = os.path.join(box.env["PDG_TX_ROOT"], "index.jsonl")
    lines = [json.loads(x) for x in open(audit, encoding="utf-8")]
    if lines and all("txid" in r and "state" in r and "op" in r for r in lines):
        ok("审计记录逐笔落盘(txid/state/op 齐全, 共 %d 条)" % len(lines))
    else:
        bad("审计记录不完整")
    if any(r["state"] == "ABORTED" for r in lines) and any(r["state"] == "COMMITTED" for r in lines):
        ok("审计里 ABORTED 与 COMMITTED 都被如实记录")
    else:
        bad("审计状态记录不全: %s" % {r["state"] for r in lines})

    # ── 12. runner / schema 固定 ──
    t = tx.Tx("test", "runner")
    m = json.load(open(os.path.join(box.env["PDG_TX_ROOT"], t.txid, "meta.json")))
    if m.get("runner_sha256") and m.get("schema_version") == tx.SCHEMA_VERSION:
        ok("每笔事务记录 runner_sha256 与 schema_version")
    else:
        bad("缺 runner/schema 记录")
    m["runner_sha256"] = "0" * 64
    tx.atomic_write(os.path.join(box.env["PDG_TX_ROOT"], t.txid, "meta.json"),
                    json.dumps(m).encode(), 0o600)
    r = subprocess.run([sys.executable, str(ROOT / "deploy/bot/pdgtx.py"), "apply", "--tx", t.txid],
                       capture_output=True, text=True, env=dict(os.environ, **box.env))
    if r.returncode == 3 and "runner" in (r.stderr or ""):
        ok("runner 版本与事务不符 → apply 拒绝执行(退出码 3)")
    else:
        bad("runner 漂移没被拒绝: rc=%s %s" % (r.returncode, r.stderr[:120]))

    # ── 13. DoT 证书部署: 三个目标一起提交; 任一步失败继续用旧证书 ──
    box6 = Box(); tx6 = load_tx(box6.env)
    box6.up("mosdns")
    old_chain = b"-----BEGIN CERTIFICATE-----\nOLD\n-----END CERTIFICATE-----\n"
    old_key = b"-----BEGIN PRIVATE KEY-----\nOLD\n-----END PRIVATE KEY-----\n"
    box6.put("/etc/mosdns/certs/fullchain.pem", old_chain, 0o644)
    box6.put("/etc/mosdns/certs/privkey.pem", old_key, 0o600)
    box6.put("/opt/pdg-bot/dot-domain", b"old.example.com\n", 0o644)
    new_chain = b"-----BEGIN CERTIFICATE-----\nNEW\n-----END CERTIFICATE-----\n"
    new_key = b"-----BEGIN PRIVATE KEY-----\nNEW\n-----END PRIVATE KEY-----\n"
    t = tx6.Tx("bot", "dot_cert_deploy")
    t.stage("cert_fullchain", new_chain)
    t.stage("cert_privkey", new_key)
    t.stage("dot_marker", b"new.example.com\n")
    t.service("restart:mosdns")
    res = t.commit()
    if res["state"] == tx6.COMMITTED and box6.read("/etc/mosdns/certs/privkey.pem") == new_key \
            and box6.read("/opt/pdg-bot/dot-domain") == b"new.example.com\n":
        ok("证书部署: 证书 + 私钥 + 活动域名标记一笔事务提交")
    else:
        bad("证书部署失败: %s" % res)
    st = os.stat(box6.path("/etc/mosdns/certs/privkey.pem"))
    if st.st_mode & 0o777 == 0o600:
        ok("私钥保持 0600(权限随 before-image 还原, 不被候选带偏)")
    else:
        bad("私钥权限变成 %o" % (st.st_mode & 0o777))
    # mosdns 起不来 → 全部回到旧证书
    box7 = Box(svc_fail=["mosdns"]); tx7 = load_tx(box7.env)
    box7.up("mosdns")
    box7.put("/etc/mosdns/certs/fullchain.pem", old_chain, 0o644)
    box7.put("/etc/mosdns/certs/privkey.pem", old_key, 0o600)
    box7.put("/opt/pdg-bot/dot-domain", b"old.example.com\n", 0o644)
    t = tx7.Tx("bot", "dot_cert_deploy")
    t.stage("cert_fullchain", new_chain); t.stage("cert_privkey", new_key)
    t.stage("dot_marker", b"new.example.com\n"); t.service("restart:mosdns")
    res = t.commit()
    if res["state"] == tx7.ROLLED_BACK and box7.read("/etc/mosdns/certs/fullchain.pem") == old_chain \
            and box7.read("/etc/mosdns/certs/privkey.pem") == old_key \
            and box7.read("/opt/pdg-bot/dot-domain") == b"old.example.com\n":
        ok("部署后 mosdns 起不来 → 证书/私钥/域名标记全部回到旧的(DoT 继续可用)")
    else:
        bad("证书回滚不完整: %s" % res)
    box6.clean(); box7.clean()

    # ── 14. 规则集刷新的"部分来源成功"语义(5.1 定死)──
    import importlib.util as _il
    box8 = Box(); tx8 = load_tx(box8.env)
    box8.up("mihomo"); box8.up("mosdns")
    spec = _il.spec_from_file_location("pdg_bot_rs", ROOT / "deploy/bot/pdg-bot.py")
    b = _il.module_from_spec(spec); spec.loader.exec_module(b)
    b.RS_DIR = box8.path("/etc/sing-box/rs")
    b.RS_META = box8.path("/opt/pdg-bot/rulesets.json")
    b.SB = box8.path("/etc/sing-box/config.json")
    b.MIHOMO_CFG = box8.path("/etc/mihomo/config.yaml")
    b.LOCKFILE = box8.env["PDG_LOCKFILE"]
    os.makedirs(b.RS_DIR, exist_ok=True)
    box8.put("/etc/sing-box/config.json", MODEL)
    good_old, bad_old = b"OLD-GOOD\n", b"OLD-BAD\n"
    box8.put("/etc/sing-box/rs/rs_good.json", good_old, 0o644)
    box8.put("/etc/sing-box/rs/rs_bad.json", bad_old, 0o644)
    meta = {"rs_good": {"url": "https://x/good.list", "outbound": "direct", "format": "source",
                        "path": b.RS_DIR + "/rs_good.json", "label": "好源"},
            "rs_bad": {"url": "https://x/bad.list", "outbound": "direct", "format": "source",
                       "path": b.RS_DIR + "/rs_bad.json", "label": "坏源"}}
    box8.put("/opt/pdg-bot/rulesets.json", json.dumps(meta).encode(), 0o644)

    def _build(url, path):
        if "bad" in url:
            raise ValueError("下载失败")
        with open(path, "wb") as f:
            f.write(b'{"version": 1, "rules": [{"domain": ["new.example"]}]}')
        return (1, False)
    b._build_source = _build
    n, failed = b.refresh_rulesets()
    if n == 1 and any("坏源" in x for x in failed):
        ok("刷新: 下载失败的源不进候选, 成功的照常提交, 失败项如实列出")
    else:
        bad("部分成功语义不对: n=%s failed=%s" % (n, failed))
    if box8.read("/etc/sing-box/rs/rs_bad.json") == bad_old:
        ok("刷新: 拿不到的源保留旧文件(不被清空/不被半写)")
    else:
        bad("失败源的旧文件被动了")
    if b"new.example" in (box8.read("/etc/sing-box/rs/rs_good.json") or b""):
        ok("刷新: 成功源已换成新内容")
    else:
        bad("成功源没更新")

    # 内核校验不过 → 整批回滚(一个都不换), 且不谎报成功
    box9 = Box(svc_fail=["mihomo"]); tx9 = load_tx(box9.env)
    box9.up("mihomo"); box9.up("mosdns")
    spec = _il.spec_from_file_location("pdg_bot_rs2", ROOT / "deploy/bot/pdg-bot.py")
    b2 = _il.module_from_spec(spec); spec.loader.exec_module(b2)
    for attr, val in (("RS_DIR", box9.path("/etc/sing-box/rs")),
                      ("RS_META", box9.path("/opt/pdg-bot/rulesets.json")),
                      ("SB", box9.path("/etc/sing-box/config.json")),
                      ("MIHOMO_CFG", box9.path("/etc/mihomo/config.yaml")),
                      ("LOCKFILE", box9.env["PDG_LOCKFILE"])):
        setattr(b2, attr, val)
    os.makedirs(b2.RS_DIR, exist_ok=True)
    box9.put("/etc/sing-box/config.json", MODEL)
    box9.put("/etc/sing-box/rs/rs_good.json", good_old, 0o644)
    meta2 = {"rs_good": dict(meta["rs_good"], path=b2.RS_DIR + "/rs_good.json")}
    box9.put("/opt/pdg-bot/rulesets.json", json.dumps(meta2).encode(), 0o644)
    b2._build_source = _build
    # mihomo 换上新规则集后起不来(桩里 restart 直接失败)→ 观察期判失败 → 整批回滚
    n, failed = b2.refresh_rulesets()
    if n == 0 and box9.read("/etc/sing-box/rs/rs_good.json") == good_old:
        ok("刷新: 内核换上新规则集起不来 → 整批不换(旧规则集逐字节保留)且返回 0")
    else:
        bad("校验失败仍换了规则集: n=%s" % n)
    if any("整批未更新" in x for x in failed):
        ok("刷新: 整批未更新时如实说明, 不谎报已更新")
    else:
        bad("整批失败没说清楚: %s" % failed)

    # 零成功 → 不提交空事务
    _txr = box9.env["PDG_TX_ROOT"]
    before = len(os.listdir(_txr)) if os.path.isdir(_txr) else 0
    b2._build_source = lambda url, path: (_ for _ in ()).throw(ValueError("全挂"))
    n, failed = b2.refresh_rulesets()
    after = len(os.listdir(_txr)) if os.path.isdir(_txr) else 0
    if n == 0 and after == before:
        ok("刷新: 一个源都没下来 → 不开空事务, 也不报成功")
    else:
        bad("零成功却动了事务: n=%s %d→%d" % (n, before, after))
    box8.clean(); box9.clean()

    box.clean()
    print("\n通过 %d, 失败 %d" % (pass_n, fail_n))
    return 1 if fail_n else 0


if __name__ == "__main__":
    sys.exit(main())
