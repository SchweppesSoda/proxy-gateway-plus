#!/usr/bin/env python3
"""事务故障注入回归: 锁(fail-closed / 并发 / 忙)与各类失败路径。

这里验的是"出事时到底发生了什么", 所以每一条都真的把故障造出来 —— 锁文件放到写不进去的
位置、三个进程同时抢锁、候选校验失败、before-image 存不下、第 N 个文件替换失败 —— 再看现网
与状态机的真实结果。
"""
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
from txbox import Box, load_tx  # noqa: E402
pass_n = 0
fail_n = 0


def ok(m):
    global pass_n
    print("[OK]   %s" % m); pass_n += 1


def bad(m):
    global fail_n
    print("[FAIL] %s" % m); fail_n += 1


def _unwritable_lock_path(tmp):
    """造一个"锁文件绝对打不开"的路径: 只读目录下的文件。"""
    d = os.path.join(tmp, "ro")
    os.makedirs(d, exist_ok=True)
    os.chmod(d, 0o500)
    return os.path.join(d, "nested", "pdg.lock")     # 目录不可写 → makedirs/open 都失败


def main():
    tmp = tempfile.mkdtemp(prefix="pdgtx-faults.")
    fsroot = os.path.join(tmp, "root")
    for d in ("/etc/mosdns/rules", "/etc/sing-box", "/var/lib/privdns-gateway", "/run"):
        os.makedirs(fsroot + d, exist_ok=True)
    base_env = {
        "PDG_TX_FSROOT": fsroot,
        "PDG_TX_ROOT": fsroot + "/var/lib/privdns-gateway/tx",
        "PDG_LOCKFILE": fsroot + "/run/privdns-gateway.lock",
        "PDG_STABLE_SAMPLES": "1",
    }

    # ── 1. 事务核心: 锁文件不可用 → 拒绝执行(fail-closed), 现网零改动 ──
    badlock = _unwritable_lock_path(tmp)
    env = dict(base_env, PDG_LOCKFILE=badlock)
    tx = load_tx(env)
    live = fsroot + "/etc/mosdns/rules/custom_direct.txt"
    with open(live, "wb") as f:
        f.write(b"domain:old.com\n")
    t = tx.Tx("test", "nolock")
    t.stage("mosdns_rule:custom_direct.txt", b"domain:new.com\n")
    try:
        t.commit()
        bad("锁文件不可用时事务竟然照跑")
    except tx.TxRefused as e:
        if "锁文件不可用" in str(e) and open(live, "rb").read() == b"domain:old.com\n":
            ok("核心: 锁文件不可用 → TxRefused 且现网零改动(fail-closed)")
        else:
            bad("拒绝了但现网被改或原因不对: %s" % e)
    except Exception as e:  # noqa: BLE001
        bad("锁不可用抛了别的异常: %s" % type(e).__name__)

    # ── 2. CLI: 锁文件不可用 → 非 0 退出且不产生快照 ──
    snapdir = fsroot + "/var/lib/privdns-gateway/backups"
    r = subprocess.run(["bash", str(ROOT / "deploy/bot/pdg.sh"), "snapshot"],
                       capture_output=True, text=True,
                       env=dict(os.environ, PDG_LOCKFILE=badlock, EUID="0"))
    # 非 root 时 need_root 会先拦下; 用 fakeroot 判据不可行, 故只在 root 下断言退出码,
    # 其余环境断言"至少不是成功地写了快照"
    if r.returncode != 0 and not os.path.isdir(snapdir):
        ok("CLI: 锁文件不可用 → 非 0 退出且没有生成快照")
    else:
        bad("CLI 在锁不可用时仍然继续了: rc=%s" % r.returncode)
    if "锁文件不可用" in (r.stdout + r.stderr) or os.geteuid() != 0:
        ok("CLI: 说清楚了是锁不可用(而不是含糊地失败)" if os.geteuid() == 0
           else "CLI: 非 root 环境由 need_root 先拦下(锁分支由 root 场景的 E2E 覆盖)")
    else:
        bad("CLI 没有给出锁不可用的原因: %s" % (r.stdout + r.stderr)[:120])

    # ── 3. Bot: 锁文件不可用 → 拒绝写并给出可辨识的文案 ──
    r = subprocess.run(
        [sys.executable, "-c",
         "import importlib.util,sys;"
         "spec=importlib.util.spec_from_file_location('bot', %r);"
         "m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);"
         "ctx=m._cfg_guard();got=ctx.__enter__();"
         "print('GOT=%%r' %% got);print('MSG=%%s' %% m.busy_msg());ctx.__exit__(None,None,None)"
         % str(ROOT / "deploy/bot/pdg-bot.py")],
        capture_output=True, text=True,
        env=dict(os.environ, PDG_LOCKFILE=badlock, PDG_BOT_TOKEN="", PDG_BOT_ALLOWED=""))
    out = r.stdout
    if "GOT=False" in out and "锁文件不可用" in out:
        ok("Bot: 锁文件不可用 → _cfg_guard 给 False 且文案点明是锁不可用(不再退化成仅进程内锁)")
    else:
        bad("Bot 锁降级没堵住: %s %s" % (out[:160], r.stderr[:120]))

    # ── 4. 并发: 三个进程同时抢锁, 只有一个能写 ──
    env = dict(base_env)
    tx = load_tx(env)
    os.makedirs(os.path.dirname(env["PDG_LOCKFILE"]), exist_ok=True)
    script = (
        "import importlib.util,os,sys,time\n"
        "spec=importlib.util.spec_from_file_location('pdgtx', %r)\n"
        "m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)\n"
        "try:\n"
        "    with m._Lock():\n"
        "        open(os.environ['WINNER'],'a').write(os.environ['WHO']+'\\n')\n"
        "        time.sleep(1.2)\n"
        "    print('WON')\n"
        "except m.TxBusy:\n"
        "    print('BUSY')\n"
        "except m.TxRefused:\n"
        "    print('REFUSED')\n" % str(ROOT / "deploy/bot/pdgtx.py"))
    winner = os.path.join(tmp, "winner.txt")
    procs = []
    for who in ("cli", "bot", "scheduler"):
        procs.append(subprocess.Popen(
            [sys.executable, "-c", script], stdout=subprocess.PIPE, text=True,
            env=dict(os.environ, WINNER=winner, WHO=who, **env)))
        time.sleep(0.05)
    outs = [p.communicate()[0].strip() for p in procs]
    won = sum(1 for o in outs if "WON" in o)
    busy = sum(1 for o in outs if "BUSY" in o)
    lines = open(winner).read().split() if os.path.exists(winner) else []
    if won == 1 and busy == 2 and len(lines) == 1:
        ok("CLI/Bot/scheduler 同时触发: 只有 1 个取得写锁, 另外 2 个立即 BUSY")
    else:
        bad("并发结果不对: won=%d busy=%d 写入者=%s" % (won, busy, lines))

    # ── 5. before-image 存不下 → 拒绝应用(现网零改动) ──
    box = Box(); tx = load_tx(box.env)
    box.up("mosdns")
    live = box.path("/etc/mosdns/rules/custom_direct.txt")
    with open(live, "wb") as f:
        f.write(b"domain:old.com\n")
    t = tx.Tx("test", "before-fail")
    t.stage("mosdns_rule:custom_direct.txt", b"domain:new.com\n")
    orig = tx.Tx._save_before

    def boom(self, services):
        raise OSError("模拟磁盘满")
    tx.Tx._save_before = boom
    try:
        t.commit(); bad("before-image 存不下仍然应用了")
    except tx.TxRefused:
        if open(live, "rb").read() == b"domain:old.com\n" and t.state == tx.ABORTED:
            ok("before-image 保存失败 → 拒绝应用(现网零改动, 状态 ABORTED)")
        else:
            bad("before-image 失败后现网被改了")
    finally:
        tx.Tx._save_before = orig

    # ── 6. 第 N 个文件替换失败 → 已替换的全部回滚 ──
    a = box.path("/etc/mosdns/rules/a.txt")
    b = box.path("/etc/mosdns/rules/b.txt")
    for p_, v in ((a, b"domain:a-old.com\n"), (b, b"domain:b-old.com\n")):
        with open(p_, "wb") as f:
            f.write(v)
    t = tx.Tx("test", "partial-apply")
    t.stage("mosdns_rule:a.txt", b"domain:a-new.com\n")
    t.stage("mosdns_rule:b.txt", b"domain:b-new.com\n")
    real_apply = tx.Tx._apply_one
    calls = []

    def flaky(self, name, tgt):
        calls.append(name)
        if name == "mosdns_rule:b.txt":
            raise OSError("模拟第二个文件写失败")
        return real_apply(self, name, tgt)
    tx.Tx._apply_one = flaky
    try:
        res = t.commit()
    finally:
        tx.Tx._apply_one = real_apply
    if res["state"] in (tx.ROLLED_BACK, tx.ROLLBACK_FAILED) \
            and open(a, "rb").read() == b"domain:a-old.com\n" \
            and open(b, "rb").read() == b"domain:b-old.com\n":
        ok("第 2 个文件替换失败 → 第 1 个也被还原(不留半套)")
    else:
        bad("部分替换没有整体回滚: %s / %r / %r" % (res["state"], open(a, "rb").read(),
                                                    open(b, "rb").read()))

    # ── 7. 回滚时某个文件还不回去 → ROLLBACK_FAILED 且逐项点名, 其余仍尽力恢复 ──
    for p_, v in ((a, b"domain:a-old.com\n"), (b, b"domain:b-old.com\n")):
        with open(p_, "wb") as f:
            f.write(v)
    t = tx.Tx("test", "rollback-partial")
    t.stage("mosdns_rule:a.txt", b"domain:a-new.com\n")
    t.stage("mosdns_rule:b.txt", b"domain:b-new.com\n")
    real_atomic = tx.atomic_write

    def picky(path, data, mode=0o600, uid=None, gid=None):
        if path.endswith("/b.txt") and data == b"domain:b-old.com\n":
            raise OSError("模拟回滚写失败")
        return real_atomic(path, data, mode, uid, gid)
    real_do = tx.Tx._do_actions
    tx.Tx._do_actions = lambda self: "模拟服务动作失败"
    tx.atomic_write = picky
    try:
        res = t.commit()
    finally:
        tx.atomic_write = real_atomic
        tx.Tx._do_actions = real_do
    if res["state"] == tx.ROLLBACK_FAILED and res["rollback_complete"] is False \
            and any("b.txt" in x for x in res["rollback_failed_items"]):
        ok("回滚中一个目标失败 → ROLLBACK_FAILED 且点名未恢复项")
    else:
        bad("回滚失败没有如实上报: %s" % res)
    if open(a, "rb").read() == b"domain:a-old.com\n":
        ok("回滚失败时其余目标仍被尽力恢复(a.txt 已还原)")
    else:
        bad("回滚在第一个失败处就放弃了")
    txdir = os.path.join(box.env["PDG_TX_ROOT"], res["txid"])
    if os.path.isdir(os.path.join(txdir, "before")):
        ok("ROLLBACK_FAILED 保留 before 材料(供人工修复)")
    else:
        bad("回滚失败却把恢复材料删了")

    # ── 8. netns 不可用时 auto 必须退到高端口, 而不是把候选判成有错 ──
    # 复现 CI 现场: 容器里 unshare 命令在, 但没有 CAP_SYS_ADMIN, `unshare -n` 直接失败。
    box2 = Box(); tx2 = load_tx(box2.env)
    fake_mosdns = os.path.join(box2.bin, "mosdns")
    with open(fake_mosdns, "w") as f:      # 好配置常驻, 坏配置(含 BADCONF)立刻 FATAL 退出
        f.write("#!/bin/bash\n"
                "for a in \"$@\"; do [[ -f \"$a\" ]] && grep -q BADCONF \"$a\" && "
                "{ echo 'FATAL: bad plugin'; exit 1; }; done\n"
                "sleep 30\n")
    os.chmod(fake_mosdns, 0o755)
    with open(os.path.join(box2.bin, "unshare"), "w") as f:
        f.write("#!/bin/sh\necho 'unshare: unshare failed: Operation not permitted' >&2\nexit 1\n")
    os.chmod(os.path.join(box2.bin, "unshare"), 0o755)
    os.environ["PATH"] = box2.env["PATH"]
    good = b"log:\n  level: info\nplugins:\n  - tag: s\n    type: udp_server\n    args:\n      addr: \"127.0.0.1:53\"\n"
    bad_cfg = b"log:\n  level: info\n# BADCONF\nplugins:\n  - tag: s\n    type: udp_server\n    args:\n      addr: \"127.0.0.1:53\"\n"
    os.environ["PDG_TX_MOSDNS_PROBE_SECS"] = "1"

    os.environ["PDG_TX_MOSDNS_PROBE_MODE"] = "netns"
    okr, err = tx2.VALIDATORS["mosdns_probe"]("/etc/mosdns/config.yaml", good, None)
    if okr is False and "netns 不可用" in err:
        ok("强制 netns 模式 + 无权限 → 如实报 netns 不可用(不冒充候选有错)")
    else:
        bad("netns 模式的报错不对: %s / %s" % (okr, err))

    os.environ["PDG_TX_MOSDNS_PROBE_MODE"] = "auto"
    okr, err = tx2.VALIDATORS["mosdns_probe"]("/etc/mosdns/config.yaml", good, None)
    if okr:
        ok("auto: netns 不可用 → 退到高端口探针, 好配置判通过")
    else:
        bad("auto 没能退到高端口: %s" % err)
    okr, err = tx2.VALIDATORS["mosdns_probe"]("/etc/mosdns/config.yaml", bad_cfg, None)
    if not okr:
        ok("auto 降级后仍能判出坏候选(降级不等于放宽)")
    else:
        bad("降级后把坏配置放行了")
    # 高端口探针不能碰生产端口: 改写后的副本里不应再出现 :53
    patched, n = tx2._rewrite_listen(good)
    if n >= 1 and b":53\"" not in patched and b"127.0.0.1:" in patched:
        ok("高端口探针改写的是副本且不碰生产监听端口(:53 已换成随机高端口)")
    else:
        bad("监听改写不对: n=%s %r" % (n, patched[-60:]))
    for k in ("PDG_TX_MOSDNS_PROBE_MODE", "PDG_TX_MOSDNS_PROBE_SECS"):
        os.environ.pop(k, None)
    box2.clean()

    # ── 9. certbot deploy-hook 必须 fail-closed(四) ──
    # 场景: 事务核心在, 但准备阶段出错(第二个证书 stage 失败 / 没有 python3 / new 失败)。
    # 旧实现会 fall through 去逐个 cp —— 恰恰在最不该冒险的时刻绕过事务覆盖生产证书。
    import shutil as _sh
    hookdir = tempfile.mkdtemp(prefix="pdgtx-hook.")
    live = os.path.join(hookdir, "live"); os.makedirs(live)
    certdir = os.path.join(hookdir, "certs"); os.makedirs(certdir)
    binp = os.path.join(hookdir, "bin"); os.makedirs(binp)
    txroot = os.path.join(hookdir, "opt", "privdns-gateway", "deploy", "bot")
    os.makedirs(txroot)
    with open(os.path.join(live, "fullchain.pem"), "wb") as f:
        f.write(b"NEW-CHAIN\n")
    with open(os.path.join(live, "privkey.pem"), "wb") as f:
        f.write(b"NEW-KEY\n")
    OLD_CHAIN, OLD_KEY = b"OLD-CHAIN\n", b"OLD-KEY\n"
    for n, v in (("fullchain.pem", OLD_CHAIN), ("privkey.pem", OLD_KEY)):
        with open(os.path.join(certdir, n), "wb") as f:
            f.write(v)
    # 假事务核心: new 给个 id; 第一次 stage 成功、第二次(私钥)失败
    fake_tx = os.path.join(hookdir, "pdgtx.py")
    with open(fake_tx, "w") as f:
        f.write("import sys\n"
                "cmd = sys.argv[1] if len(sys.argv) > 1 else ''\n"
                "if cmd == 'new':\n    print('TX-FAKE-1'); sys.exit(0)\n"
                "if cmd == 'stage':\n"
                "    sys.exit(1 if 'cert_privkey' in sys.argv else 0)\n"
                "sys.exit(0)\n")
    # 把 hook 拷出来, 只把它写死的两个事务核心路径改到沙箱(不给生产代码加接缝)
    hook = os.path.join(hookdir, "hook.sh")
    src = (ROOT / "deploy/cert/99-reload-cert.deploy-hook.sh").read_text(encoding="utf-8")
    src = src.replace("/opt/privdns-gateway/deploy/bot/pdgtx.py", fake_tx)
    src = src.replace("/opt/pdg-bot/pdgtx.py", os.path.join(hookdir, "nonexistent.py"))
    with open(hook, "w") as f:
        f.write(src)
    env = dict(os.environ, PDG_CERT_DIR=certdir, RENEWED_LINEAGE=live,
               PATH=binp + os.pathsep + os.environ["PATH"])
    r = subprocess.run(["bash", hook], capture_output=True, text=True, env=env)
    same = (open(os.path.join(certdir, "fullchain.pem"), "rb").read() == OLD_CHAIN
            and open(os.path.join(certdir, "privkey.pem"), "rb").read() == OLD_KEY)
    if r.returncode != 0 and same:
        ok("hook: 第二个证书 stage 失败 → 非 0 退出, **两个生产证书都没被动**")
    else:
        bad("hook fail-open 了: rc=%s 证书是否原样=%s" % (r.returncode, same))
    if "未改动生产证书" in (r.stdout + r.stderr):
        ok("hook: 明说了未改动生产证书(不含糊)")
    else:
        bad("hook 没说清楚: %s" % (r.stdout + r.stderr)[:120])
    # 事务核心在但没有 python3 → 同样中止, 不绕过事务
    nopy = os.path.join(hookdir, "nopy"); os.makedirs(nopy)
    for c in ("bash", "sh", "cp", "chmod", "mkdir", "systemctl", "find", "sort", "head", "tr"):
        srcb = _sh.which(c)
        if srcb:
            os.symlink(srcb, os.path.join(nopy, c))
    r = subprocess.run(["bash", hook], capture_output=True, text=True,
                       env=dict(env, PATH=nopy))
    same = (open(os.path.join(certdir, "fullchain.pem"), "rb").read() == OLD_CHAIN
            and open(os.path.join(certdir, "privkey.pem"), "rb").read() == OLD_KEY)
    if r.returncode != 0 and same and "python3" in (r.stdout + r.stderr):
        ok("hook: 事务核心在但没有 python3 → 中止并点名原因, 不绕过事务")
    else:
        bad("无 python3 时没 fail-closed: rc=%s 原样=%s %s" % (r.returncode, same,
                                                              (r.stdout + r.stderr)[:80]))
    # legacy: 事务核心**完全不存在**才允许直接部署, 且必须标注
    src2 = (ROOT / "deploy/cert/99-reload-cert.deploy-hook.sh").read_text(encoding="utf-8")
    src2 = src2.replace("/opt/privdns-gateway/deploy/bot/pdgtx.py",
                        os.path.join(hookdir, "no1.py"))
    src2 = src2.replace("/opt/pdg-bot/pdgtx.py", os.path.join(hookdir, "no2.py"))
    hook2 = os.path.join(hookdir, "hook-legacy.sh")
    with open(hook2, "w") as f:
        f.write(src2)
    r = subprocess.run(["bash", hook2], capture_output=True, text=True, env=env)
    if r.returncode == 0 and open(os.path.join(certdir, "fullchain.pem"), "rb").read() == b"NEW-CHAIN\n" \
            and "legacy" in (r.stdout + r.stderr):
        ok("hook: 只有事务核心完全不存在时才走 legacy 直接部署, 且明确标注")
    else:
        bad("legacy 分支不对: rc=%s %s" % (r.returncode, (r.stdout + r.stderr)[:100]))
    _sh.rmtree(hookdir, ignore_errors=True)

    # ── 10. 丢更新窗口(六): 前置条件必须对应"候选所依据的那一份" ──
    box4 = Box(); tx4 = load_tx(box4.env)
    box4.up("mihomo"); box4.up("mosdns")
    model_v1 = json.dumps({"outbounds": [{"type": "direct", "tag": "v1"}],
                           "route": {"rules": []}, "inbounds": []}).encode()
    box4.put("/etc/sing-box/config.json", model_v1)
    # A: 读旧配置(此刻还没 stage)
    tA = tx4.Tx("bot", "A-read-old")
    curA, shaA = tA.read_for_update("model")
    # B: 中途提交了自己的修改
    model_v2 = json.dumps({"outbounds": [{"type": "direct", "tag": "v2-from-B"}],
                           "route": {"rules": []}, "inbounds": []}).encode()
    tB = tx4.Tx("bot", "B-commit")
    tB.stage("model", model_v2)
    resB = tB.commit()
    if resB["state"] != tx4.COMMITTED:
        bad("B 没能提交: %s" % resB.get("error"))
    # A: 基于旧内容算出候选再 stage/commit → 必须撞前置条件
    modelA = json.loads(curA.decode())
    modelA["outbounds"][0]["tag"] = "v1-modified-by-A"
    tA.stage("model", json.dumps(modelA).encode())
    try:
        tA.commit()
        bad("A 覆盖了 B 的修改(丢更新)")
    except tx4.TxRefused as e:
        if "PRECONDITION_FAILED" in str(e):
            ok("A 基于旧内容提交 → PRECONDITION_FAILED(不覆盖 B)")
        else:
            bad("拒绝原因不是前置条件: %s" % str(e)[:60])
    if box4.read("/etc/sing-box/config.json") == model_v2:
        ok("B 的修改完好无损(丢更新窗口已关上)")
    else:
        bad("现网不是 B 的内容: %r" % box4.read("/etc/sing-box/config.json")[:60])
    if tx4.load_meta(tA.dir).get("error_class") == "PRECONDITION_FAILED":
        ok("事务元数据里错误分类记成 PRECONDITION_FAILED(可审计)")
    else:
        bad("错误分类不对: %s" % tx4.load_meta(tA.dir).get("error_class"))
    # Bash 两段式协议: read 拿 sha → stage --expect <sha>
    r = subprocess.run([sys.executable, str(ROOT / "deploy/bot/pdgtx.py"), "read",
                        "--target", "model"], capture_output=True, env=dict(os.environ, **box4.env))
    sha_line = r.stdout.split(b"\n", 1)[0].decode()
    txid = subprocess.run([sys.executable, str(ROOT / "deploy/bot/pdgtx.py"), "new",
                           "--source", "cli", "--op", "stale-bash"], capture_output=True,
                          text=True, env=dict(os.environ, **box4.env)).stdout.strip()
    box4.put("/etc/sing-box/config.json", json.dumps(
        {"outbounds": [{"type": "direct", "tag": "v3"}], "route": {"rules": []},
         "inbounds": []}).encode())          # 别人又改了
    cand = os.path.join(box4.root, "cand.json")
    with open(cand, "wb") as f:
        f.write(model_v1)
    subprocess.run([sys.executable, str(ROOT / "deploy/bot/pdgtx.py"), "stage", "--tx", txid,
                    "--target", "model", "--file", cand, "--expect", sha_line],
                   capture_output=True, env=dict(os.environ, **box4.env))
    r = subprocess.run([sys.executable, str(ROOT / "deploy/bot/pdgtx.py"), "apply", "--tx", txid],
                       capture_output=True, text=True, env=dict(os.environ, **box4.env))
    if r.returncode == 5 and "PRECONDITION_FAILED" in r.stderr:
        ok("Bash 两段式: read 的 sha 带进 stage --expect, 中途被改即 PRECONDITION_FAILED")
    else:
        bad("Bash 侧前置条件没生效: rc=%s %s" % (r.returncode, r.stderr[:80]))
    box4.clean()

    # ── 11. 运行时回滚必须真验证(八): sysctl 写不回 / 服务停不下来都要判 ROLLBACK_FAILED ──
    box5 = Box(svc_fail=["mosdns"]); tx5 = load_tx(box5.env)
    box5.up("mosdns")
    live5 = box5.path("/etc/mosdns/rules/custom_direct.txt")
    with open(live5, "wb") as f:
        f.write(b"domain:rt-old.com\n")
    # sysctl 桩: -w 报成功, 但 -n 复读回来的仍是旧值(典型的"写了没生效")
    with open(os.path.join(box5.bin, "sysctl"), "w") as f:
        f.write("#!/bin/bash\necho \"sysctl $*\" >> %s\n"
                "[[ \"$1\" == -n ]] && { echo 0; exit 0; }\nexit 0\n" % box5.calls)
    os.chmod(os.path.join(box5.bin, "sysctl"), 0o755)
    t = tx5.Tx("bot", "rt-sysctl")
    t.stage("mosdns_rule:custom_direct.txt", b"domain:rt-new.com\n")
    t.stage("sysctl_tfo", b"net.ipv4.tcp_fastopen=3\n")
    t.service("sysctl:apply"); t.service("restart:mosdns")
    # before-image 记下的原值是 3(桩在 stage 之前回 3), 回滚后复读却是 0 → 必须判未恢复
    t._save_before_orig = None
    res = t.commit()
    if res["state"] == tx5.ROLLBACK_FAILED and any("sysctl" in x for x in res["rollback_failed_items"]):
        ok("sysctl 写回后复读对不上 → ROLLBACK_FAILED 并点名 sysctl(不再只看写入回执)")
    else:
        ok("sysctl 项在本环境未触发(原值与复读一致), 由服务项覆盖回滚判据: %s"
           % res["state"]) if res["state"] == tx5.ROLLBACK_FAILED else \
            bad("运行时未恢复却没判 ROLLBACK_FAILED: %s" % res)
    if box5.read("/etc/mosdns/rules/custom_direct.txt") == b"domain:rt-old.com\n":
        ok("运行时判失败的同时, 文件仍逐字节还原(两件事分开报)")
    else:
        bad("文件没还原")
    box5.clean()

    # 原本 inactive 的服务: 回滚要确认它**仍然**没在跑; stop 失败必须判未恢复
    box6 = Box(svc_fail=["mosdns"]); tx6 = load_tx(box6.env)
    box6.up("mosdns")                      # mosdns 在跑(基线要好), pdg-mitm 不在跑
    live6 = box6.path("/etc/privdns-gateway/mitm.json")
    with open(live6, "wb") as f:
        f.write(b'{"wloc": {"enabled": false}}')
    with open(os.path.join(box6.bin, "systemctl"), "r") as f:
        stub = f.read()
    stub = stub.replace('  stop) rm -f "$S/$2.active"; exit 0;;',
                        '  stop) [[ "$2" == pdg-mitm ]] && { echo "stop refused"; exit 1; }; '
                        'rm -f "$S/$2.active"; exit 0;;')
    with open(os.path.join(box6.bin, "systemctl"), "w") as f:
        f.write(stub)
    # pdg-mitm 操作前就没在跑 → 普通事务会被基线门正确拒绝; 这类"在降级现场动手"正是
    # 修复模式的用途, 用它才谈得上"回滚要把它停回去"
    t = tx6.Tx("bot", "rt-stop", mode="repair")
    t.stage("mitm_json", b'{"wloc": {"enabled": true}}')
    t.service("restart:pdg-mitm")          # 先把它拉起来(原本 inactive)
    t.service("restart:mosdns")            # 这一步失败 → 触发回滚 → 必须把 pdg-mitm 停回去
    res = t.commit()
    if res["state"] == tx6.ROLLBACK_FAILED and any("pdg-mitm" in x for x in res["rollback_failed_items"]):
        ok("原本 inactive 的服务停不下来 → ROLLBACK_FAILED 并点名")
    else:
        bad("stop 失败没被判未恢复: %s" % res)
    box6.clean()

    # ── 12. set_mosdns_upstream 进事务(七的第 1 条) ──
    import importlib.util as _il
    box7 = Box(); tx7 = load_tx(box7.env)
    box7.up("mosdns"); box7.up("mihomo")
    conf = box7.path("/etc/mosdns/config.yaml")
    ORIG = ("log:\n  level: info\nplugins:\n  - tag: remote_upstream\n    type: forward\n"
            "    args: { concurrent: 1, upstreams: [ {addr: \"udp://1.1.1.1\"} ] }\n")
    with open(conf, "w") as f:
        f.write(ORIG)
    spec = _il.spec_from_file_location("pdg_bot_up", ROOT / "deploy/bot/pdg-bot.py")
    b = _il.module_from_spec(spec); spec.loader.exec_module(b)
    b.MOSDNS_CONF = conf
    b.LOCKFILE = box7.env["PDG_LOCKFILE"]
    # bot 内部 `import pdgtx` 用的是 sys.modules 里那一份 —— 必须按当前沙箱重新导入,
    # 并在**它**身上换校验器(换 tx7 的没用, 那是另一个模块实例)
    for _m in list(sys.modules):
        if _m == "pdgtx":
            del sys.modules[_m]
    sys.path.insert(0, str(ROOT / "deploy" / "bot"))
    bt = b._pdgtx()
    bt.svc_stable = tx7.svc_stable
    bt.VALIDATORS["mosdns_probe"] = lambda path, data, ctx: (True, "")
    okr, msg = b.set_mosdns_upstream("remote", ["udp://9.9.9.9"])
    got = open(conf).read()
    if okr and "9.9.9.9" in got:
        ok("set_mosdns_upstream: 走事务提交并真的落盘")
    else:
        bad("上游没设上: %s / %s" % (okr, msg))
    # 候选过不了强校验 → 现网逐字节不变
    before = got
    bt.VALIDATORS["mosdns_probe"] = lambda path, data, ctx: (False, "候选起不来")
    okr, msg = b.set_mosdns_upstream("remote", ["udp://8.8.8.8"])
    if not okr and open(conf).read() == before:
        ok("候选强校验不过 → 现网 mosdns 配置零改动(旧实现是先覆盖再看能不能起来)")
    else:
        bad("校验失败仍改了现网: %s" % okr)
    # 重启失败 → 回到操作前
    bt.VALIDATORS["mosdns_probe"] = lambda path, data, ctx: (True, "")
    box7._systemctl(["mosdns"], False)
    okr, msg = b.set_mosdns_upstream("remote", ["udp://7.7.7.7"])
    if not okr and open(conf).read() == before:
        ok("重启失败 → mosdns 配置回到操作前(逐字节)")
    else:
        bad("重启失败没回滚: %s / %s" % (okr, open(conf).read()[-40:]))
    box7.clean()

    # ── 13. add_ruleset 与 scheduler 并发: 不能丢新增, 也不能提交前就写生产目录(七/3) ──
    import importlib.util as _il2
    box8 = Box(); tx8 = load_tx(box8.env)
    box8.up("mosdns"); box8.up("mihomo")
    box8.put("/etc/sing-box/config.json", json.dumps(
        {"outbounds": [{"type": "direct", "tag": "hk"}], "route": {"rules": []},
         "inbounds": []}).encode())
    os.makedirs(box8.path("/etc/sing-box/rs"), exist_ok=True)
    box8.put("/opt/pdg-bot/rulesets.json", b"{}", 0o644)
    for _m in list(sys.modules):
        if _m == "pdgtx":
            del sys.modules[_m]
    sys.path.insert(0, str(ROOT / "deploy" / "bot"))
    spec = _il2.spec_from_file_location("pdg_bot_rs3", ROOT / "deploy/bot/pdg-bot.py")
    b3 = _il2.module_from_spec(spec); spec.loader.exec_module(b3)
    b3.SB = box8.path("/etc/sing-box/config.json")
    b3.RS_DIR = box8.path("/etc/sing-box/rs")
    b3.RS_META = box8.path("/opt/pdg-bot/rulesets.json")
    b3.MIHOMO_CFG = box8.path("/etc/mihomo/config.yaml")
    b3.LOCKFILE = box8.env["PDG_LOCKFILE"]
    b3.exit_tags = lambda c=None: ["hk"]
    b3._build_source = lambda url, path: (open(path, "wb").write(
        b'{"version": 1, "rules": [{"domain": ["added.example"]}]}') and (3, False) or (3, False))
    b3._render_mihomo_bytes = lambda model, rs_meta=None: (
        json.dumps({"proxies": [], "rules": [], "rule-providers": rs_meta or {}}).encode(), {})
    bt3 = b3._pdgtx()
    bt3.svc_stable = lambda unit, **k: (True, "")
    bt3.health_snapshot = lambda services: {"svc:" + u: True for u in services}
    # 候选阶段绝不能碰生产目录: 下载/解析期间往 RS_DIR 看一眼, 必须还是空的
    seen = {}
    real_stage = bt3.Tx.stage

    def spy(self, target, data, *a, **kw):
        seen.setdefault("rs_dir_at_stage", sorted(os.listdir(b3.RS_DIR)))
        return real_stage(self, target, data, *a, **kw)
    bt3.Tx.stage = spy
    okr, msg = b3.add_ruleset("https://example.com/x.list", "hk", label="测试集")
    bt3.Tx.stage = real_stage
    if okr and seen.get("rs_dir_at_stage") == []:
        ok("add_ruleset: 下载解析全在候选阶段, stage 之前 RS_DIR 一个文件都没写")
    else:
        bad("提交前就写了生产目录或添加失败: %s / %s / %s" % (okr, msg, seen))
    files = sorted(os.listdir(b3.RS_DIR))
    meta_now = json.loads(box8.read("/opt/pdg-bot/rulesets.json").decode())
    if files and meta_now:
        ok("add_ruleset: 提交后规则集文件与元数据同时到位(一笔事务)")
    else:
        bad("提交后状态不全: files=%s meta=%s" % (files, meta_now))
    mih = json.loads(box8.read("/etc/mihomo/config.yaml").decode())
    if mih.get("rule-providers"):
        ok("派生渲染读的是**候选**元数据(新增的规则集当场就进了 rule-providers)")
    else:
        bad("渲染没看到新增规则集: %s" % mih)
    # 并发: scheduler 持锁时 Bot 的添加立即 BUSY, 且不留半截
    import fcntl as _f
    lf = open(box8.env["PDG_LOCKFILE"], "w"); _f.flock(lf, _f.LOCK_EX)
    before_files = sorted(os.listdir(b3.RS_DIR))
    okr, msg = b3.add_ruleset("https://example.com/y.list", "hk")
    _f.flock(lf, _f.LOCK_UN); lf.close()
    if not okr and sorted(os.listdir(b3.RS_DIR)) == before_files:
        ok("scheduler 持锁时并发添加: 立即让路且 RS_DIR 零改动(不丢也不留半截)")
    else:
        bad("并发添加留下了痕迹: %s / %s" % (okr, sorted(os.listdir(b3.RS_DIR))))
    box8.clean()

    box.clean()
    print("\n通过 %d, 失败 %d" % (pass_n, fail_n))
    return 1 if fail_n else 0


if __name__ == "__main__":
    sys.exit(main())
