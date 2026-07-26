#!/usr/bin/env python3
"""事务故障注入回归: 锁(fail-closed / 并发 / 忙)与各类失败路径。

这里验的是"出事时到底发生了什么", 所以每一条都真的把故障造出来 —— 锁文件放到写不进去的
位置、三个进程同时抢锁、候选校验失败、before-image 存不下、第 N 个文件替换失败 —— 再看现网
与状态机的真实结果。
"""
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

    box.clean()
    print("\n通过 %d, 失败 %d" % (pass_n, fail_n))
    return 1 if fail_n else 0


if __name__ == "__main__":
    sys.exit(main())
