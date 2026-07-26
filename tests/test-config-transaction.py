#!/usr/bin/env python3
"""统一配置事务核心(5.1)回归: 状态机 / 白名单 / 前置检查 / 原子落盘 / 观察 / 回滚 / 审计。

全部是**行为测试**: 在沙箱文件树(PDG_TX_FSROOT)里真跑一遍事务, 用假的 systemctl / nft /
mihomo 充当"外部世界"(桩会把每次调用记进日志, 也能按需装成失败), 断言的是磁盘与状态的真实
结果, 不是源码里有没有某个字符串。
"""
import importlib.util
import json
import os
import socket
import threading
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
pass_n = 0
fail_n = 0


def ok(m):
    global pass_n
    print("[OK]   %s" % m); pass_n += 1


def bad(m):
    global fail_n
    print("[FAIL] %s" % m); fail_n += 1


def load_tx(env):
    """按给定环境变量加载事务核心(模块级常量会读环境, 故每个沙箱重新导入一次)。"""
    for k, v in env.items():
        os.environ[k] = v
    spec = importlib.util.spec_from_file_location("pdgtx_%d" % time.time_ns(),
                                                  ROOT / "deploy/bot/pdgtx.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class Box:
    """一次性沙箱: 假文件树 + 假 systemctl/nft/mihomo/mosdns/sysctl。"""

    def __init__(self, svc_fail=None, restart_crash=False, healthy=True):
        self.root = tempfile.mkdtemp(prefix="pdgtx-box.")
        self.bin = os.path.join(self.root, "stub-bin")
        os.makedirs(self.bin)
        self.calls = os.path.join(self.root, "calls.log")
        self.state = os.path.join(self.root, "svcstate")
        os.makedirs(self.state)
        self._systemctl(svc_fail or [], restart_crash)
        self._simple("nft", 0)
        self._simple("mihomo", 0)
        self._simple("sysctl", 0)
        self._simple("openssl", 0)
        for d in ("/etc/sing-box/rs", "/etc/mosdns/rules", "/etc/mihomo",
                  "/etc/privdns-gateway", "/opt/pdg-bot", "/run", "/etc/systemd/system"):
            os.makedirs(self.root + d, exist_ok=True)
        # 硬门探针的真实落点: 一个真 UDP DNS 应答器 + 一个真 TCP 监听。
        # 判据没有被关掉 —— 把它们停掉, 健康检查就会真的判失败(见"退化"用例)。
        self._probes = []
        self.dns_port = self._start_dns() if healthy else 1
        self.redir_port = self._start_tcp() if healthy else 1
        self.env = {
            "PDG_TX_DNS_PROBE": "127.0.0.1:%d" % self.dns_port,
            "PDG_TX_REDIR_PORT": str(self.redir_port),
            "PDG_TX_FSROOT": self.root,
            "PDG_TX_ROOT": self.root + "/var/lib/privdns-gateway/tx",
            "PDG_LOCKFILE": self.root + "/run/privdns-gateway.lock",
            "PDG_STABLE_SAMPLES": "1",
            "PATH": self.bin + os.pathsep + os.environ["PATH"],
        }

    def _start_dns(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        self._probes.append(s)
        def loop():
            while True:
                try:
                    data, addr = s.recvfrom(512)
                except OSError:
                    return
                try:
                    s.sendto(data[:2] + b"\x81\x83" + data[4:12], addr)   # 回一个 NXDOMAIN
                except OSError:
                    return
        threading.Thread(target=loop, daemon=True).start()
        return port

    def _start_tcp(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0)); s.listen(8)
        port = s.getsockname()[1]
        self._probes.append(s)
        def loop():
            while True:
                try:
                    c, _ = s.accept(); c.close()
                except OSError:
                    return
        threading.Thread(target=loop, daemon=True).start()
        return port

    def stop_probes(self):
        for s in self._probes:
            try:
                s.close()
            except OSError:
                pass
        self._probes = []

    def _write(self, name, body):
        p = os.path.join(self.bin, name)
        with open(p, "w") as f:
            f.write(body)
        os.chmod(p, 0o755)

    def _systemctl(self, fail_units, crash):
        # is-active 读 <state>/<unit>; restart 写 active(或按 fail 列表失败)。
        # crash=True 时模拟"坏配置起来即崩": restart 时看 config.json 里有没有 CRASH_MARK ——
        # 有就进入崩溃循环(NRestarts 每问一次涨一次), 换回旧配置再 restart 就恢复正常。
        # 这样回滚是否**真的解决问题**才有意义, 而不是让桩无条件永远崩。
        self._write("systemctl", """#!/bin/bash
echo "systemctl $*" >> %s
S=%s
case "$1" in
  is-active) [[ -f "$S/$2.active" ]] && { echo active; exit 0; }; echo inactive; exit 3;;
  show)  # show -p PROP --value UNIT
    U="${!#}"; P="$3"; [[ "$2" != "-p" ]] && P="$2"
    case "$P" in
      NRestarts) n=$(cat "$S/$U.nr" 2>/dev/null || echo 0)
                 if [[ -f "$S/$U.crash" ]]; then n=$((n+1)); echo $n > "$S/$U.nr"; fi
                 echo "$n";;
      UnitFileState) echo enabled;;
      LoadState) echo loaded;;
      *) echo "";;
    esac; exit 0;;
  restart)
    for f in %s; do [[ "$2" == "$f" ]] && { echo "restart refused"; exit 1; }; done
    touch "$S/$2.active"; %s
    exit 0;;
  stop) rm -f "$S/$2.active"; exit 0;;
  reset-failed|daemon-reload|enable|disable) exit 0;;
esac
exit 0
""" % (self.calls, self.state, " ".join(fail_units) or "__none__",
        ('if grep -q CRASHME %s/etc/sing-box/config.json 2>/dev/null; '
         'then touch "$S/$2.crash"; else rm -f "$S/$2.crash" "$S/$2.nr"; fi' % self.root)
        if crash else ":"))

    def _simple(self, name, rc):
        self._write(name, '#!/bin/bash\necho "%s $*" >> %s\nexit %d\n' % (name, self.calls, rc))

    def fail_cmd(self, name):
        self._simple(name, 1)

    def up(self, unit):
        open(os.path.join(self.state, unit + ".active"), "w").close()

    def path(self, rel):
        return self.root + rel

    def put(self, rel, data, mode=0o600):
        p = self.path(rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(data if isinstance(data, bytes) else data.encode())
        os.chmod(p, mode)
        return p

    def read(self, rel):
        try:
            with open(self.path(rel), "rb") as f:
                return f.read()
        except OSError:
            return None

    def clean(self):
        self.stop_probes()
        shutil.rmtree(self.root, ignore_errors=True)


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

    box.clean()
    print("\n通过 %d, 失败 %d" % (pass_n, fail_n))
    return 1 if fail_n else 0


if __name__ == "__main__":
    sys.exit(main())
