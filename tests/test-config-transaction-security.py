#!/usr/bin/env python3
"""事务核心的安全边界: 路径白名单 / 链接攻击 / 权限 / 凭据脱敏 / 跨事务恢复隔离。

凭据这部分用一个**哨兵串**贯穿全链路: 把它塞进 model、私钥、日志里, 然后翻遍事务元数据、
审计、diff、stdout/stderr 与回给用户(Telegram)的文案 —— 一处出现就算失败。
"""
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
from txbox import Box, load_tx  # noqa: E402

pass_n = 0
fail_n = 0

# 哨兵: 形态覆盖 token / UUID / 节点链接 / 密码字段 / 私钥
SENTINEL_TOKEN = "123456789:AAErdxSENTINELtokenZZZZZZZZZZZZZZZZZZZZZ"
SENTINEL_UUID = "deadbeef-1234-5678-9abc-def012345678"
SENTINEL_LINK = "vmess://SENTINELlinkPAYLOAD=="
SENTINEL_PW = "S3cretSENTINELpassword"
SENTINELS = (SENTINEL_TOKEN, SENTINEL_UUID, SENTINEL_LINK, SENTINEL_PW, "SENTINEL")


def ok(m):
    global pass_n
    print("[OK]   %s" % m); pass_n += 1


def bad(m):
    global fail_n
    print("[FAIL] %s" % m); fail_n += 1


def scan(text, where):
    hit = [s for s in SENTINELS if s in (text or "")]
    if hit:
        bad("%s 里出现了凭据哨兵: %s" % (where, hit[:2]))
        return False
    return True


def main():
    box = Box(); tx = load_tx(box.env)
    box.up("mihomo"); box.up("mosdns")

    # ── 1. 路径白名单: 各种越界写法一律拒绝 ──
    for name in ("../../../etc/shadow", "/etc/passwd", "mosdns_rule:../../etc/passwd",
                 "mosdns_rule:/etc/passwd", "mosdns_rule:.hidden.txt", "ruleset:../x.json",
                 "ruleset:a/b.json", "unit:../../etc/passwd.service", "unit:x.sh",
                 "model/../../etc/shadow", "", "mosdns_rule:", "ruleset:.."):
        try:
            tx.resolve_target(name)
            bad("白名单没挡住: %r" % name)
            break
        except tx.TxError:
            continue
    else:
        ok("路径白名单挡掉 ../ / 绝对路径 / 子目录 / 隐藏文件 / 非法后缀 / 空名")

    # 解析出来的路径必须落在沙箱根内(不会因为拼接逃出去)
    escaped = []
    for name in ("model", "mosdns_rule:custom_hijack.txt", "ruleset:a.json", "unit:x.service"):
        path = os.path.realpath(tx.resolve_target(name)[0])
        if not path.startswith(os.path.realpath(box.root) + os.sep):
            escaped.append(name)
    if escaped:
        bad("这些目标解析到了根之外: %s" % escaped)
    else:
        ok("合法目标解析后仍在预期根内(realpath 复核)")

    # ── 2. 符号链接: 目标是软链 → 拒绝写(不能穿透到别处) ──
    victim = os.path.join(box.root, "victim.txt")
    with open(victim, "wb") as f:
        f.write(b"DO-NOT-TOUCH\n")
    link = box.path("/etc/mosdns/rules/custom_direct.txt")
    if os.path.exists(link):
        os.unlink(link)
    os.symlink(victim, link)
    t = tx.Tx("test", "symlink")
    try:
        t.stage("mosdns_rule:custom_direct.txt", b"domain:evil.com\n")
        bad("软链目标没被拒绝")
    except tx.TxError as e:
        if open(victim, "rb").read() == b"DO-NOT-TOUCH\n":
            ok("目标是符号链接 → 拒绝写入, 链接指向的文件毫发无损")
        else:
            bad("软链目标内容被改了")
    os.unlink(link)

    # ── 3. 硬链接: nlink>1 → 拒绝(不能借别人的 inode 改内容) ──
    hard = box.path("/etc/mosdns/rules/custom_hijack.txt")
    with open(hard, "wb") as f:
        f.write(b"domain:keep.com\n")
    peer = os.path.join(box.root, "peer.txt")
    os.link(hard, peer)
    t = tx.Tx("test", "hardlink")
    try:
        t.stage("mosdns_rule:custom_hijack.txt", b"domain:evil.com\n")
        bad("硬链接目标没被拒绝")
    except tx.TxError:
        ok("目标是硬链接(nlink>1)→ 拒绝写入")
    os.unlink(peer)

    # ── 4. 事务目录与材料权限 ──
    box.put("/etc/sing-box/config.json", json.dumps(
        {"outbounds": [], "route": {"rules": []}, "inbounds": []}).encode())
    t = tx.Tx("test", "perm")
    t.stage("mosdns_rule:custom_hijack.txt", b"domain:a.com\n")
    st = os.stat(t.dir)
    if st.st_mode & 0o777 == 0o700:
        ok("事务目录 0700")
    else:
        bad("事务目录权限 %o" % (st.st_mode & 0o777))
    cand = os.path.join(t.dir, "candidate")
    modes = {oct(os.stat(os.path.join(cand, f)).st_mode & 0o777) for f in os.listdir(cand)}
    if modes <= {"0o600"}:
        ok("候选文件 0600(含凭据的目标不会以宽权限躺在盘上)")
    else:
        bad("候选文件权限 %s" % modes)
    meta_mode = os.stat(os.path.join(t.dir, "meta.json")).st_mode & 0o777
    if meta_mode == 0o600:
        ok("meta.json 0600")
    else:
        bad("meta.json 权限 %o" % meta_mode)

    # ── 5. 凭据脱敏: 全链路都不许出现哨兵 ──
    model = {"outbounds": [{"type": "vmess", "tag": "x", "server": "1.2.3.4",
                            "server_port": 443, "uuid": SENTINEL_UUID,
                            "password": SENTINEL_PW}],
             "route": {"rules": []}, "inbounds": [],
             "experimental": {"clash_api": {"secret": SENTINEL_TOKEN}}}
    t = tx.Tx("test", "secrets")
    t.stage("model", json.dumps(model).encode())
    t.stage("cert_privkey", ("-----BEGIN PRIVATE KEY-----\n%s\n-----END PRIVATE KEY-----\n"
                            % SENTINEL_PW).encode())
    t.warn("下载 %s 失败" % SENTINEL_LINK)
    t.service("restart:mihomo")
    res = t.commit()
    if res["state"] != tx.COMMITTED:
        bad("含凭据的事务没提交成功: %s" % res.get("error"))
    meta_txt = open(os.path.join(t.dir, "meta.json"), encoding="utf-8").read()
    scan(meta_txt, "meta.json") and ok("meta.json 脱敏(token/uuid/密码/链接都不在)")
    diff_txt = open(os.path.join(t.dir, "diff.txt"), encoding="utf-8").read()
    scan(diff_txt, "diff.txt") and ok("diff.txt 脱敏(只讲键名与大小, 不含值)")
    audit_txt = open(os.path.join(box.env["PDG_TX_ROOT"], "index.jsonl"), encoding="utf-8").read()
    scan(audit_txt, "审计") and ok("审计记录脱敏")
    scan(json.dumps(res, ensure_ascii=False), "返回给调用方(Telegram)的结果") and \
        ok("回给用户的事务结果脱敏(Bot 文案直接用它)")
    if not os.path.exists(os.path.join(t.dir, "candidate")):
        ok("提交后含凭据的候选/before 材料已删除(只留脱敏元数据)")
    else:
        bad("提交后仍留着候选材料")

    # 子进程 stdout/stderr 也不许漏
    r = subprocess.run([sys.executable, str(ROOT / "deploy/bot/pdgtx.py"), "list", "--limit", "50"],
                       capture_output=True, text=True, env=dict(os.environ, **box.env))
    scan(r.stdout + r.stderr, "pdgtx list 输出") and ok("CLI 列表输出脱敏")

    # redact 本身: 各种形态都能打掉
    for s in (SENTINEL_TOKEN, SENTINEL_UUID, SENTINEL_LINK,
              'password: "%s"' % SENTINEL_PW, "secret=%s" % SENTINEL_TOKEN):
        if any(x in tx.redact(s) for x in (SENTINEL_TOKEN, SENTINEL_UUID, SENTINEL_LINK,
                                           SENTINEL_PW)):
            bad("redact 漏掉了: %r → %r" % (s[:30], tx.redact(s)[:40]))
            break
    else:
        ok("redact 覆盖 token / uuid / 节点链接 / password= / secret= 五种形态")

    # ── 6. 跨事务恢复隔离: 不能拿另一笔事务的 before-image 去覆盖 ──
    live = box.path("/etc/mosdns/rules/custom_direct.txt")
    with open(live, "wb") as f:
        f.write(b"domain:v1.com\n")
    t1 = tx.Tx("test", "first")
    t1.stage("mosdns_rule:custom_direct.txt", b"domain:v2.com\n")
    t1.commit()
    t2 = tx.Tx("test", "second")
    t2.stage("mosdns_rule:custom_direct.txt", b"domain:v3.com\n")
    t2.commit()
    r1 = tx.recover(t1.txid)
    if not r1.get("ok") and ("终态" in (r1.get("note") or "") or r1.get("error")):
        ok("已终结的事务不能被再次 recover(不会拿旧 before-image 盖掉后来的改动)")
    elif r1.get("note"):
        ok("已终结的事务 recover 是幂等空操作: %s" % r1["note"][:30])
    else:
        bad("旧事务被重放了: %s / 现网=%r" % (r1, open(live, "rb").read()))
    if open(live, "rb").read() == b"domain:v3.com\n":
        ok("现网仍是最后一笔事务的结果(没被前一笔的 before-image 覆盖)")
    else:
        bad("现网被旧事务覆盖成 %r" % open(live, "rb").read())

    # ── 7. recover 的漂移保护: 事务外被人手工改过 → 默认停手 ──
    box2 = Box(); tx2 = load_tx(box2.env)
    box2.up("mosdns")
    live2 = box2.path("/etc/mosdns/rules/custom_direct.txt")
    with open(live2, "wb") as f:
        f.write(b"domain:before.com\n")
    t = tx2.Tx("test", "drifty")
    t.stage("mosdns_rule:custom_direct.txt", b"domain:applied.com\n")
    t._save_meta()
    # 模拟"应用到一半断电": 手工把状态推到 APPLYING 并留下 before-image
    t.meta["targets"] = ["mosdns_rule:custom_direct.txt"]
    t._set_state(tx2.VALIDATED)
    t._save_before(["mosdns"])
    t._set_state(tx2.APPLYING)
    with open(live2, "wb") as f:
        f.write(b"domain:hand-fixed.com\n")        # 运维手工救场
    r = tx2.recover(t.txid)
    if not r.get("ok") and r.get("conflicts") and open(live2, "rb").read() == b"domain:hand-fixed.com\n":
        ok("recover 漂移保护: 事务外被改过 → 报冲突并**不覆盖**人工修复")
    else:
        bad("漂移保护失效: %s / 现网=%r" % (r, open(live2, "rb").read()))
    r = tx2.recover(t.txid, force=True)
    if r.get("ok") and open(live2, "rb").read() == b"domain:before.com\n":
        ok("显式 --force 才会用 before-image 覆盖(命令行专用, 不给 Telegram)")
    else:
        bad("force 恢复没生效: %s" % r)

    # ── 8. schema 不兼容 → 拒绝自动恢复 ──
    t = tx2.Tx("test", "schema")
    t.stage("mosdns_rule:custom_direct.txt", b"domain:z.com\n")
    t.meta["targets"] = ["mosdns_rule:custom_direct.txt"]
    t._set_state(tx2.VALIDATED); t._save_before(["mosdns"]); t._set_state(tx2.APPLYING)
    m = json.load(open(os.path.join(t.dir, "meta.json")))
    m["schema_version"] = 999
    tx2.atomic_write(os.path.join(t.dir, "meta.json"), json.dumps(m).encode(), 0o600)
    r = tx2.recover(t.txid)
    if not r.get("ok") and "schema" in (r.get("error") or ""):
        ok("事务 schema 版本不兼容 → 拒绝自动恢复(不拿新语义去还原旧语义写下的东西)")
    else:
        bad("schema 不兼容没拦住: %s" % r)

    box.clean(); box2.clean()
    print("\n通过 %d, 失败 %d" % (pass_n, fail_n))
    return 1 if fail_n else 0


if __name__ == "__main__":
    sys.exit(main())
