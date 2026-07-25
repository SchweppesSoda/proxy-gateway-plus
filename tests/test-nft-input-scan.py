#!/usr/bin/env python3
"""nftables input base chain 冲突扫描回归(nftscan.py / pdg.sh 前置门 / doctor)。

两件事要成立:
  ① **判据单一来源**: 迁移前置门(pdg.sh)与自检(doctor)必须用同一份实现 ——
     两处各写一遍正则迟早会漂移, 一边判冲突一边判干净比都不判还糟;
  ② **"读不到"绝不能当成"没有"**: `nft list ruleset` 失败(非 root / nft 不可用)时,
     内存里的冲突链根本没进视野。旧实现把它静默当成现场干净, 于是迁移照走 ——
     配置文本保留、端口实际不通的老毛病换个入口又回来了。

用真实 nftables 配置文本断言, 不 mock 解析逻辑本身。
"""
import importlib.util
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NFTSCAN = ROOT / "deploy/bot/nftscan.py"

spec = importlib.util.spec_from_file_location("nftscan", NFTSCAN)
nftscan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(nftscan)

pass_n = 0


def ok(msg):
    global pass_n
    print("[OK]  ", msg); pass_n += 1


# ── 真实形态的 nftables 配置文本 ───────────────────────────────────────────────
CONF_FOREIGN = """#!/usr/sbin/nft -f
flush ruleset
table inet filter {
  chain input {
    type filter hook input priority 0; policy accept;
    ct state established,related accept
    tcp dport 9443 accept
  }
  chain forward {
    type filter hook forward priority 0; policy accept;
  }
}
table inet pdg {
  chain input {
    type filter hook input priority 0; policy drop;
    ip saddr 172.22.0.0/16 tcp dport { 53, 80, 443, 853 } accept
  }
}
"""

CONF_CLEAN = """#!/usr/sbin/nft -f
flush ruleset
table ip nat {
  chain prerouting {
    type nat hook prerouting priority -100; policy accept;
    ip saddr 172.22.0.0/16 tcp dport { 80, 443 } redirect to :7893
  }
  chain postrouting {
    type nat hook postrouting priority 100; policy accept;
    oifname "eth0" masquerade
  }
}
table inet wg {
  chain fwd {
    type filter hook forward priority 0; policy accept;
    iifname "wg0" accept
  }
}
table inet pdg {
  chain input {
    type filter hook input priority 0; policy drop;
    ip saddr 172.22.0.0/16 tcp dport { 53, 80, 443 } accept
  }
}
"""

LIVE_FOREIGN = """table inet pdg {
	chain input {
		type filter hook input priority filter; policy drop;
	}
}
table inet ufw {
	chain before-input {
		type filter hook input priority filter - 10; policy accept;
		tcp dport 51820 accept
	}
}
"""


def main():
    # ── 1. 解析: 配置文件里的外部 input 链 ──
    f = nftscan.scan_text(CONF_FOREIGN, "")
    assert len(f) == 1 and "inet filter" in f[0] and "配置文件" in f[0], f
    ok("配置文件里 table inet filter 的 input 链被认出")

    # ── 2. 只有 pdg 自己 + NAT/forward 表 → 不误报 ──
    assert nftscan.scan_text(CONF_CLEAN, "") == [], nftscan.scan_text(CONF_CLEAN, "")
    ok("NAT(prerouting/postrouting) 与 forward 表不误报")

    # ── 3. 只存在于运行 ruleset(配置文件里没有)也要认出 ──
    f = nftscan.scan_text(CONF_CLEAN, LIVE_FOREIGN)
    assert len(f) == 1 and "inet ufw" in f[0] and "运行 ruleset" in f[0], f
    ok("只在内存里的冲突链(运行 ruleset)也被认出")

    # ── 4. 两边都有 → 各报一条, 不重复 ──
    f = nftscan.scan_text(CONF_FOREIGN, LIVE_FOREIGN)
    assert len(f) == 2 and len(set(f)) == 2, f
    ok("配置文件与运行 ruleset 各报一条, 已去重")

    # ── 5. live_ruleset: 读不到必须 readable=False, 不能与"读到了且干净"混为一谈 ──
    with tempfile.TemporaryDirectory() as tmp:
        # (a) nft 返回非 0(权限不足的真实形态: Operation not permitted)
        nft = os.path.join(tmp, "nft")
        with open(nft, "w") as fh:
            fh.write("#!/bin/sh\necho 'Error: Could not process rule: Operation not permitted' >&2\nexit 1\n")
        os.chmod(nft, 0o755)
        env_path = tmp + os.pathsep + os.environ["PATH"]
        old = os.environ["PATH"]; os.environ["PATH"] = env_path
        try:
            txt, readable = nftscan.live_ruleset()
            assert readable is False, "nft 非 0 退出必须判为读不到"
            ok("nft 返回非 0(权限不足)→ readable=False")

            # (b) nft 根本不存在
            os.environ["PATH"] = tmp                     # 目录里只有上面那个 nft
            os.remove(nft)
            txt, readable = nftscan.live_ruleset()
            assert readable is False, "nft 不存在必须判为读不到"
            ok("nft 不存在 → readable=False")

            # (c) 正常返回 → readable=True, 内容原样带回
            os.environ["PATH"] = env_path                 # 桩里要用 cat, 把系统 PATH 接回来
            with open(nft, "w") as fh:
                fh.write("#!/bin/sh\ncat <<'E'\n" + LIVE_FOREIGN + "E\n")
            os.chmod(nft, 0o755)
            txt, readable = nftscan.live_ruleset()
            assert readable is True and "inet ufw" in txt
            ok("nft 正常 → readable=True 且内容带回")
        finally:
            os.environ["PATH"] = old

    # ── 6. CLI 退出码: 0=有冲突 1=确认干净 2=无法确认 ──
    with tempfile.TemporaryDirectory() as tmp:
        conf = os.path.join(tmp, "nftables.conf")
        bindir = os.path.join(tmp, "bin"); os.makedirs(bindir)
        nft = os.path.join(bindir, "nft")

        def run(conf_text, nft_script):
            with open(conf, "w") as fh:
                fh.write(conf_text)
            with open(nft, "w") as fh:
                fh.write(nft_script)
            os.chmod(nft, 0o755)
            env = dict(os.environ, PATH=bindir)
            return subprocess.run([sys.executable, str(NFTSCAN), conf],
                                  capture_output=True, text=True, env=env)

        NFT_OK = "#!/bin/sh\nexit 0\n"                       # 读得到, 内存里没规则
        NFT_DENY = "#!/bin/sh\necho denied >&2\nexit 1\n"    # 读不到

        r = run(CONF_FOREIGN, NFT_OK)
        assert r.returncode == 0 and "inet filter" in r.stdout, (r.returncode, r.stdout)
        ok("CLI: 有冲突 → 退出 0 并打印冲突表")

        r = run(CONF_CLEAN, NFT_OK)
        assert r.returncode == 1, (r.returncode, r.stdout)
        ok("CLI: 确认干净 → 退出 1")

        r = run(CONF_CLEAN, NFT_DENY)
        assert r.returncode == 2, (r.returncode, r.stdout, r.stderr)
        assert "读不到" in r.stdout or "读不到" in r.stderr, (r.stdout, r.stderr)
        ok("CLI: 读不到运行 ruleset → 退出 2(不冒充干净)")

        # 读不到、但配置文件里已经有冲突 → 仍按有冲突处理(更严的那个赢)
        r = run(CONF_FOREIGN, NFT_DENY)
        assert r.returncode == 0, (r.returncode, r.stdout)
        ok("CLI: 读不到但配置文件已有冲突 → 仍判有冲突(退出 0)")

    # ── 7. doctor 必须有这一项(迁移后再加 input 链, 此前无人告警) ──
    spec_c = importlib.util.spec_from_file_location("pdg_checks", ROOT / "deploy/bot/checks.py")
    checks = importlib.util.module_from_spec(spec_c)
    spec_c.loader.exec_module(checks)
    assert hasattr(checks, "check_nft_input_chains"), "doctor 缺少 input 链冲突检查"
    assert checks.check_nft_input_chains in checks.ALL, "该检查未挂进 doctor 的 ALL"
    ok("doctor 有 check_nft_input_chains 且已挂进 ALL")

    checks.nftscan.scan = lambda conf=None: (["配置文件: 表 `inet filter` 有挂 hook input 的 base chain"], True)
    lvl, _, detail = checks.check_nft_input_chains()
    assert lvl == "fail" and "inet filter" in detail, (lvl, detail)
    ok("doctor: 存在外部 input 链 → fail 并点名")

    checks.nftscan.scan = lambda conf=None: ([], True)
    lvl, _, _ = checks.check_nft_input_chains()
    assert lvl == "ok", lvl
    ok("doctor: 确认干净 → ok")

    checks.nftscan.scan = lambda conf=None: ([], False)
    lvl, _, detail = checks.check_nft_input_chains()
    assert lvl == "warn" and "读不到" in detail, (lvl, detail)
    ok("doctor: 读不到运行 ruleset → warn(不谎报 ok)")

    # ── 8. 单一来源: pdg.sh 不得再自带一份解析实现 ──
    pdg_src = (ROOT / "deploy/bot/pdg.sh").read_text(encoding="utf-8")
    fn = pdg_src.split("_pdg_nft_foreign_input_chains(){", 1)[1].split("\n}\n", 1)[0]
    assert "nftscan.py" in fn, "pdg.sh 应调用共享的 nftscan.py"
    assert "hook\\s+input" not in fn and "hook input" not in fn.replace("hook input 的", ""), \
        "pdg.sh 里不该再内嵌一份 hook input 解析(判据必须单一来源)"
    ok("pdg.sh 委托给 nftscan.py, 未内嵌第二份解析")

    # ── 9. pdg.sh 与 doctor 对同一现场结论一致 ──
    with tempfile.TemporaryDirectory() as tmp:
        conf = os.path.join(tmp, "nftables.conf")
        bindir = os.path.join(tmp, "bin"); os.makedirs(bindir)
        with open(os.path.join(bindir, "nft"), "w") as fh:
            fh.write("#!/bin/sh\nexit 0\n")
        os.chmod(os.path.join(bindir, "nft"), 0o755)
        fnsh = os.path.join(tmp, "fn.sh")
        body = pdg_src.split("_pdg_nft_foreign_input_chains(){", 1)[1].split("\n}\n", 1)[0]
        with open(fnsh, "w") as fh:
            fh.write("_pdg_nft_foreign_input_chains(){" + body + "\n}\n")
        for text, want in ((CONF_FOREIGN, 0), (CONF_CLEAN, 1)):
            with open(conf, "w") as fh:
                fh.write(text)
            r = subprocess.run(["bash", "-c",
                                ". '%s'; _pdg_nft_foreign_input_chains '%s'" % (fnsh, conf)],
                               capture_output=True, text=True,
                               env=dict(os.environ, PATH=bindir + os.pathsep + os.environ["PATH"],
                                        REPO_DIR=str(ROOT)))
            assert r.returncode == want, (want, r.returncode, r.stdout, r.stderr)
        ok("pdg.sh 前置门与 nftscan CLI 结论一致(有冲突/干净)")

    print("\n通过 %d 项断言" % pass_n)


if __name__ == "__main__":
    main()
