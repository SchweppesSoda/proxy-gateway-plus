#!/usr/bin/env python3
"""nftables input base chain 冲突扫描 —— 迁移前置门(pdg.sh)与自检(doctor)共用的**单一判据**。

为什么这条是硬门槛: PDG 的 input chain 是 `policy drop`, 而 nftables 里同一 hook 上的多个
base chain **都会执行** —— 任一条判 drop, 包就没了。于是用户自己 input 链里对 9443 /
WireGuard 的 accept 会被架空: 配置文本还在, 端口实际已经不通。这种"看着保留、其实失效"
比直接报错难查得多。

"读不到"与"读到了且没有"必须分开: `nft list ruleset` 失败(非 root / nft 不可用)时, 只存在于
内存的冲突链根本没进视野 —— 把它当成现场干净, 等于换个入口把老毛病放回来。故 live_ruleset()
额外返回 readable, 调用方据此选择"中止/告警"而不是"放行"。

CLI:  nftscan.py [nftables.conf]
退出码: 0=有冲突(已打印) 1=确认无冲突 2=读不到运行 ruleset, 无法确认。
"""
import re
import subprocess
import sys

NFT_CONF = "/etc/nftables.conf"
OURS = "inet pdg"                    # 本项目自己的表, 不算冲突

_TBL_OPEN = re.compile(r"^\s*table\s+(\S+)\s+(\S+)\s*\{?\s*$")
_HOOK_IN = re.compile(r"\bhook\s+input\b")


def scan_text(conf_txt, live_txt):
    """扫描配置文本与运行 ruleset 文本, 返回冲突描述列表(每源一条, 已去重)。"""
    found, seen = [], set()
    for src, txt in (("配置文件", conf_txt or ""), ("运行 ruleset", live_txt or "")):
        cur, depth, opened = None, 0, False
        for ln in txt.split("\n"):
            m = _TBL_OPEN.match(ln)
            if m and cur is None:
                cur, depth, opened = "%s %s" % (m.group(1), m.group(2)), 0, False
            if cur is None:
                continue
            depth += ln.count("{") - ln.count("}")
            if depth > 0:
                opened = True
            if _HOOK_IN.search(ln) and cur != OURS:
                item = "%s: 表 `%s` 有挂 hook input 的 base chain" % (src, cur)
                if item not in seen:
                    seen.add(item); found.append(item)
            if opened and depth <= 0:
                cur, opened = None, False
    return found


def live_ruleset():
    """(文本, readable)。readable=False 表示**没读到**, 不代表现场干净。"""
    try:
        p = subprocess.run(["nft", "list", "ruleset"],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           universal_newlines=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return "", False
    if p.returncode != 0:
        return "", False
    return p.stdout, True


def read_conf(conf=NFT_CONF):
    try:
        with open(conf, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def scan(conf=NFT_CONF):
    """(冲突列表, 运行 ruleset 是否读到)。"""
    live, readable = live_ruleset()
    return scan_text(read_conf(conf), live), readable


def main(argv):
    conf = argv[1] if len(argv) > 1 else NFT_CONF
    found, readable = scan(conf)
    if found:
        print("\n".join(found))
        return 0                     # 有冲突: 比"读不到"更严, 优先按冲突处理
    if not readable:
        print("读不到运行中的 nftables ruleset(nft 不可用或权限不足), 无法确认内存里是否还有 input 链")
        return 2
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
