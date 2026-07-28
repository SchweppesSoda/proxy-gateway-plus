#!/usr/bin/env python3
"""nftables 冲突与 PDG 表归属扫描 —— 装机、迁移、卸载共用的**单一判据**。

为什么这条是硬门槛: PDG 的 input chain 是 `policy drop`, 而 nftables 里同一 hook 上的多个
base chain **都会执行** —— 任一条判 drop, 包就没了。于是用户自己 input 链里对自定义端口 /
WireGuard 的 accept 会被架空: 配置文本还在, 端口实际已经不通。这种"看着保留、其实失效"
比直接报错难查得多。

"读不到"与"读到了且没有"必须分开: `nft list ruleset` 失败(非 root / nft 不可用)时, 只存在于
内存的冲突链根本没进视野 —— 把它当成现场干净, 等于换个入口把老毛病放回来。故 live_ruleset()
额外返回 readable, 调用方据此选择"中止/告警"而不是"放行"。

CLI:  nftscan.py [--mode managed|external] [nftables.conf]
退出码: 0=有冲突(已打印) 1=确认无冲突 2=读不到运行 ruleset, 无法确认。
"""
import os
import re
import subprocess
import sys

NFT_CONF = "/etc/nftables.conf"
OURS = "inet pdg"                    # 本项目自己的表, 不算冲突
OWNER_PREFIX = "owner=privdns-gateway;schema=1;component=firewall;mode="
VALID_MODES = ("managed", "external")
MODE_FILE = "/etc/privdns-gateway/firewall-mode"
PROFILE_FILE = "/etc/privdns-gateway/profile.env"

_TBL_OPEN = re.compile(r"^\s*table\s+(\S+)\s+(\S+)\s*\{?\s*$")
_PDG_DECL = re.compile(r"^\s*table\s+inet\s+pdg(?:\s*\{)?\s*$", re.M)
_CHAIN_OPEN = re.compile(r"^\s*chain\s+(\S+)\s*\{")
_SET_OPEN = re.compile(r"^\s*set\s+(\S+)\s*\{")
_OWNER = re.compile(r'\bcomment\s+"'
                    + re.escape(OWNER_PREFIX) + r'(managed|external)"\s*;?\s*$')
# 只认**真正的 base chain 声明**(`type <类型> hook input priority …`), 不认注释或字符串里
# 恰好出现的字样。误报虽然方向保守(中止迁移), 代价却是用户被一行注释永久挡在升级门外, 而且
# 从配置上完全看不出为什么 —— 那行明明只是注释。
_HOOK_IN = re.compile(r"\btype\s+\w+\s+hook\s+input\b")
_QUOTED = re.compile(r'"[^"]*"')
_POLICY_DROP = re.compile(r"\bpolicy\s+drop\b")
# PATH 里找不到 nft 时依次试这些位置(Debian 装在 /usr/sbin)。列成常量: 测试可以指到别处,
# 免得为了验"PATH 没有但 sbin 里有"去 patch os.path.isfile 这类底层函数。
NFT_CANDIDATES = ("/usr/sbin/nft", "/sbin/nft", "/usr/local/sbin/nft",
                  "/usr/bin/nft", "/bin/nft", "/usr/local/bin/nft")


def _strip_noise(line):
    """去掉行内注释与字符串字面量 —— 判据只该看真正生效的配置。"""
    return _QUOTED.sub('""', line).split("#", 1)[0]


def _named_blocks(txt, opening):
    """Return ``[(name, block_text)]`` for brace-delimited declarations."""
    lines = (txt or "").splitlines()
    blocks, i = [], 0
    while i < len(lines):
        clean = _strip_noise(lines[i])
        match = opening.match(clean)
        if not match:
            i += 1
            continue
        start, depth, opened = i, 0, False
        while i < len(lines):
            structural = _strip_noise(lines[i])
            depth += structural.count("{") - structural.count("}")
            opened = opened or structural.count("{") > 0
            i += 1
            if opened and depth <= 0:
                break
        if not opened or depth != 0:
            blocks.append((match.group(1), "\n".join(lines[start:])))
            break
        blocks.append((match.group(1), "\n".join(lines[start:i])))
    return blocks


def _table_blocks(txt):
    opening = re.compile(r"^\s*table\s+(\S+)\s+(\S+)\s*\{")
    blocks = []
    for _family, block in _named_blocks(txt, opening):
        match = opening.match(_strip_noise(block.splitlines()[0]))
        if match:
            blocks.append((match.group(1) + " " + match.group(2), block))
    return blocks


def _pdg_blocks(txt):
    return [block for name, block in _table_blocks(txt) if name == OURS]


def _validate_owned_block(block):
    """Return the marker mode when both owner marker and schema shape are valid."""
    owners = []
    for raw in block.splitlines():
        match = _OWNER.search(raw.strip())
        if match:
            owners.append(match.group(1))
    if len(owners) != 1:
        return ""
    mode = owners[0]
    sets = _named_blocks(block, _SET_OPEN)
    set_names = [name for name, _body in sets]
    if set_names != ["pdg_tls_tcp_ports", "pdg_http_tcp_ports"]:
        return ""
    for _name, body in sets:
        clean_set = "\n".join(_strip_noise(line) for line in body.splitlines())
        if not re.search(r"\btype\s+inet_service\b", clean_set) \
                or not re.search(r"\belements\s*=", clean_set):
            return ""
    chains = _named_blocks(block, _CHAIN_OPEN)
    names = [name for name, _body in chains]
    if len(names) != len(set(names)) or "prerouting" not in names:
        return ""
    if any(name not in ("prerouting", "pdg_quic_prerouting", "input")
           for name in names):
        return ""
    bodies = dict(chains)
    prerouting = "\n".join(_strip_noise(line)
                           for line in bodies["prerouting"].splitlines())
    if not re.search(r"\btype\s+nat\s+hook\s+prerouting\b", prerouting):
        return ""
    if not re.search(r"\bip\s+saddr\b", prerouting):
        return ""
    if len(re.findall(r"\bredirect\s+to\s+:7893\b", prerouting)) != 2:
        return ""
    if "@pdg_tls_tcp_ports" not in prerouting \
            or "@pdg_http_tcp_ports" not in prerouting:
        return ""
    if "pdg_quic_prerouting" in bodies:
        quic = "\n".join(_strip_noise(line)
                         for line in bodies["pdg_quic_prerouting"].splitlines())
        if not re.search(r"\btype\s+filter\s+hook\s+prerouting"
                         r"\s+priority\s+mangle\b", quic):
            return ""
        if not re.search(r"\bip\s+saddr\b.*\budp\s+dport\s+443\b", quic):
            return ""
        if not re.search(r"\bmeta\s+mark\s+set\b.*\btproxy\s+ip\s+to\s+:7895\b",
                          quic):
            return ""
    if mode == "managed":
        if "input" not in bodies:
            return ""
        input_body = "\n".join(_strip_noise(line)
                               for line in bodies["input"].splitlines())
        if not re.search(r"\btype\s+filter\s+hook\s+input\b", input_body):
            return ""
        if not _POLICY_DROP.search(input_body):
            return ""
    else:
        if "input" in bodies:
            return ""
        clean = "\n".join(_strip_noise(line) for line in block.splitlines())
        if re.search(r"\bhook\s+input\b", clean):
            return ""
    return mode


def pdg_table_status(txt):
    """Classify the ``inet pdg`` table in one source.

    ``owned-*`` requires the exact marker and schema shape. A naked declaration,
    duplicate table, markerless table, or malformed owned table is ``foreign``.
    """
    blocks = _pdg_blocks(txt)
    if not blocks:
        return "foreign" if _PDG_DECL.search(txt or "") else "absent"
    if len(blocks) != 1:
        return "foreign"
    mode = _validate_owned_block(blocks[0])
    return "owned-" + mode if mode else "foreign"


def legacy_stock_pdg_status(txt):
    """Recognize only the exact markerless pre-schema PDG managed table.

    Shape equality is used solely as a one-way migration gate. It is not a
    general ownership classification and never authorizes uninstall cleanup.
    """
    blocks = _pdg_blocks(txt)
    if len(blocks) != 1 or OWNER_PREFIX in blocks[0]:
        return ""
    block = blocks[0]
    chains = _named_blocks(block, _CHAIN_OPEN)
    if [name for name, _body in chains] != ["prerouting", "input"]:
        return ""
    clean_lines = []
    for raw in block.splitlines():
        # Do not use _strip_noise here: that deliberately blanks quoted
        # strings for brace scanning, while exact legacy recognition needs to
        # retain iif "lo" as ownership evidence.
        line = re.sub(r"\s+", " ", raw.split("#", 1)[0]).strip().rstrip(";")
        if line:
            clean_lines.append(line)
    allowed = (
        re.compile(r"^table inet pdg \{$"),
        re.compile(r"^chain (prerouting|input) \{$"),
        re.compile(r"^\}$"),
        re.compile(r"^type nat hook prerouting priority dstnat; policy accept$"),
        re.compile(r"^type filter hook input priority 0; policy drop$"),
        re.compile(r'^iif "lo" accept$'),
        re.compile(r"^ct state established,related accept$"),
        re.compile(r"^tcp dport \{ [0-9]+ \} accept$"),
        re.compile(
            r"^ip saddr [0-9./]+ tcp dport \{ 53, 81, 853, 7893, 8445 \} accept$"),
        re.compile(r"^ip saddr [0-9./]+ udp dport (?:\{ 53 \}|53) accept$"),
        re.compile(r"^ip saddr [0-9./]+ udp dport 443 reject$"),
        re.compile(r"^ip saddr [0-9./]+ tcp dport "
                   r"\{ 80, 443(?:, 5228-5230)? \} redirect to :7893$"),
        re.compile(r"^ip protocol icmp accept$"),
        re.compile(r"^ip6 nexthdr icmpv6 accept$"),
    )
    if any(not any(pattern.fullmatch(line) for pattern in allowed)
           for line in clean_lines):
        return ""
    joined = "\n".join(clean_lines)
    required = (
        r"type nat hook prerouting priority dstnat; policy accept",
        r"type filter hook input priority 0; policy drop",
        r'iif "lo" accept',
        r"ct state established,related accept",
        r"tcp dport \{ [0-9]+ \} accept",
        r"ip saddr [0-9./]+ tcp dport \{ 53, 81, 853, 7893, 8445 \} accept",
        r"ip saddr [0-9./]+ udp dport (?:\{ 53 \}|53) accept",
        r"ip saddr [0-9./]+ udp dport 443 reject",
        r"ip saddr [0-9./]+ tcp dport "
        r"\{ 80, 443(?:, 5228-5230)? \} redirect to :7893",
        r"ip protocol icmp accept",
        r"ip6 nexthdr icmpv6 accept",
    )
    if any(len(re.findall(pattern, joined)) != 1 for pattern in required):
        return ""
    sources = re.findall(r"ip saddr ([0-9./]+)", joined)
    if not sources or len(set(sources)) != 1:
        return ""
    return "managed"


def scan_text(conf_txt, live_txt, mode="managed"):
    """扫描配置文本与运行 ruleset 文本, 返回冲突描述列表(每源一条, 已去重)。

    **空骨架不算冲突**: Debian 的 nftables 包自带一份 /etc/nftables.conf, 里面是一个
    `table inet filter`, 三条 base chain 全是 `policy accept` 且一条规则都没有 —— 全新
    VPS 上装了 nftables 就长这样。它既不 drop 任何包、也没有会被架空的放行, 完全惰性;
    把它当冲突拒掉, 等于绝大多数新机器都装不上, 而用户根本不知道要删哪一行。
    真正要挡的是两种: 链里**有规则**(那些放行会被 PDG 的 policy drop 架空), 或者链自己
    就是 **policy drop**(那它会把本项目要放行的端口直接丢掉)。"""
    if mode not in VALID_MODES:
        raise ValueError("firewall mode must be managed or external")
    found, seen = [], set()
    for src, txt in (("配置文件", conf_txt or ""), ("运行 ruleset", live_txt or "")):
        pdg_status = pdg_table_status(txt)
        if pdg_status == "foreign" and not legacy_stock_pdg_status(txt):
            item = ("%s: `table inet pdg` 缺少合法 owner/schema marker，或结构不符合已知 schema"
                    % src)
            if item not in seen:
                seen.add(item)
                found.append(item)
        if mode == "external":
            continue
        cur, depth, opened = None, 0, False
        chain_depth = None          # 正处在某条 foreign input chain 里
        chain_rules = 0
        chain_policy_drop = False
        for raw in txt.split("\n"):
            ln = _strip_noise(raw)
            m = _TBL_OPEN.match(ln)
            if m and cur is None:
                cur, depth, opened = "%s %s" % (m.group(1), m.group(2)), 0, False
            if cur is None:
                continue
            depth += ln.count("{") - ln.count("}")
            if depth > 0:
                opened = True
            if _HOOK_IN.search(ln) and cur != OURS:
                chain_depth = depth                     # 从下一行起是链体
                chain_rules = 0
                chain_policy_drop = bool(_POLICY_DROP.search(ln))
            elif chain_depth is not None:
                if depth < chain_depth:                 # 链结束: 结账
                    if chain_rules or chain_policy_drop:
                        why = "policy drop" if chain_policy_drop else "%d 条规则" % chain_rules
                        item = ("%s: 表 `%s` 有挂 hook input 的 base chain(%s)"
                                % (src, cur, why))
                        if item not in seen:
                            seen.add(item); found.append(item)
                    chain_depth = None
                elif ln.strip().strip("{}").strip():     # 非空、非纯括号 = 一条规则
                    chain_rules += 1
            if opened and depth <= 0:
                cur, opened = None, False
        if chain_depth is not None and (chain_rules or chain_policy_drop):   # 文本到头还没闭合
            why = "policy drop" if chain_policy_drop else "%d 条规则" % chain_rules
            item = "%s: 表 `%s` 有挂 hook input 的 base chain(%s)" % (src, cur, why)
            if item not in seen:
                seen.add(item); found.append(item)
    return found


def nft_bin():
    """找到 nft 可执行文件的路径(找不到返回 "")。

    不能只靠 PATH: nft 装在 /usr/sbin, 而 `su`(不带 -)、cron、某些容器的 root PATH 里没有
    sbin 目录。那时 `nft` 找不到 → 读不到运行 ruleset → 扫描返回"无法确认", 调用方再按
    "nft 没装, 没有现网规则可冲突"放行 —— 机器上明明有一整套 input 链, 却被当成裸机装上去。
    所以按 PATH → 常见 sbin 路径依次找; 这也是 shell 侧(install.sh)判断"nft 到底在不在"的
    同一份依据(见 --nft-path)。"""
    from shutil import which
    p = which("nft")
    if p:
        return p
    for cand in NFT_CANDIDATES:
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return ""


def live_ruleset():
    """(文本, readable)。readable=False 表示**没读到**, 不代表现场干净。"""
    exe = nft_bin()
    if not exe:
        return "", False
    try:
        p = subprocess.run([exe, "list", "ruleset"],
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


def persisted_mode():
    """Read persisted intent for legacy callers that do not pass ``--mode``."""
    marker = ""
    if os.path.exists(MODE_FILE):
        marker = read_conf(MODE_FILE).strip()
        if marker not in VALID_MODES:
            raise ValueError("invalid firewall mode in %s" % MODE_FILE)
    profile = read_conf(PROFILE_FILE)
    values = [match.group(1) for raw in profile.splitlines()
              for match in [re.match(r"^\s*PDG_FIREWALL_MODE=(.*)$", raw)] if match]
    if len(values) > 1:
        raise ValueError("duplicate PDG_FIREWALL_MODE in %s" % PROFILE_FILE)
    if values:
        value = values[0].strip()
        if value not in VALID_MODES:
            raise ValueError("invalid firewall mode in %s" % PROFILE_FILE)
        if marker and marker != value:
            raise ValueError("firewall mode mismatch between state and profile")
        return value
    if marker:
        return marker
    return "managed"


def scan(conf=NFT_CONF, mode=None):
    """(冲突列表, 运行 ruleset 是否读到)。"""
    if mode is None:
        mode = persisted_mode()
    live, readable = live_ruleset()
    return scan_text(read_conf(conf), live, mode=mode), readable


def main(argv):
    # --nft-path: 只回答"nft 到底在不在(在哪)" —— 让 shell 侧不必自己 `command -v nft`,
    # 那个判断会漏掉 PATH 里没有 sbin 的情况, 两处各写一份迟早给出相反答案。
    # 找到 → 打印路径并 exit 0; 找不到 → 不打印, exit 1。
    if "--nft-path" in argv[1:]:
        exe = nft_bin()
        if exe:
            print(exe)
            return 0
        return 1
    args = list(argv[1:])
    try:
        mode = persisted_mode()
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 3
    if "--mode" in args:
        pos = args.index("--mode")
        if pos + 1 >= len(args):
            print("--mode 缺少值", file=sys.stderr)
            return 3
        mode = args[pos + 1]
        del args[pos:pos + 2]
    for arg in list(args):
        if arg.startswith("--mode="):
            mode = arg.split("=", 1)[1]
            args.remove(arg)
    if mode not in VALID_MODES:
        print("firewall mode 只能是 managed 或 external", file=sys.stderr)
        return 3
    status_arg = next((arg for arg in args if arg.startswith("--table-status=")), "")
    if status_arg:
        source = status_arg.split("=", 1)[1]
        if source == "live":
            txt, readable = live_ruleset()
            if not readable:
                print("unreadable")
                return 2
        elif source == "conf":
            conf_args = [arg for arg in args if not arg.startswith("--")]
            txt = read_conf(conf_args[0] if conf_args else NFT_CONF)
        else:
            print("--table-status 只能是 conf 或 live", file=sys.stderr)
            return 3
        status = pdg_table_status(txt)
        print(status)
        if status.startswith("owned-"):
            return 0
        if status == "absent":
            return 1
        return 3
    conf_args = [arg for arg in args if not arg.startswith("--")]
    conf = conf_args[0] if conf_args else NFT_CONF
    live, readable = live_ruleset()
    found = scan_text(read_conf(conf), live, mode=mode)
    if found:
        print("\n".join(found))
        return 0                     # 有冲突: 比"读不到"更严, 优先按冲突处理
    if not readable:
        print("读不到运行中的 nftables ruleset(nft 不可用或权限不足), 无法确认内存里是否还有 input 链")
        return 2
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
