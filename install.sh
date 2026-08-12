#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# PrivDNS Gateway 一键安装 (Debian 12+ / Ubuntu 22+, 需 root)
#   sudo ./install.sh
# 非交互/自动化: 预置 PDG_* 环境变量 + PDG_NONINTERACTIVE=1 (见 docs/INSTALL.md)。
#   PDG_SERVER_IP PDG_SSH_PORT PDG_INTERNAL_CIDR PDG_BOT_TOKEN PDG_ALLOWED PDG_DOT_DOMAIN
#   PDG_FIREWALL_MODE=managed|external (默认 managed)
#   PDG_QUIC_MODE=tproxy|reject (本 fork 默认 tproxy，可显式 reject 安全回退)
#   PDG_HIJACK_TLS_TCP_PORTS / PDG_HIJACK_HTTP_TCP_PORTS (十进制逗号列表)
#   PDG_SKIP_CERT=1  跳过 certbot, 生成自签占位证书 (之后用 bot 补正式证书)
# 做什么: 装 mosdns + mihomo + 管理 bot + 防火墙 + DoT 证书。
#   自动识别公网IP / 内网卡段; DNS(域名 A 记录) 那步留给你自己做; 落地出口装好后用 bot 加。
# 也支持 curl|bash 直接跑: curl -fsSL <raw>/install.sh | sudo bash  (脚本会自动拉取仓库)
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

REPO_URL="${PDG_REPO_URL:-https://github.com/SchweppesSoda/proxy-gateway-plus.git}"
CERT_DIR="/etc/mosdns/certs"
NONINT="${PDG_NONINTERACTIVE:-}"
# 二进制版本(MOSDNS_VER/MIHOMO_VER)+ 钉死 SHA256 来自 lib/versions.sh, 自举进仓库后 source(见下)

c_g(){ echo -e "\033[1;32m[*]\033[0m $*"; }
c_y(){ echo -e "\033[1;33m[!]\033[0m $*"; }
die(){ echo -e "\033[1;31m[x]\033[0m $*" >&2; exit 1; }

# 交互读取一行到指定变量, 撞 EOF / 无可用终端时回落到默认值 —— 绝不触发 errexit。
# 用法: ask <变量名> <提示语> [默认值]
# 为什么每次新开 /dev/tty: 自举把 fd 0 绑成某一个 /dev/tty 打开描述(见下方 exec ... < /dev/tty),
# 长时间抓包(detect-internal-range.sh ~90s)后该描述在某些云主机/终端上会进入异常态, 后续 read
# 立即返回 EOF。旧写法 `read ... VAR` 的非零返回会被 set -e 判成致命错误 → 整场安装回滚, 且不留
# 任何错误行(见 issue: "内网卡来源段 CIDR [...]: [!] 安装失败")。这里每次都新开 /dev/tty 取一个
# 干净的终端描述, 并把 EOF/无终端当"用默认值"处理, 让一次 read 失手不再拖垮整场安装。
ask(){
  local __var="$1" __prompt="$2" __def="${3:-}" __ans=""
  # 探针与重跑处同款: 把重定向挂在普通命令上, 打不开只让该命令返回非零(不会让 shell 退出);
  # 能打开才 read, 且 read 的 EOF 用 `|| __ans=""` 吃掉 —— 两条路都回落到默认值, 均不触发 errexit。
  if { true < /dev/tty; } 2>/dev/null; then
    read -rp "$__prompt" __ans < /dev/tty || __ans=""
  fi
  printf -v "$__var" '%s' "${__ans:-$__def}"
}

pdg_checkout_latest_tag(){
  local dir="$1" tag cur target helper
  helper="$dir/lib/release-tags.sh"
  [[ -f "$helper" ]] || die "发布标签校验器缺失: $helper"
  # shellcheck source=lib/release-tags.sh
  source "$helper"
  pdg_origin_release_select "$dir" \
    || die "无法从 origin 选择可信 release tag, 中止安装。"
  tag="$PDG_RELEASE_TAG"; target="$PDG_RELEASE_COMMIT"
  pdg_origin_release_materialize "$dir" "$tag" "$PDG_RELEASE_OBJECT" \
    || die "无法固定 origin release tag $tag"
  cur=$(git -C "$dir" rev-parse HEAD 2>/dev/null || true)
  if [[ "$cur" != "$target" ]]; then
    git -C "$dir" checkout -q --detach "$target" \
      || die "无法 checkout 已验证的 origin release $tag"
  fi
  [[ "$(git -C "$dir" rev-parse HEAD 2>/dev/null || true)" == "$target" ]] \
    || die "checkout 后 HEAD 与 origin release $tag 不一致"
  echo "$tag"
}

[[ $EUID -eq 0 ]] || die "请用 root 运行: sudo ./install.sh  (或 curl ... | sudo bash)"
command -v apt-get >/dev/null || die "目前仅支持 Debian/Ubuntu (apt)"
case "$(dpkg --print-architecture)" in
  amd64) MARCH=amd64 ;; arm64) MARCH=arm64 ;; *) die "不支持的架构: $(dpkg --print-architecture)";;
esac

# ── 自举: 若通过 curl|bash 直接运行(不在仓库内), 自动 clone 后从文件重跑 ──
# (从文件重跑能让 read 交互正常: curl|bash 时 stdin 是脚本本身, 故把 stdin 接回 /dev/tty)
SRC="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || echo /nonexistent)"
if [[ ! -f "$SRC/deploy/mosdns/config.yaml" ]]; then
  c_g "未在仓库目录内运行 → 自动拉取 privdns-gateway…"
  command -v git >/dev/null || { apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq git; }
  DEST=/opt/privdns-gateway
  unset PDG_INSTALL_BOOTSTRAP_REPO_CREATED
  if [[ ! -d "$DEST/.git" ]]; then
    [[ ! -e "$DEST" && ! -L "$DEST" ]] \
      || die "$DEST 已存在但不是 git 仓库；拒绝在自举阶段删除来源不明的对象"
    _bootstrap_tmp="$(mktemp -d /opt/.privdns-gateway.bootstrap.XXXXXX)" \
      || die "无法创建仓库自举临时目录"
    if ! git clone -q "$REPO_URL" "$_bootstrap_tmp"; then
      rm -rf "$_bootstrap_tmp"
      die "仓库自举 clone 失败"
    fi
    if ! TAG="$(pdg_checkout_latest_tag "$_bootstrap_tmp")"; then
      rm -rf "$_bootstrap_tmp"
      die "仓库自举 checkout 最新发布失败"
    fi
    if ! mv "$_bootstrap_tmp" "$DEST"; then
      rm -rf "$_bootstrap_tmp"
      die "仓库自举副本原子落位失败"
    fi
    # exec 重跑后纳入全新安装的目录事务；否则 clone 发生在 EXIT trap 之前，安装失败会
    # 留下半套 /opt 仓库，下一次又因“.git 已存在”而错误复用旧副本。
    export PDG_INSTALL_BOOTSTRAP_REPO_CREATED=1
  else
    TAG=$(pdg_checkout_latest_tag "$DEST")
  fi
  c_g "使用最新发布 $TAG"
  # 有可用控制终端就把 stdin 接回它(交互), 否则直接重跑(靠 PDG_* 环境变量非交互)
  export PDG_TAG_BOOTSTRAPPED=1
  if { true < /dev/tty; } 2>/dev/null; then exec bash "$DEST/install.sh" "$@" < /dev/tty
  else exec bash "$DEST/install.sh" "$@"; fi
fi
REPO_DIR="$SRC"
if [[ -d "$REPO_DIR/.git" && "${PDG_TAG_BOOTSTRAPPED:-}" != "1" ]]; then
  command -v git >/dev/null || { apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq git; }
  TAG=$(pdg_checkout_latest_tag "$REPO_DIR")
  export PDG_TAG_BOOTSTRAPPED=1
  c_g "使用最新发布 $TAG"
  if { true < /dev/tty; } 2>/dev/null; then exec bash "$REPO_DIR/install.sh" "$@" < /dev/tty
  else exec bash "$REPO_DIR/install.sh" "$@"; fi
fi

# ── 版本 + 钉死 SHA256(供应链校验)──
# shellcheck source=lib/versions.sh
source "$REPO_DIR/lib/versions.sh"
# shellcheck source=lib/mosdns-artifact.sh
source "$REPO_DIR/lib/mosdns-artifact.sh"
# shellcheck source=lib/units.sh
source "$REPO_DIR/lib/units.sh"   # systemd unit 单一事实源(与 pdg 迁移共用, 免漂移)
# shellcheck source=lib/mosdns.sh
source "$REPO_DIR/lib/mosdns.sh" # mosdns 劫持形态单一事实源(与 hijack-mode/迁移共用)
# shellcheck source=lib/cidr.sh
source "$REPO_DIR/lib/cidr.sh"   # 内网卡段校验 + 抓包/手输并行(与 pdg detect-cidr 共用)
# shellcheck source=lib/nfttxn.sh
source "$REPO_DIR/lib/nfttxn.sh" # nft -c + same-directory atomic install

# ── 事务性安装: 失败自动回滚(只撤本次新装的, 不误伤既有可用部署)──
INSTALL_OK=0; ROLLBACK_DONE=0; FORCED_REINSTALL=0
NFT_CONFIG_CHANGED=0; NFT_RUNTIME_TOUCHED=0
QUIC_ROUTING_TOUCHED=0
PRESERVE_QUIC_RECOVERY=0
WEB_WAS_ENABLED=0; WEB_WAS_ACTIVE=0
# 安装状态: 全部在注册 EXIT trap 前初始化 —— rollback 在 set -u 下读到未赋值的变量会
# 二次崩溃, 把最初的安装错误盖掉, 还会漏掉它后面的 nftables/resolved/resolv.conf 还原。
PRIOR_INSTALL=0; MOSDNS_INSTALLED=0; MIHOMO_INSTALLED=0; RESOLVED_DISABLED=0
# 二进制安装事务台账: 每项 "目标路径|装前是否存在(0/1)|备份路径|装前SHA"。
# 只要"即将改动目标"就先记一笔 —— *_INSTALLED 表示的是"装成功了吗", 不能拿来表示
# "这次碰过目标没有": install 写了一半才失败时它还是 0, 回滚就会漏掉那个半成品。
BIN_TXN=()
# 目录事务台账: 每项 "目录|装前是否存在(0/1)|装前内容备份路径"。
# 回滚只该撤销**本次**造成的改动: 本次新建的目录才删, 装前就存在的要按备份还原 ——
# 直接 rm -rf 那几个目录会把装前就在那儿的东西(可能是别人的)一并抹掉。
DIR_TXN=()
# curl|bash 自举新建的仓库早于本次 shell 的 EXIT trap。用一笔“装前不存在”的合成台账
# 把它并入同一安装事务；正常从现有 /opt checkout 运行时没有该内部标志，不会误删源仓库。
if [[ "${PDG_INSTALL_BOOTSTRAP_REPO_CREATED:-0}" == 1 \
      && "$REPO_DIR" == /opt/privdns-gateway ]]; then
  DIR_TXN+=("/opt/privdns-gateway|0|")
fi
SAFE_DIRECTORY_ADDED=0
[[ -f /opt/pdg-bot/bot.py || -x /usr/local/bin/pdg \
   || -f /opt/pdg-web/pdg-web.py || -x /usr/local/bin/pdg-webctl ]] \
  && PRIOR_INSTALL=1
# Capture the optional Web service state before any Web code/unit can be
# overwritten.  A forced reinstall preserves these two state bits exactly:
# enabled+inactive stays inactive, and disabled+active stays disabled.
systemctl is-enabled --quiet pdg-web >/dev/null 2>&1 && WEB_WAS_ENABLED=1
systemctl is-active --quiet pdg-web >/dev/null 2>&1 && WEB_WAS_ACTIVE=1

# 主机防火墙意图必须在任何 nft 冲突判断前确定。显式环境变量优先；覆盖重装/重渲时沿用
# 独立 state marker，再回退 profile.env；三处任一已有但值未知都 fail closed，不能静默改回默认。
_fm_values="$(sed -n 's/^[[:space:]]*PDG_FIREWALL_MODE=//p' \
  /etc/privdns-gateway/profile.env 2>/dev/null || true)"
_fm_count="$(grep -c '^[[:space:]]*PDG_FIREWALL_MODE=' \
  /etc/privdns-gateway/profile.env 2>/dev/null || true)"
[[ "$_fm_count" -le 1 ]] \
  || die "profile.env 存在重复 PDG_FIREWALL_MODE；拒绝采用「最后一个值」继续安装。"
_fm_profile="$(printf '%s\n' "$_fm_values" | head -1)"
_fm_marker=""
if [[ -e /etc/privdns-gateway/firewall-mode ]]; then
  _fm_marker="$(cat /etc/privdns-gateway/firewall-mode 2>/dev/null || true)"
fi
if [[ -n "$_fm_marker" && -n "$_fm_profile" && "$_fm_marker" != "$_fm_profile" ]]; then
  die "firewall-mode state 与 profile.env 不一致；拒绝静默选择其一。"
fi
if [[ -v PDG_FIREWALL_MODE ]]; then
  FIREWALL_MODE="$PDG_FIREWALL_MODE"
elif [[ -e /etc/privdns-gateway/firewall-mode ]]; then
  FIREWALL_MODE="$_fm_marker"
elif [[ "$_fm_count" == 1 ]]; then
  FIREWALL_MODE="$_fm_profile"
else
  FIREWALL_MODE=managed
fi
case "$FIREWALL_MODE" in
  managed|external) ;;
  *) die "PDG_FIREWALL_MODE 只能是 managed 或 external（当前: ${FIREWALL_MODE@Q}）" ;;
esac

# ── 第三方路径冲突: 在改动任何东西之前中止 ──────────────────────────────────
# 本项目把 /etc/sing-box/config.json 当数据模型, 而手工装的 sing-box 也常用这个路径。
# 若机器上已有一份**证明不了归属**的 sing-box(unit / 二进制 / 配置), 继续装就会覆盖别人的
# 配置且不可逆 —— 直接中止, 把处置权交回用户。
# shellcheck source=lib/singbox.sh
source "$REPO_DIR/lib/singbox.sh"
if [[ "$PRIOR_INSTALL" == 0 ]]; then
  _sb_conflict=()
  [[ -e /etc/systemd/system/sing-box.service ]] && _sb_conflict+=("/etc/systemd/system/sing-box.service")
  [[ -e /usr/local/bin/sing-box ]] && _sb_conflict+=("/usr/local/bin/sing-box")
  [[ -e /etc/sing-box/config.json ]] && _sb_conflict+=("/etc/sing-box/config.json")
  if [[ ${#_sb_conflict[@]} -gt 0 ]] && ! pdg_singbox_is_ours; then
    die "检测到已存在的 sing-box, 且无法确认是本项目安装的 → 中止安装(未改动任何文件)。
  冲突路径: ${_sb_conflict[*]}
  本项目会把 /etc/sing-box/config.json 用作数据模型, 继续装会覆盖上面这些内容, 且不可逆。
  请先确认它们的归属: 确实不再需要就自行备份并移除, 再重跑本脚本;
  若那是你自己在跑的 sing-box, 请换一台机器部署本项目。"
  fi
fi

# 已有部署: install.sh 会重写配置, 半途失败难以无损还原 → 默认拒绝, 引导走 pdg update(带快照+回滚)。
# 确需原机覆盖重装的显式 PDG_FORCE_REINSTALL=1; 此时先打快照, 失败用 pdg rollback 恢复。
if [[ "$PRIOR_INSTALL" == 1 ]]; then
  if [[ -z "${PDG_FORCE_REINSTALL:-}" ]]; then
    die "检测到已有 PrivDNS Gateway 部署。
  升级请用:  sudo pdg update   (带快照 + 校验门 + 失败自动回滚, 不动出口/分流/证书)
  确要原机覆盖重装(会重写配置): sudo PDG_FORCE_REINSTALL=1 ./install.sh"
  fi
  FORCED_REINSTALL=1
  # 覆盖重装会重写既有部署的配置, 没有快照就等于不可恢复 → 快照拿不到就在动任何文件之前中止。
  command -v pdg >/dev/null 2>&1 \
    || die "PDG_FORCE_REINSTALL: 找不到 pdg 命令, 无法在覆盖前留快照 → 中止。"
  c_y "PDG_FORCE_REINSTALL: 在已有部署上覆盖重装 → 先留一份快照…"
  pdg snapshot >/dev/null 2>&1 \
    || die "覆盖重装前快照失败 → 中止(拒绝在无法恢复配置的前提下覆盖已有部署)。"
fi

# ── 防火墙冲突/归属: 同样在改动任何东西之前中止 ─────────────────────────────
# managed 的 table inet pdg 带 `hook input priority 0; policy drop`, 而 nftables 里同一 hook
# 上的多个 base chain **都会执行** —— 任一条判 drop 包就没了。机器上已有别的 input base chain
# 时装上去, 用户那些放行(自定义端口/VPN)会被架空: 配置看着还在, 端口实际不通。
# external 不挂 input hook，故允许其它 input base chain；两种模式都严格拒绝 foreign 同名表。
# 判据与迁移共用 deploy/bot/nftscan.py, 不另写一套。
# **安全检查前置依赖**: 扫描器是 python3 写的。极简 Debian 12 默认没有 python3, 那时
# `python3 …` 直接 127 —— 旧写法的 case 只认 0 和 2, 127 静默落空, 于是"有冲突的机器照样
# 装下去", 这道门等于不存在。所以先把 python3 装上(只装它, 与后面那批正式依赖分开: 这是
# 为了**能做检查**, 不是开始部署), 装不上就中止 —— 检查做不了就不能往下走。
_NFTSCAN="$REPO_DIR/deploy/bot/nftscan.py"
[[ -f "$_NFTSCAN" ]] || die "缺少防火墙冲突扫描器 $_NFTSCAN → 中止安装(未改动任何文件)。
  仓库不完整? 请重新 clone 后再装。"
if ! command -v python3 >/dev/null 2>&1; then
  c_y "[*] 安全检查前置依赖: 本机没有 python3, 先装上它才能做防火墙冲突检查…"
  apt-get update -qq >/dev/null 2>&1 || true
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3-minimal >/dev/null 2>&1 \
    || DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 >/dev/null 2>&1 || true
  command -v python3 >/dev/null 2>&1 \
    || die "装不上 python3 → 无法检查现有 nftables 是否与本项目冲突, 中止安装(未改动配置)。
  本项目本来就依赖 python3(bot / 自检 / 渲染都用它)。请先手工装好:
    sudo apt-get update && sudo apt-get install -y python3
  再重跑本脚本。"
fi

# 退出码本身就是结论(0=有冲突 1=干净 2=读不到), 非零是正常返回 —— 赋值必须自己接住,
# 否则 set -e 会在"现场干净"时把安装直接杀掉。stderr 单独留一份: 出了别的错(解释器炸了 /
# 脚本语法坏了)要能看见原因, 不能只丢一句"检查失败"。
_nft_rc=0
_nft_err="$(mktemp)" || die "无法创建临时文件"
_nft_conflict="$(python3 "$_NFTSCAN" --mode "$FIREWALL_MODE" /etc/nftables.conf 2>"$_nft_err")" || _nft_rc=$?
_nft_stderr="$(head -c 2000 "$_nft_err" 2>/dev/null)"; rm -f "$_nft_err"
case "$_nft_rc" in
  0) die "检测到 nftables 冲突或 foreign \`table inet pdg\` → 中止安装(未改动任何文件)。
$(printf '%s\n' "$_nft_conflict" | sed 's/^/    /')
  managed 模式下请先处理不兼容的 input base chain；同名 foreign 表则两种模式都不会接管、
  删除或替换，请先由管理员确认归属并改名/移除后再重跑。" ;;
  1) : ;;   # 确认无冲突 → 继续
  2) # 读不到运行中的 ruleset。机器上压根没有 nft = 还没装 nftables, 没有现网规则可冲突,
     # 照常继续(本脚本随后会装 nftables); nft 在却读不到 = 权限/内核异常, 不能盲目往下写规则。
     #
     # "在不在"必须与扫描器用**同一份**判据: `command -v nft` 只看 PATH, 而 nft 装在
     # /usr/sbin —— `su`(不带 -)、cron、某些容器的 root PATH 里没有 sbin, 于是明明装着
     # nftables 却被判成"没装", 一整套现网 input 链就这么被当成裸机放过去了。
     _nft_bin="$(python3 "$_NFTSCAN" --nft-path 2>/dev/null || true)"
     if [[ -n "$_nft_bin" && -x "$_nft_bin" ]]; then
       die "无法确认现有 nftables 规则(nft 在 $_nft_bin, 但 list ruleset 读不到)
  → 中止安装(未改动任何文件)。
$(printf '%s\n' "$_nft_conflict" | sed 's/^/    /')
  请用 root 重跑; 若 nftables 本身不可用(内核缺 nf_tables 模块等), 请先修好它再装。"
     fi
     c_y "[*] 本机还没有 nftables(扫描器也找不到 nft)→ 仅依据 /etc/nftables.conf 判定, 继续安装。" ;;
  *) # 127=找不到解释器 / 126=不可执行 / 1xx=被信号杀 / 其它=扫描器自己出错。
     # 一律中止: "检查没跑成"和"检查通过"是两回事, 后者才有资格继续装。
     die "防火墙冲突检查没能跑起来(退出码 $_nft_rc)→ 中止安装(未改动任何文件)。
$( [[ -n "$_nft_stderr" ]] && printf '  扫描器输出:\n%s\n' "$(printf '%s\n' "$_nft_stderr" | sed 's/^/    /')" )
  常见原因: python3 不可用或版本过旧(127/126)、$_NFTSCAN 损坏、被 OOM/信号杀掉。
  先确认 \`python3 $_NFTSCAN /etc/nftables.conf; echo \$?\` 能跑出 0/1/2, 再重跑本脚本。" ;;
esac

_sha(){ sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }

# 覆盖既有内核/解析器二进制前先留一份原件。别人装的 mosdns/sing-box/mihomo(哪怕版本
# 不同)不算"本次新增", 回滚时应当还原原件而不是删掉。
#
# 返回非 0 = 备份不可靠, 调用方**必须中止**, 绝不能继续覆盖 —— 备份失败还照装, 等于
# 在没有退路的前提下改别人的二进制。目标本来就不存在时返回 0(没什么可留)。
_stash_bin(){
  local p="$1" bak="$1.pdg-preinstall" tmp sha
  if [[ ! -e "$p" ]]; then
    BIN_TXN+=("$p|0||")               # 仍要记账: 回滚时要删掉本次可能留下的半成品
    return 0
  fi
  sha="$(_sha "$p")"
  [[ -n "$sha" ]] || { c_y "读不到 $p 的校验和 → 中止(无法保证可回退)。"; return 1; }
  if [[ -e "$bak" ]]; then
    # 残留备份分两种: 与当前文件**内容一致** = 上次装成功后没清掉的, 清掉继续即可(常见, 安全);
    # 内容不同 = 来源不明, 既不能拿当前文件盖掉它, 也不能拿它顶替当前文件 → 交人工。
    if [[ "$(_sha "$bak")" == "$sha" ]]; then
      rm -f "$bak" 2>/dev/null || { c_y "清理残留备份 $bak 失败 → 中止。"; return 1; }
    else
      c_y "发现上次遗留的备份: $bak(内容与当前 $p 不同, 来源不明)"
      c_y "  拒绝覆盖。请先人工确认(确是旧版就 mv 回 $p, 无用则删除), 再重跑。"
      return 1
    fi
  fi
  # 先写同目录临时文件, 校验通过再原子 mv 落位: 半截拷贝不会被当成完整原件
  tmp="$(mktemp "$(dirname "$p")/.pdg-stash.XXXXXX" 2>/dev/null)" \
    || { c_y "无法在 $(dirname "$p") 创建临时文件 → 中止。"; return 1; }
  if ! cp -a "$p" "$tmp" 2>/dev/null || [[ "$(_sha "$tmp")" != "$sha" ]]; then
    rm -f "$tmp" 2>/dev/null
    c_y "备份 $p 失败(拷贝不完整) → 中止, 不在无法回退的前提下覆盖二进制。"; return 1
  fi
  if ! mv -f "$tmp" "$bak" 2>/dev/null; then
    rm -f "$tmp" 2>/dev/null; c_y "备份落位失败 → 中止。"; return 1
  fi
  BIN_TXN+=("$p|1|$bak|$sha")
  return 0
}

# 回滚二进制: 按事务台账逐条独立处理, 失败计入调用方的 failed(动态作用域)。
# 台账在"即将改动目标"之前就记好, 所以 install 写了一半才失败也能被恢复 ——
# 用 *_INSTALLED(装成功了吗)判断"这次碰过目标没有"会漏掉正是这种情况。
_rollback_bins(){
  local entry p pre bak sha
  for entry in ${BIN_TXN[@]+"${BIN_TXN[@]}"}; do
    IFS='|' read -r p pre bak sha <<<"$entry"
    if [[ "${PRESERVE_QUIC_RECOVERY:-0}" == 1 \
          && ( "$p" == /usr/local/libexec/pdg-quic-routing.sh \
               || "$p" == /etc/systemd/system/pdg-quic-routing.service ) ]]; then
      continue
    fi
    if [[ "$pre" == 1 ]]; then
      if [[ -z "$bak" || ! -e "$bak" ]]; then failed+=("还原 $p(备份丢失)"); continue; fi
      if ! mv -f "$bak" "$p" 2>/dev/null;   then failed+=("还原 $p(mv 失败)");  continue; fi
      # 只看"文件在"不够: 必须确认还原出来的确实等于备份下来的那一份
      if [[ -n "$sha" && "$(_sha "$p")" != "$sha" ]]; then failed+=("还原 $p(校验和不符)"); continue; fi
    else
      rm -f "$p" 2>/dev/null || failed+=("移除 $p")
    fi
  done
}

# 安装确认成功后清理备份(原件不再需要)。
_commit_bins(){
  local entry p pre bak sha
  for entry in ${BIN_TXN[@]+"${BIN_TXN[@]}"}; do
    IFS='|' read -r p pre bak sha <<<"$entry"
    [[ -n "$bak" ]] && rm -f "$bak" 2>/dev/null
  done
  return 0
}

_commit_dirs(){
  local entry d pre bak
  for entry in ${DIR_TXN[@]+"${DIR_TXN[@]}"}; do
    IFS='|' read -r d pre bak <<<"$entry"
    [[ -n "$bak" ]] && rm -rf "$bak" 2>/dev/null
  done
  return 0
}

_web_service_stable(){
  local streak=0
  for _ in 1 2 3 4 5; do
    if systemctl is-active --quiet pdg-web 2>/dev/null; then
      streak=$((streak + 1))
    else
      streak=0
    fi
    [[ "$streak" -ge 3 ]] && return 0
    sleep 1
  done
  return 1
}

_restore_web_service_state(){
  local restore_failed=0
  systemctl daemon-reload >/dev/null 2>&1 || restore_failed=1
  if [[ ! -e /etc/systemd/system/pdg-web.service \
        && "${WEB_WAS_ENABLED:-0}" != 1 \
        && "${WEB_WAS_ACTIVE:-0}" != 1 ]]; then
    return "$restore_failed"
  fi
  if [[ "${WEB_WAS_ENABLED:-0}" == 1 ]]; then
    systemctl enable pdg-web >/dev/null 2>&1 || restore_failed=1
  else
    systemctl disable pdg-web >/dev/null 2>&1 || restore_failed=1
  fi
  if [[ "${WEB_WAS_ACTIVE:-0}" == 1 ]]; then
    systemctl reset-failed pdg-web >/dev/null 2>&1 || true
    systemctl restart pdg-web >/dev/null 2>&1 \
      && _web_service_stable || restore_failed=1
  else
    systemctl stop pdg-web >/dev/null 2>&1 || restore_failed=1
    systemctl is-active --quiet pdg-web 2>/dev/null && restore_failed=1
  fi
  if [[ "${WEB_WAS_ENABLED:-0}" == 1 ]]; then
    systemctl is-enabled --quiet pdg-web >/dev/null 2>&1 || restore_failed=1
  else
    systemctl is-enabled --quiet pdg-web >/dev/null 2>&1 && restore_failed=1
  fi
  return "$restore_failed"
}

rollback(){
  # set +e 只关 errexit, nounset 仍然生效 → 下面一律用 ${VAR:-0} 兜底, 不整体关 nounset。
  set +e
  local failed=()                       # 未能恢复的项; 单项失败不中断后续恢复
  [[ "${ROLLBACK_DONE:-0}" == 1 ]] && return; ROLLBACK_DONE=1
  if [[ "${FORCED_REINSTALL:-0}" == 1 ]]; then
    c_y "覆盖重装中途失败 —— 既有部署的配置可能已被改写。"
    # 配置交给 pdg rollback(有安装前快照), 但**本次事务动过的二进制必须自己还原**:
    # 旧版本的快照未必含内核二进制, 指望 pdg rollback 收拾它们并不可靠。
    local force_snapshot_rc=0
    if ! pdg rollback 0 >/dev/null 2>&1; then
      force_snapshot_rc=1
      failed+=("自动应用覆盖重装前快照")
      [[ -e /etc/privdns-gateway/quic-routing.state ]] \
        && PRESERVE_QUIC_RECOVERY=1
    fi
    _rollback_bins
    _restore_web_service_state \
      || failed+=("恢复 pdg-web 安装前 enabled/active 状态")
    if [[ ${#failed[@]} -eq 0 ]]; then
      c_y "  本次覆盖的二进制已还原(无备份残留)。"
    else
      c_y "  以下二进制未能还原, 请手工检查: ${failed[*]}"
    fi
    if [[ "$force_snapshot_rc" == 0 ]]; then
      c_y "  已自动应用覆盖重装前快照；请运行 sudo pdg doctor 复查。"
    else
      c_y "  自动快照回滚失败；recovery state/profile/helper 已按需保留，请人工运行 sudo pdg rollback。"
    fi
    [[ ${#failed[@]} -eq 0 ]] || return 1
    return 0
  fi
  c_y "安装失败 → 回滚本次全新安装的改动…"
  # 各步骤相互独立: 单项失败只记账, 不挡住后面的恢复; 但也绝不因此谎报"已回滚"。
  local units="pdg-bot.service pdg-probe81.service pdg-web.service mosdns.service sing-box.service mihomo.service
               pdg-mitm.service pdg-quic-routing.service pdg-rules-update.service pdg-health.service
               pdg-rules-update.timer pdg-health.timer"
  local quic_cleanup_failed=0
  for u in $units; do
    [[ -e "/etc/systemd/system/$u" ]] || continue        # 本次没创建过的 unit 不算失败
    systemctl disable --now "$u" >/dev/null 2>&1 || failed+=("停用 $u")
  done
  if [[ "${QUIC_ROUTING_TOUCHED:-0}" == 1 ]]; then
    if [[ -x /usr/local/libexec/pdg-quic-routing.sh ]] \
      && /usr/local/libexec/pdg-quic-routing.sh remove >/dev/null 2>&1 \
      && /usr/local/libexec/pdg-quic-routing.sh cleanup-status >/dev/null 2>&1; then
      :
    else
      quic_cleanup_failed=1
      PRESERVE_QUIC_RECOVERY=1
      failed+=("精确清理/证明 QUIC policy routing（保留 recovery state/profile/helper）")
    fi
  fi
  for u in $units; do
    [[ -e "/etc/systemd/system/$u" ]] || continue
    [[ "$u" == pdg-quic-routing.service && "$quic_cleanup_failed" == 1 ]] && continue
    rm -f "/etc/systemd/system/$u" || failed+=("删除 unit $u")
  done
  for d in /etc/systemd/journald.conf.d/50-pdg.conf /etc/systemd/system/journald.conf.d/50-pdg.conf; do
    [[ -e "$d" ]] || continue                            # 正确 + 历史错路径都删
    rm -f "$d" || failed+=("删除 $d")
  done
  systemctl daemon-reload 2>/dev/null || failed+=("daemon-reload")
  systemctl restart systemd-journald 2>/dev/null || true   # CanReload=no: 必须 restart 才松开封顶
  # 只撤本次合并的 owned 表。不能拿安装前整份 nftables.conf 覆盖当前文件：安装开始后管理员
  # 或其它服务追加的规则也属于当前配置，整份覆盖会把它们一并抹掉。
  if [[ "${NFT_CONFIG_CHANGED:-0}" == 1 ]]; then
    local nft_out
    nft_out="$(mktemp)" || nft_out=""
    if [[ -z "$nft_out" ]] \
      || ! python3 "$REPO_DIR/deploy/bot/nftmerge.py" --remove \
           /etc/nftables.conf "$nft_out" 2>/dev/null \
      || ! pdg_nft_atomic_install "$nft_out" /etc/nftables.conf \
           "$(python3 "$_NFTSCAN" --nft-path 2>/dev/null || true)"; then
      failed+=("从 nftables.conf 摘除 owned PDG 表")
    fi
    [[ -n "$nft_out" ]] && rm -f "$nft_out"
  fi
  if [[ "${NFT_RUNTIME_TOUCHED:-0}" == 1 ]]; then
    local nft_status_rc=0 nft_exe
    python3 "$_NFTSCAN" --table-status=live >/dev/null 2>&1 || nft_status_rc=$?
    if [[ "$nft_status_rc" == 0 ]]; then
      nft_exe="$(python3 "$_NFTSCAN" --nft-path 2>/dev/null || true)"
      if [[ -n "$nft_exe" && -x "$nft_exe" ]]; then
        "$nft_exe" delete table inet pdg 2>/dev/null || failed+=("删除运行态 owned nft 表 inet pdg")
      else
        failed+=("定位 nft 可执行文件")
      fi
    elif [[ "$nft_status_rc" == 3 ]]; then
      failed+=("运行态 table inet pdg 为 foreign，已保留")
    elif [[ "$nft_status_rc" == 2 ]]; then
      failed+=("无法确认运行态 table inet pdg 归属，已保留")
    fi
  fi
  # 按目录事务台账还原: 本次新建的删掉; 装前就存在的按备份原样还原 —— 无差别 rm -rf 会把
  # 装前就在那儿的东西(可能是第三方 sing-box 的配置)一并抹掉, 那不是"回滚"而是破坏。
  # 台账可能还没建(极早期失败) —— 在 set -u 下必须先安全取用, 直接 ${#DIR_TXN[@]} 会 unbound,
  # 那会让回滚自己崩掉并盖住最初的安装错误(正是本项目专门防的那类事故)。
  local dirtxn=(); dirtxn=(${DIR_TXN[@]+"${DIR_TXN[@]}"})
  if [[ ${#dirtxn[@]} -gt 0 ]]; then
    local entry d pre bak
    for entry in "${dirtxn[@]}"; do
      IFS='|' read -r d pre bak <<<"$entry"
      if [[ "$quic_cleanup_failed" == 1 \
            && ( "$d" == /etc/privdns-gateway || "$d" == /opt/pdg-bot ) ]]; then
        continue
      fi
      if [[ "$pre" == 1 ]]; then
        rm -rf "$d" 2>/dev/null
        if [[ -n "$bak" && -d "$bak" ]]; then
          mkdir -p "$d" && cp -a "$bak/." "$d/" 2>/dev/null || failed+=("还原 $d")
          rm -rf "$bak"
        else
          failed+=("还原 $d(备份丢失)")
        fi
      else
        [[ -e "$d" ]] && { rm -rf "$d" || failed+=("删除 $d"); }
      fi
    done
  else
    # 极早期失败时还没有任何已登记的目录改动，故没有目录可撤。绝不能用固定列表猜测
    # “可能是本项目的目录”并 rm -rf；它们可能在安装前就属于其它服务。
    :
  fi
  rm -f /usr/local/bin/{pdg,pdg-set-token,pdg-webctl,proxy-gateway-open-cert-http.sh,proxy-gateway-restore-firewall.sh} \
    || failed+=("删除本次安装的管理脚本")
  if [[ "$quic_cleanup_failed" == 0 ]]; then
    rm -f /usr/local/libexec/pdg-quic-routing.sh \
      || failed+=("删除 QUIC routing helper")
  fi
  if [[ "${SAFE_DIRECTORY_ADDED:-0}" == 1 ]]; then
    git config --system --unset-all safe.directory '/opt/privdns-gateway' 2>/dev/null \
      || failed+=("移除本次添加的 git safe.directory")
  fi
  _rollback_bins        # 按事务台账还原/清除二进制(装前存在的还原原件, 不存在的删半成品)
  # 还原其它系统级改动(仅全新安装才到这里)。逐项独立判定，任一项失败不挡住后续。
  if [[ "${RESOLVED_DISABLED:-0}" == 1 ]]; then
    systemctl enable --now systemd-resolved 2>/dev/null || failed+=("systemd-resolved 恢复")
  fi
  if [[ -e /etc/resolv.conf.pdg-orig ]]; then
    # 同装机那侧: bind-mount 的 resolv.conf 删不掉也 mv 不上去, 但内容能原地写回。
    # 退化路径丢的是"原来是个符号链接"这一属性, 内容(上游 DNS)是对的 —— 比整条还原失败强。
    if rm -f /etc/resolv.conf 2>/dev/null && mv /etc/resolv.conf.pdg-orig /etc/resolv.conf 2>/dev/null; then
      :
    elif cat /etc/resolv.conf.pdg-orig > /etc/resolv.conf 2>/dev/null; then
      rm -f /etc/resolv.conf.pdg-orig 2>/dev/null
    else
      failed+=("resolv.conf 还原")
    fi
  fi
  if [[ ${#failed[@]} -eq 0 ]]; then
    c_y "已回滚到安装前状态。修正问题后可重跑 install.sh。"
  else
    c_y "回滚已尽力执行完, 但以下项未能恢复, 请手工检查: ${failed[*]}"
    return 1
  fi
}
# 不在此处 exit: 让 shell 保持触发退出的原始状态码, 回滚的失败不改写最初的安装错误。
on_exit(){
  local rc="$1"
  if [[ "${INSTALL_OK:-0}" == 1 || "$rc" == 0 ]]; then
    _commit_bins                      # 装成了, 原件备份不再需要
    _commit_dirs                      # 目录 before-image 同样不再需要
    return 0
  fi
  rollback || true                    # 回滚自身的成败已在上面打印, 不改写最初的安装退出码
  return 0
}
trap 'on_exit $?' EXIT

# ── 1. 依赖 ──
c_g "安装依赖…"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
# zstd: 读 mihomo .mrs 规则集的头部(判 domain/ipcidr), 没它大文件就只能让用户手填类型
# iproute2: install.sh 用 ss 探 SSH 端口, pdg status/report/doctor 也靠它看监听 —— 极简
# Debian 12 默认不带, 缺了它"监听端口"整块是空的, 而装机不会报任何错。
apt-get install -y -qq curl tar unzip zstd nftables iproute2 python3 python3-yaml openssl certbot dnsutils tcpdump jq ca-certificates vnstat >/dev/null
python3 -c 'import yaml' >/dev/null 2>&1 \
  || die "python3-yaml 安装后仍无法 import yaml，拒绝安装会在启动后失效的配置导入功能。"
systemctl enable --now vnstat >/dev/null 2>&1 || true   # 网卡流量统计(轻量, ~3MB)

# ── 2. mosdns ──
# 不能只解析 v5.3.4: 官方 stock 与本项目 no-ticket flavor 的语义版本相同。这里要求精确
# build marker + 发布哈希或本地/KFC attestation; stock v5.3.4 必然进入升级路径。
MOSDNS_PREPARED_ARTIFACT_SHA=""; MOSDNS_PREPARED_BINARY_SHA=""
MOSDNS_PREPARED_CHANNEL=""
if ! pdg_mosdns_is_project_build /usr/local/bin/mosdns "$PDG_MOSDNS_ATTESTATION" "$MARCH"; then
  c_g "安装 MosDNS 修补版 $MOSDNS_BUILD_VERSION ($MARCH)…"
  t=$(mktemp -d)
  if ! pdg_prepare_mosdns_candidate "$MARCH" "$t"; then
    rm -rf "$t"
    die "MosDNS 修补产物获取/校验失败 → 拒绝安装；不会回退到官方 stock $MOSDNS_VER。"
  fi
  _stash_bin /usr/local/bin/mosdns || {
    rm -rf "$t"
    die "备份既有 mosdns 失败 → 中止(不在无法回退的前提下覆盖二进制)。"
  }
  install -m755 "$PDG_MOSDNS_PREPARED_BIN" /usr/local/bin/mosdns \
    || { rm -rf "$t"; die "MosDNS 修补候选安装失败"; }
  MOSDNS_PREPARED_ARTIFACT_SHA="$PDG_MOSDNS_PREPARED_ARTIFACT_SHA256"
  MOSDNS_PREPARED_BINARY_SHA="$PDG_MOSDNS_PREPARED_BINARY_SHA256"
  MOSDNS_PREPARED_CHANNEL="$PDG_MOSDNS_PREPARED_CHANNEL"
  # shellcheck disable=SC2034  # 保留为"装成功了吗"的标记并保持 trap 前初始化;
  # 回滚已改看 BIN_TXN 事务台账(它才代表"这次碰过目标没有")。
  MOSDNS_INSTALLED=1
  rm -rf "$t"
fi

# ── 3. 内核: mihomo(clash.meta)—— 唯一流量内核 ──
# 历史上支持 sing-box(1.12.x)/mihomo 二选一; 但 sing-box 1.13 移除了本网关依赖的
# sniff_override_destination、被钉死在死胡同, 故 v1.6.0 起彻底移除 sing-box 运行时,
# mihomo 成唯一内核。旧的 sing-box 机器 `pdg update` 时由 migrate_drop_singbox 自动迁移。
CORE=mihomo
CORE_SVC=mihomo
if ! pdg_mihomo_is_version "$MIHOMO_VER"; then
  c_g "下载 mihomo $MIHOMO_VER ($MARCH)…"
  t=$(mktemp -d)
  curl -fsSL "https://github.com/MetaCubeX/mihomo/releases/download/${MIHOMO_VER}/mihomo-linux-${MARCH}-${MIHOMO_VER}.gz" -o "$t/mihomo.gz"
  pdg_verify_sha256 "$t/mihomo.gz" "${PDG_SHA256[mihomo-$MARCH]:-}" "mihomo $MIHOMO_VER ($MARCH)" \
    || { rm -rf "$t"; die "mihomo 二进制校验未通过 → 拒绝安装(供应链异常, 或版本与 lib/versions.sh 不符)"; }
  gunzip -c "$t/mihomo.gz" > "$t/mihomo"
  _stash_bin /usr/local/bin/mihomo || die "备份既有 mihomo 失败 → 中止(不在无法回退的前提下覆盖二进制)。"
  install -m755 "$t/mihomo" /usr/local/bin/mihomo
  # shellcheck disable=SC2034  # 保留为"装成功了吗"的标记并保持 trap 前初始化;
  # 回滚已改看 BIN_TXN 事务台账(它才代表"这次碰过目标没有")。
  MIHOMO_INSTALLED=1
  rm -rf "$t"
fi

# ── 4. 收集参数 (env 预置优先; PDG_NONINTERACTIVE=1 则不交互) ──
echo
SERVER_IP="${PDG_SERVER_IP:-}"
if [[ -z "$SERVER_IP" ]]; then
  DET_IP=$(curl -fsSL --max-time 8 https://api.ipify.org 2>/dev/null || ip -4 route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}')
  if [[ -n "$NONINT" ]]; then SERVER_IP="$DET_IP"; else ask SERVER_IP "本机公网 IP [${DET_IP}]: " "$DET_IP"; fi
fi
[[ -n "$SERVER_IP" ]] || die "公网 IP 不能为空"
SERVER_IP="$(python3 "$REPO_DIR/deploy/bot/pdgprofile.py" \
  canonical-ipv4 "$SERVER_IP")" \
  || die "PDG_SERVER_IP 必须是安全、canonical 的 IPv4 地址"

SSH_PORT="${PDG_SSH_PORT:-}"
if [[ -z "$SSH_PORT" ]]; then
  DET_SSH=$(ss -lntpH 2>/dev/null | awk '/sshd/{n=split($4,a,":"); print a[n]; exit}'); DET_SSH="${DET_SSH:-22}"
  if [[ -n "$NONINT" ]]; then SSH_PORT="$DET_SSH"; else ask SSH_PORT "SSH 端口 [${DET_SSH}]: " "$DET_SSH"; fi
fi

INTERNAL_CIDR="${PDG_INTERNAL_CIDR:-}"
if [[ -z "$INTERNAL_CIDR" ]]; then
  if [[ -n "$NONINT" ]]; then
    INTERNAL_CIDR="172.16.0.0/12"
  else
    echo; c_y "识别【内网卡来源段】(抓包 ~90s; 期间可随时直接手输网段, 谁先给出结果就用谁)"
    # 抓包与手输并行: 知道网段的人不必干等 90 秒, 抓到了也不用再确认一遍。
    INTERNAL_CIDR="$(pdg_detect_cidr_race 90 "$SERVER_IP" || true)"
    if [[ -n "$INTERNAL_CIDR" ]]; then
      c_g "内网卡来源段: $INTERNAL_CIDR"
    else
      c_y "没抓到(手机没走内网卡? 云安全组挡了 80/ICMP?)。"
      c_y "先手填一个即可; 装完再从容跑 \`sudo pdg detect-cidr\` 重新识别并一键应用。"
    fi
    # 取不到/填错都再给机会 —— 等满 90 秒后因一个空回车就回滚整场安装, 那是白等。
    _cidr_try=0
    while ! pdg_cidr_valid "$INTERNAL_CIDR"; do
      [[ -n "$INTERNAL_CIDR" ]] && c_y "「$INTERNAL_CIDR」不是合法网段(形如 172.22.0.0/16)。"
      _cidr_try=$((_cidr_try + 1))
      if [[ "$_cidr_try" -gt 3 ]]; then
        die "未取得内网卡来源段 (形如 172.22.0.0/16; 非交互/无终端请用 PDG_INTERNAL_CIDR)"
      fi
      # 无终端时再问也白问(ask 会立刻回空), 直接给出可操作的出路, 不空转三次
      if ! { true < /dev/tty; } 2>/dev/null; then
        die "无可用终端且未取得内网卡来源段 (请用 PDG_INTERNAL_CIDR=172.22.0.0/16 重跑)"
      fi
      ask INTERNAL_CIDR "内网卡来源段 CIDR (如 172.22.0.0/16): " ""
    done
  fi
fi
# Validate every source, including noninteractive env input, and persist only
# canonical network notation.  The renderer repeats this check before touching
# nftables, so a CIDR-shaped nft injection can never reach the template.
INTERNAL_CIDR="$(python3 "$REPO_DIR/deploy/bot/pdgprofile.py" \
  canonical-cidr "$INTERNAL_CIDR")" \
  || die "PDG_INTERNAL_CIDR 不是安全的 IPv4 CIDR"

# 手机平台: ios | android。一台网关服务一个内网卡手机号, 故平台是每台装机的固定属性。
# 决定客户端下发方式(iOS 描述文件 / 安卓私密DNS)+ 是否提供 iOS 专属功能(如 MITM 插件, 安卓需 root 故不提供)。
PLATFORM="${PDG_PLATFORM:-}"
# 覆盖重装(PDG_FORCE_REINSTALL)未显式传 PDG_PLATFORM 时: 优先沿用已有平台标记 —— 不能默认把 iOS 改成 Android。
if [[ -z "$PLATFORM" ]]; then
  # 全新装时该文件尚不存在, cat 返 1 —— 在 set -e 下"赋值里命令替换失败"是致命错误, 会当场
  # 中止并回滚(屏幕上只剩"安装失败", 真原因被埋掉; 正是交互全新装偏偏挂在这里的根因)。故 || true。
  _ep="$(cat /etc/privdns-gateway/platform 2>/dev/null || true)"
  [[ "$_ep" == ios || "$_ep" == android ]] && { PLATFORM="$_ep"; c_g "沿用已有平台标记: $PLATFORM"; }
fi
if [[ -z "$PLATFORM" ]]; then
  if [[ -n "$NONINT" ]]; then PLATFORM="android"
  else
    echo; c_y "你的手机平台?(决定客户端下发 + iOS 专属功能;一台网关对一个手机)"
    _p=""; ask _p "平台 [1=iOS / 2=Android, 默认 2]: " ""
    case "$_p" in 1 | ios | iOS | IOS) PLATFORM=ios;; *) PLATFORM=android;; esac
  fi
fi
[[ "$PLATFORM" == ios || "$PLATFORM" == android ]] || die "PDG_PLATFORM 只能是 ios 或 android"

# Transparent data-plane intent is resolved once, strictly, from environment
# overrides plus the persisted profile.  Every later Mihomo/nft/systemd render
# consumes these normalized values; no lifecycle hook is allowed to invent a
# second set of defaults.
_PDGPROFILE="$REPO_DIR/deploy/bot/pdgprofile.py"
[[ -f "$_PDGPROFILE" ]] || die "缺少严格 profile 渲染器 $_PDGPROFILE"
_dp_lines="$(python3 "$_PDGPROFILE" --profile /etc/privdns-gateway/profile.env \
  --platform "$PLATFORM" --ssh-port "$SSH_PORT" --listener-preflight lines)" \
  || die "QUIC/TCP 劫持 profile 校验失败（未写入配置）。"
QUIC_MODE="" HIJACK_TLS_TCP_PORTS="" HIJACK_HTTP_TCP_PORTS=""
QUIC_MARK="" QUIC_MARK_MASK="" QUIC_ROUTE_TABLE="" QUIC_RULE_PRIORITY=""
_dp_seen=0
while IFS='=' read -r _dp_key _dp_value; do
  case "$_dp_key" in
    PDG_QUIC_MODE) QUIC_MODE="$_dp_value";;
    PDG_HIJACK_TLS_TCP_PORTS) HIJACK_TLS_TCP_PORTS="$_dp_value";;
    PDG_HIJACK_HTTP_TCP_PORTS) HIJACK_HTTP_TCP_PORTS="$_dp_value";;
    PDG_QUIC_MARK) QUIC_MARK="$_dp_value";;
    PDG_QUIC_MARK_MASK) QUIC_MARK_MASK="$_dp_value";;
    PDG_QUIC_ROUTE_TABLE) QUIC_ROUTE_TABLE="$_dp_value";;
    PDG_QUIC_RULE_PRIORITY) QUIC_RULE_PRIORITY="$_dp_value";;
    *) die "严格 profile 渲染器返回未知键: $_dp_key";;
  esac
  _dp_seen=$((_dp_seen + 1))
done <<<"$_dp_lines"
[[ "$_dp_seen" == 7 && -n "$QUIC_MODE" && -n "$HIJACK_TLS_TCP_PORTS" \
   && -n "$HIJACK_HTTP_TCP_PORTS" && -n "$QUIC_MARK" \
   && -n "$QUIC_MARK_MASK" && -n "$QUIC_ROUTE_TABLE" \
   && -n "$QUIC_RULE_PRIORITY" ]] \
  || die "严格 profile 渲染器返回不完整，拒绝继续。"

BOT_TOKEN="${PDG_BOT_TOKEN:-}"; ALLOWED_IDS="${PDG_ALLOWED:-}"; DOT_DOMAIN="${PDG_DOT_DOMAIN:-}"
if [[ -z "$NONINT" ]]; then
  echo
  if [[ -z "$BOT_TOKEN" ]]; then
    c_y "提示: 出口(落地节点)和分流规则都在 Telegram bot 里设置。不填 token 也能装完,"
    c_y "      但要等之后 sudo pdg-set-token 设好 token、给 bot 发 /start 才能配代理。"
    ask BOT_TOKEN "Telegram bot token (可留空): " ""
  fi
  if [[ -n "$BOT_TOKEN" && -z "$ALLOWED_IDS" ]]; then ask ALLOWED_IDS "你的 Telegram user id (只允许它管理): " ""; fi
  [[ -n "$DOT_DOMAIN" ]] || ask DOT_DOMAIN "DoT 域名 (如 dot.example.com): " ""
fi
[[ -n "$DOT_DOMAIN" ]] || die "DoT 域名不能为空 (非交互请用 PDG_DOT_DOMAIN)"
DOT_DOMAIN="$(python3 "$_PDGPROFILE" canonical-hostname "$DOT_DOMAIN")" \
  || die "PDG_DOT_DOMAIN 必须是安全、lowercase canonical hostname"
# token / user id 可留空 → 装完先不启 bot, 之后 sudo pdg-set-token 补

# ── 5. 目录 + 静态文件 ──
c_g "铺设文件…"
# 记目录事务: 在**动这些目录之前**记下"装前存在吗", 存在的先备份一份内容。
# 回滚据此只撤本次的改动: 本次新建的删掉, 装前就有的按备份还原(不再无差别 rm -rf)。
_dir_txn_record(){
  local d bak
  for d in "$@"; do
    if [[ -e "$d" ]]; then
      bak="$(mktemp -d)" || { c_y "无法为 $d 备份 → 中止(拒绝在无法回退的前提下改动它)"; return 1; }
      cp -a "$d/." "$bak/" 2>/dev/null || { rm -rf "$bak"; c_y "备份 $d 失败 → 中止"; return 1; }
      DIR_TXN+=("$d|1|$bak")
    else
      DIR_TXN+=("$d|0|")
    fi
  done
}
if [[ "$REPO_DIR" == /opt/privdns-gateway ]]; then
  _dir_txn_record /etc/mosdns /etc/sing-box /etc/mihomo /opt/pdg-bot /opt/pdg-web /etc/privdns-gateway \
    /var/lib/privdns-gateway \
    || die "目录备份失败, 未改动任何文件。"
else
  # 仓库目标也必须先入账。失败时：装前不存在就删除，装前存在就原样还原。
  _dir_txn_record /etc/mosdns /etc/sing-box /etc/mihomo /opt/pdg-bot /opt/pdg-web /etc/privdns-gateway \
    /var/lib/privdns-gateway /opt/privdns-gateway \
    || die "目录备份失败, 未改动任何文件。"
fi
install -d /etc/mosdns/rules /etc/sing-box/rs /opt/pdg-bot /opt/pdg-web/static/templates "$CERT_DIR" \
  /etc/letsencrypt/renewal-hooks/deploy /etc/systemd/journald.conf.d \
  /usr/local/libexec
# Persistent Web maintenance records are command authority.  Pre-create their
# final directory root:root/0700 instead of relying on a later chmod-only fixup.
install -d -o root -g root -m700 /var/lib/privdns-gateway/web-jobs
install -d -o root -g root -m700 /var/lib/privdns-gateway/web-imports
install -d -o root -g root -m700 /etc/mihomo/providers
if [[ "$MOSDNS_INSTALLED" == 1 ]]; then
  pdg_write_mosdns_attestation "$PDG_MOSDNS_ATTESTATION" "$MARCH" \
    "$MOSDNS_PREPARED_ARTIFACT_SHA" "$MOSDNS_PREPARED_BINARY_SHA" \
    "$MOSDNS_PREPARED_CHANNEL" \
    || die "MosDNS 安装证明写入失败 → 中止并回滚二进制/配置"
  pdg_mosdns_is_project_build /usr/local/bin/mosdns "$PDG_MOSDNS_ATTESTATION" "$MARCH" \
    || die "MosDNS 安装后 provenance 复核失败 → 中止并回滚"
fi
install -m755 "$REPO_DIR"/deploy/bot/pdg-bot.py            /opt/pdg-bot/bot.py
install -m755 "$REPO_DIR"/deploy/bot/parse-geosite.py     /opt/pdg-bot/
install -m755 "$REPO_DIR"/deploy/bot/update-rules.sh      /opt/pdg-bot/
install -m755 "$REPO_DIR"/deploy/bot/scheduled-update.sh  /opt/pdg-bot/
install -m755 "$REPO_DIR"/deploy/bot/healthcheck.py      /opt/pdg-bot/
install -m755 "$REPO_DIR"/deploy/bot/checks.py           /opt/pdg-bot/
install -m755 "$REPO_DIR"/deploy/bot/dot_session_probe.py /opt/pdg-bot/
install -m755 "$REPO_DIR"/deploy/bot/nftscan.py          /opt/pdg-bot/
install -m755 "$REPO_DIR"/deploy/bot/pdgtx.py            /opt/pdg-bot/
install -m755 "$REPO_DIR"/deploy/bot/nftmerge.py         /opt/pdg-bot/
install -m755 "$REPO_DIR"/deploy/bot/doctor.py           /opt/pdg-bot/
install -m755 "$REPO_DIR"/deploy/bot/report.py           /opt/pdg-bot/
install -m755 "$REPO_DIR"/deploy/bot/sb2mihomo.py        /opt/pdg-bot/
install -m755 "$REPO_DIR"/deploy/bot/pdgmodel.py         /opt/pdg-bot/
install -m755 "$REPO_DIR"/deploy/bot/pdgprofile.py        /opt/pdg-bot/
# 可选 Web 管理面只铺设代码与 unit，默认不配置、不启用，也不修改任何 input/firewall。
install -m755 "$REPO_DIR"/deploy/web/pdg-web.py           /opt/pdg-web/
install -m755 "$REPO_DIR"/deploy/web/pdg-web-job.py       /opt/pdg-web/
install -m755 "$REPO_DIR"/deploy/web/pdgcontrol.py        /opt/pdg-web/
install -m755 "$REPO_DIR"/deploy/web/pdgconfigio.py       /opt/pdg-web/
install -m755 "$REPO_DIR"/deploy/web/pdg-web-setup.py     /opt/pdg-web/
install -m644 "$REPO_DIR"/deploy/web/pdgwebconfig.py      /opt/pdg-web/
install -m644 "$REPO_DIR"/deploy/web/static/index.html    /opt/pdg-web/static/
install -m644 "$REPO_DIR"/deploy/web/static/app.js        /opt/pdg-web/static/
install -m644 "$REPO_DIR"/deploy/web/static/style.css     /opt/pdg-web/static/
install -m644 "$REPO_DIR"/deploy/web/static/manifest.webmanifest /opt/pdg-web/static/
install -m644 "$REPO_DIR"/deploy/web/static/icon.svg      /opt/pdg-web/static/
install -m644 "$REPO_DIR"/deploy/web/static/templates/mihomo-import.example.yaml /opt/pdg-web/static/templates/
install -m644 "$REPO_DIR"/deploy/web/static/templates/mosdns-import.example.yaml /opt/pdg-web/static/templates/
# iOS 专属组件(MITM 模块 / :81 探测 / 描述文件模板)只在 iOS 平台安装; Android 不装。
if [[ "$PLATFORM" == ios ]]; then
  install -m755 "$REPO_DIR"/deploy/bot/mitm_ca.py          /opt/pdg-bot/
  install -m755 "$REPO_DIR"/deploy/bot/mitm_server.py      /opt/pdg-bot/
  install -m755 "$REPO_DIR"/deploy/bot/mitm_wloc.py        /opt/pdg-bot/
  install -m755 "$REPO_DIR"/deploy/ios/probe81.py           /opt/pdg-bot/
  install -m644 "$REPO_DIR"/deploy/ios/pdg-dot-ondemand.mobileconfig.tmpl /opt/pdg-bot/pdg-dot.mobileconfig.tmpl
fi
install -m755 "$REPO_DIR"/deploy/cert/proxy-gateway-open-cert-http.sh     /usr/local/bin/
install -m755 "$REPO_DIR"/deploy/cert/proxy-gateway-restore-firewall.sh   /usr/local/bin/
_stash_bin /etc/letsencrypt/renewal-hooks/deploy/99-pdg-cert.sh \
  || die "备份既有证书 deploy hook 失败"
install -m755 "$REPO_DIR"/deploy/cert/99-reload-cert.deploy-hook.sh       /etc/letsencrypt/renewal-hooks/deploy/99-pdg-cert.sh
install -m755 "$REPO_DIR"/deploy/bot/pdg-set-token.sh                     /usr/local/bin/pdg-set-token
install -m755 "$REPO_DIR"/deploy/bot/pdg.sh                               /usr/local/bin/pdg
_stash_bin /usr/local/bin/pdg-webctl \
  || die "备份既有 pdg-webctl 失败"
install -m755 "$REPO_DIR"/deploy/web/pdg-webctl.sh                         /usr/local/bin/pdg-webctl
_stash_bin /etc/systemd/system/pdg-web.service \
  || die "备份既有 pdg-web.service 失败"
install -m644 "$REPO_DIR"/deploy/web/pdg-web.service                      /etc/systemd/system/pdg-web.service
_stash_bin /usr/local/libexec/pdg-quic-routing.sh \
  || die "备份既有 QUIC helper 失败"
_stash_bin /etc/systemd/system/pdg-quic-routing.service \
  || die "备份既有 QUIC unit 失败"
install -m755 "$REPO_DIR"/deploy/firewall/pdg-quic-routing.sh \
  /usr/local/libexec/pdg-quic-routing.sh
install -m644 "$REPO_DIR"/deploy/firewall/pdg-quic-routing.service \
  /etc/systemd/system/pdg-quic-routing.service
# 把仓库放到 /opt/privdns-gateway 供 `pdg update` / `pdg uninstall` 用。
# 复制失败**必须中止**: 旧写法 `|| true` 吞掉错误, 装完机器上没有仓库副本, 之后 pdg update
# 和 pdg uninstall 都无从谈起, 而装机全程一句提示都没有。
if [[ "$REPO_DIR" != "/opt/privdns-gateway" ]]; then
  # 每次都从本次实际执行的源码刷新目标，而不是只看“.git 是否存在”。后者会复用上次
  # 失败留下的旧副本。先完整复制到 /opt 同文件系统临时目录，验证后才替换目标；目录事务
  # 已保存目标 before-image，替换之后任一步失败都能还原。
  _repo_tmp="$(mktemp -d /opt/.privdns-gateway.copy.XXXXXX)" \
    || die "无法创建仓库复制临时目录"
  if ! cp -a "$REPO_DIR/." "$_repo_tmp/" || [[ ! -d "$_repo_tmp/.git" ]]; then
    rm -rf "$_repo_tmp"
    die "复制仓库到临时目录失败(磁盘满/权限?)"
  fi
  rm -rf /opt/privdns-gateway \
    || { rm -rf "$_repo_tmp"; die "无法替换旧的 /opt/privdns-gateway"; }
  mv "$_repo_tmp" /opt/privdns-gateway \
    || { rm -rf "$_repo_tmp"; die "仓库副本落位失败"; }
fi
# 属主统一收归 root: 用户常见做法是普通账号 git clone 后 sudo ./install.sh, 复制过去的副本
# 于是归那个普通用户所有。之后 root 跑 pdg update, git 会以 "dubious ownership" 拒绝一切操作
# (连 describe/tag 都读不到), 表现成"更新检查不出新版"这种莫名其妙的样子。
chown -R root:root /opt/privdns-gateway 2>/dev/null || true
if ! git config --system --get-all safe.directory 2>/dev/null | grep -qx '/opt/privdns-gateway'; then
  if git config --system --add safe.directory /opt/privdns-gateway 2>/dev/null; then
    SAFE_DIRECTORY_ADDED=1
  else
    c_y "无法写 git safe.directory；之后 pdg update 可能需要手工配置。"
  fi
fi
: > /etc/mosdns/rules/custom_direct.txt
: > /etc/mosdns/rules/ruleset_direct.txt  # target=direct 规则集聚合；Bot 仅在同一 pdgtx 事务内派生
: > /etc/mosdns/rules/custom_hijack.txt   # bot 指到出口的域名(必须被 mosdns 劫持才会进代理)
: > /etc/mosdns/rules/ruleset_hijack.txt # 指到 VPS 出口的 source 规则集聚合；与路由事务同步派生
: > /etc/mosdns/rules/unlock.txt          # WDA 解锁域名集(空=休眠; bot『🔓 解锁走 WDA』填充)
: > /etc/mosdns/rules/mitm_hijack.txt     # MITM 接管域名集(空=休眠; iOS 启用 MITM 插件时填充)

# 内存模式(克制版): PDG_LOWMEM=auto(默认)|1|0; MemTotal ≤ 1300MiB 判低内存。持久化到 profile.env。
# 只调确认安全的项: mosdns cache(8192/2048)+ journald 上限(50M/20M)。不动 sysctl/swap/MemoryMax。
case "${PDG_LOWMEM:-auto}" in
  1) LOWMEM=1;; 0) LOWMEM=0;;
  *) _cur=""; [[ -f /etc/privdns-gateway/profile.env ]] && _cur=$(sed -n 's/^PDG_LOWMEM=//p' /etc/privdns-gateway/profile.env | tail -1)
     if [[ "$_cur" == 0 || "$_cur" == 1 ]]; then LOWMEM="$_cur"   # 已固定的模式沿用(强制重装不覆盖用户选择)
     else _mt=$(sed -n 's/^MemTotal:[[:space:]]*\([0-9]*\).*/\1/p' /proc/meminfo 2>/dev/null)
          if [[ -n "$_mt" && "$_mt" -le 1331200 ]]; then LOWMEM=1; else LOWMEM=0; fi; fi;;
esac
if [[ "$LOWMEM" == 1 ]]; then MOSDNS_CACHE=2048; JOURNALD_MAXUSE=20M; else MOSDNS_CACHE=8192; JOURNALD_MAXUSE=50M; fi

# 劫持模式: all(默认, 非CN域名全劫持进代理) | gfw(只劫持 GFWList 真被墙域名, 非墙海外域名返真实IP直连)。
# gfw 模式修 "SSH/直连走域名被劫持到网关" 的问题; 但要求内网卡 SIM 能直达一般互联网(非墙海外可达)。持久化到 profile.env。
case "${PDG_HIJACK_MODE:-}" in
  gfw) HIJACK_MODE=gfw;; all) HIJACK_MODE=all;;
  *) _hm=""; [[ -f /etc/privdns-gateway/profile.env ]] && _hm=$(sed -n 's/^PDG_HIJACK_MODE=//p' /etc/privdns-gateway/profile.env | tail -1)
     [[ "$_hm" == gfw || "$_hm" == all ]] && HIJACK_MODE="$_hm" || HIJACK_MODE=all;;
esac
[[ "$HIJACK_MODE" == gfw ]] && HIJACK_SET_FILE="geosite_gfw.txt" || HIJACK_SET_FILE="geosite_geolocation-!cn.txt"

install -d -m700 /etc/privdns-gateway
# Write every render-driving key atomically. Existing reinstall keeps unknown
# keys, but it may not keep duplicate/invalid managed keys (strict resolver
# above has already rejected those).
# 保留 profile.env 里其余键 —— 尤其 PDG_TFO(bot 持久化的 TFO 意图)与未知/自定义键, 不被重装清掉。
#
# 走临时文件 + 原子替换, 且每一步的失败都要看见。旧写法是
#     { printf …; [[ -f old ]] && grep -v … old; } > new && mv new old
# 新装时 `[[ -f old ]]` 为假 → 整个 group 返回 1 → `&& mv` 不执行(而 && 列表里的失败又不触发
# set -e), 于是机器上只剩一个 profile.env.new: PDG_HIJACK_MODE 根本没落盘, 下一次 pdg restart
# 读不到就按默认 all 把 mosdns 形态改回去 —— 装机时选的 gfw 悄悄没了。
_prof_tmp="$(mktemp /etc/privdns-gateway/.profile.env.XXXXXX)" || die "创建 profile.env 临时文件失败"
{
  printf '%s\n' \
    "PDG_LOWMEM=$LOWMEM" \
    "PDG_HIJACK_MODE=$HIJACK_MODE" \
    "PDG_PLATFORM=$PLATFORM" \
    "PDG_FIREWALL_MODE=$FIREWALL_MODE" \
    "PDG_INTERNAL_CIDR=$INTERNAL_CIDR" \
    "PDG_SSH_PORT=$SSH_PORT" \
    "PDG_QUIC_MODE=$QUIC_MODE" \
    "PDG_HIJACK_TLS_TCP_PORTS=$HIJACK_TLS_TCP_PORTS" \
    "PDG_HIJACK_HTTP_TCP_PORTS=$HIJACK_HTTP_TCP_PORTS" \
    "PDG_QUIC_MARK=$QUIC_MARK" \
    "PDG_QUIC_MARK_MASK=$QUIC_MARK_MASK" \
    "PDG_QUIC_ROUTE_TABLE=$QUIC_ROUTE_TABLE" \
    "PDG_QUIC_RULE_PRIORITY=$QUIC_RULE_PRIORITY"
  if [[ -f /etc/privdns-gateway/profile.env ]]; then
    # grep -v 在"旧文件只有受管键"时没有输出 → 返回 1, 不能让它把整段判成失败
    grep -vE '^[[:space:]]*(PDG_LOWMEM|PDG_HIJACK_MODE|PDG_PLATFORM|PDG_FIREWALL_MODE|PDG_INTERNAL_CIDR|PDG_SSH_PORT|PDG_QUIC_MODE|PDG_HIJACK_TLS_TCP_PORTS|PDG_HIJACK_HTTP_TCP_PORTS|PDG_QUIC_MARK|PDG_QUIC_MARK_MASK|PDG_QUIC_ROUTE_TABLE|PDG_QUIC_RULE_PRIORITY)=' \
      /etc/privdns-gateway/profile.env || true
  fi
} > "$_prof_tmp" || { rm -f "$_prof_tmp"; die "写 profile.env 失败(磁盘满/只读?)"; }
chmod 600 "$_prof_tmp"
mv -f "$_prof_tmp" /etc/privdns-gateway/profile.env \
  || { rm -f "$_prof_tmp"; die "落盘 profile.env 失败"; }
rm -f /etc/privdns-gateway/profile.env.new          # 清掉历史版本留下的半成品
grep -q "^PDG_HIJACK_MODE=$HIJACK_MODE$" /etc/privdns-gateway/profile.env \
  || die "profile.env 未写入预期的 PDG_HIJACK_MODE"
grep -q "^PDG_FIREWALL_MODE=$FIREWALL_MODE$" /etc/privdns-gateway/profile.env \
  || die "profile.env 未写入预期的 PDG_FIREWALL_MODE"
grep -q "^PDG_QUIC_MODE=$QUIC_MODE$" /etc/privdns-gateway/profile.env \
  || die "profile.env 未写入预期的 PDG_QUIC_MODE"
grep -q "^PDG_HIJACK_TLS_TCP_PORTS=$HIJACK_TLS_TCP_PORTS$" \
  /etc/privdns-gateway/profile.env \
  || die "profile.env 未写入预期的 PDG_HIJACK_TLS_TCP_PORTS"
grep -q "^PDG_HIJACK_HTTP_TCP_PORTS=$HIJACK_HTTP_TCP_PORTS$" \
  /etc/privdns-gateway/profile.env \
  || die "profile.env 未写入预期的 PDG_HIJACK_HTTP_TCP_PORTS"
_fm_tmp="$(mktemp /etc/privdns-gateway/.firewall-mode.XXXXXX)" \
  || die "创建 firewall-mode 临时文件失败"
printf '%s\n' "$FIREWALL_MODE" > "$_fm_tmp" \
  || { rm -f "$_fm_tmp"; die "写 firewall-mode 失败"; }
chmod 600 "$_fm_tmp"
mv -f "$_fm_tmp" /etc/privdns-gateway/firewall-mode \
  || { rm -f "$_fm_tmp"; die "落盘 firewall-mode 失败"; }
printf '%s\n' "$PLATFORM" > /etc/privdns-gateway/platform
/usr/local/libexec/pdg-quic-routing.sh preflight \
  || die "原生 QUIC policy-routing 冲突预检失败；未接管现有 rule/route。"

render(){ sed -e "s|__SERVER_IP__|$SERVER_IP|g" -e "s|__INTERNAL_CIDR__|$INTERNAL_CIDR|g" \
              -e "s|__CERT_DIR__|$CERT_DIR|g"   -e "s|__SSH_PORT__|$SSH_PORT|g" \
              -e "s|__FIREWALL_MODE__|$FIREWALL_MODE|g" \
              -e "s|__MOSDNS_CACHE__|$MOSDNS_CACHE|g" -e "s|__JOURNALD_MAXUSE__|$JOURNALD_MAXUSE|g" \
              -e "s|__HIJACK_SET_FILE__|$HIJACK_SET_FILE|g" "$1"; }

render "$REPO_DIR/deploy/mosdns/config.yaml"          > /etc/mosdns/config.yaml
# 模板自带 gfw 那道劫持门; all 模式要去掉它 —— all 的语义是"不是国内就劫持"(排除式),
# 留着门会退化成"只劫持 geosite 策展分类里的域名"。
_mosdns_hijack_shape "$HIJACK_MODE" /etc/mosdns/config.yaml "$HIJACK_SET_FILE" >/dev/null \
  || die "mosdns 劫持形态渲染失败"
render "$REPO_DIR/deploy/singbox/config.json.tmpl"    > /etc/sing-box/config.json   # 始终是 bot 的数据模型(mihomo 模式下也由它渲染)
# iOS: 模板含 GMS(in-gms-5228/5229/5230)入站, iOS 走 APNs 不需要 → 删掉, 让 canonical model 从一开始就无 GMS。
if [[ "$PLATFORM" == ios ]]; then
  python3 - /etc/sing-box/config.json <<'PY'
import json, sys
f = sys.argv[1]; c = json.load(open(f))
c["inbounds"] = [i for i in c.get("inbounds", []) if i.get("tag") not in ("in-gms-5228", "in-gms-5229", "in-gms-5230")]
json.dump(c, open(f, "w"), ensure_ascii=False, indent=2)
PY
fi
chmod 700 /etc/sing-box; chmod 600 /etc/sing-box/config.json   # config 含出口密码/uuid
# /etc/sing-box 是本项目的**数据模型**目录(即便 v1.6 起已不装 sing-box 运行时)。落一份归属
# 标记, 卸载 --purge 才知道该删它 —— 里面是出口密码/UUID/节点地址, 留在盘上等于凭据没清。
# 标记落在 /etc/privdns-gateway 下, 已在目录事务台账里(装机失败回滚会连它一起还原)。
pdg_sbmodel_mark_owned || die "写数据模型归属标记失败(磁盘满/只读?)"
# 内核后端: 标记(恒 mihomo)+ 防火墙(mihomo REDIRECT 入站变体)+ 初始渲染 mihomo 配置
printf '%s\n' "$CORE" > /etc/privdns-gateway/backend
# 防火墙: **合并**而不是整文件覆盖 —— 用户的 VPN/NAT/转发/开放端口原样保留(与迁移同一实现)。
# iOS 的 GMS 剥离在**渲染出来的块上**做, 不在合并结果上做: 后者会拿正则去扫用户自己的规则行。
_nft_block="$(mktemp)"; _nft_merged="$(mktemp)"
python3 "$_PDGPROFILE" --profile /etc/privdns-gateway/profile.env \
  --profile-only --platform "$PLATFORM" --ssh-port "$SSH_PORT" render-nft \
  --template "$REPO_DIR/deploy/firewall/nftables-mihomo.conf" \
  --internal-cidr "$INTERNAL_CIDR" --firewall-mode "$FIREWALL_MODE" \
  > "$_nft_block" \
  || { rm -f "$_nft_block" "$_nft_merged"; die "防火墙 data-plane 渲染失败"; }
python3 "$REPO_DIR/deploy/bot/nftmerge.py" --mode "$FIREWALL_MODE" \
  "$_nft_block" /etc/nftables.conf "$_nft_merged" \
  || { rm -f "$_nft_block" "$_nft_merged"
       die "无法安全合并 /etc/nftables.conf(见上方冲突位置)→ 未改动防火墙。
  请把本项目所需规则手工并入 table inet pdg 后重试, 或先备份并清理冲突配置。"; }
# 用与扫描器同一份解析结果调 nft(PATH 缺 sbin 时不能因此跳过校验 —— 那等于不校验就落盘)
_nft_exe="$(python3 "$_NFTSCAN" --nft-path 2>/dev/null || true)"
[[ -n "$_nft_exe" && -x "$_nft_exe" ]] || _nft_exe=""     # 输出不是可执行文件就当没拿到
if [[ -n "$_nft_exe" ]] && ! "$_nft_exe" -c -f "$_nft_merged" >/dev/null 2>&1; then
  rm -f "$_nft_block" "$_nft_merged"; die "合并后的 nftables 配置校验(nft -c)未过 → 未改动防火墙。"
fi
pdg_nft_atomic_install "$_nft_merged" /etc/nftables.conf "$_nft_exe" \
  || { rm -f "$_nft_block" "$_nft_merged"; die "原子写入 /etc/nftables.conf 失败"; }
NFT_CONFIG_CHANGED=1
rm -f "$_nft_block" "$_nft_merged"
install -d -m700 /etc/mihomo
python3 - <<PY
import json, os, sys
sys.path.insert(0, "$REPO_DIR/deploy/bot")
import sb2mihomo
model = json.load(open("/etc/sing-box/config.json"))   # config.json 仍是核无关的数据模型
import pdgprofile
dp = pdgprofile.resolve(
    "/etc/privdns-gateway/profile.env", platform="$PLATFORM", environ={})
cfg, _ = sb2mihomo.singbox_to_mihomo(
    model, redir_port=7893, quic_mode=dp["quic_mode"],
    tproxy_port=dp["tproxy_port"], tls_ports=dp["tls_ports"],
    http_ports=dp["http_ports"])
with open("/etc/mihomo/config.yaml", "w") as f:
    json.dump(cfg, f, ensure_ascii=False, indent=2)   # JSON 即合法 YAML
os.chmod("/etc/mihomo/config.yaml", 0o600)
PY
render "$REPO_DIR/deploy/bot/pdg-bot.service"         > /etc/systemd/system/pdg-bot.service
chmod 644 /etc/systemd/system/pdg-bot.service        # 不再含 token (token 在 bot.env)

# token / 允许 id 写入受限的 bot.env (目录 700 / 文件 600), 不进 unit 也不进版本库
install -d -m700 /etc/privdns-gateway
( umask 077; printf 'PDG_BOT_TOKEN=%s\nPDG_BOT_ALLOWED=%s\n' "$BOT_TOKEN" "$ALLOWED_IDS" > /etc/privdns-gateway/bot.env )
chmod 600 /etc/privdns-gateway/bot.env
install -m644 "$REPO_DIR"/deploy/bot/pdg-rules-update.service /etc/systemd/system/
install -m644 "$REPO_DIR"/deploy/bot/pdg-rules-update.timer   /etc/systemd/system/
install -m644 "$REPO_DIR"/deploy/bot/pdg-health.service       /etc/systemd/system/
install -m644 "$REPO_DIR"/deploy/bot/pdg-health.timer         /etc/systemd/system/
# pdg-probe81(:81 探测)是 iOS 专属, 仅 iOS 装 unit; Android 不装、不起、不开 81。
[[ "$PLATFORM" == ios ]] && install -m644 "$REPO_DIR"/deploy/ios/pdg-probe81.service /etc/systemd/system/
render "$REPO_DIR/deploy/firewall/journald-50-pdg.conf" > /etc/systemd/journald.conf.d/50-pdg.conf; chmod 644 /etc/systemd/journald.conf.d/50-pdg.conf

cat > /etc/systemd/system/mosdns.service <<'EOF'
[Unit]
Description=mosdns
After=network-online.target
Wants=network-online.target
[Service]
ExecStart=/usr/local/bin/mosdns start -d /etc/mosdns
Restart=on-failure
RestartSec=3
[Install]
WantedBy=multi-user.target
EOF
pdg_write_unit pdg_unit_mihomo /etc/systemd/system/mihomo.service

# pdg-mitm: MITM 插件服务(Feature B, 仅 iOS)。按 /etc/privdns-gateway/mitm.json 加载启用的插件。
if [[ "$PLATFORM" == ios ]]; then
  pdg_write_unit pdg_unit_pdg_mitm /etc/systemd/system/pdg-mitm.service
fi

# ── 6. DoT 证书 ──
if [[ -n "${PDG_SKIP_CERT:-}" ]]; then
  c_y "PDG_SKIP_CERT: 跳过 certbot, 生成自签占位证书 (生产请用 bot『🌐 DoT 自定义域名』补正式证书)"
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "$CERT_DIR/privkey.pem" \
    -out "$CERT_DIR/fullchain.pem" -days 3650 -subj "/CN=$DOT_DOMAIN" >/dev/null 2>&1
  chmod 644 "$CERT_DIR/fullchain.pem"; chmod 600 "$CERT_DIR/privkey.pem"
  echo "$DOT_DOMAIN" > /opt/pdg-bot/dot-domain
else
  echo
  c_y "现在签 DoT 证书。请先确认: $DOT_DOMAIN 的 A 记录已指向 $SERVER_IP"
  c_y "(Cloudflare 等用『灰云 / DNS only』, 不要开代理; 等生效后再继续)"
  # 交互暂停确认 A 记录: 撞 EOF/无终端不该触发 errexit → 直接继续(等同回车); Ctrl-C 仍能中止。
  if [[ -z "$NONINT" ]] && { true < /dev/tty; } 2>/dev/null; then
    read -rp "A 记录已指好? 回车继续签发 / Ctrl-C 退出去配 DNS: " _ < /dev/tty || true
  fi
  certbot certonly --standalone -d "$DOT_DOMAIN" --non-interactive --agree-tos \
    --register-unsafely-without-email --keep-until-expiring \
    --pre-hook  /usr/local/bin/proxy-gateway-open-cert-http.sh \
    --post-hook /usr/local/bin/proxy-gateway-restore-firewall.sh \
    || die "证书签发失败: 检查 A 记录是否已生效、80 口是否能从公网到达"
  echo "$DOT_DOMAIN" > /opt/pdg-bot/dot-domain
  install -m644 "/etc/letsencrypt/live/$DOT_DOMAIN/fullchain.pem" "$CERT_DIR/fullchain.pem"
  install -m600 "/etc/letsencrypt/live/$DOT_DOMAIN/privkey.pem"   "$CERT_DIR/privkey.pem"
fi
chown root:root "$CERT_DIR/fullchain.pem" "$CERT_DIR/privkey.pem"
chmod 0644 "$CERT_DIR/fullchain.pem"
chmod 0600 "$CERT_DIR/privkey.pem"

# ── 7. geosite 规则库 (此时 DNS 仍可用) ──
c_g "下载并解析 geosite 规则库…"
if [[ "$PRIOR_INSTALL" == 0 ]]; then
  # 首装没有旧规则库可保留；缺任一类别时 mosdns 根本无法安全启动。先让 systemd 读到刚写的
  # unit，再用与父安装 PID 绑定的短命 marker 开启一次 offline bootstrap。
  systemctl daemon-reload || die "systemd daemon-reload 失败"
  [[ ! -e /etc/privdns-gateway/.installing-rules \
     && ! -L /etc/privdns-gateway/.installing-rules ]] \
    || die "geosite 首装 marker 已存在；拒绝覆盖预存对象"
  ( set -o noclobber; umask 077
    printf '%s\n' "$$" > /etc/privdns-gateway/.installing-rules ) 2>/dev/null \
    || die "无法创建 geosite 首装 marker"
  if ! bash /opt/pdg-bot/update-rules.sh --bootstrap; then
    rm -f /etc/privdns-gateway/.installing-rules
    die "geosite 首装规则库下载/校验/事务落盘失败"
  fi
  rm -f /etc/privdns-gateway/.installing-rules \
    || die "无法清理 geosite 首装 marker"
else
  bash /opt/pdg-bot/update-rules.sh \
    || c_y "geosite 下载失败, 保留旧规则库；可在 bot『更新规则库』重试"
fi

# ── 8. 启动 ──
c_g "启动服务…"
# 释放 53 口: systemd-resolved 的 stub 占 127.0.0.53:53, 会和 mosdns 0.0.0.0:53 冲突
# 先备份原 resolv.conf(含符号链接), 供 uninstall 恢复
[[ -e /etc/resolv.conf.pdg-orig ]] || cp -a /etc/resolv.conf /etc/resolv.conf.pdg-orig 2>/dev/null || true
# LXC/Docker 之类的环境把 /etc/resolv.conf **bind-mount** 进来: 删不掉(EBUSY), 但能原地写。
# 直接 `rm -f` 会被 set -e 判成致命错误, 整场安装在这里中止并转入回滚 —— 而回滚打印的是
# "安装失败", 真原因(删不掉 resolv.conf)反倒看不见。删不掉就原地覆盖内容即可。
# 连写都写不进去(只读挂载)也不该中止: 那只影响**网关自己**解析用哪个上游, 转发链路照常。
_write_resolv(){
  rm -f /etc/resolv.conf 2>/dev/null || true    # 常见是指向 resolved stub 的符号链接, 删掉才落得下实文件
  printf '%s\n' "$@" > /etc/resolv.conf 2>/dev/null \
    || c_y "写不了 /etc/resolv.conf(只读挂载?), 本机自身 DNS 维持原样; 转发不受影响。"
}
if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
  systemctl disable --now systemd-resolved 2>/dev/null && RESOLVED_DISABLED=1 || true
fi
_write_resolv "nameserver 1.1.1.1"
systemctl daemon-reload
if [[ "$WEB_WAS_ENABLED" == 1 || "$WEB_WAS_ACTIVE" == 1 ]]; then
  python3 -c 'import yaml' >/dev/null 2>&1 \
    || die "pdg-web 的 YAML 解析依赖不可用；拒绝重启并回滚覆盖重装。"
  [[ -f /etc/privdns-gateway/web.json \
     && ! -L /etc/privdns-gateway/web.json ]] \
    || die "pdg-web 原为 enabled/active，但 root-only 配置缺失或不是普通文件。"
  python3 /opt/pdg-web/pdg-web-setup.py --validate-only >/dev/null 2>&1 \
    || die "pdg-web 新版本配置/TLS 校验失败；拒绝重启并回滚覆盖重装。"
fi
if [[ "$WEB_WAS_ACTIVE" == 1 ]]; then
  systemctl restart pdg-web >/dev/null 2>&1 \
    && _web_service_stable \
    || die "pdg-web 原为 active，但新版本未能稳定重启；回滚覆盖重装。"
fi
systemctl restart systemd-journald
QUIC_ROUTING_TOUCHED=1
systemctl enable --now pdg-quic-routing >/dev/null 2>&1 \
  || die "pdg-quic-routing 启动失败（严格前置条件，未启动 Mihomo）。"
/usr/local/libexec/pdg-quic-routing.sh status >/dev/null 2>&1 \
  || die "pdg-quic-routing 状态复核失败（未启动 Mihomo）。"
systemctl enable --now mosdns "$CORE_SVC" >/dev/null 2>&1 || true
# pdg-probe81 / pdg-mitm 仅 iOS: Android 不启 :81 探测、不起 MITM 服务。
[[ "$PLATFORM" == ios ]] && { systemctl enable --now pdg-probe81 >/dev/null 2>&1 || true
                             systemctl enable --now pdg-mitm >/dev/null 2>&1 || true; }
systemctl enable --now pdg-rules-update.timer >/dev/null 2>&1 || true
systemctl enable --now pdg-health.timer >/dev/null 2>&1 || true
if [[ -n "$BOT_TOKEN" && -n "$ALLOWED_IDS" ]]; then
  systemctl enable --now pdg-bot >/dev/null 2>&1 || true
else
  systemctl enable pdg-bot >/dev/null 2>&1 || true   # 开机自启; 现在没 token 暂不启动, 用 pdg-set-token 设置后启用
fi
_write_resolv "nameserver 127.0.0.1" "nameserver 1.1.1.1"

# ── 9. 防火墙 ──
c_g "应用防火墙…"
systemctl enable nftables >/dev/null 2>&1 || true
NFT_RUNTIME_TOUCHED=1
nft -f /etc/nftables.conf

# ── 提交点前: 确认核心服务"持续"起来了 ──
# systemd 默认 Type=simple, `systemctl start` 返 0 只代表 exec 成功, 进程可能随即崩溃。
# 单看一次 active 有竞态(起来又崩) → 要求连续 3 次保持 active 才算稳(flapping 的 failed/activating 会打断)。
c_g "校验核心服务(需连续保持 active, 防起来又崩)…"
# 按平台的必需服务: pdg-probe81 仅 iOS(Android 不装/不起, 不纳入门槛, 否则 Android 装机误判失败回滚)。
PLAT_SVCS=(pdg-quic-routing mosdns "$CORE_SVC")
[[ "$PLATFORM" == ios ]] && PLAT_SVCS+=(pdg-probe81)
[[ "$WEB_WAS_ACTIVE" == 1 ]] && PLAT_SVCS+=(pdg-web)
svc_ok=0; streak=0
for _ in $(seq 1 20); do
  allact=1
  for s in "${PLAT_SVCS[@]}"; do
    [[ "$(systemctl is-active "$s" 2>/dev/null)" == active ]] || allact=0
  done
  if [[ "$allact" == 1 ]]; then streak=$((streak+1)); else streak=0; fi
  [[ "$streak" -ge 3 ]] && { svc_ok=1; break; }
  sleep 1
done
if [[ "$svc_ok" != 1 ]]; then
  for s in "${PLAT_SVCS[@]}"; do printf '  %-12s %s\n' "$s" "$(systemctl is-active "$s" 2>/dev/null)"; done
  journalctl -u mosdns -u "$CORE_SVC" -n 20 --no-pager 2>/dev/null | sed 's/^/    /'
  die "核心服务未能持续保持运行(见上日志)。"   # → 触发回滚
fi
/usr/local/libexec/pdg-quic-routing.sh status >/dev/null 2>&1 \
  || die "核心服务虽运行，但 QUIC routing/profile 状态不一致。"
INSTALL_OK=1   # 提交点: 核心服务已确认稳定 active, 后面只是打印, 不再回滚

# ── 10. 自检 ──
echo; c_g "安装完成($PLATFORM 平台)。状态:"
for s in pdg-quic-routing mosdns "$CORE_SVC" pdg-bot; do
  printf "  %-18s %s\n" "$s" "$(systemctl is-active "$s")"
done
[[ "$PLATFORM" == ios ]] \
  && printf "  %-18s %s\n" pdg-probe81 "$(systemctl is-active pdg-probe81)"
printf "  %-18s enabled=%s active=%s\n" pdg-web \
  "$(systemctl is-enabled pdg-web 2>/dev/null || true)" \
  "$(systemctl is-active pdg-web 2>/dev/null || true)"
if [[ -x /usr/local/bin/pdg-webctl ]]; then
  /usr/local/bin/pdg-webctl status 2>/dev/null | sed 's/^/    /' \
    || c_y "  pdg-web 配置状态无法读取；服务保持原 enabled/active 状态。"
fi
if [[ -z "$BOT_TOKEN" || -z "$ALLOWED_IDS" ]]; then
  echo; c_y "⚠️ 管理 bot 未启用(没填 token)。出口和分流规则都在 bot 里设——"
  c_y "   现在还没法配代理。先跑:  sudo pdg-set-token  设好 token, 再给 bot 发 /start。"
fi
cat <<EOF

下一步($PLATFORM 平台):
  1) $( [[ "$PLATFORM" == ios ]] && echo "iOS:见第 3 步生成并安装 iOS 描述文件(DoT 域名:$DOT_DOMAIN)" || echo "手机「私密 DNS」填:  $DOT_DOMAIN" )
  $( [[ -z "$BOT_TOKEN" || -z "$ALLOWED_IDS" ]] && echo "2) 启用管理 bot:  sudo pdg-set-token  (之后再发 /start)" || echo "2) Telegram 给你的 bot 发 /start, 然后:" )
       • 「📤 出口管理 → 添加」粘贴 ss:// / vmess:// / trojan:// / vless:// 落地节点
       • 「📑 分流管理」按需把域名/规则集指到出口 (默认其余国际走 JP 直出)
  $( [[ "$PLATFORM" == ios ]] && echo "3) iOS:bot「📱 客户端 → iOS 描述文件」生成并安装(Wi-Fi/蜂窝由 :81 探测激活)" || echo "3) Android:私密 DNS 填上面的 DoT 域名即可" )
  4) 换域名随时用 bot「🌐 DoT 自定义域名」
  5) 可选 Web 管理面默认禁用: sudo pdg web setup
     配置后仍须显式 sudo pdg web enable；这两个命令都不会修改主机或云防火墙。

🛠 日常管理:  sudo pdg   (状态 / 更新 / Web / 换 token / 重启 / 日志 / 卸载)
$( [[ "$FIREWALL_MODE" == managed ]] \
   && echo "⚠️ managed 防火墙当前按 $SSH_PORT 放行 SSH; 之后修改 sshd Port 时须同步更新。" \
   || echo "ℹ️ external 模式仅安装 PDG scoped REDIRECT；主机端口策略由外部防火墙负责。" )
EOF
