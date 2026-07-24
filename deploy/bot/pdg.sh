#!/usr/bin/env bash
# PrivDNS Gateway 管理命令。直接 `sudo pdg` 进菜单, 或 pdg <子命令>。
#   pdg [menu] | status | update | token | restart | log [n] | uninstall [--purge]
# 设计: 生命周期(装/更新/卸载/token/状态/日志)走这里; 出口/分流/DNS上游 走 Telegram bot。
set -uo pipefail
REPO_URL="https://github.com/misaka-cpu/privdns-gateway.git"
REPO_DIR="/opt/privdns-gateway"
SVC="/etc/systemd/system/pdg-bot.service"
ENVD="/etc/privdns-gateway"
ENVF="$ENVD/bot.env"
# mihomo 路径安全: 面板 UI 在 /etc/sing-box/ui/dist(不在 /etc/mihomo 下), 放行给本脚本的所有 `mihomo -t` 校验。
export SAFE_PATHS="${SAFE_PATHS:-/etc/sing-box/ui/dist}"

c_g(){ echo -e "\033[1;32m$*\033[0m"; }
c_y(){ echo -e "\033[1;33m$*\033[0m"; }
need_root(){ [[ $EUID -eq 0 ]] || { echo "请用 root: sudo pdg $*"; exit 1; }; }
# 活动内核后端: v1.6.0 起恒 mihomo(彻底移除 sing-box 运行时)。旧机器的 backend 标记里可能还
# 写着 singbox, 但由 migrate_drop_singbox 在 update 时迁移 —— 判定一律按 mihomo。
_pdg_core(){ echo mihomo; }
_pdg_core_svc(){ echo mihomo; }
# 手机平台(ios / android; 读不到默认 android)
_pdg_platform(){ local p; p=$(cat /etc/privdns-gateway/platform 2>/dev/null); [[ "$p" == ios || "$p" == android ]] && echo "$p" || echo android; }
# 平台标记是否明确(status/doctor 据此提示"缺失回退")
_pdg_platform_present(){ local p; p=$(cat /etc/privdns-gateway/platform 2>/dev/null); [[ "$p" == ios || "$p" == android ]]; }
# 按平台的必需服务集(pdg-probe81 iOS 专属; 与 checks.expected_services 同语义)
_pdg_svcs(){ local s; s="mosdns $(_pdg_core_svc) pdg-bot"; [[ "$(_pdg_platform)" == ios ]] && s="$s pdg-probe81"; echo "$s"; }

# ── sing-box 文件归属 ────────────────────────────────────────────────────────
# 迁移/卸载要删 sing-box 的 unit 与二进制, 但机器上那份未必是本项目装的 —— 用户完全
# 可能自己在跑一个 sing-box 干别的。删掉别人的东西是不可逆的, 故只删**能证明是我们装的**。
# 判据(任一成立):
#   ① 归属标记文件(本项目装 sing-box 时留下; v1.6 起已不装 sing-box, 故仅老机器可能有);
#   ② unit 与 lib/units.sh 历史模板 pdg_unit_singbox 的特征行一致 —— ExecStart 指向本项目
#      的配置路径 /etc/sing-box/config.json, 这是老版装机生成的形态。
# 都不成立 = 来源不明 → 一律保留, 只提示, 绝不代用户决定。
PDG_SINGBOX_OWNED_MARK=/etc/privdns-gateway/singbox.pdg-owned
_pdg_singbox_is_ours(){
  local unit="${1:-/etc/systemd/system/sing-box.service}"
  [[ -e "${PDG_SINGBOX_OWNED_MARK:-/etc/privdns-gateway/singbox.pdg-owned}" ]] && return 0
  [[ -f "$unit" ]] || return 1
  grep -qE '^ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config\.json[[:space:]]*$' "$unit" \
    && grep -qE '^Description=sing-box[[:space:]]*$' "$unit"
}

# 停用并删除**本项目装的** sing-box unit 与二进制; 来源不明则原样保留并给出手工清理指引。
# $1 = 场景描述(仅用于文案)。恒返回 0: 保留第三方文件不是错误, 不该让调用方判失败。
_pdg_drop_singbox_files(){
  local why="${1:-}" unit=/etc/systemd/system/sing-box.service bin=/usr/local/bin/sing-box
  [[ -e "$unit" || -e "$bin" ]] || return 0
  if ! _pdg_singbox_is_ours "$unit"; then
    c_y "  检测到 sing-box${why:+($why)}, 但无法确认是本项目安装的 → 原样保留, 不删。"
    c_y "  (确认它无用可自行清理: systemctl disable --now sing-box; rm -f $unit $bin)"
    return 0
  fi
  systemctl disable --now sing-box >/dev/null 2>&1 || true
  rm -f "$unit" "$bin" "${PDG_SINGBOX_OWNED_MARK:-/etc/privdns-gateway/singbox.pdg-owned}"
  return 0
}
# iOS: 从已渲染的 nft 移除 GMS 5228-5230(iOS 走 APNs, 不需要)。nft 模板对两平台通用 —— 装机/切核
# 渲染后在 iOS 上剥掉, 免得 iOS 带上 GMS(或切核后 GMS 复活)。$1=nft 文件; 非 iOS 或文件不存在=空操作。
_pdg_nft_strip_gms(){
  local f="$1"
  [[ "$(_pdg_platform)" == ios && -f "$f" ]] || return 0
  sed -E -i 's#(tcp dport [{] 53, 80, 81, 443, 853), 5228-5230, 8445 [}] accept#\1, 8445 } accept#' "$f"  # sing-box 端口集
  sed -E -i 's#(tcp dport [{] 80, 443), 5228-5230 [}] redirect#\1 } redirect#' "$f"                        # mihomo REDIRECT
}

# 串行化"会写配置/重启服务"的操作(update/rollback/snapshot), 防 bot 更新按钮与命令行并发。
# 嵌套调用(update→snapshot)只锁一次。read-only 操作(status/doctor/report/log)不加锁。
LOCK="/run/privdns-gateway.lock"
PDG_LOCKED=""
_lock(){
  [[ -n "$PDG_LOCKED" ]] && return 0
  exec 9>"$LOCK" 2>/dev/null || return 0
  flock -n 9 || { echo "⛔ 已有 pdg 操作在运行, 请稍后再试 (锁: $LOCK)"; exit 1; }
  PDG_LOCKED=1
}

# ── 克制版低内存模式 ─────────────────────────────────────────────────────────
# PDG_LOWMEM=auto(默认)|1|0。MemTotal ≤ 1300 MiB 判低内存。只调确认安全的项:
# mosdns cache(8192/2048)+ journald SystemMaxUse(50M/20M)。不动 sysctl/swap/MemoryMax/GOMEMLIMIT。
# 决定持久化到 profile.env; auto 时 profile 已有就沿用(不每次更新改变用户已定模式)。
LOWMEM_THRESHOLD_KB=1331200      # 1300 MiB
PROFILE_ENV="${PDG_PROFILE:-/etc/privdns-gateway/profile.env}"
_mem_total_kb(){ sed -n 's/^MemTotal:[[:space:]]*\([0-9]*\).*/\1/p' "${PDG_MEMINFO:-/proc/meminfo}" 2>/dev/null; }
_profile_val(){ [[ -f "$PROFILE_ENV" ]] && sed -n 's/^PDG_LOWMEM=//p' "$PROFILE_ENV" | tail -1; }
pdg_cache_size(){ [[ "$1" == 1 ]] && echo 2048 || echo 8192; }
pdg_journald_max(){ [[ "$1" == 1 ]] && echo 20M || echo 50M; }

# 确保 journald drop-in 里 key= 的"未注释有效值"==val。返回: 1=已是目标(未改); 0=已改; 2=写入失败。
# 注释行不算数(避免"假成功/被误判已存在"); 追加时补 [Journal] 段与末尾换行(处理零字节/无换行文件)。
_journald_set_key(){
  local file="$1" key="$2" val="$3" cur
  cur="$(sed -n -E "s/^[[:space:]]*${key}=([^[:space:]#]+).*/\1/p" "$file" 2>/dev/null | tail -1)"
  [[ "$cur" == "$val" ]] && return 1
  if grep -qE "^[[:space:]]*${key}=" "$file" 2>/dev/null; then       # 有未注释有效行 → 替换
    sed -i -E "s|^[[:space:]]*${key}=.*|${key}=${val}|" "$file" 2>/dev/null || return 2
  else                                                               # 无有效行 → 追加(补段头/换行)
    if [[ -s "$file" && "$(tail -c1 "$file" 2>/dev/null | wc -l)" -eq 0 ]]; then
      printf '\n' >> "$file" 2>/dev/null || return 2                 # 末尾无换行 → 先补, 避免 [Journal]Key 拼接
    fi
    # 需"独立"段头(整行=[Journal]); 拼接畸形行 [Journal]Key= 不算, 缺则补一个独立段头
    grep -qxE '\[Journal\][[:space:]]*' "$file" 2>/dev/null || printf '[Journal]\n' >> "$file" 2>/dev/null || return 2
    printf '%s=%s\n' "$key" "$val" >> "$file" 2>/dev/null || return 2
  fi
  return 0
}

# 原子 upsert: 只更新 profile.env 里的 key=val 这一行, 其余键/注释/未知项原样保留。
# 语义与 pdg-bot.py 的 _profile_set 一致(去前导空白后以 key= 开头才算命中; #key= 注释不算)。
# 重复(多行同键)规范为一个有效值(保首个位置, 丢后续); 缺失则追加; 文件不存在则创建。
# 临时文件 + mv 原子替换: 失败不留半截/空文件。返回非 0 表示写入失败。
_profile_set(){
  local key="$1" val="$2" tmp found=0 line stripped
  mkdir -p "$(dirname "$PROFILE_ENV")" 2>/dev/null || true
  tmp="$(mktemp "${PROFILE_ENV}.XXXXXX" 2>/dev/null)" || return 1
  {
    if [[ -f "$PROFILE_ENV" ]]; then
      while IFS= read -r line || [[ -n "$line" ]]; do
        stripped="${line#"${line%%[![:space:]]*}"}"
        if [[ "$stripped" == "${key}="* ]]; then
          [[ "$found" == 1 ]] || { printf '%s=%s\n' "$key" "$val"; found=1; }   # 首个→规范值; 后续重复→丢弃
        else
          printf '%s\n' "$line"
        fi
      done < "$PROFILE_ENV"
    fi
    [[ "$found" == 1 ]] || printf '%s=%s\n' "$key" "$val"
  } > "$tmp" || { rm -f "$tmp" 2>/dev/null; return 1; }
  mv -f "$tmp" "$PROFILE_ENV" 2>/dev/null || { rm -f "$tmp" 2>/dev/null; return 1; }
}

# 解析并持久化内存模式, 回显 1(低内存)/0(标准)。显式 1/0 优先; auto 时 profile 已有沿用, 否则按内存检测。
pdg_lowmem_resolve(){
  local want="${PDG_LOWMEM:-auto}" cur res mt; cur="$(_profile_val)"
  case "$want" in
    1) res=1;;
    0) res=0;;
    *) if [[ "$cur" == 0 || "$cur" == 1 ]]; then res="$cur"
       else mt="$(_mem_total_kb)"; if [[ -n "$mt" && "$mt" -le "$LOWMEM_THRESHOLD_KB" ]]; then res=1; else res=0; fi; fi;;
  esac
  # 原子 upsert, 不整覆盖(保留 HIJACK_MODE/PLATFORM/TFO 等); 告警走 stderr 免污染被捕获的 $res
  _profile_set PDG_LOWMEM "$res" || c_y "⚠️ profile.env 写入失败(磁盘满/只读?), PDG_LOWMEM 本次未持久化。" >&2
  echo "$res"
}

# 只读回显当前模式(profile 有则用之, 无则按内存推断; 不写盘)。供 status/doctor。
pdg_lowmem_current(){
  local cur mt; cur="$(_profile_val)"
  if [[ "$cur" == 0 || "$cur" == 1 ]]; then echo "$cur"; return; fi
  mt="$(_mem_total_kb)"; if [[ -n "$mt" && "$mt" -le "$LOWMEM_THRESHOLD_KB" ]]; then echo 1; else echo 0; fi
}

# mosdns lazy_cache size 调到目标。失败只影响自己(return 非0), 绝不 exit 调用方 → 不连累 journald 修复。
# 生成到同目录临时文件 + 判退出码/复核/原子替换, 只有真改成功才重启; 任何失败都不改原文件、不重启。
_migrate_mosdns_cache(){
  local mos="$1" cache="$2"
  [[ -f "$mos" ]] && grep -q 'tag: lazy_cache' "$mos" || return 0
  local cur; cur="$(awk '/tag: lazy_cache/{f=1} f&&/size:/{print $2; exit}' "$mos")"
  [[ -n "$cur" && "$cur" != "$cache" ]] || return 0
  local bak tmp; bak="$mos.prelowmem.$(date +%s)"; tmp="$mos.lowmem.$$.tmp"
  cp -a "$mos" "$bak" 2>/dev/null && cmp -s "$mos" "$bak" || return 1
  if ! python3 - "$mos" "$tmp" "$cache" <<'PY'
import sys, re
src, dst, cache = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(src).read()
i = s.index('tag: lazy_cache'); head, tail = s[:i], s[i:]      # 只改 lazy_cache 块里第一处 size:
tail, n = re.subn(r'(size:\s*)\d+', r'\g<1>' + cache, tail, count=1)
assert n == 1, 'lazy_cache 块内未找到 size 行'
open(dst, 'w').write(head + tail)
PY
  then c_y "  生成 mosdns cache 失败 → 不改、不重启。"; rm -f "$tmp"; return 1; fi
  if ! grep -qE "size:[[:space:]]*$cache\b" "$tmp"; then
    c_y "  生成结果未含目标 cache size → 不改、不重启。"; rm -f "$tmp"; return 1; fi
  if ! mv "$tmp" "$mos" 2>/dev/null; then
    c_y "  原子替换 mosdns 配置失败 → 清理临时文件, 不重启。"; rm -f "$tmp"; return 1; fi
  systemctl restart mosdns 2>/dev/null; sleep 1
  if [[ "$(systemctl is-active mosdns 2>/dev/null)" != active ]]; then
    c_y "  mosdns cache 调整后重启失败 → 还原。"; cp -a "$bak" "$mos" 2>/dev/null; systemctl restart mosdns 2>/dev/null; return 1
  fi
  c_g "  mosdns cache size → $cache"
}

# journald 封顶: 清错目录残留 + 正确目录 System/Runtime 都封到 jmax。写失败/复核不符/重启失败均 warn(不假绿)。
# 我们的 drop-in 是项目独占的; 文件缺失或"没有独立有效 [Journal] 段头"(含 v1.2.3 拼接畸形 [Journal]Key=、
# 只有 key、零字节)一律按标准内容重建, 避免非法段头修不掉。
_migrate_journald_cap(){
  local jrnl="$1" jrnl_legacy="$2" jmax="$3"
  [[ "$jrnl_legacy" != "$jrnl" && -f "$jrnl_legacy" ]] && rm -f "$jrnl_legacy"
  if [[ ! -f "$jrnl" ]] || ! grep -qxE '\[Journal\][[:space:]]*' "$jrnl" 2>/dev/null; then
    if mkdir -p "$(dirname "$jrnl")" 2>/dev/null \
       && printf '[Journal]\nSystemMaxUse=%s\nRuntimeMaxUse=%s\n' "$jmax" "$jmax" > "$jrnl" 2>/dev/null; then
      if systemctl restart systemd-journald 2>/dev/null; then c_g "  journald 封顶(重建)→ $jmax(System+Runtime)"
      else c_y "  journald 封顶已写入但 journald 重启失败 → 重启系统后生效。"; fi
    else
      c_y "  journald 封顶写入失败(目录只读?)→ 未生效, 请检查 $jrnl。"
    fi
    return 0
  fi
  # 有独立合法段头 → 逐 key 设置(保留文件其它内容)
  local r1 r2; _journald_set_key "$jrnl" SystemMaxUse "$jmax"; r1=$?; _journald_set_key "$jrnl" RuntimeMaxUse "$jmax"; r2=$?
  if [[ "$r1" == 2 || "$r2" == 2 ]]; then
    c_y "  journald 封顶写入失败(目录只读?)→ 未完全生效, 请检查 $jrnl。"; return 0
  fi
  [[ "$r1" == 0 || "$r2" == 0 ]] || return 0     # 两个都"已是目标"(未改)→ 幂等, 无需重启
  local rok=1; systemctl restart systemd-journald 2>/dev/null || rok=0
  local es rs
  es="$(sed -n -E 's/^[[:space:]]*SystemMaxUse=([^[:space:]#]+).*/\1/p'  "$jrnl" | tail -1)"
  rs="$(sed -n -E 's/^[[:space:]]*RuntimeMaxUse=([^[:space:]#]+).*/\1/p' "$jrnl" | tail -1)"
  if [[ "$es" == "$jmax" && "$rs" == "$jmax" && "$rok" == 1 ]]; then
    c_g "  journald 封顶 → $jmax(System+Runtime)"
  elif [[ "$es" == "$jmax" && "$rs" == "$jmax" ]]; then
    c_y "  journald 封顶已写入但 journald 重启失败 → 重启系统后生效。"
  else
    c_y "  journald 封顶复核异常(System=${es:-空} Runtime=${rs:-空})。"
  fi
}

# 老装迁移: 按 profile(内存模式)把 mosdns cache size / journald 封顶调到目标。幂等。
# 两步互相独立: mosdns 调整失败也不影响 journald 修复(反之亦然)。
# shellcheck disable=SC2120  # $1/$2/$3 仅测试注入
migrate_lowmem(){
  local mos="${1:-/etc/mosdns/config.yaml}" jrnl="${2:-/etc/systemd/journald.conf.d/50-pdg.conf}"
  local jrnl_legacy="${3:-/etc/systemd/system/journald.conf.d/50-pdg.conf}"   # 历史装错目录
  local mode cache jmax; mode="$(pdg_lowmem_resolve)"; cache="$(pdg_cache_size "$mode")"; jmax="$(pdg_journald_max "$mode")"
  _migrate_mosdns_cache "$mos" "$cache" || true       # mosdns 失败不影响下面 journald
  _migrate_journald_cap "$jrnl" "$jrnl_legacy" "$jmax"
}

pdg_fetch_release_tags(){
  local dir="${1:-$REPO_DIR}"
  git -C "$dir" fetch -q --tags origin main || return 1
  if [[ "$(git -C "$dir" rev-parse --is-shallow-repository 2>/dev/null)" == "true" ]]; then
    git -C "$dir" fetch -q --unshallow --tags origin main || return 1
  fi
}

cmd_status(){
  c_g "== 服务 =="
  local core; core="$(_pdg_core)"
  local s
  # shellcheck disable=SC2046  # _pdg_svcs 输出有意按空白分词
  for s in $(_pdg_svcs); do   # 按平台: pdg-probe81 仅 iOS
    printf "  %-12s %s\n" "$s" "$(systemctl is-active "$s" 2>/dev/null)"
  done
  [[ "$(_pdg_platform)" == ios ]] && printf "  %-12s %s\n" "pdg-mitm" "$(systemctl is-active pdg-mitm 2>/dev/null)"
  echo "  timer        $(systemctl is-active pdg-rules-update.timer 2>/dev/null)"
  echo "  内核后端     $core$([[ "$core" == mihomo ]] && echo "(版本随项目发布更新)" || echo "(固定 1.12.x)")"
  if _pdg_platform_present; then echo "  手机平台     $(_pdg_platform)"
  else echo "  手机平台     android(⚠️ 平台标记缺失, 按 Android 安全回退; 运行 sudo pdg 触发迁移落定)"; fi
  echo "  DoT 域名     $(cat /opt/pdg-bot/dot-domain 2>/dev/null || echo ?)"
  local ports p9090="9090(local clash_api)"
  if jq -e '.experimental.clash_api as $c | $c.external_controller == "0.0.0.0:9090" and $c.external_ui == "/etc/sing-box/ui/dist" and (($c.secret // "") | length > 0)' /etc/sing-box/config.json >/dev/null 2>&1; then
    p9090="9090(panel临时内网)"
  fi
  # mihomo 模式 443/80 由 nft 转到 7893(redir), 故把 7893 一并纳入端口展示
  ports=$(ss -lntu 2>/dev/null | grep -oE ':(53|80|81|443|853|7893|8445|9090)\b' | sed 's/^://' | sort -u | sed "s|^9090$|$p9090|" | tr '\n' ' ')
  echo "  监听端口     $ports"
  if [[ -d "$REPO_DIR/.git" ]]; then echo "  代码版本     $(git -C "$REPO_DIR" describe --tags --always 2>/dev/null)"; fi
  local lm cache; lm="$(pdg_lowmem_current)"; cache="$(awk '/tag: lazy_cache/{f=1} f&&/size:/{print $2; exit}' /etc/mosdns/config.yaml 2>/dev/null)"
  echo "  内存模式     $([[ "$lm" == 1 ]] && echo 低内存 || echo 标准)(mosdns cache=${cache:-?})"
}

cmd_doctor(){ python3 /opt/pdg-bot/doctor.py "$@"; }

# 旧装把 token 写在 unit 的 Environment= 里 → 迁到 bot.env(600), unit 改用 EnvironmentFile。幂等。
migrate_botenv(){
  [[ -f "$SVC" ]] || return 0
  local tok allow
  tok=$(grep -oP '^Environment=PDG_BOT_TOKEN=\K.*'   "$SVC" | head -1)
  allow=$(grep -oP '^Environment=PDG_BOT_ALLOWED=\K.*' "$SVC" | head -1)
  install -d -m700 "$ENVD"
  if [[ ! -f "$ENVF" && -n "$tok" ]]; then
    ( umask 077; printf 'PDG_BOT_TOKEN=%s\nPDG_BOT_ALLOWED=%s\n' "$tok" "$allow" > "$ENVF" )
    chmod 600 "$ENVF"
    c_g "已把 token 从 unit 迁移到 $ENVF (600)"
  fi
  grep -qE '^Environment=PDG_BOT_(TOKEN|ALLOWED)=' "$SVC" \
    && sed -i -E '/^Environment=PDG_BOT_(TOKEN|ALLOWED)=/d' "$SVC"
  grep -q '^EnvironmentFile=-\?/etc/privdns-gateway/bot.env' "$SVC" \
    || sed -i -E 's#^\[Service\]#[Service]\nEnvironmentFile=-/etc/privdns-gateway/bot.env#' "$SVC"
}

# 判断旧 /etc/nftables.conf 是不是本项目"原装"防火墙(无用户自定义)。
# 严格白名单(默认拒绝): 去注释/空行、收紧空白后, **每一行**都必须匹配下面某条已知原装规则;
# 只要出现一行不认识的(自定义来源/端口/动作/链/表等)就判"非原装" → 不自动重建, 以免静默丢规则。
# 白名单用正则, 因此兼容历史变体: forward/output 单行或多行写法、不同年代的内网端口子集
# ({53,80,81,443} → +853 → +8445)都算原装。
_fw_is_stock(){
  local f="$1" port="$2" cidr="$3" line norm matched pat
  local cre="${cidr//./\\.}"               # 内网段做正则(转义点)
  local pset='(53|80|81|443|853|8445)'     # 内网放行端口集(任意子集/顺序)
  local -a pats=(
    '^flush ruleset$'
    '^table inet filter [{]$'
    '^chain (input|forward|output) [{]$'
    '^chain (forward|output) [{] type filter hook (forward|output) priority 0; policy accept; [}]$'
    '^type filter hook input priority 0; policy drop;$'
    '^type filter hook (forward|output) priority 0; policy accept;$'
    '^iif "lo" accept$'
    '^ct state established,related accept$'
    "^tcp dport [{] ${port}(, 853)? [}] accept$"
    "^tcp dport ${port} accept$"
    "^ip saddr ${cre} tcp dport [{] ${pset}(, ${pset})* [}] accept$"
    "^ip saddr ${cre} udp dport [{] (53|443)(, (53|443))* [}] accept$"
    "^ip saddr ${cre} udp dport (53|443) accept$"
    "^ip saddr ${cre} udp dport 443 reject$"
    '^ip protocol icmp accept$'
    '^ip6 nexthdr icmpv6 accept$'
    '^[}]$'
  )
  while IFS= read -r line; do
    norm="${line%%#*}"                                                  # 去行内/整行注释
    norm="$(printf '%s' "$norm" | tr -s ' \t' ' ' | sed 's/^ //; s/ $//')"  # 收紧空白+去首尾
    [[ -z "$norm" ]] && continue
    matched=0
    for pat in "${pats[@]}"; do printf '%s' "$norm" | grep -qE "$pat" && { matched=1; break; }; done
    [[ "$matched" == 1 ]] || return 1                                   # 出现白名单外的行 → 非原装
  done < "$f"
  return 0
}

# 旧装防火墙迁移: 把旧的 `flush ruleset` + `table inet filter` 迁到独立表 `inet pdg`。幂等。
# 不迁移则: 证书续期 pre-hook 进不了 inet pdg 开不了 80、doctor 读不到防火墙、且仍会 flush 掉别的表。
# 安全做法: 解析旧配置里的 SSH 端口/内网段 → 渲染新模板 → nft -c 校验 → 备份 → nft -f → 删旧表。
# 全程 SSH 不断(established + 新表放行 SSH; 加载新表时旧 inet filter 仍在 → 双重放行)。
migrate_firewall_to_pdg(){
  local f=/etc/nftables.conf
  [[ -f "$f" ]] || return 0
  # 已是新表(有 inet pdg 且无 inet filter)→ 无需迁移
  grep -q 'table inet pdg' "$f" && ! grep -q 'table inet filter' "$f" && return 0
  # 必须看起来像本项目的防火墙(含我们放行的端口特征), 否则不乱动用户的自定义规则
  grep -qE '\b(853|8445)\b' "$f" || return 0
  local port cidr tmp; tmp="$(mktemp)"
  port=$(grep -E 'tcp dport.*accept' "$f" | grep -v saddr | grep -oE '[0-9]+' | head -1)
  cidr=$(grep -oE 'ip saddr [0-9./]+' "$f" | head -1 | awk '{print $3}')
  if [[ -z "$port" || -z "$cidr" ]]; then
    c_y "检测到旧防火墙但解析不出 SSH端口/内网段, 跳过自动迁移(可手动重渲染)。"; rm -f "$tmp"; return 0
  fi
  # 迁移=用标准模板重建, 只保留 SSH端口+内网段; 若旧配置里有自定义端口/规则/额外表,
  # 重建会静默丢掉它们 → 检测到非原装就不自动迁移, 让用户手动并入(旧配置原样留在 $f)。
  if ! _fw_is_stock "$f" "$port" "$cidr"; then
    c_y "检测到旧防火墙含自定义规则/额外端口/额外表 → 不自动迁移(避免静默丢失你的规则)。"
    c_y "  迁移会用标准模板重建(只保留 SSH=$port + 内网段=$cidr)。请任选其一:"
    c_y "   • 把自定义规则并进 deploy/firewall/nftables-mihomo.conf 同风格后手动 nft -f; 或"
    c_y "   • sudo pdg migrate-fw 先迁标准部分, 再把自定义规则补到 inet pdg。"
    c_y "  现状: 旧 inet filter 不动(证书 hook/doctor 已兼容它, 不迁也能正常用)。"
    rm -f "$tmp"; return 0
  fi
  c_g "检测到旧版(原装)防火墙 → 迁移到独立表 inet pdg (SSH=$port, 内网段=$cidr)…"
  sed -e "s/__SSH_PORT__/$port/g" -e "s#__INTERNAL_CIDR__#$cidr#g" \
      "$REPO_DIR/deploy/firewall/nftables-mihomo.conf" > "$tmp"
  if ! nft -c -f "$tmp" >/dev/null 2>&1; then
    c_y "  新规则 nft -c 校验未过, 保留旧防火墙不动。"; rm -f "$tmp"; return 0
  fi
  # 必须先确认备份完整(cmp 逐字节相同)才敢覆盖现网配置; 磁盘满/cp 失败时中止, 不动现网。
  local bak; bak="$f.prepdg.$(date +%s)"
  if ! cp -a "$f" "$bak" 2>/dev/null || ! cmp -s "$f" "$bak"; then
    c_y "  备份 $f 失败/不完整(磁盘满?), 中止迁移、不改动现网。"; rm -f "$tmp" "$bak" 2>/dev/null; return 0
  fi
  # 写新配置; 若写失败/不完整(磁盘满), 用刚验证过的备份还原, 不动内核(尚未 nft -f)。
  if ! cp "$tmp" "$f" 2>/dev/null || ! cmp -s "$tmp" "$f"; then
    c_y "  写入新配置失败/不完整(磁盘满?), 已还原备份、不改动现网。"; cp -a "$bak" "$f" 2>/dev/null; rm -f "$tmp"; return 0
  fi
  rm -f "$tmp"
  # 关键: 只有"新表加载成功且 inet pdg 确实在内核里"才删旧表; 否则绝不删 inet filter。
  # nft -f 是原子的, 失败则内核不变(旧 inet filter 仍在生效), 只需把 on-disk 配置还原回旧的。
  if nft -f "$f" 2>/dev/null && nft list table inet pdg >/dev/null 2>&1; then
    nft delete table inet filter 2>/dev/null || true   # 确认新表已载入, 再删旧表, 只留 inet pdg
    c_g "  ✅ 已迁移为 inet pdg。"
  else
    cp -a "$bak" "$f" 2>/dev/null                       # 还原 on-disk 配置=旧(内核里旧表仍在)
    c_y "  ⚠️ 新规则加载失败 → 保留旧防火墙、未删 inet filter、配置已还原(防火墙未中断)。"
  fi
}

# 给 /etc/mosdns 里"缺 concurrent"的 forward args 行补上(单上游=1, 多上游=2)。幂等。读 $1 → stdout。
# (mosdns 默认 concurrent=1=随机选1个不故障转移; 单上游配 2 会把同一台并发查两次, 故按上游数定。)
_mosdns_add_concurrent(){
  awk '
    /args: \{ upstreams:/ {
      n = gsub(/addr:/, "addr:")        # 数本行上游个数
      c = (n <= 1) ? 1 : 2
      sub(/args: \{ upstreams:/, "args: { concurrent: " c ", upstreams:")
    }
    { print }
  ' "$1"
}

# 旧装迁移: 老的 /etc/mosdns/config.yaml 的 forward 块没有 concurrent(=默认随机单上游、不故障转移)。
# pdg update 不重渲染该文件, 故在此幂等补上(不动用户现有上游/顺序)。
migrate_mosdns_concurrent(){
  local f=/etc/mosdns/config.yaml
  [[ -f "$f" ]] || return 0
  grep -qE 'args: [{] upstreams:' "$f" || return 0     # 没有"缺 concurrent"的行 → 无需迁移
  c_g "检测到 mosdns forward 块缺 concurrent → 补上(单上游=1/多上游=2, 不动你的上游)…"
  local bak; bak="$f.preconc.$(date +%s)"
  if ! cp -a "$f" "$bak" 2>/dev/null || ! cmp -s "$f" "$bak"; then
    c_y "  备份失败(磁盘满?), 中止、不动现网。"; rm -f "$bak" 2>/dev/null; return 0
  fi
  if ! _mosdns_add_concurrent "$f" > "$f.tmp" 2>/dev/null || ! grep -q concurrent "$f.tmp"; then
    c_y "  生成失败, 中止。"; rm -f "$f.tmp"; return 0
  fi
  mv "$f.tmp" "$f"
  systemctl restart mosdns 2>/dev/null; sleep 1
  if [[ "$(systemctl is-active mosdns 2>/dev/null)" == active ]]; then
    c_g "  ✅ 已补 concurrent。"
  else
    c_y "  ⚠️ mosdns 重启失败 → 还原。"; cp -a "$bak" "$f" 2>/dev/null; systemctl restart mosdns 2>/dev/null
  fi
}

# 旧装迁移: 给 mosdns 补"WDA/流媒体解锁支"(常驻、平时休眠)。pdg update 不重渲染 config, 故在此幂等补。
# 加 unlock_upstream(22.22.22.22) + geosite_unlock(读 unlock.txt) 两个插件 + main_sequence 一条
# "本机查询命中解锁域名→解锁DNS"的支(带 jump has_resp 防被 remote_upstream 覆盖)+ 建空 unlock.txt。
# 空 unlock.txt = 不命中任何域名 = 休眠, 不改变现有行为; bot『🔓 解锁走 WDA』开启时才填充。
migrate_mosdns_unlock(){
  local f=/etc/mosdns/config.yaml
  [[ -f "$f" ]] || return 0
  grep -q 'unlock_upstream' "$f" && return 0                   # 已有 → 跳过
  grep -q 'tag: main_sequence' "$f" || return 0               # 不是本项目的 mosdns 配置 → 不动
  c_g "给 mosdns 补 WDA 解锁支(常驻休眠, 不改现有行为)…"
  local bak; bak="$f.preunlock.$(date +%s)"
  if ! cp -a "$f" "$bak" 2>/dev/null || ! cmp -s "$f" "$bak"; then
    c_y "  备份失败, 中止。"; rm -f "$bak" 2>/dev/null; return 0
  fi
  python3 - "$f" <<'PY' || { c_y "  生成失败, 中止(已留备份)。"; return 0; }
import sys
f=sys.argv[1]; s=open(f).read()
plug='''  - tag: unlock_upstream
    type: forward
    args: { concurrent: 1, upstreams: [ {addr: "udp://22.22.22.22"} ] }
  - tag: geosite_unlock
    type: domain_set
    args: { files: ["/etc/mosdns/rules/unlock.txt"] }
  - tag: geosite_cn'''
assert s.count('  - tag: geosite_cn')==1
s=s.replace('  - tag: geosite_cn', plug, 1)
old='''      - matches: client_ip $npn_clients
        exec: goto internal_sequence
      - exec: $remote_upstream'''
new='''      - matches: client_ip $npn_clients
        exec: goto internal_sequence
      - matches: qname $geosite_unlock
        exec: $unlock_upstream
      - exec: jump has_resp
      - exec: $remote_upstream'''
assert old in s
open(f,'w').write(s.replace(old,new,1))
PY
  [[ -e /etc/mosdns/rules/unlock.txt ]] || : > /etc/mosdns/rules/unlock.txt
  systemctl restart mosdns 2>/dev/null; sleep 1
  if [[ "$(systemctl is-active mosdns 2>/dev/null)" == active ]]; then
    c_g "  ✅ 已补解锁支(休眠)。bot『🌐 DNS 上游→🔓 解锁走 WDA』可启用。"
  else
    c_y "  ⚠️ mosdns 重启失败 → 还原。"; cp -a "$bak" "$f" 2>/dev/null; systemctl restart mosdns 2>/dev/null
  fi
}

# 老装迁移: 给 mosdns 补"单客户端 QPS 兜底"(rate_limiter)。幂等。
# 只对本项目形态的 config(有 internal_sequence + npn_clients)做定点插入: 加 client_limiter 插件,
# 并在 internal_sequence 缓存查询之前插一条 "!$client_limiter → reject 5"。高度自定义的配置不动(doctor 会 warn)。
# 只改这两处, 不碰用户的上游/其它内容; check(重启+active)失败自动还原。$1 可指定文件(供测试)。
# shellcheck disable=SC2120  # $1 仅测试注入, 生产调用不传参
migrate_mosdns_ratelimit(){
  local f="${1:-/etc/mosdns/config.yaml}"
  [[ -f "$f" ]] || return 0
  grep -q 'client_limiter' "$f" && return 0                       # 已有 → 幂等退出
  grep -q 'tag: internal_sequence' "$f" && grep -q 'tag: npn_clients' "$f" || return 0   # 非本项目形态 → 不动
  grep -qE '^\s+- exec: \$lazy_cache' "$f" || return 0            # 缺缓存锚点 → 不动(交 doctor warn)
  c_g "给 mosdns 补单客户端 QPS 兜底(rate_limiter, 平时无感)…"
  local bak; bak="$f.preratelimit.$(date +%s)"
  if ! cp -a "$f" "$bak" 2>/dev/null || ! cmp -s "$f" "$bak"; then
    c_y "  备份失败(磁盘满?), 中止、不动现网。"; rm -f "$bak" 2>/dev/null; return 0
  fi
  if ! python3 - "$f" <<'PY'
import sys
f=sys.argv[1]; s=open(f).read()
plug='''  - tag: client_limiter
    type: rate_limiter
    args: { qps: 200, burst: 400, mask4: 32, mask6: 128 }
  - tag: internal_sequence'''
assert s.count('  - tag: internal_sequence')==1, 'internal_sequence 锚点不唯一'
s=s.replace('  - tag: internal_sequence', plug, 1)
step='''      - matches: "!$client_limiter"
        exec: reject 5
      - exec: $lazy_cache'''
assert s.count('      - exec: $lazy_cache')==1, 'lazy_cache 锚点不唯一'
s=s.replace('      - exec: $lazy_cache', step, 1)
open(f,'w').write(s)
PY
  then c_y "  生成失败 → 还原。"; cp -a "$bak" "$f"; return 0; fi
  systemctl restart mosdns 2>/dev/null; sleep 1
  if [[ "$(systemctl is-active mosdns 2>/dev/null)" == active ]]; then
    c_g "  ✅ 已补 client_limiter。"
  else
    c_y "  ⚠️ mosdns 重启失败 → 还原。"; cp -a "$bak" "$f" 2>/dev/null; systemctl restart mosdns 2>/dev/null
  fi
}


# 老装迁移: 防火墙内网放行集补 5228-5230(GMS/FCM 推送 mtalk.google.com 的原生端口;
# mihomo 靠 nft 把它们 REDIRECT 进 redir 端口再嗅 SNI 分流)。幂等。
# 只动"原装形态"的那一行(严格匹配现行端口集); 自定义端口集不碰, 提示手动加。
# $1 可指定文件(供测试), 默认 /etc/nftables.conf; 测试时 nft 可用函数打桩。
# shellcheck disable=SC2120  # $1 仅测试注入, 生产调用不传参
migrate_fw_gms(){
  local f="${1:-/etc/nftables.conf}"
  [[ "$(_pdg_platform 2>/dev/null)" == ios ]] && return 0     # GMS/FCM 仅 Android; iOS 不放行 5228-5230
  [[ -f "$f" ]] || return 0
  grep -q 'table inet pdg' "$f" || return 0                   # 未迁到 inet pdg 的先走 migrate_firewall_to_pdg, 下次再补
  grep -qE 'tcp dport [{][^}]*5228' "$f" && return 0          # 已有 → 幂等退出
  if ! grep -qE 'ip saddr [0-9./]+ tcp dport [{] 53, 80, 81, 443, 853, 8445 [}] accept' "$f"; then
    c_y "防火墙端口集非原装形态, 不自动加 GMS 推送端口。可手动把 5228-5230 加进内网 tcp 放行集。"
    return 0
  fi
  c_g "检测到防火墙缺 GMS 推送端口 → 内网放行集补 5228-5230…"
  local bak; bak="$f.pregms.$(date +%s)"
  if ! cp -a "$f" "$bak" 2>/dev/null || ! cmp -s "$f" "$bak"; then
    c_y "  备份失败(磁盘满?), 中止、不动现网。"; rm -f "$bak" 2>/dev/null; return 0
  fi
  sed -E -i 's#(ip saddr [0-9./]+ tcp dport [{] 53, 80, 81, 443, 853), 8445 [}] accept#\1, 5228-5230, 8445 } accept#' "$f"
  if ! grep -qE 'tcp dport [{][^}]*5228-5230' "$f"; then
    c_y "  改写未生效 → 还原。"; cp -a "$bak" "$f"; return 0
  fi
  if ! nft -c -f "$f" >/dev/null 2>&1; then
    c_y "  nft -c 校验未过 → 还原、内核未动。"; cp -a "$bak" "$f"; return 0
  fi
  if nft -f "$f" 2>/dev/null; then
    c_g "  ✅ 已放行 5228-5230(仅内网卡来源)。"
  else
    c_y "  ⚠️ 加载失败 → 还原配置(内核里旧规则仍在生效)。"; cp -a "$bak" "$f"
  fi
}

# 返回一个已创建的非空临时目录；失败不输出路径。供 snapshot/rollback 共用，避免空路径退化到 /etc。
_pdg_mktemp_dir(){
  local d=""
  d="$(mktemp -d)" || return 1
  [[ -n "$d" && -d "$d" ]] || return 1
  printf '%s\n' "$d"
}

# 按原归档成员清单把已验证临时树落到目标根；不递归顶层隐式父目录，避免误改 /etc、/opt 元数据。
_pdg_apply_snapshot_tree(){
  local tree="$1" members="$2" dest="$3"
  [[ -d "$tree" && -s "$members" && -d "$dest" ]] || return 1
  (
    set -o pipefail
    tar --no-recursion -cf - -C "$tree" -T "$members" 2>/dev/null \
      | tar xpf - -C "$dest" 2>/dev/null
  )
}

# 面板临时态净化(与 bot backup_blob/restore_from 对称): 快照/回滚不持久化面板的公网监听+密钥+UI。
# 只认"本项目受管开启态"(0.0.0.0:9090 + 项目 UI 目录 + 有 secret + 项目下载地址); 自定义 clash_api 不动。
_sb_panel_managed_on(){
  command -v jq >/dev/null 2>&1 || return 1
  jq -e '.experimental.clash_api as $c | ($c.external_controller=="0.0.0.0:9090")
         and ($c.external_ui=="/etc/sing-box/ui/dist") and ((($c.secret) // "")|length>0)
         and (($c.external_ui_download_url // "") as $d |
              if ($d|type)!="string" then false
              else ($d=="" or ($d|test("^https://github[.]com/Zephyruso/zashboard/releases/download/[^/]+/dist-no-fonts[.]zip$"))) end)' \
      "$1" >/dev/null 2>&1
}
# 生成关闭态净化副本；调用方只传临时目标。成功副本固定 600，失败不留半成品。
_sb_write_sanitized(){
  local src="$1" dst="$2"
  [[ "$src" != "$dst" ]] || return 1
  if jq '.experimental.clash_api={external_controller:"127.0.0.1:9090"}' "$src" > "$dst" 2>/dev/null \
     && [[ -s "$dst" ]] && chmod 600 "$dst"; then
    return 0
  fi
  rm -f "$dst"; return 1
}
# 把受管开启态原子净化为关闭态(clash_api 只留本地控制器)。改了返回 0, 未改/失败非 0。
_sb_sanitize_panel(){
  _sb_panel_managed_on "$1" || return 1
  local dir base t=""
  dir="$(dirname -- "$1")"; base="$(basename -- "$1")"
  t="$(mktemp "$dir/.${base}.pdg.XXXXXX")" || return 2
  if _sb_write_sanitized "$1" "$t" && mv -f -- "$t" "$1"; then
    return 0
  fi
  rm -f "$t"; return 2
}

SNAP_DIR="/var/lib/privdns-gateway/backups"

# 供 cmd_update 读取"本次刚创建的快照目录"(精确回滚目标, 不靠 index 0 猜)。
_PDG_SNAP_CREATED=""
cmd_snapshot(){
  need_root snapshot; _lock
  _PDG_SNAP_CREATED=""
  local ts d; ts=$(date +%Y%m%d-%H%M%S); d="$SNAP_DIR/$ts"
  install -d -m700 "$d"
  # 整机配置 + 防火墙 + bot.env(含 token)+ service + journald 封顶(含历史错路径)(相对 / 打包, 回滚 -C / 解开)
  # 含: 已安装脚本(pdg / pdg-set-token / cert hook)+ 全部 pdg unit —— 升级会改它们, 回滚要一并还原。
  # 只打包"存在的"路径 —— 历史错路径可能已被迁移清掉, 无条件列进去会让 tar 报 Cannot stat 并返 2。
  local cand=(etc/mosdns etc/sing-box etc/mihomo opt/pdg-bot etc/privdns-gateway etc/nftables.conf
              etc/systemd/system/pdg-bot.service etc/systemd/journald.conf.d/50-pdg.conf
              etc/systemd/system/journald.conf.d/50-pdg.conf
              etc/systemd/system/mihomo.service etc/systemd/system/sing-box.service
              etc/systemd/system/pdg-mitm.service etc/systemd/system/pdg-probe81.service
              etc/systemd/system/pdg-rules-update.service etc/systemd/system/pdg-rules-update.timer
              etc/systemd/system/pdg-health.service etc/systemd/system/pdg-health.timer
              etc/letsencrypt/renewal-hooks/deploy/99-pdg-cert.sh
              usr/local/bin/pdg usr/local/bin/pdg-set-token
              usr/local/bin/mihomo usr/local/bin/sing-box
              usr/local/bin/proxy-gateway-open-cert-http.sh usr/local/bin/proxy-gateway-restore-firewall.sh)
  local items=(); local p; for p in "${cand[@]}"; do [[ -e "/$p" ]] && items+=("$p"); done
  # 面板受管开启态: 用净化后的 config 入档(排除真实 config.json, 追加净化版), 快照不含临时监听/密钥/UI。
  local stg=""
  if [[ -e /etc/sing-box/config.json ]] && _sb_panel_managed_on /etc/sing-box/config.json; then
    if ! stg="$(_pdg_mktemp_dir)"; then
      c_y "❌ 快照创建临时目录失败"; rmdir "$d" 2>/dev/null; return 1
    fi
    if ! mkdir -p "$stg/etc/sing-box" \
       || ! _sb_write_sanitized /etc/sing-box/config.json "$stg/etc/sing-box/config.json"; then
      c_y "❌ 快照净化面板配置失败"; rm -rf "$stg"; rmdir "$d" 2>/dev/null; return 1
    fi
  fi
  if [[ -n "$stg" ]]; then      # cf(排除真实 config)+ rf(追加净化 config)+ gzip: --exclude 只对第一次 tar 生效
    if ! tar cf "$d/snap.tar" --exclude='etc/sing-box/config.json' -C / "${items[@]}" 2>/dev/null \
       || ! tar rf "$d/snap.tar" -C "$stg" etc/sing-box/config.json 2>/dev/null \
       || ! gzip -f "$d/snap.tar" 2>/dev/null; then
      c_y "❌ 快照打包失败"; rm -f "$d/snap.tar" "$d/snap.tar.gz"; rm -rf "$stg"; rmdir "$d" 2>/dev/null; return 1
    fi
    rm -rf "$stg"
  elif ! tar czf "$d/snap.tar.gz" -C / "${items[@]}" 2>/dev/null; then
    c_y "❌ 快照打包失败"; rm -f "$d/snap.tar.gz"; rmdir "$d" 2>/dev/null; return 1
  fi
  chmod 600 "$d/snap.tar.gz"
  _PDG_SNAP_CREATED="$d"
  echo "✅ 快照: $d/snap.tar.gz"
  ls -1dt "$SNAP_DIR"/*/ 2>/dev/null | tail -n +11 | xargs -r rm -rf   # 只留最近 10 份
}

cmd_rollback(){
  need_root rollback; _lock
  # 参数: <序号>(默认0) | --dir <快照目录>(精确指定, 供 update 用) | --git <ref>(回滚后把 REPO_DIR 复位到该提交)
  local idx="" dir="" git_ref="" target
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --dir) dir="${2:-}"; shift 2 || { echo "--dir 缺参数"; return 1; };;
      --git) git_ref="${2:-}"; shift 2 || { echo "--git 缺参数"; return 1; };;
      *) idx="$1"; shift;;
    esac
  done
  if [[ -n "$dir" ]]; then
    target="$dir"; [[ -d "$target" ]] || { echo "指定快照目录不存在: $target"; return 1; }
  else
    local snaps; mapfile -t snaps < <(ls -1dt "$SNAP_DIR"/*/ 2>/dev/null)
    [[ ${#snaps[@]} -gt 0 ]] || { echo "没有快照(先 pdg snapshot)"; return 1; }
    echo "可用快照(新→旧):"; local i=0; for s in "${snaps[@]}"; do echo "  [$i] $(basename "$s")"; i=$((i+1)); done
    idx="${idx:-0}"
    [[ "$idx" =~ ^[0-9]+$ ]] || { echo "无效序号 $idx"; return 1; }
    idx=$((10#$idx))
    (( idx >= ${#snaps[@]} )) && { echo "无效序号 $idx"; return 1; }
    target="${snaps[$idx]}"
  fi
  local f="$target/snap.tar.gz"
  [[ -f "$f" ]] || { echo "快照文件缺失: $f"; return 1; }
  # 先完整解包、净化并校验临时树，再把同一棵树落盘；坏包/净化失败不碰现网。
  local tmp="" tree="" members="" panel_sanitized=0
  if ! tmp="$(_pdg_mktemp_dir)"; then echo "❌ 无法创建回滚临时目录"; return 1; fi
  tree="$tmp/tree"; members="$tmp/members"
  if ! mkdir -p "$tree" || ! tar tzf "$f" > "$members" 2>/dev/null || [[ ! -s "$members" ]]; then
    echo "❌ 快照目录或成员清单读取失败, 中止"; rm -rf "$tmp"; return 1
  fi
  if grep -Eq '(^/|(^|/)\.\.(/|$))' "$members" || grep -Evq '^(etc|opt|usr/local/bin)(/|$)' "$members"; then
    echo "❌ 快照含越界路径, 中止"; rm -rf "$tmp"; return 1
  fi
  if ! tar xzf "$f" -C "$tree" 2>/dev/null; then
    echo "❌ 快照解包失败, 中止"; rm -rf "$tmp"; return 1
  fi
  if _sb_panel_managed_on "$tree/etc/sing-box/config.json"; then
    if ! _sb_sanitize_panel "$tree/etc/sing-box/config.json"; then
      echo "❌ 快照面板临时态净化失败, 中止"; rm -rf "$tmp"; return 1
    fi
    panel_sanitized=1
  fi
  # 内核配置校验(v1.6.0 只剩 mihomo)。快照带 mihomo 配置就用 mihomo 校验(优先用快照自带的
  # mihomo 二进制 —— 拿刚升上来的新核校验旧配置可能误挡回滚)。迁移前(singbox)快照没有 mihomo
  # 配置, 此处不拦, 留待落盘后从还原出的 config.json 现渲染再核验(见下方内核收尾)。
  local snap_mbin=""
  [[ -x "$tree/usr/local/bin/mihomo" ]] && snap_mbin="$tree/usr/local/bin/mihomo"
  if [[ -f "$tree/etc/mihomo/config.yaml" ]]; then
    "${snap_mbin:-mihomo}" -t -d "$tree/etc/mihomo" -f "$tree/etc/mihomo/config.yaml" >/dev/null 2>&1 \
      || { echo "❌ 快照的 mihomo 配置 check 失败, 中止"; rm -rf "$tmp"; return 1; }
  fi
  [[ -f "$tree/etc/nftables.conf" ]] && { nft -c -f "$tree/etc/nftables.conf" >/dev/null 2>&1 || { echo "❌ 快照的 nftables 语法错, 中止"; rm -rf "$tmp"; return 1; }; }
  echo "回滚到 $(basename "$target") …"
  if ! _pdg_apply_snapshot_tree "$tree" "$members" /; then
    echo "❌ 快照落盘失败, 系统可能已部分恢复, 请立即检查"; rm -rf "$tmp"; return 1
  fi
  rm -rf "$tmp"
  (( panel_sanitized == 1 )) && c_g "  已净化回滚出的面板临时态 → 关闭"
  local unrestored=()                         # 未能恢复项(内核激活/仓库Git); 非空即"未完全回滚"
  # daemon-reload 失败必须计入: 后面 enable/start 全建立在它之上, 吞掉它等于谎报回滚成功。
  systemctl daemon-reload || unrestored+=("daemon-reload")
  nft -f /etc/nftables.conf 2>/dev/null || true
  # v1.6.0: mihomo 是唯一内核。无论快照记录的是 mihomo 还是迁移前的 singbox, 一律起 mihomo ——
  # config.json 是核无关数据模型, mihomo 总能从它渲染。并清掉快照可能带回来的 sing-box 残留。
  # shellcheck source=/dev/null
  source "$REPO_DIR/lib/units.sh" 2>/dev/null || true
  if [[ ! -f /etc/mihomo/config.yaml ]] && [[ -f /etc/sing-box/config.json ]]; then
    install -d -m700 /etc/mihomo                # 迁移前快照只有 config.json → 现渲染 mihomo 配置
    (cd /opt/pdg-bot && python3 -c 'import sys;sys.path.insert(0,"/opt/pdg-bot");import bot;bot._render_mihomo_file()') 2>/dev/null \
      || unrestored+=("mihomo配置渲染")
  fi
  printf 'mihomo\n' > /etc/privdns-gateway/backend
  # 快照里已经带回 unit 的就别再重生成 —— 快照那份才是"回滚目标状态"的权威。
  # 只有快照没有(或空文件)时才用模板补一份, 免得回滚顺手把状态又改成了当前版本的样子。
  if [[ ! -s /etc/systemd/system/mihomo.service ]]; then
    pdg_write_unit pdg_unit_mihomo /etc/systemd/system/mihomo.service \
      || unrestored+=("mihomo.service 生成")
  fi
  # sing-box 残留只清"项目自己装的"(见 _pdg_singbox_is_ours), 第三方的原样保留
  _pdg_drop_singbox_files "快照带回的"
  systemctl daemon-reload || unrestored+=("daemon-reload(清理后)")
  # 激活失败必须计入 unrestored: 内核没起来就不是"已回滚", 不能只 warn 后照报成功。
  if ! _core_kernel_activate mihomo sing-box; then
    c_y "  mihomo 起核核验未达标, 请 pdg doctor 复查"
    unrestored+=("内核激活(mihomo)")
  fi
  systemctl restart mosdns pdg-bot pdg-probe81 2>/dev/null || true
  systemctl is-enabled pdg-mitm >/dev/null 2>&1 && { systemctl reset-failed pdg-mitm 2>/dev/null; systemctl restart pdg-mitm 2>/dev/null; }   # iOS/WLOC: 清 start-limit + 一并恢复 MITM 服务
  systemctl restart systemd-journald 2>/dev/null || true   # journald CanReload=no: 还原封顶需 restart 才生效
  # 仓库 Git 复位(update 回滚: 让 REPO_DIR 与还原出的旧脚本版本一致); 记录未能恢复项, 不谎报"完全回滚"
  if [[ -n "$git_ref" ]]; then
    if [[ -d "$REPO_DIR/.git" ]] && git -C "$REPO_DIR" reset --hard -q "$git_ref" 2>/dev/null; then
      c_g "  仓库已复位到 ${git_ref:0:12}"
    else
      unrestored+=("仓库Git($git_ref)")
    fi
  fi
  if [[ ${#unrestored[@]} -eq 0 ]]; then
    echo "✅ 已回滚并重启服务"
  else
    c_y "⚠️ 已回滚配置/服务, 但以下项未能恢复(未完全回滚): ${unrestored[*]}"
    return 1
  fi
}

# 内核二进制目录(默认 /usr/local/bin; 测试可用 PDG_CORE_BINDIR 指到沙箱)。
_core_bindir(){ echo "${PDG_CORE_BINDIR:-/usr/local/bin}"; }

# 用**刚装上的**新内核二进制对现网配置跑 check(显式走路径, 不依赖 PATH)。
_core_config_check(){
  local svc="$1" bindir="$2"   # svc 恒为 mihomo(v1.6.0 唯一内核); 保留形参以兼容调用方
  "$bindir/mihomo" -t -d /etc/mihomo -f /etc/mihomo/config.yaml >/dev/null 2>&1
}

# 内核活性 + 稳定判定: 起得来, 且持续观察若干次仍在跑。
# 只抽两次 is-active 挡不住"起来即崩": systemd 会把它反复拉起, 每次抽样都可能正好撞上
# 刚起来的那一瞬。故再比对 NRestarts —— 观察窗口内重启计数涨了就是崩溃循环。
_core_kernel_stable(){
  local svc="$1" i n="${PDG_STABLE_SAMPLES:-3}" r0 r1
  r0="$(systemctl show -p NRestarts --value "$svc" 2>/dev/null)"; r0="${r0:-0}"
  for ((i = 0; i < n; i++)); do
    [[ "$(systemctl is-active "$svc" 2>/dev/null)" == active ]] || return 1
    sleep 1
  done
  r1="$(systemctl show -p NRestarts --value "$svc" 2>/dev/null)"; r1="${r1:-0}"
  [[ "$r0" == "$r1" ]] || { c_y "  $svc 在观察窗口内重启了($r0→$r1), 判为不稳定"; return 1; }
  [[ "$(systemctl is-active "$svc" 2>/dev/null)" == active ]]
}

_pdg_sha(){ sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }

# 把当前内核二进制备份到**本次事务专属**的临时文件, 回显 "备份路径|SHA256"。
# 用 mktemp 而不是固定的 <svc>.prev: 固定名会撞上历史遗留的 .prev —— 备份没拷成时
# 那个来源不明的旧文件会在还原那步被 mv 成正在跑的内核。
# 旧内核存在但备份没做成 → 返回非 0, 调用方必须中止, 绝不能去装新内核。
_core_stash_kernel(){
  local svc="$1" bindir="$2" tmp sha
  local bin="$bindir/$svc"
  [[ -e "$bin" ]] || { echo "|"; return 0; }        # 装前没有旧内核: 没什么可备份
  sha="$(_pdg_sha "$bin")"; [[ -n "$sha" ]] || return 1
  tmp="$(mktemp "$bindir/.$svc.pdg-prev.XXXXXX" 2>/dev/null)" || return 1
  if ! cp -a "$bin" "$tmp" 2>/dev/null || [[ "$(_pdg_sha "$tmp")" != "$sha" ]]; then
    rm -f "$tmp" 2>/dev/null; return 1
  fi
  echo "$tmp|$sha"
}

# 还原本次事务备份的旧内核并重新拉起。逐项校验: mv 成功 → 内容 SHA 与备份一致 →
# 旧服务 active 且稳定。任一步不达标返回非 0(只看"服务 active"不算数)。
_core_restore_prev(){
  local svc="$1" bindir="${2:-$(_core_bindir)}" bak="${3:-}" sha="${4:-}"
  local bin="$bindir/$svc"
  if [[ -n "$bak" ]]; then
    [[ -e "$bak" ]] || { c_y "  旧内核备份不存在($bak), 无法还原"; return 1; }
    mv -f "$bak" "$bin" 2>/dev/null || { c_y "  旧内核还原失败(mv)"; return 1; }
    if [[ -n "$sha" && "$(_pdg_sha "$bin")" != "$sha" ]]; then
      c_y "  旧内核还原后校验和与备份不符"; return 1
    fi
  fi
  systemctl restart "$svc" 2>/dev/null || true
  _core_kernel_stable "$svc" || { c_y "  旧内核重启后未稳定运行"; return 1; }
}

# 内核热切(mihomo/sing-box 同一套): 备份旧核 → 装新 → 配置 check → 重启 → 活性/稳定判定。
# 关键安全: **确认新核已稳定运行后才删 .prev**; 在此之前任一步失败都还原旧核并 return 1
# (旧实现在 check 通过时就删了 .prev, 新核重启失败便无核可退)。
_core_swap_verify(){
  local svc="$1" newbin="$2" bindir="$3" ver="$4"
  local bin="$bindir/$svc" stash bak="" sha=""
  # 备份必须先成: 拷不下来就在这里停, 绝不能带着"无核可退"的状态去装新内核。
  if ! stash="$(_core_stash_kernel "$svc" "$bindir")"; then
    c_y "  备份现有 $svc 失败 → 中止换核(不在无法回退的前提下装新内核)。"; return 1
  fi
  IFS='|' read -r bak sha <<<"$stash"
  if ! install -m755 "$newbin" "$bin"; then
    c_y "  新内核安装失败, 还原旧版内核"
    _core_restore_prev "$svc" "$bindir" "$bak" "$sha" || c_y "  ⚠️ 旧版内核回退未达标, 请立即 pdg doctor"
    return 1
  fi
  if ! _core_config_check "$svc" "$bindir"; then
    c_y "  新版与当前配置不兼容(check 失败), 已还原旧版内核"
    _core_restore_prev "$svc" "$bindir" "$bak" "$sha" || c_y "  ⚠️ 旧版内核回退未达标, 请立即 pdg doctor"
    return 1
  fi
  systemctl restart "$svc" 2>/dev/null || true
  if ! _core_kernel_stable "$svc"; then
    c_y "  新版内核重启后未稳定运行, 已还原旧版内核并重启"
    _core_restore_prev "$svc" "$bindir" "$bak" "$sha" || c_y "  ⚠️ 旧版内核回退未达标, 请立即 pdg doctor"
    return 1
  fi
  [[ -n "$bak" ]] && rm -f "$bak" 2>/dev/null    # 到此新核确认可用, 旧核备份才可以删
  c_g "  → $svc $ver 已装并重启"
}

# 内核二进制更新: 比对 versions.sh 钉死版本与已装版本, 不一致则下载+SHA校验+装。
# 关键安全: 先备份旧二进制, 用新二进制对现有配置跑 check + 重启稳定判定, 全过才切换; 失败还原旧版, 不留坏内核。
# 返回: 0=已是钉死版/下载或校验失败(保留现版本, 非致命); 1=换核失败(已还原) → 调用方须回滚整次更新。
_update_core_binary(){
  local march ver tmp bindir   # v1.6.0: mihomo 是唯一内核
  bindir="$(_core_bindir)"
  # shellcheck source=/dev/null
  # 读不到 versions.sh 就无从知道该装哪个版本 —— 以前"跳过"后照报成功, 实际内核可能没升上去。
  source "$REPO_DIR/lib/versions.sh" 2>/dev/null \
    || { c_y "读不到 versions.sh, 无法确认内核目标版本"; return 1; }
  march=$(dpkg --print-architecture 2>/dev/null); [[ "$march" == arm64 ]] || march=amd64
  tmp=$(mktemp -d)
  ver="$MIHOMO_VER"
  pdg_mihomo_is_version "$ver" && { rm -rf "$tmp"; return 0; }   # 已是钉死版本(精确比较, 非子串)
  c_g "更新 mihomo 内核 → $ver …"
  curl -fsSL "https://github.com/MetaCubeX/mihomo/releases/download/${ver}/mihomo-linux-${march}-${ver}.gz" -o "$tmp/m.gz" \
    || { c_y "  下载失败(版本与发布不一致, 不能当作已更新)"; rm -rf "$tmp"; return 1; }
  pdg_verify_sha256 "$tmp/m.gz" "${PDG_SHA256[mihomo-$march]:-}" "mihomo $ver ($march)" \
    || { c_y "  SHA 校验失败 → 判为更新失败(不降级成警告后继续)"; rm -rf "$tmp"; return 1; }
  gunzip -c "$tmp/m.gz" > "$tmp/mihomo" || { c_y "  解压失败"; rm -rf "$tmp"; return 1; }
  [[ -s "$tmp/mihomo" ]] || { c_y "  解压产物为空"; rm -rf "$tmp"; return 1; }
  if ! _core_swap_verify mihomo "$tmp/mihomo" "$bindir" "$ver"; then rm -rf "$tmp"; return 1; fi
  rm -rf "$tmp"
}

cmd_update(){
  need_root update
  command -v git >/dev/null || { apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq git; }
  if [[ "${1:-}" == "--dry-run" ]]; then
    [[ -d "$REPO_DIR/.git" ]] && pdg_fetch_release_tags "$REPO_DIR" 2>/dev/null
    local tgt; tgt=$(git -C "$REPO_DIR" tag -l 'v*' --sort=-v:refname 2>/dev/null | head -1)
    echo "当前: $(git -C "$REPO_DIR" describe --tags --always 2>/dev/null)   最新发布: ${tgt:-(无 tag)}"
    [[ -n "$tgt" ]] && { echo "待更新提交(HEAD..$tgt):"; git -C "$REPO_DIR" log --oneline "HEAD..$tgt" 2>/dev/null || echo "  (已是最新或无法比较)"; }
    return 0
  fi
  _lock   # 取锁(嵌套的 cmd_snapshot 不会重复锁)
  c_g "更新前留快照…"
  if ! cmd_snapshot >/dev/null 2>&1 || [[ -z "$_PDG_SNAP_CREATED" || ! -f "$_PDG_SNAP_CREATED/snap.tar.gz" ]]; then
    c_y "❌ 更新前快照失败, 中止更新(拒绝在无法回滚的前提下继续)。"; return 1
  fi
  local snap_dir="$_PDG_SNAP_CREATED"                                    # 精确回滚目标(不靠 index 0 猜)
  local pre_sha; pre_sha="$(git -C "$REPO_DIR" rev-parse HEAD 2>/dev/null)"   # 升级前精确提交, 回滚据此复位仓库
  c_g "拉取最新发布 tag…"
  [[ -d "$REPO_DIR/.git" ]] || { rm -rf "$REPO_DIR"; git clone -q "$REPO_URL" "$REPO_DIR"; }
  if ! pdg_fetch_release_tags "$REPO_DIR"; then
    c_y "拉取发布 tag 失败, 中止更新。"; return 1
  fi
  local tgt; tgt=$(git -C "$REPO_DIR" tag -l 'v*' --sort=-v:refname | head -1)
  if [[ -z "$tgt" ]]; then
    c_y "仓库没有发布 tag(v*), 中止更新。"; return 1
  fi
  if ! git -C "$REPO_DIR" reset --hard -q "$tgt"; then
    c_y "git reset 到 $tgt 失败, 回滚到更新前快照…"; cmd_rollback --dir "$snap_dir" --git "$pre_sha"; return 1
  fi
  c_g "→ 已切到发布 $tgt"
  c_g "刷新代码(配置/出口/token/证书均不动)…"
  # 必需文件: 任一装失败即立即回滚(拒绝新旧混部)。`! A || ! B` 在首个失败处短路。
  if   ! install -m755 "$REPO_DIR"/deploy/bot/pdg-bot.py           /opt/pdg-bot/bot.py \
    || ! install -m755 "$REPO_DIR"/deploy/bot/parse-geosite.py     /opt/pdg-bot/ \
    || ! install -m755 "$REPO_DIR"/deploy/bot/update-rules.sh      /opt/pdg-bot/ \
    || ! install -m755 "$REPO_DIR"/deploy/bot/scheduled-update.sh  /opt/pdg-bot/ \
    || ! install -m755 "$REPO_DIR"/deploy/bot/healthcheck.py       /opt/pdg-bot/ \
    || ! install -m755 "$REPO_DIR"/deploy/bot/checks.py            /opt/pdg-bot/ \
    || ! install -m755 "$REPO_DIR"/deploy/bot/doctor.py            /opt/pdg-bot/ \
    || ! install -m755 "$REPO_DIR"/deploy/bot/report.py           /opt/pdg-bot/ \
    || ! install -m755 "$REPO_DIR"/deploy/bot/sb2mihomo.py        /opt/pdg-bot/ \
    || ! install -m755 "$REPO_DIR"/deploy/cert/proxy-gateway-open-cert-http.sh   /usr/local/bin/ \
    || ! install -m755 "$REPO_DIR"/deploy/cert/proxy-gateway-restore-firewall.sh /usr/local/bin/ \
    || ! install -m755 "$REPO_DIR"/deploy/bot/pdg-set-token.sh     /usr/local/bin/pdg-set-token \
    || ! install -m755 "$REPO_DIR"/deploy/bot/pdg.sh               /usr/local/bin/pdg; then
    c_y "必需文件安装失败, 回滚到更新前快照…"; cmd_rollback --dir "$snap_dir" --git "$pre_sha"; return 1
  fi
  # iOS 专属组件按平台部署: Android 更新不把 iOS 文件装回来(migrate_android_cleanup 亦会清残留)。
  # iOS 上这些**不是可选项**: probe81 与描述文件模板是 iOS 基础能力, WLOC 开着时 mitm 三件
  # 也是必需件。以前一律 `|| true`, 装失败就把上一版的旧文件留在原地 → 新旧混装, 而 doctor
  # 只看"文件在不在", 照样判绿。
  if [[ "$(_pdg_platform)" == ios ]]; then
    if   ! install -m755 "$REPO_DIR"/deploy/bot/mitm_ca.py          /opt/pdg-bot/ \
      || ! install -m755 "$REPO_DIR"/deploy/bot/mitm_server.py      /opt/pdg-bot/ \
      || ! install -m755 "$REPO_DIR"/deploy/bot/mitm_wloc.py        /opt/pdg-bot/ \
      || ! install -m755 "$REPO_DIR"/deploy/ios/probe81.py          /opt/pdg-bot/ \
      || ! install -m644 "$REPO_DIR"/deploy/ios/pdg-dot-ondemand.mobileconfig.tmpl /opt/pdg-bot/pdg-dot.mobileconfig.tmpl; then
      c_y "iOS 平台组件安装失败, 回滚到更新前快照…"; cmd_rollback --dir "$snap_dir" --git "$pre_sha"; return 1
    fi
  fi
  install -m644 "$REPO_DIR"/deploy/bot/pdg-health.service  /etc/systemd/system/ 2>/dev/null || true
  install -m644 "$REPO_DIR"/deploy/bot/pdg-health.timer    /etc/systemd/system/ 2>/dev/null || true
  install -m755 "$REPO_DIR"/deploy/cert/99-reload-cert.deploy-hook.sh     /etc/letsencrypt/renewal-hooks/deploy/99-pdg-cert.sh 2>/dev/null || true
  # 迁移用"刚装好的新脚本"跑(本进程还是旧 bash, 直接调会用旧版函数 → 新迁移要等下次命令才生效)。
  if ! bash /usr/local/bin/pdg __migrate; then
    c_y "迁移(__migrate)失败, 回滚到更新前快照…"; cmd_rollback --dir "$snap_dir" --git "$pre_sha"; return 1
  fi
  # 内核二进制: mihomo 按 versions.sh 钉死版本更新。
  if ! _update_core_binary; then
    c_y "内核二进制更新失败, 回滚到更新前快照…"; cmd_rollback --dir "$snap_dir" --git "$pre_sha"; return 1
  fi

  # ── 更新后校验门: 任一硬校验失败即回滚到更新前快照 ──
  c_g "校验新版本…"
  if ! python3 -m py_compile /opt/pdg-bot/*.py 2>/dev/null; then
    c_y "Python 语法错误, 回滚到更新前快照…"; cmd_rollback --dir "$snap_dir" --git "$pre_sha"; return 1
  fi
  if ! mihomo -t -d /etc/mihomo -f /etc/mihomo/config.yaml >/dev/null 2>&1; then
    c_y "mihomo 配置 check 失败, 回滚…"; cmd_rollback --dir "$snap_dir" --git "$pre_sha"; return 1
  fi
  if ! nft -c -f /etc/nftables.conf >/dev/null 2>&1; then
    c_y "nftables 配置 check 失败, 回滚…"; cmd_rollback --dir "$snap_dir" --git "$pre_sha"; return 1
  fi
  if ! systemctl daemon-reload; then
    c_y "systemctl daemon-reload 失败, 回滚到更新前快照…"; cmd_rollback --dir "$snap_dir" --git "$pre_sha"; return 1
  fi
  systemctl enable --now pdg-health.timer >/dev/null 2>&1 || true   # 老装升级时补上健康自检
  systemctl restart pdg-bot pdg-probe81 2>/dev/null || true
  systemctl is-enabled pdg-mitm >/dev/null 2>&1 && { systemctl reset-failed pdg-mitm 2>/dev/null; systemctl restart pdg-mitm 2>/dev/null; }   # iOS/WLOC: 清 start-limit + 载新插件代码, 否则 doctor 判 pdg-mitm 未运行而误回滚
  sleep 2

  # token 是否已配置(未配则 pdg-bot 不在跑属正常, 不据此回滚)
  local token_set=0
  [[ -f "$ENVF" ]] && grep -qE '^PDG_BOT_TOKEN=.+' "$ENVF" && grep -qE '^PDG_BOT_ALLOWED=.+' "$ENVF" && token_set=1
  if [[ "$token_set" == 1 && "$(systemctl is-active pdg-bot 2>/dev/null)" != "active" ]]; then
    c_y "pdg-bot 更新后起不来, 回滚到更新前快照…"; cmd_rollback --dir "$snap_dir" --git "$pre_sha"; return 1
  fi

  # doctor 自检门: 自检本身必须跑通且输出可信, 才有资格说"已更新"。
  # 以前 doctor 用 `|| true` 吞掉退出码, 且没有 jq 就整段跳过 —— 自检崩了/输出坏了/机器没装
  # jq, 都会直接跳到"✅ 已更新"。改用 python3 解析(本项目本来就硬依赖 python3, 不再依赖 jq),
  # 并要求输出是**非空的 JSON 数组**; 任何一环不成立都按"无法确认更新结果"回滚。
  # (未配 token 时把"服务: 未运行: pdg-bot"这单一项排除, 避免误判)
  local j rcd=0 summary nfail
  if ! command -v python3 >/dev/null 2>&1; then   # 与"自检输出坏"区分开, 免得排错走偏
    c_y "python3 不可用, 无法运行/判读自检 → 回滚到更新前快照…"
    cmd_rollback --dir "$snap_dir" --git "$pre_sha"; return 1
  fi
  j=$(python3 /opt/pdg-bot/doctor.py --json 2>/dev/null) || rcd=$?
  # doctor 的约定是"有 fail → 1, 否则 0", 所以 **1 是正常结果**而不是"没跑起来"。
  # 把 1 也当异常会直接绕过下面按 JSON 做的判定 —— 包括"未配 token 时 pdg-bot 未运行"
  # 那条豁免, 于是没配 bot token 的机器会永远升级失败; 也拿不到逐项失败清单。
  # 真正的异常是**别的**退出码(崩溃 / 找不到 / 被杀)。
  if [[ "$rcd" != 0 && "$rcd" != 1 ]]; then
    c_y "自检命令异常退出(exit $rcd), 无法确认更新结果, 回滚到更新前快照…"
    cmd_rollback --dir "$snap_dir" --git "$pre_sha"; return 1
  fi
  if ! summary=$(printf '%s' "$j" | python3 -c '
import json, sys
d = json.load(sys.stdin)
if not isinstance(d, list) or not d:
    raise SystemExit("doctor 输出不是非空 JSON 数组")
tok = sys.argv[1] == "1"
fails = [x for x in d if x.get("level") == "fail"
         and (tok or x.get("check") != "服务" or x.get("detail") != "未运行: pdg-bot")]
warns = [x for x in d if x.get("level") == "warn"]
print(len(fails))
for x in fails: print("  ❌ %s: %s" % (x.get("check"), x.get("detail")))
print("@@WARN@@")
for x in warns: print("  ⚠️ %s: %s" % (x.get("check"), x.get("detail")))
' "$token_set" 2>/dev/null); then
    c_y "自检输出不可解析(应为非空 JSON 数组), 无法确认更新结果, 回滚到更新前快照…"
    cmd_rollback --dir "$snap_dir" --git "$pre_sha"; return 1
  fi
  nfail="$(sed -n 1p <<<"$summary")"
  if [[ ! "$nfail" =~ ^[0-9]+$ ]]; then
    c_y "自检结果无法判读, 回滚到更新前快照…"; cmd_rollback --dir "$snap_dir" --git "$pre_sha"; return 1
  fi
  if [[ "$nfail" -gt 0 ]]; then
    c_y "自检发现 $nfail 项失败, 回滚到更新前快照:"
    sed -n '2,/^@@WARN@@$/p' <<<"$summary" | sed '/^@@WARN@@$/d'
    cmd_rollback --dir "$snap_dir" --git "$pre_sha"; return 1
  fi
  local warnlines; warnlines="$(sed -n '/^@@WARN@@$/,$p' <<<"$summary" | tail -n +2)"
  [[ -n "$warnlines" ]] && { c_y "自检有警告(不回滚, 仅提示):"; printf '%s\n' "$warnlines"; }
  c_g "✅ 已更新。"
}

cmd_token(){ need_root token; pdg-set-token; }   # 不 exec, 设完/取消都回菜单

# shellcheck disable=SC2086  # $svcs 是有意按空白分词的服务名列表
cmd_restart(){ need_root restart; local svcs; svcs="$(_pdg_svcs)"; systemctl restart $svcs 2>/dev/null; echo "已重启: $svcs"; }

# 内核日志跟当前后端走(mihomo 机上取 sing-box 只会得到空日志), 与 report.py 同口径。
cmd_log(){ journalctl -u pdg-bot -u mosdns -u "$(_pdg_core_svc)" -n "${1:-40}" --no-pager -o cat; }

cmd_traffic(){ command -v vnstat >/dev/null && vnstat || echo "vnstat 未装: sudo apt install -y vnstat && systemctl enable --now vnstat"; }

cmd_report(){ need_root report; python3 /opt/pdg-bot/report.py "$@"; }

# 抓包识别内网卡来源段, 检测到与现配不符时可一键写回 mosdns+nftables 并重启(装完随时跑, 比装机时从容)。
cmd_detect_cidr(){
  need_root detect-cidr
  local dur="${1:-30}" sip det cur
  # shellcheck source=/dev/null
  source "$REPO_DIR/lib/cidr.sh" 2>/dev/null || { echo "❌ 读不到 lib/cidr.sh"; return 1; }
  sip=$(grep -oE '"[0-9.]+/32"' /etc/sing-box/config.json 2>/dev/null | tr -d '"' | grep -v '^127' | head -1 | cut -d/ -f1)
  # 抓包与手输并行(与装机同款): 知道网段就直接输, 不必干等抓包
  det=$(pdg_detect_cidr_race "$dur" "${sip:-本机IP}" || true)
  if [[ -z "$det" ]]; then
    c_y "没抓到。确认手机走内网卡(关 WiFi), 或云安全组放行入站 80/ICMP, 再重试。"; return 1
  fi
  if ! pdg_cidr_valid "$det"; then
    c_y "「$det」不是合法网段(形如 172.22.0.0/16), 未改动。"; return 1
  fi
  cur=$(grep -oE 'ip saddr [0-9./]+' /etc/nftables.conf 2>/dev/null | head -1 | awk '{print $3}')
  echo "  检测到内网卡段: $det"
  echo "  当前配置:       ${cur:-未知}"
  [[ "$det" == "$cur" ]] && { c_g "✅ 与当前一致, 无需改动。"; return 0; }
  read -rp "把内网卡段 ${cur:-?} → $det 并应用(写 mosdns+nftables 并重启)? [y/N]: " yn
  [[ "$yn" == [yY] ]] || { echo "已取消, 未改动。"; return 0; }
  _lock; c_g "先留快照…"; cmd_snapshot >/dev/null 2>&1 || true
  [[ -n "$cur" ]] && sed -i "s#${cur//./\\.}#$det#g" /etc/nftables.conf
  sed -i -E "s#(ips:[[:space:]]*\[[[:space:]]*\")[0-9./]+(\")#\1$det\2#" /etc/mosdns/config.yaml
  if ! nft -c -f /etc/nftables.conf >/dev/null 2>&1; then c_y "nft 校验失败, 回滚…"; cmd_rollback 0; return 1; fi
  nft -f /etc/nftables.conf
  systemctl restart mosdns; sleep 2
  [[ "$(systemctl is-active mosdns)" == active ]] || { c_y "mosdns 重启异常, 回滚…"; cmd_rollback 0; return 1; }
  c_g "✅ 内网卡段已更新为 $det 并重启 mosdns。"
}

cmd_ios(){
  need_root ios
  # 平台门控: Android 直接拒绝 —— 不装 qrencode、不临时改 nft、不开 8443。
  if [[ "$(_pdg_platform)" != ios ]]; then
    echo "❌ iOS 描述文件仅 iOS 平台可用(本机为 Android)。"
    # 推测态下不能把"本机是 Android"当成事实说 —— 没人确认过。v1.4.x 升上来的 iPhone
    # 机器正落在这里, 一句干巴巴的拒绝会让人以为功能没了, 其实只差一条确认命令。
    if [[ -e /etc/privdns-gateway/platform.guessed ]]; then
      echo "   ⚠️ 这个 android 是**推测**的(老装升级时无确凿证据), 没人确认过。"
      echo "   若本网关服务的是 iPhone: sudo pdg platform ios   (确认后本功能立即可用)"
    else
      echo "   Android 请在手机『私密 DNS』直接填 DoT 域名。"
    fi
    return 1
  fi
  local TMPL=/opt/pdg-bot/pdg-dot.mobileconfig.tmpl
  [[ -f "$TMPL" ]] || { echo "缺少 $TMPL, 先装好 PrivDNS Gateway"; return 1; }
  command -v qrencode >/dev/null || { c_g "装 qrencode…"; apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq qrencode; }
  # 取 DoT 主机名(证书 CN)/ 公网 IP / 内网卡段
  local CERT=/etc/mosdns/certs/fullchain.pem; [[ -f /etc/dnsdist/certs/fullchain.pem ]] && CERT=/etc/dnsdist/certs/fullchain.pem
  local HOST IP CIDR
  HOST=$(openssl x509 -in "$CERT" -noout -subject 2>/dev/null | grep -oE 'CN *= *[A-Za-z0-9.*-]+' | sed 's/.*= *//')
  IP=$(grep -oE '"[0-9.]+/32"' /etc/sing-box/config.json 2>/dev/null | tr -d '"' | grep -v '^127' | head -1 | cut -d/ -f1)
  [[ -n "$IP" ]] || IP=$(curl -fsSL --max-time 6 https://api.ipify.org)
  CIDR=$(grep -oE 'ip saddr [0-9./]+' /etc/nftables.conf 2>/dev/null | head -1 | awk '{print $3}')
  [[ -n "$HOST" && -n "$IP" && -n "$CIDR" ]] || { echo "信息不全 (HOST=$HOST IP=$IP CIDR=$CIDR)"; return 1; }

  local PORT=8443 TOK U1 U2 WWW URL
  TOK=$(openssl rand -hex 6)
  U1=$(cat /proc/sys/kernel/random/uuid | tr a-z A-Z); U2=$(cat /proc/sys/kernel/random/uuid | tr a-z A-Z)
  WWW=$(mktemp -d)
  sed -e "s/__DOT_HOST__/$HOST/g" -e "s/__JP_IP__/$IP/g" -e "s/__UUID1__/$U1/g" -e "s/__UUID2__/$U2/g" \
      "$TMPL" > "$WWW/$TOK.mobileconfig"
  URL="http://$IP:$PORT/$TOK.mobileconfig"

  local SRV=""
  trap 'kill "$SRV" 2>/dev/null; nft -f /etc/nftables.conf 2>/dev/null; rm -rf "$WWW"; trap - INT TERM' INT TERM
  nft insert rule inet pdg input ip saddr "$CIDR" tcp dport "$PORT" accept 2>/dev/null
  ( cd "$WWW" && timeout 600 python3 -m http.server "$PORT" --bind 0.0.0.0 >/dev/null 2>&1 ) &
  SRV=$!
  qrencode -o /opt/pdg-bot/ios-qr.png "$URL" 2>/dev/null || true
  echo
  c_g "用手机(走【内网卡/蜂窝】, 关 WiFi)扫下面二维码 → Safari 打开 → 安装描述文件:"
  echo; qrencode -t ANSIUTF8 "$URL"; echo
  echo "  链接: $URL"
  echo "  DoT:  $HOST   (PNG 已存 /opt/pdg-bot/ios-qr.png)"
  c_y "装好后按回车收尾(10 分钟自动收)…"
  read -t 600 -r _ || true
  kill "$SRV" 2>/dev/null
  nft -f /etc/nftables.conf 2>/dev/null   # 撤掉临时放行
  rm -rf "$WWW"
  echo "已关闭临时下载服务。"
}

cmd_uninstall(){
  need_root uninstall
  if [[ -f "$REPO_DIR/uninstall.sh" ]]; then bash "$REPO_DIR/uninstall.sh" "${1:-}"
  else c_y "没找到 $REPO_DIR/uninstall.sh, 先 pdg update 拉取仓库"; fi
}

menu(){
  while true; do
    echo; c_g "===== PrivDNS Gateway 管理 ====="
    echo "  1) 状态"
    echo "  2) 自检 (doctor)"
    echo "  3) 更新"
    echo "  4) 快照备份"
    echo "  5) 回滚"
    echo "  6) 设置/更换 Bot Token 与 TG ID"
    echo "  7) 重启服务"
    echo "  8) 日志"
    echo "  9) 流量 (vnstat)"
    [[ "$(_pdg_platform)" == ios ]] && echo " 10) iOS 描述文件"   # iOS 专属: Android 不显示
    echo " 11) 诊断报告 (脱敏)"
    echo " 12) 识别内网卡段"
    echo " 13) 卸载"
    echo "  0) 退出"
    echo "  下次打开本菜单命令: pdg"
    printf "选择: "
    read -r c || exit 0
    case "$c" in
      1) cmd_status;;
      2) cmd_doctor;;
      3) cmd_update && exec /usr/local/bin/pdg menu;;
      4) cmd_snapshot;;
      5) read -rp "回滚到第几个快照(默认 0=最近, 回车确认): " i; cmd_rollback "${i:-0}";;
      6) cmd_token;;
      7) cmd_restart;;
      8) cmd_log 60;;
      9) cmd_traffic;;
      10) cmd_ios;;
      11) cmd_report;;
      12) cmd_detect_cidr;;
      13) read -rp "卸载: 留空取消 / yes 仅卸载 / purge 连配置一起删: " x
         case "$x" in yes) cmd_uninstall;; purge) cmd_uninstall --purge;; *) echo "已取消";; esac;;
      0|q) exit 0;;
      *) echo "无效选择";;
    esac
  done
}

# 老装升级"自愈": 旧版 pdg update 跑的是旧脚本, 不会调用迁移 → 装上新 pdg.sh 后,
# 全部老装迁移(幂等)。集中一处, 供管理类命令的自愈调用 + cmd_update 装好新脚本后经 `pdg __migrate` 调"新版"。
# 老装 mihomo: 给 mihomo.service 补 Environment=SAFE_PATHS(面板 UI 在 /etc/sing-box/ui/dist, 不在 -d 下)。幂等。
migrate_mihomo_safepaths(){
  [[ "$(_pdg_core)" == mihomo ]] || return 0
  local unit=/etc/systemd/system/mihomo.service
  [[ -f "$unit" ]] || return 0
  grep -q 'SAFE_PATHS' "$unit" && return 0
  c_g "补 mihomo.service 的 SAFE_PATHS(面板 UI 路径放行)…"
  sed -i '/^ExecStart=.*mihomo/a Environment=SAFE_PATHS=/etc/sing-box/ui/dist' "$unit"
  systemctl daemon-reload; systemctl restart mihomo 2>/dev/null || true
}

# 老装升级: 确保所有 bot 模块(.py)都部署到 /opt/pdg-bot。修「旧版 cmd_update 安装列表缺新模块
# (如 sb2mihomo/mitm_*)、首次升级时序滞后漏装」→ 迁移/WLOC 渲染报 ModuleNotFoundError。
# pdg-bot.py 由主安装装成 bot.py, 此处跳过。幂等。
migrate_deploy_botfiles(){
  [[ -d "$REPO_DIR/deploy/bot" ]] || return 0
  local f base plat; plat="$(_pdg_platform)"
  for f in "$REPO_DIR"/deploy/bot/*.py; do
    base=$(basename "$f")
    [[ "$base" == "pdg-bot.py" ]] && continue
    case "$base" in                                   # iOS 专属 MITM 模块: 仅 iOS 装, Android 不装/不复活
      mitm_ca.py|mitm_server.py|mitm_wloc.py) [[ "$plat" == ios ]] || continue;;
    esac
    install -m755 "$f" /opt/pdg-bot/ 2>/dev/null || true
  done
}

# 统一平台判定源: 确保 /etc/privdns-gateway/platform 存在且合法(canonical)。幂等。
# 缺失/非法时按证据回退: profile.env 的 PDG_PLATFORM → 明确 iOS 证据(pdg-mitm unit / WLOC 配置) → android。
# 仍无法确定=android, 但 status/doctor 会另行提示"标记缺失回退"(见 _pdg_platform_present / check_platform)。
migrate_platform_marker(){
  # 路径可用 env 覆盖(供测试注入), 生产用默认 /etc/privdns-gateway/*。
  local pf="${PDG_PLATFORM_FILE:-/etc/privdns-gateway/platform}"
  local prof="${PROFILE_ENV:-/etc/privdns-gateway/profile.env}"
  local mj="${PDG_MITM_JSON:-/etc/privdns-gateway/mitm.json}"
  local mu="${PDG_MITM_UNIT:-/etc/systemd/system/pdg-mitm.service}"
  local cur; cur="$(cat "$pf" 2>/dev/null)"
  [[ "$cur" == ios || "$cur" == android ]] && return 0        # 已合法 → 幂等
  local plat=""
  # 1) profile.env 的 PDG_PLATFORM
  if [[ -f "$prof" ]]; then
    local pp; pp="$(sed -n 's/^PDG_PLATFORM=//p' "$prof" | tail -1)"
    [[ "$pp" == ios || "$pp" == android ]] && plat="$pp"
  fi
  # 2) 明确 iOS 证据: 已装 pdg-mitm unit 或存在 WLOC 配置(启用过接管)
  if [[ -z "$plat" ]]; then
    if [[ -f "$mu" ]] || grep -q '"wloc"' "$mj" 2>/dev/null; then plat=ios; fi
  fi
  # 3) 仍无法确定 → 安全回退 android, 但**标记为推测**。v1.4.x 把 probe81/描述文件装给所有
  #    机器, 它们的存在证明不了平台; 贸然按 android 做破坏性清理会把真 iPhone 部署的 iOS
  #    组件删掉。打上 .guessed 后: 破坏性清理一律不做, doctor 持续提示, 等人工确认。
  local guessed=0
  [[ -n "$plat" ]] || { plat=android; guessed=1; }
  mkdir -p "$(dirname "$pf")" 2>/dev/null || true
  local t; t="$(mktemp "$(dirname "$pf")/.platform.XXXXXX" 2>/dev/null)" || return 0
  if printf '%s\n' "$plat" > "$t" && mv -f "$t" "$pf"; then
    if [[ "$guessed" == 1 ]]; then
      : > "$(dirname "$pf")/platform.guessed" 2>/dev/null || true
      c_y "补平台标记: android(**推测**, 无确凿证据)。若这台服务 iPhone, 请运行: sudo pdg platform ios"
    else
      rm -f "$(dirname "$pf")/platform.guessed" 2>/dev/null || true
      c_g "补平台标记: $plat(据现有证据)。"
    fi
  else rm -f "$t" 2>/dev/null; fi
}

# 老装(v1.4.x, WLOC 之前)迁移: 给 mosdns 补 MITM 接管结构 —— force_hijack domain_set +
# force_hijack_seq + internal_sequence 里的优先级规则 + 空 mitm_hijack.txt。平时空文件=休眠, 零影响。
# 只认标准结构(有 internal_sequence + geosite_cn 优先级锚点 + 可提取的网关 IP); 自定义配置不强改(交 doctor)。
# 幂等(已有 force_hijack 即退); 备份→生成→校验重启→失败还原。$1 可指定文件(供测试)。
# shellcheck disable=SC2120
migrate_mosdns_mitm(){
  local f="${1:-/etc/mosdns/config.yaml}"
  [[ -f "$f" ]] || return 0
  grep -q 'tag: force_hijack' "$f" && return 0                          # 已有 → 幂等退出
  grep -q 'tag: internal_sequence' "$f" && grep -q 'tag: ecs_china' "$f" || return 0   # 非本项目形态 → 不动
  grep -qE '^\s+- matches: qname \$geosite_cn' "$f" || return 0         # 缺优先级锚点 → 不动(交 doctor warn)
  local sip; sip="$(grep -oE 'black_hole [0-9.]+' "$f" | head -1 | awk '{print $2}')"
  [[ -n "$sip" ]] || { c_y "  [MITM迁移] 提取网关IP失败(未渲染?), 跳过(交 doctor)。"; return 0; }
  # 规则目录从现有 geosite_cn 路径推导(生产=/etc/mosdns/rules; 测试=临时目录), 保证注入路径与实际文件一致
  local rdir; rdir="$(grep -oE '"/[^"]*/geosite_cn\.txt"' "$f" | head -1 | tr -d '"')"
  rdir="$(dirname "$rdir" 2>/dev/null)"; [[ -n "$rdir" && "$rdir" != "." ]] || rdir="/etc/mosdns/rules"
  c_g "补 mosdns MITM 接管结构(force_hijack, 平时空文件=休眠)…"
  install -d -m755 "$rdir" 2>/dev/null || true
  [[ -e "$rdir/mitm_hijack.txt" ]] || : > "$rdir/mitm_hijack.txt"   # 空接管集(休眠)
  local bak; bak="$f.premitm.$(date +%s)"
  if ! cp -a "$f" "$bak" 2>/dev/null || ! cmp -s "$f" "$bak"; then
    c_y "  备份失败(磁盘满?), 中止、不动现网。"; rm -f "$bak" 2>/dev/null; return 0
  fi
  if ! python3 - "$f" "$sip" "$rdir" <<'PY'
import sys
f, sip, rdir = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(f).read()
# 1. force_hijack domain_set(锚点: ecs_china 定义行之前)
ds = ('  - tag: force_hijack\n'
      '    type: domain_set\n'
      '    args: { files: ["%s/mitm_hijack.txt"] }\n'
      '  - tag: ecs_china') % rdir
assert s.count('  - tag: ecs_china') == 1, 'ecs_china 锚点不唯一'
s = s.replace('  - tag: ecs_china', ds, 1)
# 2. force_hijack_seq(锚点: internal_sequence 定义行之前); black_hole 用真实网关 IP
seq = ('  - tag: force_hijack_seq\n'
       '    type: sequence\n'
       '    args:\n'
       '      - matches: qtype 28\n'
       '        exec: reject 0\n'
       '      - matches: qtype 65\n'
       '        exec: reject 0\n'
       '      - exec: jump has_resp\n'
       '      - matches: qtype 1\n'
       '        exec: black_hole %s\n'
       '  - tag: internal_sequence') % sip
assert s.count('  - tag: internal_sequence') == 1, 'internal_sequence 锚点不唯一'
s = s.replace('  - tag: internal_sequence', seq, 1)
# 3. 优先级规则(锚点: 第一个 geosite_cn 匹配之前, 即 CN 判定前强制接管)
anchor = '      - matches: qname $geosite_cn'
rule = ('      - matches: qname $force_hijack\n'
        '        exec: goto force_hijack_seq\n' + anchor)
i = s.find(anchor)
assert i != -1, 'geosite_cn 锚点缺失'
s = s[:i] + rule + s[i + len(anchor):]
open(f, 'w').write(s)
PY
  then c_y "  生成失败 → 还原。"; cp -a "$bak" "$f"; return 0; fi
  # 校验: 若装了 mosdns 就真起一遍确认可加载, 否则只留新配置(测试环境无 mosdns)
  if command -v mosdns >/dev/null 2>&1 && systemctl list-units --all 2>/dev/null | grep -q mosdns.service; then
    systemctl restart mosdns 2>/dev/null; sleep 1
    if [[ "$(systemctl is-active mosdns 2>/dev/null)" == active ]]; then
      c_g "  ✅ 已补 force_hijack(MITM 接管结构)。"
    else
      c_y "  ⚠️ mosdns 重启失败 → 还原。"; cp -a "$bak" "$f" 2>/dev/null; systemctl restart mosdns 2>/dev/null
    fi
  else
    c_g "  ✅ 已补 force_hijack(未起 mosdns 校验: 本机无 mosdns 服务)。"
  fi
}

# 老装迁移: iOS 平台补 pdg-mitm 服务(MITM 插件宿主)。仅 iOS; Android 不建。
# 需 mitm_server.py 已就位(靠 migrate_deploy_botfiles 先补)。幂等(已有 unit 且 enabled 即退)。
migrate_pdg_mitm_service(){
  [[ "$(_pdg_platform)" == ios ]] || return 0                          # 仅 iOS; Android 无 MITM
  [[ -f /etc/systemd/system/pdg-mitm.service ]] && systemctl is-enabled pdg-mitm >/dev/null 2>&1 && return 0
  [[ -f /opt/pdg-bot/mitm_server.py ]] || return 0                     # MITM 服务代码未就位 → 下轮 botfiles 迁移后再补
  # shellcheck source=/dev/null
  source "$REPO_DIR/lib/units.sh" 2>/dev/null || return 0
  pdg_write_unit pdg_unit_pdg_mitm /etc/systemd/system/pdg-mitm.service
  systemctl daemon-reload 2>/dev/null || true
  systemctl reset-failed pdg-mitm 2>/dev/null; systemctl enable --now pdg-mitm >/dev/null 2>&1 || true
  c_g "  ✅ 已补 iOS pdg-mitm 服务(MITM 插件宿主)。"
}

# 老装迁移(Android): 清理误装/残留的 iOS 专属组件。幂等; 仅匹配本项目精确路径/unit, 不误删用户文件。
# CA / WLOC 地点数据不永久删 —— 留作休眠(Android 上 _mitm_enabled_domains 恒空, 本就不生效)。
migrate_android_cleanup(){
  [[ "$(_pdg_platform)" == android ]] || return 0
  # 推测出来的 android 不做破坏性清理: 万一这台其实服务 iPhone, 一删就把描述文件/probe81/
  # MITM 组件全没了, 而且 doctor 之后还会一路判绿(它已经认为自己是 Android 机)。
  local _gf; _gf="$(dirname "${PDG_PLATFORM_FILE:-/etc/privdns-gateway/platform}")/platform.guessed"
  if [[ -e "$_gf" ]]; then
    c_y "  平台是推测的 android(无确凿证据) → 跳过 iOS 组件清理。"
    c_y "  确认后运行: sudo pdg platform android(或 ios), 再重跑。"
    return 0
  fi
  # 有启用中的 WLOC → 先安全休眠: 清运行时接管 + enabled=false(保留地点/CA 数据)
  if grep -q '"enabled": *true' /etc/privdns-gateway/mitm.json 2>/dev/null; then
    : > /etc/mosdns/rules/mitm_hijack.txt 2>/dev/null || true
    python3 - /etc/privdns-gateway/mitm.json <<'PY' 2>/dev/null || true
import json, sys
f = sys.argv[1]; c = json.load(open(f))
if isinstance(c.get("wloc"), dict): c["wloc"]["enabled"] = False
json.dump(c, open(f, "w"), ensure_ascii=False, indent=2)
PY
    systemctl restart mosdns 2>/dev/null || true
  fi
  local removed=0 u f
  for u in pdg-probe81 pdg-mitm; do
    if [[ -f /etc/systemd/system/$u.service ]]; then
      systemctl disable --now "$u" 2>/dev/null; rm -f "/etc/systemd/system/$u.service"; removed=1
    fi
  done
  for f in /opt/pdg-bot/probe81.py /opt/pdg-bot/mitm_ca.py /opt/pdg-bot/mitm_server.py /opt/pdg-bot/mitm_wloc.py \
           /opt/pdg-bot/pdg-dot.mobileconfig.tmpl /opt/pdg-bot/pdg-mitm.mobileconfig.tmpl; do
    [[ -f "$f" ]] && { rm -f "$f"; removed=1; }
  done
  [[ "$removed" == 1 ]] && { systemctl daemon-reload 2>/dev/null || true
    c_g "Android: 已清理 iOS 专属残留(pdg-probe81/pdg-mitm 服务 + mitm 模块 + 描述文件模板; CA/地点数据保留为休眠)。"; }
  return 0
}

# 老装迁移(iOS): 精确、幂等清除本项目误装的 GMS 5228-5230(iOS 走 APNs, 不需要)。
# 只删 tag=in-gms-5228/5229/5230 的入站 + 从原装端口集/ mihomo REDIRECT 移除 5228-5230。
# 改前备份, sing-box/nft 均校验, 失败自动还原; 自定义配置不动。$1/$2 供测试注入。
# shellcheck disable=SC2120
migrate_ios_gms_cleanup(){
  [[ "$(_pdg_platform)" == ios ]] || return 0
  local sb="${1:-/etc/sing-box/config.json}" nf="${2:-/etc/nftables.conf}"
  # 1) sing-box canonical model: 删 in-gms-* 入站
  # 不再硬要求 sing-box 二进制: mihomo-only 机器上根本没有它, 整步会被静默跳过 → 残留
  # 永远清不掉(例如从 Android 备份恢复之后)。校验改用**当前内核**, 见下。
  if [[ -f "$sb" ]] && grep -q '"in-gms-5228"' "$sb"; then
    local bak; bak="$sb.preiosgms.$(date +%s)"
    if cp -a "$sb" "$bak" 2>/dev/null && cmp -s "$sb" "$bak"; then
      if python3 - "$sb" <<'PY'
import json, sys
f = sys.argv[1]; c = json.load(open(f))
c["inbounds"] = [i for i in c.get("inbounds", []) if i.get("tag") not in ("in-gms-5228", "in-gms-5229", "in-gms-5230")]
json.dump(c, open(f, "w"), ensure_ascii=False, indent=2)
PY
      then
        # 用内核校验: canonical model 是渲染源, 得重渲染再 `mihomo -t`;
        # 内核不可用时(装到一半/沙盒), JSON 解析通过即接受(model 本身不被直接执行)。
        local _vok=0
        if command -v mihomo >/dev/null 2>&1; then
          if ( cd /opt/pdg-bot && python3 -c 'import bot; bot._render_mihomo_file()' ) >/dev/null 2>&1 \
             && mihomo -t -d /etc/mihomo -f /etc/mihomo/config.yaml >/dev/null 2>&1; then _vok=1; fi
        else
          _vok=1
        fi
        if [[ "$_vok" == 1 ]]; then
          systemctl restart "$(_pdg_core_svc)" 2>/dev/null; sleep 1
          if [[ "$(systemctl is-active "$(_pdg_core_svc)" 2>/dev/null)" == active ]]; then
            rm -f "$bak"; c_g "  iOS: 已移除 sing-box GMS 入站(in-gms-5228/5229/5230)。"
          else c_y "  内核重启失败 → 还原。"; cp -a "$bak" "$sb"; systemctl restart "$(_pdg_core_svc)" 2>/dev/null; fi
        else c_y "  内核校验未过 → 还原。"; cp -a "$bak" "$sb"; fi
      else c_y "  生成失败 → 还原。"; cp -a "$bak" "$sb"; fi
    else rm -f "$bak" 2>/dev/null; fi
  fi
  # 2) nft: 只从**端口集**精确移除 5228-5230(复用 _pdg_nft_strip_gms, 保留整条 { 80, 443 } redirect),
  #    绝不按行删 redirect。仅当端口集(非注释)真含 5228 才动; 剥完仍残留=自定义形态 → 还原不破坏(交 doctor warn)。
  if [[ -f "$nf" ]] && grep -qE 'tcp dport [{][^}]*5228' "$nf"; then
    local bak; bak="$nf.preiosgms.$(date +%s)"
    if cp -a "$nf" "$bak" 2>/dev/null; then
      _pdg_nft_strip_gms "$nf"
      if grep -qE 'tcp dport [{][^}]*5228' "$nf"; then
        c_y "  防火墙 5228-5230 非原装形态, 未自动改(交 doctor); 已还原。"; cp -a "$bak" "$nf" 2>/dev/null; rm -f "$bak"
      elif nft -c -f "$nf" >/dev/null 2>&1; then
        nft -f "$nf" 2>/dev/null || true; rm -f "$bak"; c_g "  iOS: 已从防火墙端口集移除 GMS 5228-5230(保留 80/443 redirect)。"
      else c_y "  nft 校验失败 → 还原。"; cp -a "$bak" "$nf" 2>/dev/null; nft -f "$nf" 2>/dev/null || true; rm -f "$bak"; fi
    fi
  fi
  return 0
}

# issue #1: bot 把域名"指到出口"时只改了内核路由, 没让 mosdns 劫持该域名 → 手机拿到真实 IP
# 直连, 流量根本不到网关, 那条出口规则是死的(用户现场: 加了 ip.skk.moe→jp 仍显示国内直连,
# 手工塞进 geosite 文件并重启 mosdns 才生效)。老装补: 建用户劫持表 → 并入 hijack_set →
# 回填已有的显式出口域名 → 有改动才重启 mosdns。幂等。
migrate_custom_hijack(){
  local mc=/etc/mosdns/config.yaml hj=/etc/mosdns/rules/custom_hijack.txt sb=/etc/sing-box/config.json out
  [[ -f "$mc" ]] || return 0
  install -d -m755 /etc/mosdns/rules 2>/dev/null || true
  if ! out=$(python3 - "$mc" "$sb" "$hj" <<'MIGPY'
import json, os, re, sys
mc, sb, hj = sys.argv[1], sys.argv[2], sys.argv[3]
changed = False

# 先保证劫持表文件存在, 再改 config —— mosdns 对 domain_set 文件是**强依赖**(缺文件直接
# FATAL 起不来), 顺序反了万一中途失败就把 mosdns 干趴了。
doms = set()
try:
    c = json.load(open(sb, encoding="utf-8"))
    for r in c.get("route", {}).get("rules", []):
        if "outbound" in r and not r.get("rule_set"):
            doms |= set(r.get("domain_suffix") or []) | set(r.get("domain") or [])
except Exception:
    pass
cur = set()
if os.path.exists(hj):
    cur = {l.strip().replace("domain:", "") for l in open(hj, encoding="utf-8")
           if l.strip() and not l.startswith("#")}
if not os.path.exists(hj) or (doms - cur):
    with open(hj, "w", encoding="utf-8") as f:
        f.write("# pdg-bot 显式出口域名劫持表(指到出口的域名必须由 mosdns 劫持才会进代理)\n")
        f.writelines("domain:" + d + "\n" for d in sorted(cur | doms))
    changed = True

s = open(mc, encoding="utf-8").read()
if hj not in s:                      # 按实际路径判幂等, 不靠硬编码文件名子串
    m = re.search(r"(- tag: hijack_set\b[\s\S]*?files: \[)([^\]]*)(\])", s)
    if not m:
        raise SystemExit("hijack_set 形态不认识")
    s = s[:m.end(2)] + ',"' + hj + '"' + s[m.end(2):]
    open(mc, "w", encoding="utf-8").write(s)
    changed = True
print("changed" if changed else "nochange")
MIGPY
  ); then
    c_y "  mosdns 配置里没有可识别的 hijack_set(自定义形态), 用户劫持表未并入; 劫持表本身已就绪。"; return 0
  fi
  if [[ "$out" == changed ]]; then
    systemctl restart mosdns 2>/dev/null || true
    c_g "  已建用户劫持表并回填显式出口域名(修: 指到出口的域名此前不被 mosdns 劫持)。"
  fi
}

# 把已有机器的 mosdns 劫持形态归一到"与 PDG_HIJACK_MODE 一致"。两类机器都要修:
#   · 老形态(无 hijack_set, 排除式): 补上 hijack_set 插件, 获得 gfw 能力; all 语义不变。
#   · 新形态(有劫持门)但模式是 all: 去掉那道门 —— 它把 all 悄悄退化成了"只劫持 geosite
#     策展分类里的域名", 用户指到出口的任意域名照样直连(issue #1)。
migrate_mosdns_hijack_shape(){
  local mc=/etc/mosdns/config.yaml mode file out
  [[ -f "$mc" ]] || return 0
  # shellcheck source=/dev/null
  source "$REPO_DIR/lib/mosdns.sh" 2>/dev/null || return 0
  mode="$(sed -n 's/^PDG_HIJACK_MODE=//p' /etc/privdns-gateway/profile.env 2>/dev/null | tail -1)"
  [[ "$mode" == gfw || "$mode" == all ]] || mode=all
  [[ "$mode" == gfw ]] && file=geosite_gfw.txt || file="geosite_geolocation-!cn.txt"
  # gfw 模式但劫持集文件不在 → 别把门装上(会把所有海外域名放行), 维持现状交人工
  if [[ "$mode" == gfw && ! -s "/etc/mosdns/rules/$file" ]]; then
    c_y "  gfw 模式但缺 /etc/mosdns/rules/$file, 劫持形态未动。"; return 0
  fi
  if ! out=$(_mosdns_hijack_shape "$mode" "$mc" "$file"); then
    c_y "  mosdns 劫持形态是自定义的, 未动(不猜着改)。"; return 0
  fi
  if [[ "$out" == changed ]]; then
    systemctl restart mosdns 2>/dev/null || true
    c_g "  已归一 mosdns 劫持形态 → $mode(all=不是国内就劫持; gfw=只劫持劫持集内域名)。"
  fi
}

# 老装(v1.4.x)从来没有 backend 标记。据现场证据把它落地(unit 文件存在才算数, 免得 is-active
# 的异常输出误导), 让"这台机器此刻跑的是哪个核"成为显式状态而非默认值。
# v1.6.0 起唯一内核是 mihomo, 本函数仍有用: 它跑在 migrate_drop_singbox **之前**, 于是万一
# 迁移失败, 标记如实停在 singbox(而不是谎称已是 mihomo) —— 下次 update 会据此重试迁移。
# 这里的 sing-box 探测只是**读现场**, 不是运行时依赖。
migrate_backend_marker(){
  local bm=/etc/privdns-gateway/backend cur core=""
  cur="$(cat "$bm" 2>/dev/null)"
  [[ "$cur" == mihomo || "$cur" == singbox ]] && return 0       # 已有合法标记 → 幂等
  local u_m=/etc/systemd/system/mihomo.service u_s=/etc/systemd/system/sing-box.service
  if   [[ -e "$u_m" ]] && [[ "$(systemctl is-active mihomo   2>/dev/null)" == active ]]; then core=mihomo
  elif [[ -e "$u_s" ]] && [[ "$(systemctl is-active sing-box 2>/dev/null)" == active ]]; then core=singbox
  elif [[ -e "$u_m" ]] && systemctl is-enabled mihomo   >/dev/null 2>&1; then core=mihomo
  elif [[ -e "$u_s" ]] && systemctl is-enabled sing-box >/dev/null 2>&1; then core=singbox
  elif [[ -f /etc/mihomo/config.yaml ]] && command -v mihomo >/dev/null 2>&1; then core=mihomo
  else core=singbox; fi                                          # 兜底与历史默认一致, 不改变现有行为
  install -d -m700 /etc/privdns-gateway 2>/dev/null || true
  printf '%s\n' "$core" > "$bm" \
    && c_g "  补内核标记: $core(据现场证据; 老装此前一直靠默认值兜底)。"
}

run_all_migrations(){
  local rc=0
  migrate_platform_marker || true          # 先统一平台判定源(后续平台相关迁移据此走)
  migrate_backend_marker || true           # 再把内核标记落地(别再靠默认值兜底)
  migrate_botenv || true; migrate_firewall_to_pdg || true; migrate_mosdns_concurrent || true
  migrate_mosdns_unlock || true; migrate_fw_gms || true
  migrate_mosdns_ratelimit || true; migrate_lowmem || true; migrate_mihomo_safepaths || true
  migrate_deploy_botfiles || true
  migrate_mosdns_hijack_shape || true
  migrate_custom_hijack || true
  migrate_mosdns_mitm || true; migrate_pdg_mitm_service || true
  migrate_android_cleanup || true; migrate_ios_gms_cleanup || true   # 平台隔离清理(各自平台内幂等)
  # 内核迁移放最后: 上面的 config.json / mosdns / 防火墙 迁移都先按老路子跑完(它们只动数据模型
  # 与 nft, 与内核无关), 这里再把**最终形态的** config.json 转 mihomo 并移除 sing-box 运行时。
  # 唯一"失败必须传出"的迁移 —— 失败即让 __migrate 返回非0,
  # cmd_update 据此回滚到更新前快照(其余迁移都是幂等自愈, 失败 best-effort 吞掉不挡后续)。
  migrate_drop_singbox || rc=1
  return $rc
}

# 迁移到 mihomo 时渲染并应用 mihomo 的 nft 入站模型(REDIRECT→7893)。出口/分流/证书/DoT/mosdns
# 全不动(model 共用)。$1 目前恒为 mihomo(唯一内核), 保留形参以兼容 _activate_mihomo_core 调用。
# 把渲染好的 pdg 表块**合并**进现网 nftables.conf: 只替换本项目管理区(table inet pdg 的
# 声明/delete/表体), 其余内容逐字节保留。$1=渲染好的块文件 $2=目标 conf $3=输出文件。
# 无法证明能安全合并(pdg 块括号不配平 / 文件里有 flush ruleset 又还有别的表)→ 返回非 0,
# 调用方必须在改动运行环境**之前**中止 —— 整文件覆盖会把用户的 VPN/NAT/转发/开放端口抹掉。
_pdg_nft_splice(){
  python3 - "$1" "$2" "$3" <<'PY'
import re, sys
block_f, target_f, out_f = sys.argv[1:4]
block = open(block_f, encoding="utf-8").read()
# 只取模板里的规则部分(从第一处 `table inet pdg` 起) —— 整个模板带 shebang 与大段头注释,
# 原样插进现网文件中段会多出一个 `#!/usr/sbin/nft -f`, 既难看也容易误导读者。
_m = re.search(r"^\s*table\s+inet\s+pdg\b", block, re.M)
if _m:
    block = ("# ==== PrivDNS Gateway 管理区(table inet pdg): 由 pdg 自动维护, 勿手改 ====\n"
             + block[_m.start():])
block = block.rstrip("\n")
try:
    lines = open(target_f, encoding="utf-8").read().split("\n")
except OSError:
    lines = []

decl = re.compile(r"^\s*table\s+inet\s+pdg\s*$")
dele = re.compile(r"^\s*delete\s+table\s+inet\s+pdg\s*$")
open_ = re.compile(r"^\s*table\s+inet\s+pdg\s*\{")
other_table = re.compile(r"^\s*(table)\s+\S+\s+(\S+)")

keep, i, first_hit, n = [], 0, None, len(lines)
while i < n:
    ln = lines[i]
    if decl.match(ln) or dele.match(ln):
        first_hit = len(keep) if first_hit is None else first_hit
        i += 1; continue
    if open_.match(ln):                      # 整个 table inet pdg { ... } 块
        first_hit = len(keep) if first_hit is None else first_hit
        depth = 0
        while i < n:
            depth += lines[i].count("{") - lines[i].count("}")
            i += 1
            if depth <= 0:
                break
        else:
            print("pdg 表块括号不配平, 无法安全合并", file=sys.stderr); sys.exit(2)
        if depth > 0:
            print("pdg 表块括号不配平, 无法安全合并", file=sys.stderr); sys.exit(2)
        continue
    keep.append(ln); i += 1

# 剩下的内容里若还有 flush ruleset + 别的表 → 应用时会连别人的表一起冲掉, 不能算安全合并
rest = "\n".join(keep)
if re.search(r"^\s*flush\s+ruleset\s*$", rest, re.M):
    others = [m.group(0).strip() for m in other_table.finditer(rest)]
    if others:
        print("现网 nftables.conf 含 `flush ruleset` 且另有表(%s) —— 合并后应用会冲掉它们, 拒绝自动处理"
              % ", ".join(others[:3]), file=sys.stderr)
        sys.exit(3)

if first_hit is None:                         # 现网没有 pdg 区 → 追加到末尾
    while keep and not keep[-1].strip():
        keep.pop()
    merged = "\n".join(keep) + ("\n\n" if keep else "") + block
else:
    merged = "\n".join(keep[:first_hit] + block.split("\n") + keep[first_hit:])
if not merged.endswith("\n"):
    merged += "\n"
open(out_f, "w", encoding="utf-8").write(merged)
PY
}

_switchcore_nft(){   # $1=target(mihomo)  渲染并应用 mihomo nft(用当前 SSH端口/内网段)
  local target="$1" sshp icidr
  [[ "$target" == mihomo ]] || { echo "内部错误: _switchcore_nft 只支持 mihomo(收到 $target)"; return 1; }
  sshp=$(grep -oP '^\s*tcp dport \{ \K[0-9]+(?= \} accept)' /etc/nftables.conf | head -1)
  # 现网 nft 认不出 SSH 端口时(自定义/异形防火墙)不能直接判死 —— 这条路现在跑在**自动迁移**里,
  # 硬失败会把用户永久挡在旧版上。退回问 sshd 实际在听哪个口, 再退回 22(与装机探测同口径)。
  if [[ -z "$sshp" ]]; then
    sshp=$(ss -lntpH 2>/dev/null | awk '/sshd/{n=split($4,a,":"); print a[n]; exit}')
    sshp="${sshp:-22}"
    c_y "  未能从 /etc/nftables.conf 认出 SSH 端口 → 按实际监听/默认值取 $sshp(新防火墙会放行它)。"
  fi
  icidr=$(python3 -c "import sys;sys.path.insert(0,'/opt/pdg-bot');import checks;print(checks._internal_cidr())" 2>/dev/null)
  [[ -n "$sshp" && -n "$icidr" ]] || { echo "提取 SSH端口/内网段失败(ssh=$sshp cidr=$icidr)"; return 1; }
  [[ -f "$REPO_DIR/deploy/firewall/nftables-mihomo.conf" ]] || { echo "缺 nftables-mihomo.conf(先 pdg update)"; return 1; }
  local wd rendered merged bak rc
  wd="$(mktemp -d)" || { echo "无法创建临时目录"; return 1; }
  rendered="$wd/pdg.nft"; merged="$wd/merged.conf"; bak="$wd/nftables.conf.bak"
  sed -e "s|__SSH_PORT__|$sshp|g" -e "s|__INTERNAL_CIDR__|$icidr|g" \
      "$REPO_DIR/deploy/firewall/nftables-mihomo.conf" > "$rendered"
  _pdg_nft_strip_gms "$rendered"          # iOS: 渲染后剥掉 GMS 5228-5230
  # 备份必须先成立(逐字节校验): 后面任何一步失败都要靠它把现网原样放回去
  if [[ -e /etc/nftables.conf ]]; then
    if ! cp -a /etc/nftables.conf "$bak" 2>/dev/null || ! cmp -s /etc/nftables.conf "$bak"; then
      rm -rf "$wd"; echo "备份 /etc/nftables.conf 失败(磁盘满?), 未改动防火墙"; return 1
    fi
  fi
  # 只替换本项目管理区(table inet pdg), 用户的额外表/VPN/NAT/转发/开放端口原样保留。
  # 合并不了(块不配平 / flush ruleset 与别的表共存)→ 在改动运行环境之前就中止。
  if ! _pdg_nft_splice "$rendered" /etc/nftables.conf "$merged"; then
    rm -rf "$wd"
    echo "无法安全合并防火墙配置 → 未改动 /etc/nftables.conf(见上方冲突位置)"
    echo "  请把本项目所需规则手工并入 table inet pdg 后重试, 或先备份并清理冲突配置。"
    return 1
  fi
  if ! nft -c -f "$merged" >/dev/null 2>&1; then
    rm -rf "$wd"; echo "合并后的 nftables 配置校验(nft -c)未过, 未改动防火墙"; return 1
  fi
  if ! cp -f "$merged" /etc/nftables.conf 2>/dev/null || ! cmp -s "$merged" /etc/nftables.conf; then
    [[ -e "$bak" ]] && cp -a "$bak" /etc/nftables.conf 2>/dev/null
    rm -rf "$wd"; echo "写入 /etc/nftables.conf 失败(磁盘满?), 已还原"; return 1
  fi
  if ! nft -f /etc/nftables.conf; then
    rc=1
    if [[ -e "$bak" ]]; then
      cp -a "$bak" /etc/nftables.conf 2>/dev/null
      nft -f /etc/nftables.conf 2>/dev/null || true
      echo "应用新防火墙失败 → 已还原并重新应用原配置"
    fi
    rm -rf "$wd"; return "$rc"
  fi
  rm -rf "$wd"
}

# 内核切换的 enable/disable 收尾 + 状态核验(单一职责, 便于打桩测试)。
# 目标: 目标核 enable --now 且 active+enabled; 旧核 disable --now 且 inactive+非 enabled
# (旧核只 stop 不 disable = 仍自启, 重启会双起 → 冲突)。任一不满足返回非 0。
# $1=目标核 svc  $2=旧核 svc。
_core_kernel_activate(){
  local tgt="$1" old="$2"
  systemctl reset-failed "$tgt" 2>/dev/null
  systemctl enable --now "$tgt" >/dev/null 2>&1 || { echo "  enable/start $tgt 失败"; return 1; }
  systemctl disable --now "$old" >/dev/null 2>&1 || true   # 旧核停用+关自启; 下面核验兜底
  sleep 2
  [[ "$(systemctl is-active  "$tgt" 2>/dev/null)" == active  ]] || { echo "  $tgt 未 active";  return 1; }
  [[ "$(systemctl is-enabled "$tgt" 2>/dev/null)" == enabled ]] || { echo "  $tgt 未 enabled"; return 1; }
  [[ "$(systemctl is-active  "$old" 2>/dev/null)" != active  ]] || { echo "  旧核 $old 仍 active"; return 1; }
  [[ "$(systemctl is-enabled "$old" 2>/dev/null)" == enabled ]] && { echo "  旧核 $old 仍 enabled(重启会双起)"; return 1; }
  return 0
}

# 切换失败回退: 目标核 disable+stop, 旧核 enable --now 恢复原态。
# $1=目标核 svc  $2=旧核 svc。
_core_kernel_restore(){
  local tgt="$1" old="$2"
  systemctl disable --now "$tgt" >/dev/null 2>&1 || true
  systemctl reset-failed "$old" 2>/dev/null
  systemctl enable --now "$old" >/dev/null 2>&1 || true
}

# 把当前机器激活成 mihomo 内核: 下核 → 渲染(拒 unknown_proxies) → mihomo -t 校验 → 写 unit →
# nft REDIRECT 入站 → 起 mihomo 并停旧 sing-box(_core_kernel_activate)。带失败回滚。成功 0 / 失败非 0。
# 由 migrate_drop_singbox 调用(旧 sing-box 机器 update 时迁移)。出口/分流/证书/DoT/mosdns 均不动(model 共用)。
_activate_mihomo_core(){
  local march plat prev_backend why t
  prev_backend="$(cat /etc/privdns-gateway/backend 2>/dev/null)"
  march=$(dpkg --print-architecture 2>/dev/null); [[ "$march" == arm64 ]] || march=amd64
  plat="$(_pdg_platform)"
  # shellcheck source=/dev/null
  source "$REPO_DIR/lib/versions.sh" 2>/dev/null || { echo "❌ 读不到 versions.sh"; return 1; }
  # shellcheck source=/dev/null
  source "$REPO_DIR/lib/units.sh"   2>/dev/null || { echo "❌ 读不到 units.sh"; return 1; }
  cp /etc/nftables.conf /etc/nftables.conf.scbak 2>/dev/null

  if ! pdg_mihomo_is_version "$MIHOMO_VER"; then
    c_g "下载 mihomo $MIHOMO_VER…"; t=$(mktemp -d)
    if ! curl -fsSL "https://github.com/MetaCubeX/mihomo/releases/download/${MIHOMO_VER}/mihomo-linux-${march}-${MIHOMO_VER}.gz" -o "$t/m.gz" \
       || ! pdg_verify_sha256 "$t/m.gz" "${PDG_SHA256[mihomo-$march]:-}" "mihomo $MIHOMO_VER" \
       || ! gunzip -c "$t/m.gz" > "$t/mihomo"; then rm -rf "$t"; echo "❌ mihomo 下载/校验失败, 未迁移"; return 1; fi
    install -m755 "$t/mihomo" /usr/local/bin/mihomo; rm -rf "$t"
  fi
  install -d -m700 /etc/mihomo
  printf 'mihomo\n' > /etc/privdns-gateway/backend      # 先切标记, 让渲染/迁移按 mihomo 走
  # 渲染前先拦: 有出口 mihomo 无法无损转换(unknown_proxies)→ 拒绝迁移, 免得凭空丢一个出口。
  # 把**真实原因**带出来(渲染抛异常 / 有出口转不了 分开报), 用户据此在 bot 里删/换该出口再重试。
  if ! why=$(cd /opt/pdg-bot && python3 - <<'SCPY' 2>&1
import sys
sys.path.insert(0, "/opt/pdg-bot")
import bot
try:
    meta = bot._render_mihomo_file()
except Exception as e:
    print("渲染 mihomo 配置失败: %s: %s" % (type(e).__name__, e)); sys.exit(1)
bad = (meta or {}).get("unknown_proxies") or []
if bad:
    print("这些出口 mihomo 无法转换(迁移会凭空丢失): " + ", ".join(str(x) for x in bad)); sys.exit(1)
# 规则/规则集同理: 进不了 mihomo 运行配置就不能迁 —— 迁过去 `mihomo -t` 照样会过, 但那条
# 分流实际已经不存在了。典型是老机器上遗留的 sing-box 二进制 .srs 规则集(mihomo 读不了)。
drop = (meta or {}).get("dropped") or []
if drop:
    names = [str(d.get("rule_set") or d) for d in drop] if isinstance(drop[0], dict) else [str(x) for x in drop]
    print("这些规则/规则集无法进入 mihomo 运行配置(迁移会凭空丢失): " + ", ".join(names[:8]))
    print("  .srs 是 sing-box 二进制规则集, mihomo 读不了 —— 请先在 bot 里删掉并换成 "
          ".list/.txt/.yaml/.mrs, 再重试 sudo pdg update。")
    sys.exit(1)
SCPY
  ); then
    printf '%s\n' "${prev_backend:-singbox}" > /etc/privdns-gateway/backend
    echo "❌ 未迁移(已回滚标记): ${why:-渲染 mihomo 配置失败(无输出)}"; return 1
  fi
  if ! why=$(mihomo -t -d /etc/mihomo -f /etc/mihomo/config.yaml 2>&1); then
    printf '%s\n' "${prev_backend:-singbox}" > /etc/privdns-gateway/backend
    echo "❌ 未迁移(已回滚标记): mihomo 配置校验失败:"
    printf '%s\n' "$why" | tail -c 400 | sed 's/^/    /'; return 1
  fi
  pdg_write_unit pdg_unit_mihomo /etc/systemd/system/mihomo.service   # 与装机同源(含 SAFE_PATHS)
  [[ "$plat" == ios ]] && pdg_write_unit pdg_unit_pdg_mitm /etc/systemd/system/pdg-mitm.service
  systemctl daemon-reload
  _switchcore_nft mihomo || { printf '%s\n' "${prev_backend:-singbox}" > /etc/privdns-gateway/backend; [[ -f /etc/nftables.conf.scbak ]] && { cp /etc/nftables.conf.scbak /etc/nftables.conf; nft -f /etc/nftables.conf; }; echo "❌ nft 应用失败, 已回滚"; return 1; }
  if ! _core_kernel_activate mihomo sing-box; then
    c_y "mihomo 启动/自启核验失败 → 回滚"
    printf '%s\n' "${prev_backend:-singbox}" > /etc/privdns-gateway/backend
    [[ -f /etc/nftables.conf.scbak ]] && { cp /etc/nftables.conf.scbak /etc/nftables.conf; nft -f /etc/nftables.conf 2>/dev/null; }
    _core_kernel_restore mihomo sing-box; rm -f /etc/nftables.conf.scbak
    echo "❌ 迁移失败, 已回滚。mihomo 最近日志:"
    journalctl -u mihomo -n 15 --no-pager -o cat 2>/dev/null | sed 's/^/    /'
    return 1
  fi
  [[ "$plat" == ios ]] && { systemctl reset-failed pdg-mitm 2>/dev/null; systemctl enable --now pdg-mitm >/dev/null 2>&1 || true; }
  rm -f /etc/nftables.conf.scbak
  return 0
}

# 旧 sing-box 机器迁到 mihomo(v1.6.0 彻底移除 sing-box 运行时)。加入 run_all_migrations, 故 `pdg update`
# 走 __migrate 时自动执行。幂等: 已是纯 mihomo(无 sing-box 服务/二进制)直接返回 0。
# 失败(unknown_proxies / 渲染 / 校验 / 起核)返回非 0 → run_all_migrations 传出 → cmd_update 回滚到
# 更新前快照(用户仍留在旧 sing-box 版, 数据无损), 而不是把机器留在半迁移态。
migrate_drop_singbox(){
  local cur; cur="$(cat /etc/privdns-gateway/backend 2>/dev/null)"
  if [[ "$cur" == mihomo ]] && [[ ! -e /etc/systemd/system/sing-box.service ]] && [[ ! -e /usr/local/bin/sing-box ]]; then
    return 0                                    # 已是纯 mihomo → 幂等短路
  fi
  # backend 已是 mihomo, 只剩来源不明的 sing-box 文件 → 那不是本项目的东西, 不该每次更新都去动它
  if [[ "$cur" == mihomo ]] && ! _pdg_singbox_is_ours; then
    _pdg_drop_singbox_files "非本项目安装"      # 只打印保留提示, 不删
    return 0
  fi
  c_y "检测到 sing-box 运行时(v1.6.0 已移除)→ 迁移到 mihomo 唯一内核(出口/分流/证书/DoT 不动)…"
  _activate_mihomo_core || { echo "❌ 迁移到 mihomo 失败(见上)。请在 TG bot 处理无法转换的出口后, 重试 sudo pdg update。"; return 1; }
  # 收尾: _core_kernel_activate 已 stop+disable sing-box; 再删掉**本项目装的** unit + 二进制
  # (来源不明的一律保留 —— 删别人的东西不可逆)。
  _pdg_drop_singbox_files
  systemctl daemon-reload 2>/dev/null || true
  printf 'mihomo\n' > /etc/privdns-gateway/backend
  c_g "  已迁移到 mihomo 内核, sing-box 运行时已移除。"
  return 0
}

# 切换劫持模式: all(非CN全劫持) | gfw(只劫持 GFWList 真被墙域名, 非墙海外直连)。换 hijack_set 加载的域名文件。
# 人工确认手机平台。装机时会写标记; 只有老装(v1.4.x 无平台概念)推断不出来才需要手工定。
cmd_platform(){
  need_root platform
  local p="${1:-}" cur; cur="$(_pdg_platform)"
  if [[ "$p" != ios && "$p" != android ]]; then
    echo "用法: pdg platform <ios|android>"
    echo "  当前: $cur$( [[ -e /etc/privdns-gateway/platform.guessed ]] && echo "  ⚠️ 推测值, 未确认" )"
    echo "  确认后才会执行该平台的组件清理(推测状态下一律不做破坏性清理)。"
    return 1
  fi
  install -d -m700 /etc/privdns-gateway
  printf '%s\n' "$p" > /etc/privdns-gateway/platform
  rm -f /etc/privdns-gateway/platform.guessed
  c_g "平台已确认: $cur → $p"
  run_all_migrations        # 让平台相关的部署/清理按确认后的平台立刻落地
}

cmd_hijack_mode(){
  need_root hijack-mode
  # shellcheck source=/dev/null
  source "$REPO_DIR/lib/mosdns.sh" 2>/dev/null || { echo "❌ 读不到 lib/mosdns.sh"; return 1; }
  local mode="${1:-}" file
  if [[ "$mode" != all && "$mode" != gfw ]]; then
    echo "用法: pdg hijack-mode <all|gfw>"
    echo "  all = 不是国内域名就劫持进代理(默认, 排除式)"
    echo "  gfw = 只劫持 hijack_set 里的域名(GFWList + 你在 bot 里指到出口的域名);"
    echo "        其余海外域名返真实 IP 直连(修 SSH/直连走域名被劫持)。前提: 内网卡 SIM 能直达一般互联网"
    echo "  当前: $(cat /etc/privdns-gateway/profile.env 2>/dev/null | sed -n 's/^PDG_HIJACK_MODE=//p' | tail -1 || echo '?')"
    return 1
  fi
  [[ -f /etc/mosdns/config.yaml ]] || { echo "❌ 找不到 /etc/mosdns/config.yaml"; return 1; }
  if [[ "$mode" == gfw ]]; then
    file="geosite_gfw.txt"
    if [[ ! -s /etc/mosdns/rules/geosite_gfw.txt ]]; then
      c_g "生成 GFWList(geosite_gfw.txt)…"; bash /opt/pdg-bot/update-rules.sh >/dev/null 2>&1 || true
    fi
    [[ -s /etc/mosdns/rules/geosite_gfw.txt ]] || { echo "❌ geosite_gfw.txt 生成失败, 仍为原模式"; return 1; }
  else
    file="geosite_geolocation-!cn.txt"
  fi
  cp /etc/mosdns/config.yaml /etc/mosdns/config.yaml.hjbak
  # 用归一化器改形态(all=去掉劫持门/排除式, gfw=装上劫持门/白名单式), 而不是只换文件名 ——
  # 只换文件名在旧形态机器上一个字都改不到, 却照样打印"✅ 劫持模式 → xxx"(空转报成功)。
  local shape
  if ! shape=$(_mosdns_hijack_shape "$mode" /etc/mosdns/config.yaml "$file"); then
    c_y "mosdns 配置是自定义形态, 未改动(不猜着改)。"; rm -f /etc/mosdns/config.yaml.hjbak; return 1
  fi
  if [[ "$shape" == changed ]]; then
    systemctl restart mosdns; sleep 1.5
    if [[ "$(systemctl is-active mosdns 2>/dev/null)" != active ]]; then
      c_y "mosdns 重启失败 → 还原"; cp /etc/mosdns/config.yaml.hjbak /etc/mosdns/config.yaml
      systemctl restart mosdns; rm -f /etc/mosdns/config.yaml.hjbak; return 1
    fi
  else
    echo "  (配置已是 $mode 形态, 无需改动)"
  fi
  rm -f /etc/mosdns/config.yaml.hjbak
  install -d -m700 /etc/privdns-gateway
  if grep -q '^PDG_HIJACK_MODE=' /etc/privdns-gateway/profile.env 2>/dev/null; then
    sed -i "s/^PDG_HIJACK_MODE=.*/PDG_HIJACK_MODE=$mode/" /etc/privdns-gateway/profile.env
  else
    echo "PDG_HIJACK_MODE=$mode" >> /etc/privdns-gateway/profile.env
  fi
  echo "✅ 劫持模式 → $mode"
}

# 下一次以 root 运行"管理类"命令(update/restart/menu/…)时幂等自动迁移防火墙(已迁移则首个 grep 秒退)。
# 只读命令(status/doctor/log/traffic/report)与卸载不触发, 以保持"只读命令不写任何东西"的语义;
# 只跑只读命令的用户可显式 `sudo pdg migrate-fw` 迁移(且证书 hook/doctor 已兼容旧 inet filter, 不迁也能用)。
if [[ $EUID -eq 0 ]]; then
  case "${1:-menu}" in
    status|st|doctor|dr|log|logs|traffic|tr|report|uninstall|rm|__migrate) : ;;   # 只读/卸载/内部迁移: 不重复迁移
    *) run_all_migrations ;;   # 管理类命令才迁移(idempotent)
  esac
fi

case "${1:-menu}" in
  menu|"")       menu;;
  __migrate)     need_root __migrate; run_all_migrations;;   # 内部: cmd_update 装好新脚本后据此跑"新版"迁移
  status|st)     cmd_status;;
  doctor|dr)     shift || true; cmd_doctor "${1:-}";;
  update|up)     shift || true; cmd_update "${1:-}";;
  migrate-fw)    need_root migrate-fw; migrate_firewall_to_pdg;;
  snapshot|snap) cmd_snapshot;;
  rollback)      shift || true; cmd_rollback "${1:-0}";;
  token)         cmd_token;;
  restart)       cmd_restart;;
  log|logs)      shift || true; cmd_log "${1:-40}";;
  traffic|tr)    cmd_traffic;;
  ios)           cmd_ios;;
  report)        shift || true; cmd_report "$@";;
  detect-cidr|cidr) shift || true; cmd_detect_cidr "${1:-}";;
  platform)      shift || true; cmd_platform "${1:-}";;
  hijack-mode)   shift || true; cmd_hijack_mode "${1:-}";;
  uninstall|rm)  shift || true; cmd_uninstall "${1:-}";;
  *) echo "用法: pdg [menu|status|doctor [--json|--deep]|update [--dry-run]|snapshot|rollback [n]|token|restart|log [n]|traffic|ios(仅 iOS)|report [--redact-ip|--full]|detect-cidr|platform <ios|android>|hijack-mode <all|gfw>|migrate-fw|uninstall [--purge]]";;
esac
