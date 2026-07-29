#!/usr/bin/env bash
# PrivDNS Gateway 管理命令。直接 `sudo pdg` 进菜单, 或 pdg <子命令>。
#   pdg [menu] | status | update | web <action> | token | restart | log [n] | uninstall [--purge]
# 设计: 生命周期(装/更新/卸载/Web/token/状态/日志)走这里; 出口/分流/DNS上游 走管理面。
set -uo pipefail
REPO_URL="${PDG_REPO_URL:-https://github.com/SchweppesSoda/proxy-gateway-plus.git}"
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
# 展示用的服务集(status 逐个列状态): 恒含 pdg-bot —— 用户想看到它在不在跑, 哪怕没配凭据。
# pdg-probe81 仍是 iOS 专属。
_pdg_svcs(){ local s; s="pdg-quic-routing mosdns $(_pdg_core_svc) pdg-bot"; [[ "$(_pdg_platform)" == ios ]] && s="$s pdg-probe81"; echo "$s"; }

# **必需**服务集(校验门用): 与 checks.expected_services() 同语义 —— bot.env 两项都空是合法的
# "这台机器不用 Telegram 管理", pdg-bot 不运行属正常禁用态, 不该把它算成必须在跑的服务。
# 以前平台切换直接用 _pdg_svcs 校验, 于是没配 bot 的机器 `pdg platform ios` 必然卡在
# "pdg-bot 未稳定运行"并整体回滚 —— 而那台机器本来就没打算起 bot。
_pdg_required_svcs(){
  local s; s="pdg-quic-routing mosdns $(_pdg_core_svc)"
  [[ "$(_pdg_bot_cred)" == ready ]] && s="$s pdg-bot"
  [[ "$(_pdg_platform)" == ios ]] && s="$s pdg-probe81"
  echo "$s"
}

# nft 可执行文件位置: 判据集中在 lib/nftbin.sh(pdg / uninstall / certbot 钩子共用), 详见
# 该文件注释 —— 只看 PATH 会把"nft 在 /usr/sbin 但 PATH 没导出"当成没装。找不到回显空串。
_pdg_nft_bin(){
  # shellcheck source=lib/nftbin.sh
  source "${REPO_DIR:-/opt/privdns-gateway}/lib/nftbin.sh" 2>/dev/null \
    || { command -v nft 2>/dev/null || true; return 0; }   # 连判据文件都没有: 至少别比以前差
  pdg_nft_bin || true
}

_pdg_profile_tool(){
  local p
  for p in /opt/pdg-bot/pdgprofile.py "$REPO_DIR/deploy/bot/pdgprofile.py"; do
    [[ -f "$p" ]] && { printf '%s\n' "$p"; return 0; }
  done
  return 1
}

_pdg_quic_helper(){
  local p
  for p in /usr/local/libexec/pdg-quic-routing.sh \
           "$REPO_DIR/deploy/firewall/pdg-quic-routing.sh"; do
    [[ -f "$p" ]] && { printf '%s\n' "$p"; return 0; }
  done
  return 1
}

# Strict single-value profile read. Duplicate/invalid managed keys fail.
_pdg_profile_get(){
  local key="$1" tool
  tool="$(_pdg_profile_tool)" || return 1
  _pdg_profile_get_from "$tool" "$key"
}

_pdg_profile_get_from(){
  local tool="$1" key="$2"
  python3 - "$tool" "$PROFILE_ENV" "$key" <<'PY'
import importlib.util, sys
from pathlib import Path
tool, profile, key = sys.argv[1:]
sys.path.insert(0, str(Path(tool).resolve().parent))
spec = importlib.util.spec_from_file_location("pdgprofile_pdg_cli", tool)
mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
values = mod.read_values(profile)
if key not in values:
    raise SystemExit(1)
print(values[key])
PY
}

_pdg_firewall_mode(){
  local mode marker=""
  mode="$(_pdg_profile_get PDG_FIREWALL_MODE)" || return 1
  [[ "$mode" == managed || "$mode" == external ]] || return 1
  [[ ! -e /etc/privdns-gateway/firewall-mode ]] \
    || marker="$(cat /etc/privdns-gateway/firewall-mode 2>/dev/null)"
  [[ -z "$marker" || "$marker" == "$mode" ]] || {
    echo "firewall-mode state 与 profile.env 不一致" >&2; return 1; }
  printf '%s\n' "$mode"
}

_pdg_render_mihomo_candidate(){
  local out="$1" bundle="${2:-/opt/pdg-bot}"
  ( cd "$bundle" && python3 - "$out" "$bundle" <<'PY'
import importlib.util, os, sys
from pathlib import Path
dst, root = sys.argv[1:]
root = str(Path(root).resolve())
sys.path.insert(0, root)
source = Path(root, "bot.py")
if not source.is_file():
    source = Path(root, "pdg-bot.py")
if not source.is_file():
    raise SystemExit("bundle lacks bot.py/pdg-bot.py: " + root)
spec = importlib.util.spec_from_file_location("bot", str(source))
bot = importlib.util.module_from_spec(spec)
sys.modules["bot"] = bot
spec.loader.exec_module(bot)
model = bot.load()
data, meta = bot._render_mihomo_bytes(model)
if meta.get("unknown_proxies"):
    raise SystemExit("unknown proxies: " + ",".join(meta["unknown_proxies"]))
with open(dst, "wb") as fh:
    fh.write(data)
os.chmod(dst, 0o600)
PY
  )
}

_pdg_atomic_install_file(){
  local source="$1" target="$2" mode="${3:-600}" dir
  [[ -s "$source" ]] || return 1
  dir="$(dirname "$target")"; mkdir -p "$dir" || return 1
  python3 - "$source" "$target" "$mode" <<'PY'
import os
import shutil
import stat
import sys
import tempfile

source, target, raw_mode = sys.argv[1:]
try:
    mode = int(raw_mode, 8)
except ValueError:
    raise SystemExit(1)
if mode < 0 or mode > 0o777:
    raise SystemExit(1)
directory = os.path.dirname(os.path.abspath(target))
directory_info = os.lstat(directory)
if (
    not stat.S_ISDIR(directory_info.st_mode)
    or stat.S_ISLNK(directory_info.st_mode)
):
    raise SystemExit(1)
flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
flags |= getattr(os, "O_NOFOLLOW", 0)
source_fd = os.open(source, flags)
fd = -1
temporary = ""
try:
    before = os.fstat(source_fd)
    if not stat.S_ISREG(before.st_mode) or before.st_size <= 0:
        raise SystemExit(1)
    fd, temporary = tempfile.mkstemp(prefix=".pdg-file.", dir=directory)
    os.fchmod(fd, mode)
    with os.fdopen(fd, "wb", closefd=True) as out:
        fd = -1
        with os.fdopen(os.dup(source_fd), "rb", closefd=True) as inp:
            shutil.copyfileobj(inp, out)
        out.flush()
        os.fsync(out.fileno())
    after = os.fstat(source_fd)
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise SystemExit(1)
    os.replace(temporary, target)
    temporary = ""
    directory_fd = os.open(
        directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    )
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
finally:
    os.close(source_fd)
    if fd >= 0:
        os.close(fd)
    if temporary:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
PY
}

# 用 before-image 的 mode/uid/gid 原子恢复目标；数据与目录均 fsync 后才算成功。
_pdg_atomic_restore_file(){
  local source="$1" target="$2"
  [[ -f "$source" && ! -L "$source" && -d "$(dirname "$target")" ]] || return 1
  python3 - "$source" "$target" <<'PY'
import os
import shutil
import stat
import sys
import tempfile

source, target = sys.argv[1:]
st = os.lstat(source)
if not stat.S_ISREG(st.st_mode):
    raise SystemExit("before-image is not regular")
directory = os.path.dirname(target)
fd, tmp = tempfile.mkstemp(prefix=".pdg-restore.", dir=directory)
try:
    if hasattr(os, "fchmod"):
        os.fchmod(fd, stat.S_IMODE(st.st_mode))
    if hasattr(os, "fchown"):
        os.fchown(fd, st.st_uid, st.st_gid)
    with os.fdopen(fd, "wb") as out, open(source, "rb") as inp:
        fd = -1
        shutil.copyfileobj(inp, out)
        out.flush()
        os.fsync(out.fileno())
    os.chmod(tmp, stat.S_IMODE(st.st_mode))
    os.replace(tmp, target)
    if os.name != "nt":
        dfd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
finally:
    if fd >= 0:
        os.close(fd)
    try:
        os.unlink(tmp)
    except FileNotFoundError:
        pass
PY
}

_pdg_ensure_ruleset_direct_file(){
  local target="$1" seed=""
  if [[ -L "$target" || ( -e "$target" && ! -f "$target" ) ]]; then
    return 1
  fi
  [[ -f "$target" ]] && return 0
  seed="$(mktemp)" || return 1
  if ! printf '%s\n' \
      '# pdg-bot 规则集手机本地直连聚合（事务派生；不要手工编辑）' >"$seed" \
     || ! _pdg_atomic_install_file "$seed" "$target" 644 \
     || [[ ! -f "$target" || -L "$target" ]]; then
    rm -f "$seed"; return 1
  fi
  rm -f "$seed"
}

# ── sing-box 文件归属 ────────────────────────────────────────────────────────
# 判据集中在 lib/singbox.sh(install/uninstall/pdg 共用), 详见该文件注释:
# 只有可信归属标记, 或"完整匹配历史 PDG unit 形态 + 现场另有本项目特征", 才算自家的。
# 手工装 sing-box 最常见的 ExecStart 与本项目历史模板逐字一致, 单凭它认亲会误删别人的东西。
_pdg_singbox_is_ours(){
  # shellcheck source=lib/singbox.sh
  source "$REPO_DIR/lib/singbox.sh" 2>/dev/null || return 1
  pdg_singbox_is_ours "$@"
}

_pdg_drop_singbox_files(){
  local why="${1:-}" require_drop="${2:-0}" expected_root="${3:-}"
  local pfx="${PDG_ROOT_PREFIX:-}" state
  local unit="$pfx/etc/systemd/system/sing-box.service"
  local bin="$pfx/usr/local/bin/sing-box"
  local marker="$pfx/etc/privdns-gateway/singbox.pdg-owned"
  [[ -e "$unit" || -L "$unit" || -e "$bin" || -L "$bin" ]] || return 0
  if ! _pdg_singbox_is_ours "$unit"; then
    local kept reason
    kept="$(pdg_singbox_kept_paths 2>/dev/null)"
    reason="$(pdg_singbox_why_not_ours "$unit" 2>/dev/null)"
    c_y "  检测到 sing-box${why:+($why)}, 但无法确认是本项目安装的 → 原样保留, 不删:"
    [[ -n "$kept" ]] && printf '%s\n' "$kept" | sed 's/^/      /'
    c_y "  判不出归属的原因: ${reason:-未知}"
    c_y "  (确认它无用可自行清理: systemctl disable --now sing-box; rm -f $unit $bin)"
    [[ "$require_drop" == 1 ]] && return 1
    return 0
  fi
  if [[ "$require_drop" == 1 ]]; then
    [[ -n "$expected_root" \
       && -f "$expected_root/etc/systemd/system/sing-box.service" \
       && -f "$expected_root/usr/local/bin/sing-box" ]] || return 1
    cmp -s "$expected_root/etc/systemd/system/sing-box.service" "$unit" \
      && cmp -s "$expected_root/usr/local/bin/sing-box" "$bin" || {
        c_y "  sing-box 运行时在 capture 后发生漂移，拒绝删除。"
        return 1
      }
  fi
  # 确认是自家的 → 先落一份可信标记再动手: 中途崩了(断电/被杀)下次仍认得出是本项目所有,
  # 不至于因为 unit 已删、判据失效而退化成"证明不了", 从此再也清不掉残留。
  # shellcheck source=lib/singbox.sh
  if ! source "$REPO_DIR/lib/singbox.sh" 2>/dev/null \
     || ! pdg_singbox_mark_owned; then
    c_y "  sing-box 归属标记写入失败，未删除运行时。"
    return 1
  fi
  if ! systemctl disable --now sing-box >/dev/null 2>&1; then
    c_y "  sing-box 停用失败，未删除运行时。"
    return 1
  fi
  state="$(systemctl is-active sing-box 2>/dev/null)"
  [[ "$state" != active ]] || return 1
  state="$(systemctl is-enabled sing-box 2>/dev/null)"
  [[ "$state" != enabled && "$state" != enabled-runtime ]] || return 1
  if [[ "$require_drop" == 1 ]]; then
    cmp -s "$expected_root/etc/systemd/system/sing-box.service" "$unit" \
      && cmp -s "$expected_root/usr/local/bin/sing-box" "$bin" || {
        c_y "  sing-box 运行时在停用后发生漂移，拒绝删除。"
        return 1
      }
  fi
  if ! rm -f "$unit" "$bin" "$marker"; then
    c_y "  sing-box 运行时删除失败。"
    return 1
  fi
  if [[ -e "$unit" || -L "$unit" || -e "$bin" || -L "$bin" \
        || -e "$marker" || -L "$marker" ]]; then
    c_y "  sing-box 运行时删除后 read-back 仍存在。"
    return 1
  fi
  state="$(systemctl is-active sing-box 2>/dev/null)"
  [[ "$state" != active ]] || return 1
  state="$(systemctl is-enabled sing-box 2>/dev/null)"
  [[ "$state" != enabled && "$state" != enabled-runtime ]]
}
# 仅用于精确识别的 pre-profile 旧防火墙单向迁移。当前 profile-owned set 不走文本
# 剥离：_plat_write_profile 先同步 canonical TLS ports，再由统一 renderer 重建 nft。
_pdg_nft_strip_gms(){
  local f="$1"
  [[ "$(_pdg_platform)" == ios && -f "$f" ]] || return 0
  sed -E -i \
    's#(tcp dport [{] 53, 80, 81, 443, 853), 5228-5230, 8445 [}] accept#\1, 8445 } accept#' \
    "$f"
  sed -E -i \
    's#(tcp dport [{] 80, 443), 5228-5230 [}] redirect#\1 } redirect#' \
    "$f"
}

# 串行化"会写配置/重启服务"的操作(update/rollback/snapshot), 防 bot 更新按钮与命令行并发。
# 嵌套调用(update→snapshot)只锁一次。read-only 操作(status/doctor/report/log)不加锁。
LOCK="${PDG_LOCKFILE:-/run/privdns-gateway.lock}"
PDG_LOCKED=""
_lock(){
  [[ -n "$PDG_LOCKED" ]] && return 0
  # 打不开锁文件 → **拒绝执行**(fail-closed)。以前这里 `|| return 0` 继续往下写: 而
  # /run 出问题往往正意味着系统不正常, 恰恰是最不该让两个进程同时改配置的时候。
  if ! exec 9>"$LOCK" 2>/dev/null; then
    echo "⛔ 锁文件不可用($LOCK) —— 为避免并发写坏配置, 本次拒绝执行。"
    echo "   请检查 /run 是否可写(磁盘满/只读挂载/权限), 修好后重试。"
    exit 1
  fi
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
# 语义与 pdg-bot.py 的 _profile_text_with 一致(去前导空白后以 key= 开头才算命中; #key= 注释不算)。
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
  local status_failed=0
  c_g "== 服务 =="
  local core; core="$(_pdg_core)"
  local s required_svcs
  # shellcheck disable=SC2046  # _pdg_svcs 输出有意按空白分词
  local _cred; _cred="$(_pdg_bot_cred)"
  required_svcs="$(_pdg_required_svcs)"
  for s in $(_pdg_svcs); do   # 按平台: pdg-probe81 仅 iOS
    local _st; _st="$(systemctl is-active "$s" 2>/dev/null)"
    if [[ " $required_svcs " == *" $s "* && "$_st" != active ]]; then
      status_failed=1
    fi
    if [[ "$s" == pdg-bot && "$_cred" != ready ]]; then
      # 合法禁用态不是故障: 两项都空 = 这台机器不用 Telegram 管理; 只配一半才是配置错误
      [[ "$_cred" == partial ]] \
        && printf "  %-12s %s (⚠️ 凭据只配了一项, 需成对配置)\n" "$s" "$_st" \
        || printf "  %-12s %s (未配置凭据, 正常禁用态; 需要时 pdg-set-token)\n" "$s" "$_st"
    else
      printf "  %-12s %s\n" "$s" "$_st"
    fi
  done
  [[ "$(_pdg_platform)" == ios ]] && printf "  %-12s %s\n" "pdg-mitm" "$(systemctl is-active pdg-mitm 2>/dev/null)"
  echo "  timer        $(systemctl is-active pdg-rules-update.timer 2>/dev/null)"
  echo "  内核后端     $core$([[ "$core" == mihomo ]] && echo "(版本随项目发布更新)" || echo "(固定 1.12.x)")"
  if _pdg_platform_present; then echo "  手机平台     $(_pdg_platform)"
  else echo "  手机平台     android(⚠️ 平台标记缺失, 按 Android 安全回退; 运行 sudo pdg 触发迁移落定)"; fi
  local dptool dpline
  if dptool="$(_pdg_profile_tool)" \
    && dpline="$(python3 - "$dptool" "$PROFILE_ENV" <<'PY'
import importlib.util, sys
from pathlib import Path
tool, profile = sys.argv[1:]
sys.path.insert(0, str(Path(tool).resolve().parent))
spec = importlib.util.spec_from_file_location("pdgprofile_status", tool)
mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
values = mod.read_values(profile, missing_ok=False)
c = mod.resolve(profile, platform=values.get("PDG_PLATFORM"), environ={},
                ssh_port=values.get("PDG_SSH_PORT"))
print("%s|%s|%s|%s/%s|%s|%s" % (
    c["quic_mode"], ",".join(map(str, c["tls_ports"])),
    ",".join(map(str, c["http_ports"])), c["mark_text"], c["mask_text"],
    c["route_table"], c["rule_priority"]))
PY
)" ; then
    IFS='|' read -r _qm _tls _http _mark _table _prio <<<"$dpline"
    echo "  QUIC 模式     $_qm"
    echo "  TCP 劫持      TLS=$_tls HTTP=$_http"
    echo "  QUIC 路由     mark=$_mark table=$_table priority=$_prio"
    if [[ -x /usr/local/libexec/pdg-quic-routing.sh ]]; then
      echo "  路由复核      $(/usr/local/libexec/pdg-quic-routing.sh status 2>&1 || echo FAILED)"
    else
      echo "  路由复核      FAILED(helper missing)"
    fi
  else
    echo "  透明数据面   ⚠️ profile 缺失/重复/非法"
    status_failed=1
  fi
  local dpcheck="" dpstate="" dpmsg=""
  dpcheck="$(python3 - <<'PY'
import sys
sys.path.insert(0, "/opt/pdg-bot")
import checks
state, title, message = checks.check_dataplane_profile()
print(state + "|" + title + "|" + message)
PY
)" || dpcheck="fail|透明数据面|无法运行共享 checks.check_dataplane_profile"
  dpstate="${dpcheck%%|*}"; dpmsg="${dpcheck#*|}"; dpmsg="${dpmsg#*|}"
  if [[ "$dpstate" == ok ]]; then
    echo "  数据面复核   OK($dpmsg)"
  else
    echo "  数据面复核   FAILED($dpmsg)"
    status_failed=1
  fi
  echo "  DoT 域名     $(cat /opt/pdg-bot/dot-domain 2>/dev/null || echo ?)"
  local ports p9090="9090(local clash_api)"
  if jq -e '.experimental.clash_api as $c | $c.external_controller == "0.0.0.0:9090" and $c.external_ui == "/etc/sing-box/ui/dist" and (($c.secret // "") | length > 0)' /etc/sing-box/config.json >/dev/null 2>&1; then
    p9090="9090(panel临时内网)"
  fi
  # mihomo 模式 443/80 由 nft 转到 7893(redir), 故把 7893 一并纳入端口展示
  ports=$(ss -lntu 2>/dev/null | grep -oE ':(53|80|81|443|853|7893|7895|8445|9090)\b' | sed 's/^://' | sort -u | sed "s|^9090$|$p9090|" | tr '\n' ' ')
  echo "  监听端口     $ports"
  # 读不到就说读不到 —— 以前 describe 失败(仓库损坏 / dubious ownership)时这里输出一个空值,
  # 看起来像"版本号是空的", 排错方向全歪。
  if [[ -d "$REPO_DIR/.git" ]]; then
    local ver
    if ver="$(git -C "$REPO_DIR" describe --tags --always 2>/dev/null)" && [[ -n "$ver" ]]; then
      echo "  代码版本     $ver"
    else
      echo "  代码版本     未知(仓库不可读: 试 git -C $REPO_DIR describe --tags --always 看具体原因)"
    fi
  else
    echo "  代码版本     未知($REPO_DIR 不是 git 仓库 → pdg update 不可用)"
  fi
  local lm cache; lm="$(pdg_lowmem_current)"; cache="$(awk '/tag: lazy_cache/{f=1} f&&/size:/{print $2; exit}' /etc/mosdns/config.yaml 2>/dev/null)"
  echo "  内存模式     $([[ "$lm" == 1 ]] && echo 低内存 || echo 标准)(mosdns cache=${cache:-?})"
  return "$status_failed"
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
  # Superseded by pdgprofile platform defaults and the central render/apply
  # transaction. Never mutate generated nft output with a fixed sed rewrite.
  return 0
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

# CLI 回滚绝不信任快照里的 ruleset_direct/ruleset_hijack 聚合。调用当前仓库的
# 可信 Bot 实现，从候选元数据 + 候选 source JSON 重建并验证候选 MosDNS 接口。
_pdg_snapshot_rederive_ruleset_direct(){
  local tree="$1" source="$REPO_DIR/deploy/bot/pdg-bot.py"
  [[ -d "$tree" && -f "$source" ]] || return 1
  python3 - "$source" "$tree" <<'PY'
import importlib.util
import os
import sys

source, tree = sys.argv[1:]
spec = importlib.util.spec_from_file_location("pdg_bot_snapshot_rederive", source)
module = importlib.util.module_from_spec(spec)
try:
    spec.loader.exec_module(module)
    present = module._derive_ruleset_direct_tree(tree)
except Exception as exc:
    print("规则集 DNS 聚合候选重建失败(%s)" % type(exc).__name__, file=sys.stderr)
    raise SystemExit(1)
print("present" if present else "absent")
PY
}

_pdg_ruleset_direct_interface_ready_file(){
  local config="$1" source="$REPO_DIR/deploy/bot/pdg-bot.py"
  [[ -f "$config" && ! -L "$config" && -f "$source" ]] || return 1
  python3 - "$source" "$config" <<'PY'
import importlib.util
import sys

source, config = sys.argv[1:]
spec = importlib.util.spec_from_file_location("pdg_bot_interface_ready", source)
module = importlib.util.module_from_spec(spec)
try:
    spec.loader.exec_module(module)
    with open(config, "rb") as stream:
        module._ruleset_direct_interface_bytes(stream.read())
except Exception:
    raise SystemExit(1)
PY
}

_pdg_ruleset_aggregate_candidates(){
  local config="$1" direct_out="$2" hijack_out="$3"
  local transition_out="$4" old_hijack="$5"
  local source="$REPO_DIR/deploy/bot/pdg-bot.py"
  [[ -f "$config" && ! -L "$config" && -f "$source" \
     && -n "$direct_out" && -n "$hijack_out" \
     && -n "$transition_out" && -n "$old_hijack" ]] || return 1
  python3 - "$source" "$config" /opt/pdg-bot/rulesets.json \
    /etc/sing-box/rs "$direct_out" "$hijack_out" "$transition_out" \
    "$old_hijack" <<'RSAGGPY'
import importlib.util
import json
import os
import stat
import sys

(
    source, config, meta_path, rs_dir, direct_out, hijack_out,
    transition_out, old_hijack,
) = sys.argv[1:]
spec = importlib.util.spec_from_file_location("pdg_bot_migration_derive", source)
module = importlib.util.module_from_spec(spec)


def read_regular(path, required, limit):
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        if not required:
            return None
        raise
    try:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size < 0
            or before.st_size > limit
        ):
            raise ValueError("migration input is not a trusted regular file")
        chunks = []
        total = 0
        while True:
            chunk = os.read(fd, min(1024 * 1024, limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                raise ValueError("migration input exceeds size limit")
        after = os.fstat(fd)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise ValueError("migration input changed during read")
        return b"".join(chunks)
    finally:
        os.close(fd)


def write_exclusive(path, data):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short migration candidate write")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)


def aggregate_entries(data):
    entries = {"full": set(), "domain": set(), "keyword": set()}
    if data is None:
        return entries
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("old hijack aggregate is not UTF-8") from exc
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            raise ValueError("old hijack aggregate line shape unknown")
        prefix, value = line.split(":", 1)
        if (
            prefix not in entries
            or not value
            or len(value.encode("utf-8")) > 253
            or any(ord(char) < 0x21 or ord(char) == 0x7f for char in value)
        ):
            raise ValueError("old hijack aggregate value is unsafe")
        entries[prefix].add(value.lower())
    return entries


try:
    spec.loader.exec_module(module)
    config_data = read_regular(config, True, 4 * 1024 * 1024)
    module._ruleset_direct_interface_bytes(config_data)
    raw_meta = read_regular(meta_path, False, 4 * 1024 * 1024)
    meta = {} if raw_meta is None else json.loads(raw_meta.decode("utf-8"))
    if not isinstance(meta, dict):
        raise ValueError("ruleset metadata must be an object")
    managed = module._managed_rulesets(meta)
    staged = {}
    for name, leaf in sorted(managed.items()):
        if not leaf.endswith(".json"):
            continue
        staged["ruleset:" + leaf] = read_regular(
            os.path.join(rs_dir, leaf), True, 64 * 1024 * 1024
        )
    direct_data = module._ruleset_direct_bytes(meta, staged, {})
    hijack_data = module._ruleset_hijack_bytes(meta, staged, {})
    transition_entries = aggregate_entries(hijack_data)
    old_entries = aggregate_entries(
        read_regular(old_hijack, False, 64 * 1024 * 1024)
    )
    transition_lines = [
        "# pdg-bot 迁移过渡劫持聚合（old ∪ candidate；提交完成后替换）\n"
    ]
    for prefix in ("full", "domain", "keyword"):
        transition_entries[prefix].update(old_entries[prefix])
        transition_lines.extend(
            "%s:%s\n" % (prefix, item)
            for item in sorted(transition_entries[prefix])
        )
    transition_data = "".join(transition_lines).encode("utf-8")
    write_exclusive(direct_out, direct_data)
    write_exclusive(hijack_out, hijack_data)
    write_exclusive(transition_out, transition_data)
except Exception as exc:
    print(
        "规则集 DNS 聚合迁移候选生成失败(%s)" % type(exc).__name__,
        file=sys.stderr,
    )
    raise SystemExit(1)
RSAGGPY
}

_pdg_restore_ruleset_migration_before(){
  local work="$1" config="$2" direct="$3" hijack="$4"
  local direct_pre="$5" hijack_pre="$6" failed=0
  _pdg_atomic_restore_file "$work/config.before" "$config" 2>/dev/null \
    && cmp -s "$work/config.before" "$config" || failed=1
  if [[ "$direct_pre" == 1 ]]; then
    _pdg_atomic_restore_file "$work/direct.before" "$direct" 2>/dev/null \
      && cmp -s "$work/direct.before" "$direct" || failed=1
  else
    rm -f "$direct" 2>/dev/null || failed=1
    [[ ! -e "$direct" && ! -L "$direct" ]] || failed=1
  fi
  if [[ "$hijack_pre" == 1 ]]; then
    _pdg_atomic_restore_file "$work/hijack.before" "$hijack" 2>/dev/null \
      && cmp -s "$work/hijack.before" "$hijack" || failed=1
  else
    rm -f "$hijack" 2>/dev/null || failed=1
    [[ ! -e "$hijack" && ! -L "$hijack" ]] || failed=1
  fi
  [[ "$failed" == 0 ]]
}

_pdg_capture_ruleset_migration_before(){
  local work="$1" config="$2" direct="$3" hijack="$4"
  local direct_pre="$5" hijack_pre="$6"
  cp -a "$config" "$work/config.before" 2>/dev/null \
    && cmp -s "$config" "$work/config.before" || return 1
  if [[ "$direct_pre" == 1 ]]; then
    cp -a "$direct" "$work/direct.before" 2>/dev/null \
      && cmp -s "$direct" "$work/direct.before" || return 1
  fi
  if [[ "$hijack_pre" == 1 ]]; then
    cp -a "$hijack" "$work/hijack.before" 2>/dev/null \
      && cmp -s "$hijack" "$work/hijack.before" || return 1
  fi
}

_pdg_sync_ruleset_migration_path(){
  local path="$1"
  [[ -n "$path" ]] || return 1
  python3 - "$path" <<'PY'
import os
import stat
import sys

root = os.path.abspath(sys.argv[1])
st = os.lstat(root)
if not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode):
    raise SystemExit(1)
if st.st_uid != 0 or st.st_gid != 0 or st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
    raise SystemExit(1)
for current, directories, files in os.walk(root, topdown=True, followlinks=False):
    for name in directories:
        item = os.path.join(current, name)
        info = os.lstat(item)
        if (
            not stat.S_ISDIR(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_uid != 0
            or info.st_gid != 0
            or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise SystemExit(1)
    for name in files:
        item = os.path.join(current, name)
        info = os.lstat(item)
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != 0
            or info.st_gid != 0
            or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise SystemExit(1)
        fd = os.open(item, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
for current, _, _ in os.walk(root, topdown=False, followlinks=False):
    fd = os.open(current, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
PY
}

_pdg_sync_parent_dir(){
  local path="$1"
  python3 - "$path" <<'PY'
import os
import sys

parent = os.path.dirname(os.path.abspath(sys.argv[1]))
fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
try:
    os.fsync(fd)
finally:
    os.close(fd)
PY
}

_pdg_recover_ruleset_migration_journal(){
  local journal="$1" config="$2" direct="$3" hijack="$4"
  local direct_pre=0 hijack_pre=0
  [[ -d "$journal" && ! -L "$journal" \
     && -f "$journal/config.before" && ! -L "$journal/config.before" ]] \
    || return 1
  _pdg_sync_ruleset_migration_path "$journal" || return 1
  if [[ -f "$journal/direct.before" && ! -L "$journal/direct.before" ]]; then
    direct_pre=1
  elif [[ -f "$journal/direct.absent" && ! -L "$journal/direct.absent" ]]; then
    direct_pre=0
  else
    return 1
  fi
  if [[ -f "$journal/hijack.before" && ! -L "$journal/hijack.before" ]]; then
    hijack_pre=1
  elif [[ -f "$journal/hijack.absent" && ! -L "$journal/hijack.absent" ]]; then
    hijack_pre=0
  else
    return 1
  fi
  _pdg_restore_ruleset_migration_before \
    "$journal" "$config" "$direct" "$hijack" "$direct_pre" "$hijack_pre" \
    || return 1
  systemctl restart mosdns 2>/dev/null && _core_kernel_stable mosdns \
    || return 1
  rm -rf -- "$journal" || return 1
  _pdg_sync_parent_dir "$journal"
}

_pdg_legacy_snapshot_mihomo_prove(){
  local tree="$1" work="$2" expected=""
  [[ -f "$tree/etc/sing-box/config.json" \
     && -f "$tree/etc/systemd/system/sing-box.service" \
     && -x "$tree/usr/local/bin/sing-box" \
     && ! -e "$tree/etc/mihomo/config.yaml" \
     && ! -e "$tree/etc/systemd/system/mihomo.service" ]] || {
    echo "旧 sing-box 快照缺 unit/bin/model，无法建立失败恢复路径" >&2
    return 1
  }
  if [[ -e /etc/mihomo/config.yaml ]]; then
    expected="$work/current-managed-mihomo.yaml"
    _pdg_render_mihomo_candidate "$expected" "$REPO_DIR/deploy/bot" \
      && cmp -s "$expected" /etc/mihomo/config.yaml \
      || { echo "当前 Mihomo config 无法证明为本项目生成，拒绝删除" >&2; return 2; }
    : >"$work/remove-mihomo-config"
  fi
  if [[ -e /etc/systemd/system/mihomo.service ]]; then
    expected="$work/current-managed-mihomo.service"
    # shellcheck source=lib/units.sh
    source "$REPO_DIR/lib/units.sh" 2>/dev/null \
      && pdg_unit_mihomo >"$expected" \
      && cmp -s "$expected" /etc/systemd/system/mihomo.service \
      || { echo "当前 Mihomo unit 无法证明为本项目生成，拒绝删除" >&2; return 2; }
    : >"$work/remove-mihomo-unit"
  fi
}

_pdg_legacy_snapshot_mihomo_remove(){
  local work="$1"
  if [[ -e "$work/remove-mihomo-config" ]]; then
    cmp -s "$work/current-managed-mihomo.yaml" /etc/mihomo/config.yaml \
      || { echo "Mihomo config 在证明后发生漂移，拒绝删除" >&2; return 1; }
    rm -f /etc/mihomo/config.yaml || return 1
  fi
  if [[ -e "$work/remove-mihomo-unit" ]]; then
    cmp -s "$work/current-managed-mihomo.service" \
      /etc/systemd/system/mihomo.service \
      || { echo "Mihomo unit 在证明后发生漂移，拒绝删除" >&2; return 1; }
    rm -f /etc/systemd/system/mihomo.service || return 1
  fi
}

_pdg_snapshot_restore_managed_files(){
  local tree="$1" manifest="$2" failed=0 present path src dir tmp target
  local pfx="${PDG_ROOT_PREFIX:-}"
  [[ -d "$tree" && -f "$manifest" ]] || return 1
  while IFS='|' read -r present path; do
    [[ "$present" == 0 || "$present" == 1 ]] || { failed=1; continue; }
    [[ "$path" =~ ^(etc|opt|usr/local/(bin|libexec))/ \
       && "$path" != *".."* && "$path" != */ ]] || { failed=1; continue; }
    if [[ "$present" == 1 ]]; then
      src="$tree/$path"; target="$pfx/$path"; dir="$(dirname "$target")"
      [[ -f "$src" ]] || { failed=1; continue; }
      mkdir -p "$dir" || { failed=1; continue; }
      tmp="$(mktemp "$dir/.pdg-snapshot-restore.XXXXXX")" \
        || { failed=1; continue; }
      if ! cp -a "$src" "$tmp" || ! cmp -s "$src" "$tmp" \
         || ! mv -f "$tmp" "$target" || ! cmp -s "$src" "$target"; then
        rm -f "$tmp"; failed=1
      fi
    else
      target="$pfx/$path"
      rm -f -- "$target" || failed=1
      [[ ! -e "$target" ]] || failed=1
    fi
  done <"$manifest"
  return "$failed"
}

_pdg_snapshot_failure_restore(){
  local tmp="$1" qbefore="$2" captured_helper="$3" captured_tool="$4"
  local nftexe="$5" had_live="$6" failed=0
  local pfx="${PDG_ROOT_PREFIX:-}"
  local nft_target="${PDG_NFT_CONF:-$pfx/etc/nftables.conf}"
  if [[ -n "$captured_helper" ]]; then
    PDG_QUIC_STATE="$pfx/etc/privdns-gateway/quic-routing.state" \
      PDG_PROFILE_TOOL="$captured_tool" bash "$captured_helper" \
        rollback-state "$qbefore" >/dev/null 2>&1 || failed=1
  fi
  _pdg_snapshot_restore_managed_files \
    "$tmp/current-managed" "$tmp/current-managed.manifest" || failed=1
  if [[ -n "$nftexe" ]]; then
    # shellcheck source=lib/nfttxn.sh
    if source "$tmp/nfttxn.current.sh" 2>/dev/null \
       && declare -F pdg_nft_atomic_install >/dev/null; then
      _pdg_switchcore_restore_nft_before \
        "$tmp" "$tmp/nftables.current.before" "$nftexe" "$had_live" \
        "$tmp/pdg.live.current.restore" "$tmp/pdg.live.current.before" \
        || failed=1
    else
      failed=1
    fi
  else
    [[ ! -e "$nft_target" ]] || failed=1
  fi
  systemctl daemon-reload >/dev/null 2>&1 || failed=1
  if [[ -e "$tmp/quic-service.existed" ]]; then
    if [[ -e "$tmp/quic-service.was-enabled" ]]; then
      systemctl enable pdg-quic-routing >/dev/null 2>&1 || failed=1
      systemctl is-enabled pdg-quic-routing >/dev/null 2>&1 || failed=1
    else
      systemctl disable pdg-quic-routing >/dev/null 2>&1 || failed=1
      systemctl is-enabled pdg-quic-routing >/dev/null 2>&1 && failed=1
    fi
    if [[ -e "$tmp/quic-service.was-active" ]]; then
      systemctl start pdg-quic-routing >/dev/null 2>&1 || failed=1
      systemctl is-active pdg-quic-routing >/dev/null 2>&1 || failed=1
    else
      systemctl stop pdg-quic-routing >/dev/null 2>&1 || failed=1
      systemctl is-active pdg-quic-routing >/dev/null 2>&1 && failed=1
    fi
  fi
  if [[ -n "$captured_helper" ]]; then
    PDG_PROFILE="$pfx/etc/privdns-gateway/profile.env" \
      PDG_QUIC_STATE="$pfx/etc/privdns-gateway/quic-routing.state" \
      PDG_PROFILE_TOOL="$captured_tool" bash "$captured_helper" status \
        >/dev/null 2>&1 || failed=1
  fi
  return "$failed"
}

_pdg_snapshot_abort(){
  local tmp="$1" qbefore="$2" captured_helper="$3" captured_tool="$4"
  local nftexe="$5" had_live="$6" reason="$7" restore_rc=0
  _pdg_snapshot_failure_restore \
    "$tmp" "$qbefore" "$captured_helper" "$captured_tool" \
    "$nftexe" "$had_live" || restore_rc=1
  if [[ "$restore_rc" == 0 ]]; then
    echo "❌ $reason；已验证恢复当前 route/files/persistent+live nft before-images" >&2
  else
    echo "❌ $reason；事务回滚不完整，必须人工复核" >&2
  fi
  rm -rf "$tmp"
  return 1
}

_pdg_capture_managed_files(){
  local tree="$1" manifest="$2" pfx="${PDG_ROOT_PREFIX:-}" path target
  shift 2
  mkdir -p "$tree" || return 1
  : >"$manifest" || return 1
  for path in "$@"; do
    [[ "$path" =~ ^(etc|opt|usr/local/(bin|libexec))/ \
       && "$path" != *".."* && "$path" != */ ]] || return 1
    target="$pfx/$path"
    if [[ -f "$target" && ! -L "$target" ]]; then
      mkdir -p "$tree/$(dirname "$path")" \
        && cp -a "$target" "$tree/$path" \
        && cmp -s "$target" "$tree/$path" \
        && printf '1|%s\n' "$path" >>"$manifest" \
        || return 1
    elif [[ -e "$target" || -L "$target" ]]; then
      echo "legacy migration 受管路径不是普通文件: $target" >&2
      return 1
    else
      printf '0|%s\n' "$path" >>"$manifest" || return 1
    fi
  done
}

_pdg_legacy_quiesce_new_dataplane(){
  local svc state failed=0
  for svc in pdg-quic-routing mihomo; do
    systemctl disable --now "$svc" >/dev/null 2>&1 || true
    state="$(systemctl is-active "$svc" 2>/dev/null)"
    [[ "$state" != active ]] || failed=1
    state="$(systemctl is-enabled "$svc" 2>/dev/null)"
    [[ "$state" != enabled && "$state" != enabled-runtime ]] || failed=1
  done
  return "$failed"
}

_pdg_legacy_activate_singbox(){
  local pfx="${PDG_ROOT_PREFIX:-}" state
  [[ -f "$pfx/etc/systemd/system/sing-box.service" \
     && -x "$pfx/usr/local/bin/sing-box" \
     && -f "$pfx/etc/sing-box/config.json" ]] || {
    echo "legacy sing-box unit/bin/model 不完整" >&2; return 1; }
  systemctl daemon-reload >/dev/null 2>&1 || return 1
  systemctl enable --now sing-box >/dev/null 2>&1 || return 1
  state="$(systemctl is-active sing-box 2>/dev/null)"
  [[ "$state" == active ]] || return 1
  state="$(systemctl is-enabled sing-box 2>/dev/null)"
  [[ "$state" == enabled || "$state" == enabled-runtime ]]
}

_pdg_legacy_migration_capture(){
  local work="$1" nftexe="$2" pfx="${PDG_ROOT_PREFIX:-}"
  local nft_target="${PDG_NFT_CONF:-$pfx/etc/nftables.conf}"
  local paths=(
    etc/privdns-gateway/profile.env
    etc/privdns-gateway/firewall-mode
    etc/privdns-gateway/backend
    etc/privdns-gateway/quic-routing.state
    etc/systemd/system/pdg-quic-routing.service
    usr/local/libexec/pdg-quic-routing.sh
    opt/pdg-bot/bot.py
    opt/pdg-bot/sb2mihomo.py
    opt/pdg-bot/pdgprofile.py
    etc/mihomo/config.yaml
    etc/systemd/system/mihomo.service
    etc/sing-box/config.json
    etc/systemd/system/sing-box.service
    usr/local/bin/sing-box
    etc/privdns-gateway/singbox.pdg-owned
  )
  local tables=""
  [[ -n "$nftexe" && -x "$nftexe" ]] || return 1
  _pdg_capture_managed_files "$work/files" "$work/files.manifest" \
    "${paths[@]}" || return 1
  mkdir -p "$work/source" || return 1
  cp -a "$REPO_DIR/deploy/firewall/pdg-quic-routing.sh" \
    "$work/source/pdg-quic-routing.sh" \
    && cp -a "$REPO_DIR/deploy/bot/pdgprofile.py" \
      "$work/source/pdgprofile.py" \
    && cp -a "$REPO_DIR/deploy/bot/sb2mihomo.py" \
      "$work/source/sb2mihomo.py" \
    && cp -a "$REPO_DIR/lib/nfttxn.sh" "$work/source/nfttxn.sh" \
    && cmp -s "$REPO_DIR/deploy/firewall/pdg-quic-routing.sh" \
      "$work/source/pdg-quic-routing.sh" \
    && cmp -s "$REPO_DIR/deploy/bot/pdgprofile.py" \
      "$work/source/pdgprofile.py" \
    && cmp -s "$REPO_DIR/deploy/bot/sb2mihomo.py" \
      "$work/source/sb2mihomo.py" \
    && cmp -s "$REPO_DIR/lib/nfttxn.sh" "$work/source/nfttxn.sh" \
    || return 1
  if [[ -f "$nft_target" ]]; then
    cp -a "$nft_target" "$work/nftables.before" \
      && cmp -s "$nft_target" "$work/nftables.before" || return 1
  elif [[ -e "$nft_target" || -L "$nft_target" ]]; then
    return 1
  fi
  PDG_LEGACY_HAD_LIVE=0
  if "$nftexe" list table inet pdg >"$work/pdg.live.before" 2>/dev/null; then
    PDG_LEGACY_HAD_LIVE=1
    {
      printf 'table inet pdg\n'
      printf 'delete table inet pdg\n'
      cat "$work/pdg.live.before"
    } >"$work/pdg.live.restore" || return 1
    "$nftexe" -c -f "$work/pdg.live.restore" >/dev/null 2>&1 || return 1
  else
    tables="$("$nftexe" list tables 2>/dev/null)" || return 1
    if grep -Eq \
        '^[[:space:]]*table[[:space:]]+inet[[:space:]]+pdg([[:space:]]|$)' \
        <<<"$tables"; then
      return 1
    fi
    : >"$work/pdg.live.before"; : >"$work/pdg.live.restore"
  fi
  PDG_LEGACY_QBEFORE=-
  if [[ -f "$pfx/etc/privdns-gateway/quic-routing.state" ]]; then
    cp -a "$pfx/etc/privdns-gateway/quic-routing.state" \
      "$work/quic.state.before" \
      && cmp -s "$pfx/etc/privdns-gateway/quic-routing.state" \
        "$work/quic.state.before" || return 1
    PDG_LEGACY_QBEFORE="$work/quic.state.before"
  fi
}

_pdg_legacy_migration_restore(){
  local work="$1" nftexe="$2" had_live="$3" qbefore="$4"
  local pfx="${PDG_ROOT_PREFIX:-}" failed=0
  _pdg_legacy_quiesce_new_dataplane || failed=1
  PDG_QUIC_STATE="$pfx/etc/privdns-gateway/quic-routing.state" \
    PDG_PROFILE_TOOL="$work/source/pdgprofile.py" \
    bash "$work/source/pdg-quic-routing.sh" rollback-state "$qbefore" \
      >/dev/null 2>&1 || failed=1
  _pdg_snapshot_restore_managed_files \
    "$work/files" "$work/files.manifest" || failed=1
  # shellcheck source=lib/nfttxn.sh
  if source "$work/source/nfttxn.sh" 2>/dev/null \
     && declare -F pdg_nft_atomic_install >/dev/null; then
    _pdg_switchcore_restore_nft_before \
      "$work" "$work/nftables.before" "$nftexe" "$had_live" \
      "$work/pdg.live.restore" "$work/pdg.live.before" || failed=1
  else
    failed=1
  fi
  _pdg_legacy_quiesce_new_dataplane || failed=1
  _pdg_legacy_activate_singbox || failed=1
  return "$failed"
}

_pdg_legacy_new_unit_ready(){
  local work="$1" pfx="${PDG_ROOT_PREFIX:-}"
  local unit="$pfx/etc/systemd/system/mihomo.service"
  [[ -f "$unit" && -s "$unit" ]] || return 1
  # shellcheck source=lib/units.sh
  source "$REPO_DIR/lib/units.sh" 2>/dev/null \
    && pdg_unit_mihomo >"$work/mihomo.expected.service" \
    && [[ -s "$work/mihomo.expected.service" ]] \
    && cmp -s "$work/mihomo.expected.service" "$unit" || return 1
  systemctl daemon-reload >/dev/null 2>&1 || return 1
}

_pdg_legacy_quic_ready(){
  local pfx="${PDG_ROOT_PREFIX:-}" state
  local unit="$pfx/etc/systemd/system/pdg-quic-routing.service"
  local helper="$pfx/usr/local/libexec/pdg-quic-routing.sh"
  local profile="$pfx/etc/privdns-gateway/profile.env"
  local qstate="$pfx/etc/privdns-gateway/quic-routing.state"
  local tool="$pfx/opt/pdg-bot/pdgprofile.py"
  [[ -f "$unit" && -s "$unit" && -x "$helper" \
     && -f "$profile" && -f "$tool" ]] || return 1
  cmp -s "$REPO_DIR/deploy/firewall/pdg-quic-routing.service" "$unit" \
    && cmp -s "$REPO_DIR/deploy/firewall/pdg-quic-routing.sh" "$helper" \
    || return 1
  systemctl enable --now pdg-quic-routing >/dev/null 2>&1 || return 1
  state="$(systemctl is-active pdg-quic-routing 2>/dev/null)"
  [[ "$state" == active ]] || return 1
  state="$(systemctl is-enabled pdg-quic-routing 2>/dev/null)"
  [[ "$state" == enabled || "$state" == enabled-runtime ]] || return 1
  PDG_PROFILE="$profile" PDG_QUIC_STATE="$qstate" \
    PDG_PROFILE_TOOL="$tool" bash "$helper" status >/dev/null 2>&1
}

_pdg_legacy_dataplane_equivalent(){
  local source_root="$REPO_DIR/deploy/bot"
  [[ -f "$source_root/checks.py" && -f "$source_root/nftscan.py" \
     && -f "$source_root/pdgprofile.py" ]] || return 1
  PYTHONDONTWRITEBYTECODE=1 python3 - "$source_root" <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
import checks
raise SystemExit(0 if checks.check_dataplane_profile()[0] == "ok" else 1)
PY
}

_pdg_legacy_singbox_commit_proven(){
  local work="$1" pfx="${PDG_ROOT_PREFIX:-}"
  local unit="$pfx/etc/systemd/system/sing-box.service"
  local bin="$pfx/usr/local/bin/sing-box"
  [[ -f "$work/files/etc/systemd/system/sing-box.service" \
     && -f "$work/files/usr/local/bin/sing-box" ]] || return 1
  _pdg_singbox_is_ours "$unit" || return 1
  cmp -s "$work/files/etc/systemd/system/sing-box.service" "$unit" \
    && cmp -s "$work/files/usr/local/bin/sing-box" "$bin"
}

_pdg_legacy_transaction_abort(){
  local work="$1" nftexe="$2" had_live="$3" qbefore="$4" reason="$5"
  if _pdg_legacy_migration_restore \
      "$work" "$nftexe" "$had_live" "$qbefore"; then
    PDG_LEGACY_TX_RECOVERY=ok
    echo "legacy transaction 在「$reason」失败；已验证恢复迁移前 legacy target 并启动 sing-box" >&2
    rm -rf "$work" \
      || echo "legacy target 已恢复，但 before-image 清理失败并保留于 $work" >&2
  else
    PDG_LEGACY_TX_RECOVERY=failed
    echo "legacy transaction 在「$reason」失败且恢复不完整；before-image 保留于 $work" >&2
  fi
  return 1
}

PDG_LEGACY_TX_RECOVERY=not-run
_pdg_legacy_migrate_transaction(){
  local work="" nftexe="" had_live=0 qbefore=- pfx="${PDG_ROOT_PREFIX:-}"
  local backend_source="" backend_target=""
  PDG_LEGACY_TX_RECOVERY=not-run
  if ! _pdg_legacy_quiesce_new_dataplane; then
    echo "无法停用回滚前 Mihomo/QUIC，拒绝迁移旧快照" >&2
    _pdg_legacy_activate_singbox \
      && PDG_LEGACY_TX_RECOVERY=ok || PDG_LEGACY_TX_RECOVERY=failed
    return 1
  fi
  if ! work="$(_pdg_mktemp_dir)"; then
    _pdg_legacy_activate_singbox \
      && PDG_LEGACY_TX_RECOVERY=ok || PDG_LEGACY_TX_RECOVERY=failed
    return 1
  fi
  nftexe="$(_pdg_nft_bin)"
  if ! _pdg_legacy_migration_capture "$work" "$nftexe"; then
    echo "legacy target before-image capture 失败，未运行迁移" >&2
    _pdg_legacy_activate_singbox \
      && PDG_LEGACY_TX_RECOVERY=ok || PDG_LEGACY_TX_RECOVERY=failed
    rm -rf "$work"
    return 1
  fi
  had_live="$PDG_LEGACY_HAD_LIVE"; qbefore="$PDG_LEGACY_QBEFORE"
  if ! migrate_dataplane_profile; then
    _pdg_legacy_transaction_abort \
      "$work" "$nftexe" "$had_live" "$qbefore" "数据面迁移"
    return 1
  fi
  if ! _pdg_legacy_new_unit_ready "$work"; then
    _pdg_legacy_transaction_abort \
      "$work" "$nftexe" "$had_live" "$qbefore" "Mihomo unit prepare/read-back"
    return 1
  fi
  if ! _pdg_legacy_quic_ready; then
    _pdg_legacy_transaction_abort \
      "$work" "$nftexe" "$had_live" "$qbefore" "QUIC service/status"
    return 1
  fi
  if ! _pdg_legacy_dataplane_equivalent; then
    _pdg_legacy_transaction_abort \
      "$work" "$nftexe" "$had_live" "$qbefore" \
      "profile/persistent/live nft 与 Mihomo 等价性"
    return 1
  fi
  if ! _pdg_legacy_singbox_commit_proven "$work"; then
    _pdg_legacy_transaction_abort \
      "$work" "$nftexe" "$had_live" "$qbefore" \
      "sing-box ownership/capture proof"
    return 1
  fi
  if ! _core_kernel_activate mihomo sing-box \
     || ! _core_kernel_stable mihomo; then
    _pdg_legacy_transaction_abort \
      "$work" "$nftexe" "$had_live" "$qbefore" "Mihomo stable activation"
    return 1
  fi
  backend_source="$work/backend.mihomo"
  backend_target="$pfx/etc/privdns-gateway/backend"
  if ! printf 'mihomo\n' >"$backend_source" \
     || ! _pdg_atomic_install_file "$backend_source" "$backend_target" 600; then
    _pdg_legacy_transaction_abort \
      "$work" "$nftexe" "$had_live" "$qbefore" "backend atomic write"
    return 1
  fi
  if ! cmp -s "$backend_source" "$backend_target"; then
    _pdg_legacy_transaction_abort \
      "$work" "$nftexe" "$had_live" "$qbefore" "backend read-back"
    return 1
  fi
  if ! _pdg_drop_singbox_files "legacy transaction commit" 1 "$work/files" \
     || ! systemctl daemon-reload >/dev/null 2>&1; then
    _pdg_legacy_transaction_abort \
      "$work" "$nftexe" "$had_live" "$qbefore" "sing-box owned runtime drop"
    return 1
  fi
  PDG_LEGACY_TX_RECOVERY=committed
  rm -rf "$work" \
    || c_y "  commit 已完成，但 legacy before-image 清理失败并保留于 $work"
  c_g "  legacy target 已完整迁移并提交到 Mihomo+QUIC；旧 PDG sing-box 运行时已移除。"
  return 0
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

# 快照已恢复 persistent/live nft 后，oneshot 的 active(exited) 状态不代表其
# fwmark policy rule/table route 仍在。enable 只恢复开机状态；必须显式
# restart 重新执行 ExecStart，再由 helper status 校验内核 tuple。
# 返回 2 表示 profile 声明了 QUIC 数据面但 helper 缺失，便于调用方准确报告。
_pdg_rollback_restore_quic(){
  local helper="${1:-/usr/local/libexec/pdg-quic-routing.sh}"
  local profile="${2:-${PROFILE_ENV:-/etc/privdns-gateway/profile.env}}"
  if [[ -x "$helper" ]]; then
    systemctl enable pdg-quic-routing >/dev/null 2>&1 || return 1
    systemctl restart pdg-quic-routing >/dev/null 2>&1 || return 1
    "$helper" status >/dev/null 2>&1 || return 1
    return 0
  fi
  grep -q '^PDG_QUIC_MODE=' "$profile" 2>/dev/null && return 2
  return 0
}

SNAP_DIR="/var/lib/privdns-gateway/backups"

# 供 cmd_update 读取"本次刚创建的快照目录"(精确回滚目标, 不靠 index 0 猜)。
_PDG_SNAP_CREATED=""
cmd_snapshot(){
  need_root snapshot; _lock
  _PDG_SNAP_CREATED=""
  local ts d="" suffix attempt
  ts=$(date +%Y%m%d-%H%M%S)
  install -d -m700 "$SNAP_DIR" || {
    c_y "❌ 快照根目录不可用"; return 1; }
  # 时间戳便于人读，随机后缀让同一秒内并发/连续创建也有稳定、不可猜错的目录 ID。
  # mkdir 的排他创建很重要；install -d 遇到同名目录会成功，反而可能覆盖旧快照。
  for attempt in {1..10}; do
    suffix="$(python3 -c 'import secrets; print(secrets.token_hex(4))')" || {
      c_y "❌ 无法生成快照 ID"; return 1; }
    d="$SNAP_DIR/$ts-$suffix"
    if mkdir -m700 "$d" 2>/dev/null; then
      break
    fi
    d=""
  done
  [[ -n "$d" ]] || { c_y "❌ 无法分配唯一快照 ID"; return 1; }
  # 整机配置 + 防火墙 + bot.env(含 token)+ service + journald 封顶(含历史错路径)(相对 / 打包, 回滚 -C / 解开)
  # 含: 已安装脚本(pdg / pdg-set-token / cert hook)+ 全部 pdg unit —— 升级会改它们, 回滚要一并还原。
  # 只打包"存在的"路径 —— 历史错路径可能已被迁移清掉, 无条件列进去会让 tar 报 Cannot stat 并返 2。
  local cand=(etc/mosdns etc/sing-box etc/mihomo opt/pdg-bot opt/pdg-web etc/privdns-gateway etc/nftables.conf
              etc/systemd/system/pdg-bot.service etc/systemd/journald.conf.d/50-pdg.conf
              etc/systemd/system/journald.conf.d/50-pdg.conf
              etc/systemd/system/mihomo.service etc/systemd/system/sing-box.service
              etc/systemd/system/pdg-mitm.service etc/systemd/system/pdg-probe81.service
              etc/systemd/system/pdg-rules-update.service etc/systemd/system/pdg-rules-update.timer
              etc/systemd/system/pdg-health.service etc/systemd/system/pdg-health.timer
              etc/systemd/system/pdg-quic-routing.service
              etc/systemd/system/pdg-web.service
              etc/letsencrypt/renewal-hooks/deploy/99-pdg-cert.sh
              usr/local/bin/pdg usr/local/bin/pdg-set-token usr/local/bin/pdg-webctl
              usr/local/bin/mosdns usr/local/bin/mihomo usr/local/bin/sing-box
              usr/local/libexec/pdg-quic-routing.sh
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
  local tmp="" tree="" members="" apply_members="" panel_sanitized=0 rb_nft=""
  local legacy_singbox_snapshot=0 legacy_migration_ok=1
  local legacy_migration_committed=0
  local txn_nftexe="" current_had_live=0 captured_helper="" captured_tool=""
  if ! tmp="$(_pdg_mktemp_dir)"; then echo "❌ 无法创建回滚临时目录"; return 1; fi
  tree="$tmp/tree"; members="$tmp/members"; apply_members="$tmp/apply-members"
  if ! mkdir -p "$tree" || ! tar tzf "$f" > "$members" 2>/dev/null || [[ ! -s "$members" ]]; then
    echo "❌ 快照目录或成员清单读取失败, 中止"; rm -rf "$tmp"; return 1
  fi
  if grep -Eq '(^/|(^|/)\.\.(/|$))' "$members" \
     || grep -Evq '^(etc|opt|usr/local/bin)(/|$)|^usr/local/libexec/pdg-quic-routing[.]sh$' "$members"; then
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
  local rsdirect_member="etc/mosdns/rules/ruleset_direct.txt"
  local rshijack_member="etc/mosdns/rules/ruleset_hijack.txt"
  local rsaggregate_members="$tmp/members-ruleset-aggregates"
  if ! _pdg_snapshot_rederive_ruleset_direct "$tree" >/dev/null; then
    echo "❌ 快照的规则集手机直连候选无法可信重建, 中止"
    rm -rf "$tmp"; return 1
  fi
  if ! awk -v p="$rsdirect_member" -v q="$rshijack_member" \
      '$0 != p && $0 != q' "$members" >"$rsaggregate_members"; then
    echo "❌ 无法重建回滚成员清单, 中止"; rm -rf "$tmp"; return 1
  fi
  local aggregate_member
  for aggregate_member in "$rsdirect_member" "$rshijack_member"; do
    if [[ -f "$tree/$aggregate_member" ]]; then
      printf '%s\n' "$aggregate_member" >>"$rsaggregate_members" \
        || { echo "❌ 无法登记重建后的规则集聚合, 中止"; rm -rf "$tmp"; return 1; }
    fi
  done
  mv -f "$rsaggregate_members" "$members" \
    || { echo "❌ 无法提交回滚成员清单, 中止"; rm -rf "$tmp"; return 1; }
  # 内核配置校验(v1.6.0 只剩 mihomo)。快照带 mihomo 配置就用 mihomo 校验(优先用快照自带的
  # mihomo 二进制 —— 拿刚升上来的新核校验旧配置可能误挡回滚)。迁移前(singbox)快照没有 mihomo
  # 配置, 此处不拦, 留待落盘后从还原出的 config.json 现渲染再核验(见下方内核收尾)。
  local snap_mbin=""
  [[ -x "$tree/usr/local/bin/mihomo" ]] && snap_mbin="$tree/usr/local/bin/mihomo"
  if [[ -f "$tree/etc/mihomo/config.yaml" ]]; then
    "${snap_mbin:-mihomo}" -t -d "$tree/etc/mihomo" -f "$tree/etc/mihomo/config.yaml" >/dev/null 2>&1 \
      || { echo "❌ 快照的 mihomo 配置 check 失败, 中止"; rm -rf "$tmp"; return 1; }
  fi
  if [[ -f "$tree/etc/nftables.conf" ]]; then
    rb_nft="$(_pdg_nft_bin)"
    [[ -n "$rb_nft" ]] \
      || { echo "❌ 找不到 nft，无法验证快照"; rm -rf "$tmp"; return 1; }
    "$rb_nft" -c -f "$tree/etc/nftables.conf" >/dev/null 2>&1 \
      || { echo "❌ 快照的 nftables 语法错, 中止"; rm -rf "$tmp"; return 1; }
  fi
  if [[ -f "$tree/etc/sing-box/config.json" \
        && ! -e "$tree/etc/mihomo/config.yaml" \
        && ! -e "$tree/etc/systemd/system/mihomo.service" ]]; then
    _pdg_legacy_snapshot_mihomo_prove "$tree" "$tmp" \
      || { echo "❌ 旧 sing-box 快照的较新 Mihomo 资产归属不可信"; rm -rf "$tmp"; return 1; }
    legacy_singbox_snapshot=1
  fi
  local current_managed=(
    etc/systemd/system/pdg-quic-routing.service
    usr/local/libexec/pdg-quic-routing.sh
    usr/local/bin/pdg
    usr/local/bin/mosdns
    usr/local/bin/proxy-gateway-restore-firewall.sh
    etc/privdns-gateway/quic-routing.state
    etc/privdns-gateway/profile.env
    etc/privdns-gateway/firewall-mode
    etc/privdns-gateway/backend
    etc/privdns-gateway/mosdns-build.env
    etc/mosdns/rules/ruleset_direct.txt
    etc/mosdns/rules/ruleset_hijack.txt
    opt/pdg-bot/pdgprofile.py
    opt/pdg-bot/sb2mihomo.py
    opt/pdg-bot/bot.py
    opt/pdg-bot/checks.py
    opt/pdg-bot/report.py
    opt/pdg-bot/nftscan.py
    opt/pdg-bot/nftmerge.py
    opt/pdg-web/pdg-web.py
    opt/pdg-web/pdg-web-job.py
    opt/pdg-web/pdgcontrol.py
    opt/pdg-web/pdg-web-setup.py
    opt/pdg-web/pdgwebconfig.py
    opt/pdg-web/static/index.html
    opt/pdg-web/static/app.js
    opt/pdg-web/static/style.css
    opt/pdg-web/static/manifest.webmanifest
    opt/pdg-web/static/icon.svg
    usr/local/bin/pdg-webctl
    etc/systemd/system/pdg-web.service
    etc/privdns-gateway/web.json
    etc/mihomo/config.yaml
    etc/systemd/system/mihomo.service
  ) cp_path
  mkdir -p "$tmp/current-managed" || { rm -rf "$tmp"; return 1; }
  : >"$tmp/current-managed.manifest" || { rm -rf "$tmp"; return 1; }
  for cp_path in "${current_managed[@]}"; do
    if [[ -f "/$cp_path" && ! -L "/$cp_path" ]]; then
      mkdir -p "$tmp/current-managed/$(dirname "$cp_path")" \
        && cp -a "/$cp_path" "$tmp/current-managed/$cp_path" \
        && cmp -s "/$cp_path" "$tmp/current-managed/$cp_path" \
        || { echo "❌ 当前 managed file before-image 失败: /$cp_path"; rm -rf "$tmp"; return 1; }
      printf '1|%s\n' "$cp_path" >>"$tmp/current-managed.manifest" \
        || { rm -rf "$tmp"; return 1; }
    elif [[ -e "/$cp_path" || -L "/$cp_path" ]]; then
      echo "❌ 受管路径不是普通文件，拒绝回滚: /$cp_path"
      rm -rf "$tmp"; return 1
    else
      printf '0|%s\n' "$cp_path" >>"$tmp/current-managed.manifest" \
        || { rm -rf "$tmp"; return 1; }
    fi
  done
  captured_helper="$tmp/current-managed/usr/local/libexec/pdg-quic-routing.sh"
  captured_tool="$tmp/current-managed/opt/pdg-bot/pdgprofile.py"
  [[ -f "$captured_helper" ]] || captured_helper=""
  [[ -f "$captured_tool" ]] || captured_tool="$REPO_DIR/deploy/bot/pdgprofile.py"
  if [[ -f /etc/systemd/system/pdg-quic-routing.service ]]; then
    : >"$tmp/quic-service.existed"
    systemctl is-enabled pdg-quic-routing >/dev/null 2>&1 \
      && : >"$tmp/quic-service.was-enabled"
    systemctl is-active pdg-quic-routing >/dev/null 2>&1 \
      && : >"$tmp/quic-service.was-active"
  fi
  if [[ -f /etc/nftables.conf ]]; then
    cp -a /etc/nftables.conf "$tmp/nftables.current.before" \
      && cmp -s /etc/nftables.conf "$tmp/nftables.current.before" \
      || { echo "❌ 当前 persistent nft before-image 失败"; rm -rf "$tmp"; return 1; }
  fi
  txn_nftexe="$(_pdg_nft_bin)"
  if [[ -n "$txn_nftexe" ]]; then
    cp -a "$REPO_DIR/lib/nfttxn.sh" "$tmp/nfttxn.current.sh" \
      && cmp -s "$REPO_DIR/lib/nfttxn.sh" "$tmp/nfttxn.current.sh" \
      || { echo "❌ 当前 nft transaction helper before-image 失败"; rm -rf "$tmp"; return 1; }
    if "$txn_nftexe" list table inet pdg \
        >"$tmp/pdg.live.current.before" 2>/dev/null; then
      current_had_live=1
      {
        printf 'table inet pdg\n'
        printf 'delete table inet pdg\n'
        cat "$tmp/pdg.live.current.before"
      } >"$tmp/pdg.live.current.restore" \
        || { rm -rf "$tmp"; return 1; }
      "$txn_nftexe" -c -f "$tmp/pdg.live.current.restore" >/dev/null 2>&1 \
        || { echo "❌ 当前 live nft before-image 无法校验"; rm -rf "$tmp"; return 1; }
    else
      local current_tables=""
      current_tables="$("$txn_nftexe" list tables 2>/dev/null)" \
        || { echo "❌ 无法 capture live nft inventory"; rm -rf "$tmp"; return 1; }
      if grep -Eq \
          '^[[:space:]]*table[[:space:]]+inet[[:space:]]+pdg([[:space:]]|$)' \
          <<<"$current_tables"; then
        echo "❌ live PDG table 存在但无法 capture"; rm -rf "$tmp"; return 1
      fi
      : >"$tmp/pdg.live.current.before"
      : >"$tmp/pdg.live.current.restore"
    fi
  elif [[ -f /etc/nftables.conf ]]; then
    echo "❌ 当前 persistent nft 存在但找不到 nft binary"
    rm -rf "$tmp"; return 1
  fi
  # Prove and remove the current trusted tuple before profile/state/helper files
  # are overwritten. This prevents a current tuple B becoming an unowned
  # kernel orphan when an older snapshot A is restored.
  local cur_qhelper=/usr/local/libexec/pdg-quic-routing.sh q_current_before="-"
  if [[ -x "$cur_qhelper" ]]; then
    if [[ -e /etc/privdns-gateway/quic-routing.state ]]; then
      cp -a /etc/privdns-gateway/quic-routing.state "$tmp/quic-current.state" \
        && cmp -s /etc/privdns-gateway/quic-routing.state "$tmp/quic-current.state" \
        || { echo "❌ 当前 QUIC state before-image 失败"; rm -rf "$tmp"; return 1; }
      q_current_before="$tmp/quic-current.state"
      "$cur_qhelper" status >/dev/null 2>&1 \
        || { echo "❌ 当前 QUIC tuple/state 不可信，拒绝回滚"; rm -rf "$tmp"; return 1; }
    else
      "$cur_qhelper" cleanup-status >/dev/null 2>&1 \
        || { echo "❌ 无 state 时无法证明当前 profile tuple 未占用"; rm -rf "$tmp"; return 1; }
    fi
    if ! "$cur_qhelper" remove >/dev/null 2>&1 \
       || ! "$cur_qhelper" cleanup-status >/dev/null 2>&1; then
      _pdg_snapshot_abort "$tmp" "$q_current_before" \
        "$captured_helper" "$captured_tool" "$txn_nftexe" \
        "$current_had_live" "当前 QUIC tuple 清理失败"
      return $?
    fi
  elif [[ -e /etc/privdns-gateway/quic-routing.state ]] \
       || grep -q '^PDG_QUIC_MODE=' "$PROFILE_ENV" 2>/dev/null; then
    echo "❌ 当前安装声明 QUIC 数据面但 helper 缺失，拒绝产生 orphan"
    rm -rf "$tmp"; return 1
  fi
  if grep -q '^PDG_QUIC_MODE=' "$tree/etc/privdns-gateway/profile.env" 2>/dev/null; then
    local snap_qhelper="$tree/usr/local/libexec/pdg-quic-routing.sh"
    local snap_qtool="$tree/opt/pdg-bot/pdgprofile.py"
    if [[ ! -f "$snap_qhelper" || ! -f "$snap_qtool" ]] \
       || ! PDG_PROFILE="$tree/etc/privdns-gateway/profile.env" \
            PDG_QUIC_STATE="$tree/etc/privdns-gateway/quic-routing.state" \
            PDG_PROFILE_TOOL="$snap_qtool" bash "$snap_qhelper" preflight \
              >/dev/null 2>&1; then
      _pdg_snapshot_abort "$tmp" "$q_current_before" \
        "$captured_helper" "$captured_tool" "$txn_nftexe" \
        "$current_had_live" "snapshot QUIC profile/state/target preflight 失败"
      return $?
    fi
  fi
  if [[ "$legacy_singbox_snapshot" == 1 ]]; then
    _pdg_legacy_snapshot_mihomo_remove "$tmp" \
      || {
        _pdg_snapshot_abort "$tmp" "$q_current_before" \
          "$captured_helper" "$captured_tool" "$txn_nftexe" \
          "$current_had_live" "较新受管 Mihomo 资产删除失败"
        return $?
      }
  fi
  # Tar extraction does not delete newer optional managed files. Remove only
  # this exact Phase-3 manifest when the older snapshot did not contain them.
  # Restoring a snapshot from before the optional Web UI must not leave its newer root service,
  # authentication config or expected project files active. Disable first; remove only this exact
  # managed manifest and preserve any unexpected file in /opt/pdg-web.
  if [[ ( ! -e "$tree/etc/systemd/system/pdg-web.service" \
          || ! -e "$tree/etc/privdns-gateway/web.json" ) ]] \
     && { systemctl is-enabled pdg-web >/dev/null 2>&1 \
          || systemctl is-active pdg-web >/dev/null 2>&1; }; then
    if ! systemctl disable --now pdg-web >/dev/null 2>&1; then
      _pdg_snapshot_abort "$tmp" "$q_current_before" \
        "$captured_helper" "$captured_tool" "$txn_nftexe" \
        "$current_had_live" "无法停用快照中不存在的 pdg-web service"
      return $?
    fi
  fi
  local managed_optional=(
    etc/mosdns/rules/ruleset_direct.txt
    etc/mosdns/rules/ruleset_hijack.txt
    etc/systemd/system/pdg-quic-routing.service
    usr/local/libexec/pdg-quic-routing.sh
    etc/privdns-gateway/quic-routing.state
    opt/pdg-bot/pdgprofile.py
    etc/systemd/system/pdg-web.service
    etc/privdns-gateway/web.json
    usr/local/bin/pdg-webctl
    opt/pdg-web/pdg-web.py
    opt/pdg-web/pdg-web-job.py
    opt/pdg-web/pdgcontrol.py
    opt/pdg-web/pdg-web-setup.py
    opt/pdg-web/pdgwebconfig.py
    opt/pdg-web/static/index.html
    opt/pdg-web/static/app.js
    opt/pdg-web/static/style.css
    opt/pdg-web/static/manifest.webmanifest
    opt/pdg-web/static/icon.svg
  ) mp
  for mp in "${managed_optional[@]}"; do
    if [[ ! -e "$tree/$mp" ]]; then
      if [[ "$mp" == etc/systemd/system/pdg-quic-routing.service ]] \
         && ! systemctl disable --now pdg-quic-routing >/dev/null 2>&1; then
        _pdg_snapshot_abort "$tmp" "$q_current_before" \
          "$captured_helper" "$captured_tool" "$txn_nftexe" \
          "$current_had_live" "无法停用快照中不存在的 QUIC routing service"
        return $?
      fi
      rm -f -- "/$mp" \
        || {
          _pdg_snapshot_abort "$tmp" "$q_current_before" \
            "$captured_helper" "$captured_tool" "$txn_nftexe" \
            "$current_had_live" "无法移除快照中不存在的受管文件 /$mp"
          return $?
        }
    fi
  done
  rmdir /opt/pdg-web/static /opt/pdg-web 2>/dev/null || true
  if ! awk '$0 !~ /^etc[/]nftables[.]conf$/' "$members" >"$apply_members"; then
    _pdg_snapshot_abort "$tmp" "$q_current_before" \
      "$captured_helper" "$captured_tool" "$txn_nftexe" \
      "$current_had_live" "无法生成 snapshot tree apply manifest"
    return $?
  fi
  echo "回滚到 $(basename "$target") …"
  if [[ -s "$apply_members" ]] && ! _pdg_apply_snapshot_tree "$tree" "$apply_members" /; then
    _pdg_snapshot_abort "$tmp" "$q_current_before" \
      "$captured_helper" "$captured_tool" "$txn_nftexe" \
      "$current_had_live" "快照 tree apply 失败"
    return $?
  fi
  if [[ -f "$tree/etc/nftables.conf" ]]; then
    [[ -n "$rb_nft" ]] || rb_nft="$(_pdg_nft_bin)"
    # shellcheck source=lib/nfttxn.sh
    source "$REPO_DIR/lib/nfttxn.sh" 2>/dev/null || {
      _pdg_snapshot_abort "$tmp" "$q_current_before" \
        "$captured_helper" "$captured_tool" "$txn_nftexe" \
        "$current_had_live" "缺 nft atomic helper"
      return $?
    }
    pdg_nft_atomic_install "$tree/etc/nftables.conf" /etc/nftables.conf "$rb_nft" \
      || {
        _pdg_snapshot_abort "$tmp" "$q_current_before" \
          "$captured_helper" "$captured_tool" "$txn_nftexe" \
          "$current_had_live" "snapshot persistent nft install 失败"
        return $?
      }
    "$rb_nft" -f /etc/nftables.conf >/dev/null 2>&1 \
      || {
        _pdg_snapshot_abort "$tmp" "$q_current_before" \
          "$captured_helper" "$captured_tool" "$txn_nftexe" \
          "$current_had_live" "snapshot live nft apply 失败"
        return $?
      }
  elif [[ -f /etc/nftables.conf ]]; then
    # Snapshot predates the managed PDG table. Remove only the strictly
    # marker-validated owned block; retain every foreign/VPN/NAT table.
    rb_nft="$(_pdg_nft_bin)"
    [[ -n "$rb_nft" ]] \
      || {
        _pdg_snapshot_abort "$tmp" "$q_current_before" \
          "$captured_helper" "$captured_tool" "$txn_nftexe" \
          "$current_had_live" "找不到 nft"
        return $?
      }
    local no_pdg="$tmp/nftables.without-pdg"
    python3 "$REPO_DIR/deploy/bot/nftmerge.py" --remove \
      /etc/nftables.conf "$no_pdg" \
      || {
        _pdg_snapshot_abort "$tmp" "$q_current_before" \
          "$captured_helper" "$captured_tool" "$txn_nftexe" \
          "$current_had_live" "persistent PDG 表归属不可信"
        return $?
      }
    # shellcheck source=lib/nfttxn.sh
    source "$REPO_DIR/lib/nfttxn.sh" 2>/dev/null \
      || {
        _pdg_snapshot_abort "$tmp" "$q_current_before" \
          "$captured_helper" "$captured_tool" "$txn_nftexe" \
          "$current_had_live" "缺 nft atomic helper"
        return $?
      }
    pdg_nft_atomic_install "$no_pdg" /etc/nftables.conf "$rb_nft" \
      || {
        _pdg_snapshot_abort "$tmp" "$q_current_before" \
          "$captured_helper" "$captured_tool" "$txn_nftexe" \
          "$current_had_live" "移除受管 persistent PDG 表失败"
        return $?
      }
    if "$rb_nft" list table inet pdg >"$tmp/live-pdg.current" 2>/dev/null; then
      if ! python3 - "$tmp/live-pdg.current" "$REPO_DIR/deploy/bot" <<'PY'
import sys
sys.path.insert(0, sys.argv[2])
import nftscan
text = open(sys.argv[1], encoding="utf-8").read()
raise SystemExit(0 if nftscan.pdg_table_status(text).startswith("owned-") else 1)
PY
      then
        _pdg_snapshot_abort "$tmp" "$q_current_before" \
          "$captured_helper" "$captured_tool" "$txn_nftexe" \
          "$current_had_live" "live PDG 表归属不可信"
        return $?
      fi
      "$rb_nft" delete table inet pdg >/dev/null 2>&1 \
        || {
          _pdg_snapshot_abort "$tmp" "$q_current_before" \
            "$captured_helper" "$captured_tool" "$txn_nftexe" \
            "$current_had_live" "删除 snapshot 不存在的 live PDG 表失败"
          return $?
        }
    fi
    local live_tables=""
    live_tables="$("$rb_nft" list tables 2>/dev/null)" \
      || {
        _pdg_snapshot_abort "$tmp" "$q_current_before" \
          "$captured_helper" "$captured_tool" "$txn_nftexe" \
          "$current_had_live" "无法 read-back live table inventory"
        return $?
      }
    if grep -Eq \
        '^[[:space:]]*table[[:space:]]+inet[[:space:]]+pdg([[:space:]]|$)' \
        <<<"$live_tables"; then
      _pdg_snapshot_abort "$tmp" "$q_current_before" \
        "$captured_helper" "$captured_tool" "$txn_nftexe" \
        "$current_had_live" "live PDG 表删除后仍存在"
      return $?
    fi
  fi
  rm -rf "$tmp"
  (( panel_sanitized == 1 )) && c_g "  已净化回滚出的面板临时态 → 关闭"
  local unrestored=()                         # 未能恢复项(内核激活/仓库Git); 非空即"未完全回滚"
  # daemon-reload 失败必须计入: 后面 enable/start 全建立在它之上, 吞掉它等于谎报回滚成功。
  systemctl daemon-reload || unrestored+=("daemon-reload")
  local rb_nft_runtime; rb_nft_runtime="$(_pdg_nft_bin)"
  if [[ -f /etc/nftables.conf ]]; then
    [[ -n "$rb_nft_runtime" ]] \
      && "$rb_nft_runtime" -f /etc/nftables.conf >/dev/null 2>&1 \
      || unrestored+=("live nft apply")
  fi
  # v1.6.0: mihomo 是唯一当前内核。迁移前的 sing-box 快照只有在完整兼容迁移成功后才提交
  # backend 标记、清理旧资产并起 Mihomo；失败时旧 sing-box 恢复资产必须留在原位。
  # shellcheck source=/dev/null
  source "$REPO_DIR/lib/units.sh" 2>/dev/null || true
  if [[ "$legacy_singbox_snapshot" == 1 ]]; then
    legacy_migration_ok=0
    if _pdg_legacy_migrate_transaction; then
      legacy_migration_ok=1
      legacy_migration_committed=1
    else
      unrestored+=("旧 sing-box model → 当前单 Mihomo+QUIC 兼容迁移")
      [[ "$PDG_LEGACY_TX_RECOVERY" == ok ]] \
        || unrestored+=("旧 sing-box target 事务恢复/激活")
    fi
  elif [[ ! -f /etc/mihomo/config.yaml ]] && [[ -f /etc/sing-box/config.json ]]; then
    install -d -m700 /etc/mihomo                # 迁移前快照只有 config.json → 现渲染 mihomo 配置
    (cd /opt/pdg-bot && python3 -c 'import sys;sys.path.insert(0,"/opt/pdg-bot");import bot;bot._render_mihomo_file()') 2>/dev/null \
      || unrestored+=("mihomo配置渲染")
  fi
  if [[ "$legacy_migration_committed" == 1 ]]; then
    : # complete legacy prepare/validate/commit already owns backend/drop/activation
  elif [[ "$legacy_migration_ok" == 1 ]]; then
    printf 'mihomo\n' > /etc/privdns-gateway/backend \
      || unrestored+=("backend 标记")
    # 快照里已经带回 unit 的就别再重生成 —— 快照那份才是"回滚目标状态"的权威。
    # 只有快照没有(或空文件)时才用模板补一份, 免得回滚顺手把状态又改成了当前版本的样子。
    if [[ ! -s /etc/systemd/system/mihomo.service ]]; then
      pdg_write_unit pdg_unit_mihomo /etc/systemd/system/mihomo.service \
        || unrestored+=("mihomo.service 生成")
    fi
    # sing-box 残留只清"项目自己装的"(见 _pdg_singbox_is_ours), 第三方的原样保留
    _pdg_drop_singbox_files "快照带回的"
    systemctl daemon-reload || unrestored+=("daemon-reload(清理后)")
    local quic_restore_rc=0
    _pdg_rollback_restore_quic \
      /usr/local/libexec/pdg-quic-routing.sh "$PROFILE_ENV" \
      || quic_restore_rc=$?
    case "$quic_restore_rc" in
      0) ;;
      2) unrestored+=("QUIC routing helper缺失") ;;
      *) unrestored+=("QUIC routing恢复(enable/restart/status)") ;;
    esac
    if grep -q '^PDG_QUIC_MODE=' "$PROFILE_ENV" 2>/dev/null; then
      local dpstate=""
      dpstate="$(python3 - <<'PY'
import sys
sys.path.insert(0, "/opt/pdg-bot")
import checks
print(checks.check_dataplane_profile()[0])
PY
)" || dpstate=fail
      [[ "$dpstate" == ok ]] || unrestored+=("persistent/live nft 与 Mihomo/profile 等价性")
    fi
    # 激活失败必须计入 unrestored: 内核没起来就不是"已回滚", 不能只 warn 后照报成功。
    if ! _core_kernel_activate mihomo sing-box; then
      c_y "  mihomo 起核核验未达标, 请 pdg doctor 复查"
      unrestored+=("内核激活(mihomo)")
    fi
  else
    c_y "  旧 sing-box 快照迁移失败：保留原 backend/unit/bin/model，未尝试提交或激活 Mihomo"
  fi
  systemctl restart mosdns pdg-bot pdg-probe81 2>/dev/null || true
  systemctl is-enabled pdg-mitm >/dev/null 2>&1 && { systemctl reset-failed pdg-mitm 2>/dev/null; systemctl restart pdg-mitm 2>/dev/null; }   # iOS/WLOC: 清 start-limit + 一并恢复 MITM 服务
  if [[ -f /etc/systemd/system/pdg-web.service \
        && -f /etc/privdns-gateway/web.json ]] \
     && { systemctl is-enabled pdg-web >/dev/null 2>&1 \
          || systemctl is-active pdg-web >/dev/null 2>&1; }; then
    systemctl restart pdg-web >/dev/null 2>&1 \
      && systemctl is-active --quiet pdg-web \
      || unrestored+=("pdg-web 恢复")
  fi
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

# Restore the MosDNS binary + provenance file saved by
# _mosdns_swap_verify. Every move is followed by a SHA read-back before the
# old service is considered recovered.
_mosdns_restore_prev(){
  local bin="$1" bin_pre="$2" bin_bak="$3" bin_sha="$4"
  local attest="$5" attest_pre="$6" attest_bak="$7" attest_sha="$8"
  local failed=0
  if [[ "$bin_pre" == 1 ]]; then
    [[ -f "$bin_bak" ]] && mv -f "$bin_bak" "$bin" \
      && [[ "$(_pdg_sha "$bin")" == "$bin_sha" ]] || failed=1
  else
    rm -f "$bin" || failed=1
  fi
  if [[ "$attest_pre" == 1 ]]; then
    [[ -f "$attest_bak" ]] && mv -f "$attest_bak" "$attest" \
      && [[ "$(_pdg_sha "$attest")" == "$attest_sha" ]] || failed=1
  else
    rm -f "$attest" || failed=1
  fi
  if [[ "$bin_pre" == 1 ]]; then
    systemctl restart mosdns >/dev/null 2>&1 || failed=1
    _core_kernel_stable mosdns || failed=1
  else
    systemctl stop mosdns >/dev/null 2>&1 || true
  fi
  [[ "$failed" == 0 ]]
}

# Hot-swap a fully verified patched candidate. The outer update snapshot is a
# second safety net; this local transaction immediately restores stock/custom
# MosDNS bytes if install, attestation, restart, or stability checks fail.
_mosdns_swap_verify(){
  local newbin="$1" arch="$2" artifact_sha="$3" binary_sha="$4" channel="$5"
  local bin="${PDG_MOSDNS_BIN:-/usr/local/bin/mosdns}"
  local attest="${PDG_MOSDNS_ATTESTATION:-/etc/privdns-gateway/mosdns-build.env}"
  local bindir bin_pre=0 bin_bak="" bin_sha=""
  local attest_pre=0 attest_bak="" attest_sha="" stash
  bindir="$(dirname "$bin")"
  if [[ -e "$attest" || -L "$attest" ]]; then
    [[ -f "$attest" && ! -L "$attest" ]] \
      || { c_y "  MosDNS provenance 路径不是普通文件, 拒绝覆盖"; return 1; }
    attest_pre=1
    attest_sha="$(_pdg_sha "$attest")"; [[ -n "$attest_sha" ]] || return 1
    attest_bak="$(mktemp "$(dirname "$attest")/.mosdns-build.pdg-prev.XXXXXX")" \
      || return 1
    if ! cp -a "$attest" "$attest_bak" \
       || [[ "$(_pdg_sha "$attest_bak")" != "$attest_sha" ]]; then
      rm -f "$attest_bak"
      c_y "  备份 MosDNS provenance 失败 → 中止换版"
      return 1
    fi
  fi
  [[ -e "$bin" ]] && bin_pre=1
  if ! stash="$(_core_stash_kernel mosdns "$bindir")"; then
    rm -f "$attest_bak"
    c_y "  备份现有 MosDNS 失败 → 中止换版"
    return 1
  fi
  IFS='|' read -r bin_bak bin_sha <<<"$stash"

  if ! install -m755 "$newbin" "$bin" \
     || ! pdg_write_mosdns_attestation "$attest" "$arch" \
          "$artifact_sha" "$binary_sha" "$channel" \
     || ! pdg_mosdns_is_project_build "$bin" "$attest" "$arch"; then
    c_y "  MosDNS 候选安装/provenance 复核失败，恢复旧版"
    _mosdns_restore_prev "$bin" "$bin_pre" "$bin_bak" "$bin_sha" \
      "$attest" "$attest_pre" "$attest_bak" "$attest_sha" \
      || c_y "  ⚠️ MosDNS 旧版恢复未达标，请立即运行 pdg doctor"
    return 1
  fi
  systemctl restart mosdns >/dev/null 2>&1 || true
  if ! _core_kernel_stable mosdns; then
    c_y "  MosDNS 修补版重启后未稳定，恢复旧版"
    _mosdns_restore_prev "$bin" "$bin_pre" "$bin_bak" "$bin_sha" \
      "$attest" "$attest_pre" "$attest_bak" "$attest_sha" \
      || c_y "  ⚠️ MosDNS 旧版恢复未达标，请立即运行 pdg doctor"
    return 1
  fi
  rm -f "$bin_bak" "$attest_bak"
  c_g "  → MosDNS $MOSDNS_BUILD_VERSION 已装并稳定运行"
}

_update_mosdns_binary(){
  local arch tmp
  # shellcheck source=/dev/null
  source "$REPO_DIR/lib/versions.sh" 2>/dev/null \
    || { c_y "读不到 versions.sh, 无法确认 MosDNS 目标 flavor"; return 1; }
  # shellcheck source=/dev/null
  source "$REPO_DIR/lib/mosdns-artifact.sh" 2>/dev/null \
    || { c_y "读不到 mosdns-artifact.sh, 无法安全获取修补产物"; return 1; }
  arch="$(pdg_mosdns_arch)" || { c_y "无法识别 MosDNS 架构"; return 1; }
  pdg_mosdns_is_project_build "${PDG_MOSDNS_BIN:-/usr/local/bin/mosdns}" \
    "${PDG_MOSDNS_ATTESTATION:-/etc/privdns-gateway/mosdns-build.env}" "$arch" \
    && return 0
  tmp="$(mktemp -d)" || return 1
  c_g "更新 MosDNS → $MOSDNS_BUILD_VERSION …"
  if ! pdg_prepare_mosdns_candidate "$arch" "$tmp" \
     || ! _mosdns_swap_verify "$PDG_MOSDNS_PREPARED_BIN" "$arch" \
          "$PDG_MOSDNS_PREPARED_ARTIFACT_SHA256" \
          "$PDG_MOSDNS_PREPARED_BINARY_SHA256" \
          "$PDG_MOSDNS_PREPARED_CHANNEL"; then
    rm -rf "$tmp"
    return 1
  fi
  rm -rf "$tmp"
}

# Runs inside the newly installed pdg script during old-version -> new-version
# update, closing the gap where the updater process still has old functions in
# memory and therefore cannot know about the new MosDNS flavor requirement.
migrate_mosdns_patched_binary(){
  _update_mosdns_binary
}

cmd_update(){
  need_root update
  # --dry-run 只查看: 不装 git、不迁移、不写任何东西。任一步失败都要返回非 0 并说清是哪一步 ——
  # 以前 fetch/describe/tag 全用 `2>/dev/null` 吞掉, 拿不到就打印"最新发布: (无 tag)"再 return 0,
  # 用户会当成"已经是最新版", 实际是网络不通或仓库读不了。
  if [[ "${1:-}" == "--dry-run" ]]; then
    command -v git >/dev/null 2>&1 || { c_y "❌ 没有 git, 无法查看更新(dry-run 不安装任何东西)"; return 1; }
    [[ -d "$REPO_DIR/.git" ]] || { c_y "❌ $REPO_DIR 不是 git 仓库, 无法查看更新"; return 1; }
    local cur_desc tgt
    if ! pdg_fetch_release_tags "$REPO_DIR"; then
      c_y "❌ 拉取远端 tag 失败(网络不通 / 仓库地址无效 / 属主异常)→ 无法判断是否有新版"; return 1
    fi
    if ! cur_desc="$(git -C "$REPO_DIR" describe --tags --always 2>/dev/null)" || [[ -z "$cur_desc" ]]; then
      c_y "❌ 读不到当前版本(git describe 失败: 仓库损坏 / 无提交 / 属主异常)"; return 1
    fi
    tgt="$(git -C "$REPO_DIR" tag -l 'v*' --sort=-v:refname 2>/dev/null | head -1)"
    [[ -n "$tgt" ]] || { c_y "❌ 仓库里没有任何发布 tag(v*)→ 无法确定目标版本"; return 1; }
    echo "当前: $cur_desc   最新发布: $tgt"
    echo "待更新提交(HEAD..$tgt):"
    git -C "$REPO_DIR" log --oneline "HEAD..$tgt" 2>/dev/null || echo "  (已是最新或无法比较)"
    return 0
  fi
  command -v git >/dev/null || { apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq git; }
  _lock   # 取锁(嵌套的 cmd_snapshot 不会重复锁)
  c_g "更新前留快照…"
  if ! cmd_snapshot >/dev/null 2>&1 || [[ -z "$_PDG_SNAP_CREATED" || ! -f "$_PDG_SNAP_CREATED/snap.tar.gz" ]]; then
    c_y "❌ 更新前快照失败, 中止更新(拒绝在无法回滚的前提下继续)。"; return 1
  fi
  local snap_dir="$_PDG_SNAP_CREATED"                                    # 精确回滚目标(不靠 index 0 猜)
  local pre_sha; pre_sha="$(git -C "$REPO_DIR" rev-parse HEAD 2>/dev/null)"   # 升级前精确提交, 回滚据此复位仓库
  local web_was_enabled=0 web_was_active=0
  systemctl is-enabled pdg-web >/dev/null 2>&1 && web_was_enabled=1
  systemctl is-active pdg-web >/dev/null 2>&1 && web_was_active=1
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
  if   ! install -d -m755 /opt/pdg-web /opt/pdg-web/static \
    || ! install -m755 "$REPO_DIR"/deploy/bot/pdg-bot.py           /opt/pdg-bot/bot.py \
    || ! install -m755 "$REPO_DIR"/deploy/bot/parse-geosite.py     /opt/pdg-bot/ \
    || ! install -m755 "$REPO_DIR"/deploy/bot/update-rules.sh      /opt/pdg-bot/ \
    || ! install -m755 "$REPO_DIR"/deploy/bot/scheduled-update.sh  /opt/pdg-bot/ \
    || ! install -m755 "$REPO_DIR"/deploy/bot/healthcheck.py       /opt/pdg-bot/ \
    || ! install -m755 "$REPO_DIR"/deploy/bot/checks.py            /opt/pdg-bot/ \
    || ! install -m755 "$REPO_DIR"/deploy/bot/dot_session_probe.py /opt/pdg-bot/ \
    || ! install -m755 "$REPO_DIR"/deploy/bot/pdgtx.py             /opt/pdg-bot/ \
    || ! install -m755 "$REPO_DIR"/deploy/bot/doctor.py            /opt/pdg-bot/ \
    || ! install -m755 "$REPO_DIR"/deploy/bot/report.py           /opt/pdg-bot/ \
    || ! install -m755 "$REPO_DIR"/deploy/bot/sb2mihomo.py        /opt/pdg-bot/ \
    || ! install -m755 "$REPO_DIR"/deploy/bot/pdgprofile.py       /opt/pdg-bot/ \
    || ! install -m755 "$REPO_DIR"/deploy/bot/nftscan.py          /opt/pdg-bot/ \
    || ! install -m755 "$REPO_DIR"/deploy/bot/nftmerge.py         /opt/pdg-bot/ \
    || ! install -m755 "$REPO_DIR"/deploy/cert/proxy-gateway-open-cert-http.sh   /usr/local/bin/ \
    || ! install -m755 "$REPO_DIR"/deploy/cert/proxy-gateway-restore-firewall.sh /usr/local/bin/ \
    || ! install -m755 "$REPO_DIR"/deploy/bot/pdg-set-token.sh     /usr/local/bin/pdg-set-token \
    || ! install -m755 "$REPO_DIR"/deploy/bot/pdg.sh               /usr/local/bin/pdg \
    || ! install -m755 "$REPO_DIR"/deploy/web/pdg-web.py           /opt/pdg-web/ \
    || ! install -m755 "$REPO_DIR"/deploy/web/pdg-web-job.py       /opt/pdg-web/ \
    || ! install -m755 "$REPO_DIR"/deploy/web/pdgcontrol.py        /opt/pdg-web/ \
    || ! install -m755 "$REPO_DIR"/deploy/web/pdg-web-setup.py     /opt/pdg-web/ \
    || ! install -m644 "$REPO_DIR"/deploy/web/pdgwebconfig.py      /opt/pdg-web/ \
    || ! install -m644 "$REPO_DIR"/deploy/web/static/index.html    /opt/pdg-web/static/ \
    || ! install -m644 "$REPO_DIR"/deploy/web/static/app.js        /opt/pdg-web/static/ \
    || ! install -m644 "$REPO_DIR"/deploy/web/static/style.css     /opt/pdg-web/static/ \
    || ! install -m644 "$REPO_DIR"/deploy/web/static/manifest.webmanifest /opt/pdg-web/static/ \
    || ! install -m644 "$REPO_DIR"/deploy/web/static/icon.svg      /opt/pdg-web/static/ \
    || ! install -m755 "$REPO_DIR"/deploy/web/pdg-webctl.sh        /usr/local/bin/pdg-webctl \
    || ! install -m644 "$REPO_DIR"/deploy/web/pdg-web.service      /etc/systemd/system/pdg-web.service \
    || ! install -m755 "$REPO_DIR"/deploy/cert/99-reload-cert.deploy-hook.sh \
          /etc/letsencrypt/renewal-hooks/deploy/99-pdg-cert.sh; then
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
  # 迁移用"刚装好的新脚本"跑(本进程还是旧 bash, 直接调会用旧版函数 → 新迁移要等下次命令才生效)。
  if ! bash /usr/local/bin/pdg __migrate; then
    c_y "迁移(__migrate)失败, 回滚到更新前快照…"; cmd_rollback --dir "$snap_dir" --git "$pre_sha"; return 1
  fi
  # 二进制: MosDNS 要求精确 no-ticket flavor；mihomo 按 versions.sh 钉死版本。
  # 新版 __migrate 已处理 MosDNS(兼容旧 updater 仍在内存); 此处再做幂等硬门。
  if ! _update_mosdns_binary; then
    c_y "MosDNS 修补版更新失败, 回滚到更新前快照…"; cmd_rollback --dir "$snap_dir" --git "$pre_sha"; return 1
  fi
  if ! _update_core_binary; then
    c_y "内核二进制更新失败, 回滚到更新前快照…"; cmd_rollback --dir "$snap_dir" --git "$pre_sha"; return 1
  fi

  # ── 更新后校验门: 任一硬校验失败即回滚到更新前快照 ──
  c_g "校验新版本…"
  if ! python3 -m py_compile /opt/pdg-bot/*.py /opt/pdg-web/*.py 2>/dev/null; then
    c_y "Python 语法错误, 回滚到更新前快照…"; cmd_rollback --dir "$snap_dir" --git "$pre_sha"; return 1
  fi
  if [[ ( -e /etc/privdns-gateway/web.json \
          || -L /etc/privdns-gateway/web.json ) ]] \
     && ! python3 /opt/pdg-web/pdg-web-setup.py --validate-only >/dev/null 2>&1; then
    c_y "pdg-web 配置/TLS 校验失败, 回滚到更新前快照…"
    cmd_rollback --dir "$snap_dir" --git "$pre_sha"; return 1
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
  # Route ownership is a hard prerequisite of the Mihomo unit (Requires+After).
  # Re-apply it on every update and restart Mihomo only after exact status
  # verification, so a profile tuple change cannot leave a stale data plane.
  if ! systemctl enable --now pdg-quic-routing >/dev/null 2>&1 \
    || ! /usr/local/libexec/pdg-quic-routing.sh status >/dev/null 2>&1; then
    c_y "QUIC routing 前置单元未能应用/复核, 回滚到更新前快照…"
    cmd_rollback --dir "$snap_dir" --git "$pre_sha"; return 1
  fi
  if ! systemctl restart mihomo >/dev/null 2>&1; then
    c_y "mihomo 未能按新 data-plane 重启, 回滚…"
    cmd_rollback --dir "$snap_dir" --git "$pre_sha"; return 1
  fi
  systemctl enable --now pdg-health.timer >/dev/null 2>&1 || true   # 老装升级时补上健康自检
  systemctl restart pdg-bot pdg-probe81 2>/dev/null || true
  systemctl is-enabled pdg-mitm >/dev/null 2>&1 && { systemctl reset-failed pdg-mitm 2>/dev/null; systemctl restart pdg-mitm 2>/dev/null; }   # iOS/WLOC: 清 start-limit + 载新插件代码, 否则 doctor 判 pdg-mitm 未运行而误回滚
  # Web 是可选且默认禁用；更新绝不替用户启用。只恢复更新前已经 enabled/active 的实例。
  if [[ "$web_was_enabled" == 1 || "$web_was_active" == 1 ]]; then
    if [[ ! -f /etc/privdns-gateway/web.json ]] \
       || ! systemctl restart pdg-web >/dev/null 2>&1 \
       || ! systemctl is-active --quiet pdg-web; then
      c_y "pdg-web 更新后未能恢复运行, 回滚到更新前快照…"
      cmd_rollback --dir "$snap_dir" --git "$pre_sha"; return 1
    fi
  fi
  sleep 2

  # token 是否已配置(未配则 pdg-bot 不在跑属正常, 不据此回滚)
  # 凭据状态取 checks.bot_credentials(与 status/doctor/healthcheck 同一份判断), 不再本地
  # 各写一遍 grep。ready=两项都配 / unset=两项都空(正常禁用态) / partial=只配一半(配置错)。
  local cred token_set=0
  cred="$(_pdg_bot_cred)"
  [[ "$cred" == ready ]] && token_set=1
  if [[ "$token_set" == 1 && "$(systemctl is-active pdg-bot 2>/dev/null)" != "active" ]]; then
    c_y "pdg-bot 更新后起不来, 回滚到更新前快照…"; cmd_rollback --dir "$snap_dir" --git "$pre_sha"; return 1
  fi

  # doctor 自检门: 自检本身必须跑通且输出可信, 才有资格说"已更新"。
  # 以前 doctor 用 `|| true` 吞掉退出码, 且没有 jq 就整段跳过 —— 自检崩了/输出坏了/机器没装
  # jq, 都会直接跳到"✅ 已更新"。改用 python3 解析(本项目本来就硬依赖 python3, 不再依赖 jq),
  # 并要求输出是**非空的 JSON 数组**; 任何一环不成立都按"无法确认更新结果"回滚。
  # 不再按文案豁免任何检查项: 未配凭据时 pdg-bot 压根不在 expected_services() 里, doctor
  # 自己就不会报它 —— 靠比对 doctor 的 detail 字符串做豁免, 那句话多一个服务名
  # 或改个措辞就会失效, 属于最脆的一类耦合。
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
fails = [x for x in d if x.get("level") == "fail"]
warns = [x for x in d if x.get("level") == "warn"]
print(len(fails))
for x in fails: print("  ❌ %s: %s" % (x.get("check"), x.get("detail")))
print("@@WARN@@")
for x in warns: print("  ⚠️ %s: %s" % (x.get("check"), x.get("detail")))
' 2>/dev/null); then
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

cmd_web(){
  local ctl=/usr/local/bin/pdg-webctl
  [[ -x "$ctl" ]] || { c_y "❌ 找不到 $ctl；请先运行 sudo pdg update"; return 1; }
  "$ctl" "$@"
}

# shellcheck disable=SC2086  # $svcs 是有意按空白分词的服务名列表
# Bot 凭据状态: ready | unset | partial。判据在 checks.bot_credentials(单一来源),
# 读不到 checks 时按最保守的 unset 处理(不因为拿不到判断就去要求 pdg-bot 必须在跑)。
_pdg_bot_cred(){
  python3 -c 'import sys; sys.path.insert(0, "/opt/pdg-bot"); import checks; print(checks.bot_credentials())' \
    2>/dev/null || echo unset
}

# 重启并**确认真的起来了**。旧实现 `systemctl restart $svcs 2>/dev/null; echo 已重启` ——
# 返回值直接丢掉: mihomo 配置是空的、服务一直 activating/failed, 它照样返回 0 说"已重启",
# 用户以为好了, 实际整条链是断的。
cmd_restart(){
  need_root restart
  _lock
  local core; core="$(_pdg_core_svc)"
  local cred; cred="$(_pdg_bot_cred)"
  if ! systemctl enable --now pdg-quic-routing >/dev/null 2>&1 \
    || ! /usr/local/libexec/pdg-quic-routing.sh status >/dev/null 2>&1; then
    c_y "❌ QUIC routing 前置单元未就绪 → 没有改写配置或重启服务。"
    return 1
  fi
  # Validate the generated core candidate before touching live config.
  local rwd cand
  rwd="$(mktemp -d)" || return 1; cand="$rwd/config.yaml"
  [[ -e /etc/mihomo/config.yaml ]] && {
    : >"$rwd/had-config"
    cp -a /etc/mihomo/config.yaml "$rwd/config.before" || {
      rm -rf "$rwd"; return 1; }; }
  [[ -e /etc/nftables.conf ]] && {
    : >"$rwd/had-nft"
    cp -a /etc/nftables.conf "$rwd/nft.before" \
      && cmp -s /etc/nftables.conf "$rwd/nft.before" || {
        rm -rf "$rwd"; return 1; }; }
  [[ -e /etc/privdns-gateway/quic-routing.state ]] && {
    : >"$rwd/had-state"
    cp -a /etc/privdns-gateway/quic-routing.state "$rwd/state.before" \
      && cmp -s /etc/privdns-gateway/quic-routing.state "$rwd/state.before" || {
        rm -rf "$rwd"; return 1; }; }
  if ! _pdg_render_mihomo_candidate "$cand" \
    || ! mihomo -t -d /etc/mihomo -f "$cand" >/dev/null 2>&1; then
    rm -rf "$rwd"
    c_y "❌ profile data-plane 候选渲染/校验失败 → 未改写任何 live 配置。"
    return 1
  fi
  if ! _pdg_atomic_install_file "$cand" /etc/mihomo/config.yaml 600 \
    || ! _switchcore_nft mihomo; then
    _pdg_restart_restore_before "$rwd" \
      || c_y "⚠️ restart before-image 回滚不完整，必须运行 pdg doctor 人工复核。"
    rm -rf "$rwd"
    c_y "❌ profile data-plane 渲染/QUIC routing 复核失败 → 没有重启服务。"
    return 1
  fi
  # 1) 先校验内核配置: 配置本身不合法的话重启只会换来一个起不来的服务, 不如当场说清楚
  if command -v mihomo >/dev/null 2>&1 && [[ -f /etc/mihomo/config.yaml ]]; then
    if ! mihomo -t -d /etc/mihomo -f /etc/mihomo/config.yaml >/dev/null 2>&1; then
      c_y "❌ mihomo 配置校验(mihomo -t)未过 → 没有重启任何服务。"
      mihomo -t -d /etc/mihomo -f /etc/mihomo/config.yaml 2>&1 | tail -5 | sed 's/^/    /'
      _pdg_restart_restore_before "$rwd" \
        || c_y "⚠️ restart before-image 回滚不完整，必须运行 pdg doctor 人工复核。"
      rm -rf "$rwd"
      return 1
    fi
  fi
  # 2) 要重启哪些: 平台必需服务 + 已启用的 pdg-mitm; 未配凭据的 pdg-bot 明确跳过
  local want=() s
  for s in mosdns "$core"; do want+=("$s"); done
  [[ "$(_pdg_platform)" == ios ]] && want+=(pdg-probe81)
  if [[ "$cred" == ready ]]; then
    want+=(pdg-bot)
  elif [[ "$cred" == partial ]]; then
    c_y "⚠️ Bot 凭据只配了一项(token 与允许 id 必须成对)→ 跳过 pdg-bot; 用 pdg-set-token 补齐。"
  else
    c_y "ℹ️ Bot 凭据未配置 → pdg-bot 未启动(正常禁用态; 需要时运行 pdg-set-token)。"
  fi
  [[ -f /etc/systemd/system/pdg-mitm.service ]] \
    && systemctl is-enabled pdg-mitm >/dev/null 2>&1 && want+=(pdg-mitm)
  # 3) 重启并逐个确认"持续 active"(_core_kernel_stable 连采多次 + 比对 NRestarts)
  local bad=()
  for s in "${want[@]}"; do
    systemctl reset-failed "$s" >/dev/null 2>&1 || true
    systemctl restart "$s" >/dev/null 2>&1 || { bad+=("$s"); continue; }
  done
  for s in "${want[@]}"; do
    _core_kernel_stable "$s" || { [[ " ${bad[*]} " == *" $s "* ]] || bad+=("$s"); }
  done
  if [[ ${#bad[@]} -gt 0 ]]; then
    c_y "❌ 以下服务未能稳定运行: ${bad[*]}"
    for s in "${bad[@]}"; do
      echo "  ── $s 最近日志 ──"
      journalctl -u "$s" -n 12 --no-pager -o cat 2>/dev/null | sed 's/^/    /'
    done
    _pdg_restart_restore_before "$rwd" \
      || c_y "⚠️ restart before-image 回滚不完整，必须运行 pdg doctor 人工复核。"
    rm -rf "$rwd"
    return 1
  fi
  rm -rf "$rwd"
  c_g "✅ 已重启并确认运行: ${want[*]}"
}

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
  cur="$(_pdg_profile_get PDG_INTERNAL_CIDR 2>/dev/null)" || {
    c_y "profile 缺失/重复 PDG_INTERNAL_CIDR，拒绝从渲染产物反推后继续写。"; return 1; }
  echo "  检测到内网卡段: $det"
  echo "  当前配置:       ${cur:-未知}"
  [[ "$det" == "$cur" ]] && { c_g "✅ 与当前一致, 无需改动。"; return 0; }
  read -rp "把内网卡段 ${cur:-?} → $det 并应用(写 mosdns+nftables 并重启)? [y/N]: " yn
  [[ "$yn" == [yY] ]] || { echo "已取消, 未改动。"; return 0; }
  _lock
  # 快照必须成立, 且要记住**这一次**的目录 —— 旧写法 `cmd_snapshot || true` 把失败吞掉,
  # 后面出事再 `cmd_rollback 0` 按序号回滚, 回到的可能是上周某次无关快照(index 0 是"最新一份",
  # 而这次根本没留下快照)。宁可一个字节都不改。
  c_g "先留快照…"
  # 与 cmd_update 同口径: 用 cmd_snapshot 自己回报的 _PDG_SNAP_CREATED 记住**本次**那一份,
  # 不按 index 猜(index 0 是"最新一份", 这次没留成时它指向的是上一次的无关快照)。
  local snap_dir
  if ! cmd_snapshot >/dev/null 2>&1 || [[ -z "$_PDG_SNAP_CREATED" || ! -f "$_PDG_SNAP_CREATED/snap.tar.gz" ]]; then
    c_y "❌ 快照失败 → 未改动任何文件(拒绝在没有回退手段的前提下改内网卡段)。"; return 1
  fi
  snap_dir="$_PDG_SNAP_CREATED"
  # Exact before-images: profile/mosdns plus persistent and live nft. Capture
  # and validate every rollback input before the first write.
  local wd nft_bak nftexe livebak live_restore tables="" had_live=0
  wd="$(mktemp -d)" || { echo "❌ 无法创建临时目录"; return 1; }
  nft_bak="$wd/nftables.conf.before"
  livebak="$wd/pdg.live.before"
  live_restore="$wd/pdg.live.restore"
  if ! cp -a "$PROFILE_ENV" "$wd/profile.env" 2>/dev/null \
     || ! cmp -s "$PROFILE_ENV" "$wd/profile.env"; then
    rm -rf "$wd"; echo "❌ profile before-image 捕获失败 → 未改动任何文件。"; return 1
  fi
  if ! cp -a /etc/mosdns/config.yaml "$wd/config.yaml" 2>/dev/null \
     || ! cmp -s /etc/mosdns/config.yaml "$wd/config.yaml"; then
    rm -rf "$wd"; echo "❌ mosdns before-image 捕获失败 → 未改动任何文件。"; return 1
  fi
  if [[ -e /etc/nftables.conf || -L /etc/nftables.conf ]]; then
    if [[ ! -f /etc/nftables.conf || -L /etc/nftables.conf || ! -s /etc/nftables.conf ]] \
       || ! cp -a /etc/nftables.conf "$nft_bak" 2>/dev/null \
       || ! cmp -s /etc/nftables.conf "$nft_bak"; then
      rm -rf "$wd"; echo "❌ persistent nft before-image 捕获失败 → 未改动任何文件。"; return 1
    fi
  fi
  nftexe="$(_pdg_nft_bin)"
  [[ -n "$nftexe" && -x "$nftexe" ]] \
    || { rm -rf "$wd"; echo "❌ 找不到 nft，无法捕获 live before-image → 未改动任何文件。"; return 1; }
  if "$nftexe" list table inet pdg >"$livebak" 2>/dev/null; then
    had_live=1
    {
      printf 'table inet pdg\n'
      printf 'delete table inet pdg\n'
      cat "$livebak"
    } >"$live_restore" \
      || { rm -rf "$wd"; echo "❌ live nft before-image 构造失败 → 未改动任何文件。"; return 1; }
    "$nftexe" -c -f "$live_restore" >/dev/null 2>&1 \
      || { rm -rf "$wd"; echo "❌ live nft before-image 预检失败(nft -c) → 未改动任何文件。"; return 1; }
  else
    tables="$("$nftexe" list tables 2>/dev/null)" \
      || { rm -rf "$wd"; echo "❌ 无法确认 live nft inventory → 未改动任何文件。"; return 1; }
    if grep -Eq '^[[:space:]]*table[[:space:]]+inet[[:space:]]+pdg([[:space:]]|$)' \
         <<<"$tables"; then
      rm -rf "$wd"; echo "❌ live inet pdg 存在但无法捕获 → 未改动任何文件。"; return 1
    fi
  fi
  # shellcheck source=lib/nfttxn.sh
  source "$REPO_DIR/lib/nfttxn.sh" 2>/dev/null \
    || { rm -rf "$wd"; echo "❌ 读不到 nft transaction helper → 未改动任何文件。"; return 1; }
  local newmos="$wd/mosdns.new"
  cp -a "$wd/config.yaml" "$newmos" 2>/dev/null || { rm -rf "$wd"; echo "❌ 读不到 mosdns 配置"; return 1; }
  _dc_restore(){   # 只用本次备份还原, 不碰别的快照
    local failed=0
    if ! cp -a "$wd/profile.env" "$PROFILE_ENV" 2>/dev/null \
       || ! cmp -s "$wd/profile.env" "$PROFILE_ENV"; then failed=1; fi
    if ! cp -a "$wd/config.yaml" /etc/mosdns/config.yaml 2>/dev/null \
       || ! cmp -s "$wd/config.yaml" /etc/mosdns/config.yaml; then failed=1; fi
    _pdg_switchcore_restore_nft_before \
      "$wd" "$nft_bak" "$nftexe" "$had_live" "$live_restore" "$livebak" || failed=1
    if ! systemctl restart mosdns >/dev/null 2>&1 \
       || ! _core_kernel_stable mosdns; then failed=1; fi
    if [[ "$failed" == 0 ]]; then
      c_y "已验证恢复本次事务的 profile/mosdns/persistent+live nft before-images(快照留在 $snap_dir)。"
    else
      c_y "❌ 本次事务 before-image 回滚不完整，必须人工复核(快照留在 $snap_dir，可 sudo pdg rollback --dir $snap_dir)。"
    fi
    return "$failed"
  }
  # mosdns remains a separately owned service config; nft is never edited with
  # sed here and will be rendered from the profile after its atomic upsert.
  sed -i -E "s#(ips:[[:space:]]*\[[[:space:]]*\")[0-9./]+(\")#\1$det\2#" "$newmos"
  if ! grep -qE "ips:[[:space:]]*\[[[:space:]]*\"${det//./\\.}\"" "$newmos"; then
    rm -rf "$wd"; c_y "❌ mosdns 配置里的 ips 段未能替换(自定义形态?) → 未改动任何文件。"; return 1
  fi
  _profile_set PDG_INTERNAL_CIDR "$det" \
    && cp -a "$newmos" /etc/mosdns/config.yaml || {
    if _dc_restore; then c_y "❌ 落盘失败, 已验证还原。"
    else c_y "❌ 落盘失败，且回滚不完整，必须人工复核。"; fi
    rm -rf "$wd"; return 1; }
  if ! _switchcore_nft mihomo; then
    if _dc_restore; then c_y "❌ profile 防火墙重渲/应用失败, 已验证还原。"
    else c_y "❌ profile 防火墙重渲/应用失败，且回滚不完整，必须人工复核。"; fi
    rm -rf "$wd"; return 1
  fi
  systemctl reset-failed mosdns >/dev/null 2>&1 || true
  if ! systemctl restart mosdns || ! _core_kernel_stable mosdns; then
    if _dc_restore; then c_y "❌ mosdns 未能稳定运行, 已验证还原。近期日志:"
    else c_y "❌ mosdns 未能稳定运行，且回滚不完整，必须人工复核。近期日志:"; fi
    rm -rf "$wd"
    journalctl -u mosdns -n 12 --no-pager -o cat 2>/dev/null | sed 's/^/    /'
    return 1
  fi
  # 成功后三处复核一致: 防火墙文件 / mosdns 配置 / doctor 读到的内网段
  local dc_ok=1 seen
  [[ "$(_pdg_profile_get PDG_INTERNAL_CIDR 2>/dev/null)" == "$det" ]] \
    || { c_y "⚠️ 复核: profile 未持久化 $det"; dc_ok=0; }
  grep -qF "$det" /etc/nftables.conf || { c_y "⚠️ 复核: nftables 渲染产物里没有 $det"; dc_ok=0; }
  grep -qF "$det" /etc/mosdns/config.yaml || { c_y "⚠️ 复核: mosdns 配置里没有 $det"; dc_ok=0; }
  seen="$(python3 -c 'import sys; sys.path.insert(0,"/opt/pdg-bot"); import checks; print(checks._internal_cidr())' 2>/dev/null)"
  [[ "$seen" == "$det" ]] || { c_y "⚠️ 复核: 自检读到的内网段是「${seen:-空}」, 与 $det 不一致"; dc_ok=0; }
  if [[ "$dc_ok" != 1 ]]; then
    if _dc_restore; then c_y "❌ 应用后复核不一致，已验证还原。"
    else c_y "❌ 应用后复核不一致，且回滚不完整，必须人工复核。"; fi
    rm -rf "$wd"; return 1
  fi
  rm -rf "$wd"
  c_g "✅ 内网卡段已更新为 $det, mosdns 已重启, 防火墙/mosdns/自检三处一致。"
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
    echo " 14) Web 管理面 (默认禁用)"
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
      14) cmd_web status
          echo "  setup / enable / disable / status / password"
          read -rp "Web 操作(留空返回): " w
          [[ -z "$w" ]] || cmd_web "$w";;
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
# 老装迁移: 把仓库里的 systemd unit 重新部署到已装机器。幂等。
# cmd_update 只装 pdg-health.service/timer, 从不重装 pdg-bot / pdg-rules-update ——
# 于是老机器一直带着 `After=... sing-box.service ...`(v1.6 已无 sing-box, 依赖悬空且与实际
# 内核不符, 排障时极易误导)。
# 关键: pdg-bot.service 里有 __CERT_DIR__ 占位符, 必须沿用**装机时那个证书目录**(从现有 unit
# 里读回来), 直接拿模板覆盖会把占位符原样写进去, bot 就读不到证书了。
# 只更新**已经存在**的 unit(没装过就不该凭空造), 内容没变则不写也不 reload。
migrate_deploy_units(){
  [[ -d "$REPO_DIR/deploy/bot" ]] || return 0
  local changed=0 u src cur tmp certdir
  for u in pdg-bot pdg-rules-update; do
    src="$REPO_DIR/deploy/bot/$u.service"
    cur="/etc/systemd/system/$u.service"
    [[ -f "$src" && -f "$cur" ]] || continue
    tmp="$(mktemp)" || continue
    if [[ "$u" == pdg-bot ]]; then
      # 从现有 unit 取回证书目录(Environment=PDG_CERT=<dir>/fullchain.pem), 取不到用装机默认值
      certdir="$(sed -n 's#^Environment=PDG_CERT=\(.*\)/fullchain\.pem[[:space:]]*$#\1#p' "$cur" | head -1)"
      certdir="${certdir:-/etc/mosdns/certs}"
      sed -e "s|__CERT_DIR__|$certdir|g" "$src" > "$tmp"
    else
      cp -f "$src" "$tmp"
    fi
    if [[ -s "$tmp" ]] && ! cmp -s "$tmp" "$cur"; then
      if install -m644 "$tmp" "$cur" 2>/dev/null; then
        changed=1; c_g "  更新 systemd unit: $u.service"
      else
        c_y "  更新 $u.service 失败(保留原文件)"
      fi
    fi
    rm -f "$tmp"
  done
  [[ "$changed" == 1 ]] && systemctl daemon-reload 2>/dev/null
  return 0
}

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
# iOS GMS 残留清理 —— **CLI 侧的精确事务**(不复用 Python pdgtx: 这里已经在 pdg.sh 的 _lock
# 里, 再让 pdgtx 去抢同一把 flock 会自锁; 而"释放锁/跳过锁/信任调用方已锁"三种绕法都会把并发
# 保护弄没)。它按事务的规矩来: 候选先行 → 全部校验通过才落盘 → 固定顺序应用 → 任一步失败按
# before-image 完整回滚并复核 → 结果如实传播(非 0)。三个目标: canonical model、渲染出的内核
# 配置、nftables 配置(含运行态)。
migrate_ios_gms_cleanup(){
  [[ "$(_pdg_platform)" == ios ]] || return 0
  local sb="${1:-/etc/sing-box/config.json}" nf="${2:-/etc/nftables.conf}"
  # 内核配置 / 工作目录根 / bot 模块位置都可用 env 覆盖 —— 生产是默认值, 沙箱用例据此在
  # 临时树里跑真实现(不打桩被测逻辑)。
  local mh="${PDG_MIHOMO_CFG:-/etc/mihomo/config.yaml}"
  local statedir="${PDG_STATE_DIR:-/var/lib/privdns-gateway}"
  local botpy="${PDG_BOT_PY:-/opt/pdg-bot/bot.py}"
  # nft 位置用项目统一判据(_pdg_nft_bin): `command -v nft` 只看 PATH, 而 nft 常在 /usr/sbin ——
  # PATH 里没有 sbin 时会"跳过校验与应用却照样写配置并报成功", 那正是要避免的。
  local nftexe; nftexe="$(_pdg_nft_bin)"
  local need_sb=0 need_nf=0
  [[ -f "$sb" ]] && grep -q '"in-gms-5228"' "$sb" && need_sb=1
  [[ -f "$nf" ]] && grep -qE 'tcp dport [{][^}]*5228' "$nf" && need_nf=1
  # 幂等: 没有残留就一个字节都不改、一个服务都不重启
  [[ "$need_sb" == 1 || "$need_nf" == 1 ]] || return 0

  # 工作目录放 /var/lib(0700), 不放 /tmp —— before-image 里的 model 带出口凭据
  local wd rc=0 applied=() step=""
  mkdir -p "$statedir" 2>/dev/null
  wd="$(mktemp -d "$statedir/iosgms.XXXXXX" 2>/dev/null)" || {
    c_y "  iOS GMS 清理: 建不出工作目录 → 跳过本次(未改动任何文件)"; return 1; }
  chmod 700 "$wd"

  # ── 1) before-image: 逐个文件记"原本存在/不存在 + 权限", 内容留在 0600 的副本里 ──
  # ① 形态守卫: 事务目标必须是**受控普通文件**。软链会让 `cp -a` 把链接原样搬进候选目录,
  #    随后的 chmod / python 写入 / sed -i 就直接改到现网(甚至改到链接指向的别处), 而 before-image
  #    也不再是真正的旧内容; 硬链接则会让"只改这一个文件"波及另一个名字。
  #    这一步必须在任何 cp / chmod / stat / python / sed 之前完成, 拒绝时现网、链接目标、权限
  #    与服务状态都还没被碰过。
  local f name g
  for g in "$sb:config.json" "$mh:config.yaml" "$nf:nftables.conf"; do
    f="${g%%:*}"
    if [[ -L "$f" ]]; then
      c_y "  iOS GMS 清理: $f 是符号链接, 事务目标只接受普通文件 → 未改动任何文件"
      rm -rf "$wd"; return 1
    fi
    [[ -e "$f" ]] || continue                     # 不存在: absent 语义, 下面照旧
    if [[ ! -f "$f" ]]; then
      c_y "  iOS GMS 清理: $f 不是普通文件 → 未改动任何文件"; rm -rf "$wd"; return 1
    fi
    local _nl; _nl="$(stat -c '%h' "$f" 2>/dev/null)"
    if [[ -z "$_nl" ]]; then
      c_y "  iOS GMS 清理: 取不到 $f 的 stat 信息 → 未改动任何文件"; rm -rf "$wd"; return 1
    fi
    if [[ "$_nl" != 1 ]]; then
      c_y "  iOS GMS 清理: $f 是硬链接(nlink=$_nl), 改它会波及另一个名字 → 未改动任何文件"
      rm -rf "$wd"; return 1
    fi
  done
  # ② before-image: 逻辑名固定为 config.json / config.yaml / nftables.conf —— 与落盘、回滚共用
  #    同一套键名(用 basename 当键会在路径被 env 换过时对不上)。**内容用读写复制**而不是 cp -a,
  #    这样材料一定是工作目录里的独立普通文件。mode/uid/gid 取不到就拒(不许猜 600 / 0:0 —— 那会
  #    在成功提交时悄悄改掉属主)。
  for g in "$sb:config.json" "$mh:config.yaml" "$nf:nftables.conf"; do
    f="${g%%:*}"; name="${g##*:}"
    if [[ -f "$f" ]]; then
      local _m _o
      _m="$(stat -c '%a' "$f" 2>/dev/null)"; _o="$(stat -c '%u:%g' "$f" 2>/dev/null)"
      if [[ -z "$_m" || -z "$_o" ]]; then
        c_y "  iOS GMS 清理: 取不到 $name 的权限/归属 → 未改动任何文件"; rm -rf "$wd"; return 1
      fi
      ( umask 177; cat "$f" > "$wd/before-$name" ) 2>/dev/null \
        || { c_y "  iOS GMS 清理: 存 before-image 失败($name) → 未改动任何文件"; rm -rf "$wd"; return 1; }
      chmod 600 "$wd/before-$name"
      printf '%s\n' "$_m" > "$wd/mode-$name"
      printf '%s\n' "$_o" > "$wd/own-$name"
      echo 1 > "$wd/existed-$name"
    else
      echo 0 > "$wd/existed-$name"
    fi
  done

  # ── 2) 候选: 全部在工作目录里生成, 生产文件此刻一个字节都没动 ──
  if [[ "$need_sb" == 1 ]]; then
    ( umask 177; cat "$sb" > "$wd/cand-config.json" ) 2>/dev/null \
      && chmod 600 "$wd/cand-config.json" || rc=1
    if [[ $rc == 0 ]] && ! python3 - "$wd/cand-config.json" <<'PY'
import json, sys
f = sys.argv[1]
c = json.load(open(f))
c["inbounds"] = [i for i in c.get("inbounds", [])
                 if i.get("tag") not in ("in-gms-5228", "in-gms-5229", "in-gms-5230")]
with open(f, "w") as fh:
    json.dump(c, fh, ensure_ascii=False, indent=2)
PY
    then rc=1; fi
    [[ $rc == 0 ]] || { c_y "  iOS GMS 清理: 生成候选 model 失败 → 未改动任何文件"; rm -rf "$wd"; return 1; }
    # 候选 mihomo 配置: 从**候选 model** 渲染(不写生产文件), 顺带用与 Bot 相同的判据拦
    # unknown_proxies / dropped —— 那两类是"静默丢出口/丢分流", 必须在落盘前拒。
    if ! PDG_BOT_PY="$botpy" python3 - "$wd/cand-config.json" "$wd/cand-mihomo.yaml" <<'PY' 2>"$wd/render.err"
import importlib.util, json, os, sys
spec = importlib.util.spec_from_file_location("bot", os.environ["PDG_BOT_PY"])
bot = importlib.util.module_from_spec(spec); spec.loader.exec_module(bot)
data = open(sys.argv[1], "rb").read()
out = bot._mihomo_derive({"model": data})       # dropped / 无法转换的出口在这里被拒
open(sys.argv[2], "wb").write(out)
PY
    then
      c_y "  iOS GMS 清理: 候选内核配置渲染/校验未过 → 未改动任何文件"
      sed -n '$p' "$wd/render.err" 2>/dev/null | sed 's/^/    /'
      rm -rf "$wd"; return 1
    fi
    chmod 600 "$wd/cand-mihomo.yaml"
    if command -v mihomo >/dev/null 2>&1; then
      if ! mihomo -t -d /etc/mihomo -f "$wd/cand-mihomo.yaml" >/dev/null 2>&1; then
        c_y "  iOS GMS 清理: 候选内核配置 mihomo -t 未过 → 未改动任何文件"; rm -rf "$wd"; return 1
      fi
    fi
  fi
  if [[ "$need_nf" == 1 ]]; then
    # 这一步要改防火墙 → 没有可用的 nft 就**不许往下走**(以前会静默跳过校验与应用)
    if [[ -z "$nftexe" || ! -x "$nftexe" ]]; then
      c_y "  iOS GMS 清理: 找不到可执行的 nft, 无法校验/应用防火墙 → 未改动任何文件"
      rm -rf "$wd"; return 1
    fi
    # 旧配置文件必须在: 回滚运行态要靠"用旧配置再 nft -f 一次"。不在就别开始改运行态。
    if [[ ! -f "$nf" ]]; then
      c_y "  iOS GMS 清理: $nf 不存在, 无法保证运行态可回滚 → 未改动任何文件"
      rm -rf "$wd"; return 1
    fi
    ( umask 177; cat "$nf" > "$wd/cand-nftables.conf" ) 2>/dev/null \
      || { c_y "  iOS GMS 清理: 复制 nft 配置失败 → 未改动任何文件"; rm -rf "$wd"; return 1; }
    _pdg_nft_strip_gms "$wd/cand-nftables.conf"
    if grep -qE 'tcp dport [{][^}]*5228' "$wd/cand-nftables.conf"; then
      # 剥完还在 = 自定义形态, 不猜也不动(交 doctor warn), 但这不是失败
      c_y "  防火墙 5228-5230 非原装形态, 未自动改(交 doctor)"; need_nf=0
    elif ! "$nftexe" -c -f "$wd/cand-nftables.conf" >/dev/null 2>&1; then
      c_y "  iOS GMS 清理: 候选防火墙 nft -c 未过 → 未改动任何文件"; rm -rf "$wd"; return 1
    fi
  fi
  [[ "$need_sb" == 1 || "$need_nf" == 1 ]] || { rm -rf "$wd"; return 0; }

  # ── 3) 回滚: 逐文件按 before-image 还原 + 复核 SHA + nft 运行态 + 内核稳定 ──
  _iosgms_restore(){
    local bad=() g name src
    for g in "$sb:config.json" "$mh:config.yaml" "$nf:nftables.conf"; do
      f="${g%%:*}"; name="${g##*:}"
      [[ " ${applied[*]} " == *" $name "* ]] || continue
      if [[ "$(cat "$wd/existed-$name" 2>/dev/null)" == 1 ]]; then
        local want_mode want_own
        want_mode="$(cat "$wd/mode-$name")"; want_own="$(cat "$wd/own-$name" 2>/dev/null || echo 0:0)"
        install -m "$want_mode" "$wd/before-$name" "$f" 2>/dev/null || bad+=("$name 写回失败")
        # 回滚阶段允许尽力执行(非 root 环境 chown 必失败), 但**最终以下面的逐项复核为准** ——
        # 复核不过就是 rollback incomplete, 不存在"chown 失败却算还原成功"。
        chown "$want_own" "$f" 2>/dev/null || true
        cmp -s "$wd/before-$name" "$f" || bad+=("$name 内容未还原")
        [[ "$(stat -c '%a' "$f" 2>/dev/null)" == "$want_mode" ]] || bad+=("$name 权限未还原")
        [[ "$(stat -c '%u:%g' "$f" 2>/dev/null)" == "$want_own" ]] || bad+=("$name 归属未还原")
      else
        # 原本不存在的必须回到"不存在", 不许留下我们造出来的文件
        rm -f "$f" 2>/dev/null
        [[ -e "$f" ]] && bad+=("$name 本应不存在却还在")
      fi
    done
    # 只要 apply **被尝试过**就必须重放旧配置: 磁盘文件在上面已经还原, 这里用它把内核里的
    # 规则也拉回操作前, 并检查返回码 —— 第二次也失败就必须如实说"回滚不完整"。
    if [[ " ${applied[*]} " == *" nft-apply "* ]]; then
      if [[ -z "$nftexe" || ! -x "$nftexe" ]]; then
        bad+=("找不到 nft, 无法确认防火墙运行态已还原")
      elif ! "$nftexe" -f "$nf" >/dev/null 2>&1; then
        bad+=("nft 运行态未还原(用旧配置重新加载失败)")
      fi
    fi
    if [[ " ${applied[*]} " == *" core-restart "* ]]; then
      systemctl restart "$(_pdg_core_svc)" >/dev/null 2>&1 || bad+=("内核重启失败")
      _core_kernel_stable "$(_pdg_core_svc)" >/dev/null 2>&1 || bad+=("内核未稳定运行")
    fi
    if [[ ${#bad[@]} -gt 0 ]]; then
      c_r "  ⚠️ iOS GMS 清理失败, 而且**回滚不完整**: ${bad[*]}"
      c_y "     回滚材料保留在 $wd —— 请据此人工修复(内含恢复前的原文件)"
      return 1
    fi
    c_y "  已回滚: model / 内核配置 / 防火墙 均还原到清理前, 内核稳定运行。"
    rm -rf "$wd"; return 0
  }

  # ── 4) 落盘: 固定顺序 + 同目录临时文件 + 原子替换(绝不截断生产文件后再写) ──
  _iosgms_put(){  # $1=候选 $2=目标 $3=记账名
    # 原本存在的目标: 临时文件在 mv **之前**就设成原 mode/uid/gid —— 以 root 跑时, 只保 mode
    # 会把非 root:root 的文件悄悄换成 root:root。chmod/chown 任一步失败就不许覆盖生产。
    # 原本不存在的: 用该目标的明确默认 mode, owner 就是当前执行用户(生产由 need_root 保证是
    # root), 不伪造"恢复旧 owner"。
    local d t want_mode want_own
    d="$(dirname "$2")"; t="$d/.pdg-iosgms.$$"
    if [[ "$(cat "$wd/existed-$3" 2>/dev/null)" == 1 ]]; then
      want_mode="$(cat "$wd/mode-$3")"; want_own="$(cat "$wd/own-$3")"
    else
      case "$3" in nftables.conf) want_mode=644;; *) want_mode=600;; esac
      want_own="$(id -u):$(id -g)"
    fi
    cp -f "$1" "$t" 2>/dev/null || { rm -f "$t"; return 1; }
    chmod "$want_mode" "$t" 2>/dev/null || { rm -f "$t"; return 1; }
    chown "$want_own" "$t" 2>/dev/null || { rm -f "$t"; return 1; }
    mv -f "$t" "$2" 2>/dev/null || { rm -f "$t"; return 1; }
    applied+=("$3")
    # 落盘后复核: 内容 + 权限 + 归属都必须是期望值(不复核就等于"写了就算成功")
    cmp -s "$1" "$2" || return 1
    [[ "$(stat -c '%a' "$2" 2>/dev/null)" == "$want_mode" ]] || return 1
    [[ "$(stat -c '%u:%g' "$2" 2>/dev/null)" == "$want_own" ]] || return 1
    return 0
  }
  if [[ "$need_sb" == 1 ]]; then
    step="model";        _iosgms_put "$wd/cand-config.json"    "$sb" config.json  || rc=1
    [[ $rc == 0 ]] && { step="内核配置"; _iosgms_put "$wd/cand-mihomo.yaml" "$mh" config.yaml || rc=1; }
  fi
  if [[ $rc == 0 && "$need_nf" == 1 ]]; then
    step="防火墙配置"; _iosgms_put "$wd/cand-nftables.conf" "$nf" nftables.conf || rc=1
    if [[ $rc == 0 ]]; then
      # **先记账再执行**: nft -f 可能改了一部分内核状态之后才返回非 0, 那时运行态已经不是
      # 操作前的样子了 —— 只在成功后记账会让回滚只还原磁盘文件, 内核里留着半套规则。
      step="nft apply"; applied+=("nft-apply")
      "$nftexe" -f "$nf" >/dev/null 2>&1 || rc=1
    fi
  fi
  if [[ $rc == 0 && "$need_sb" == 1 ]]; then
    step="重启内核"
    systemctl reset-failed "$(_pdg_core_svc)" >/dev/null 2>&1
    if systemctl restart "$(_pdg_core_svc)" >/dev/null 2>&1; then
      applied+=("core-restart")
      _core_kernel_stable "$(_pdg_core_svc)" >/dev/null 2>&1 || { step="内核稳定观察"; rc=1; }
    else
      applied+=("core-restart"); rc=1
    fi
  fi
  if [[ $rc != 0 ]]; then
    c_y "  iOS GMS 清理在「$step」失败 → 回滚"
    _iosgms_restore || return 1
    return 1
  fi
  [[ "$need_sb" == 1 ]] && c_g "  iOS: 已移除 GMS 入站(in-gms-5228/5229/5230)并同步内核配置。"
  [[ "$need_nf" == 1 ]] && c_g "  iOS: 已从防火墙端口集移除 GMS 5228-5230(保留 80/443 redirect)。"
  rm -rf "$wd"
  return 0
}

# 把旧默认 direct-type 锚点 jp 精确迁移为 JP。与 iOS GMS 清理相同，这里已由 pdg.sh
# 持有整机写锁，不能再调用会抢同一把 flock 的 pdgtx；因此在锁内执行候选先行的三文件
# 小事务：canonical model + rulesets 元数据（若存在）+ 派生 Mihomo 配置。任一步失败均按
# before-image 原子恢复并重新启动内核；自定义 direct tag 不猜测、不改写。
migrate_default_direct_tag(){
  local sb="${PDG_SB_MODEL:-/etc/sing-box/config.json}"
  local mh="${PDG_MIHOMO_CFG:-/etc/mihomo/config.yaml}"
  local rs="${PDG_RS_META:-/opt/pdg-bot/rulesets.json}"
  local statedir="${PDG_STATE_DIR:-/var/lib/privdns-gateway}"
  local botpy="${PDG_BOT_PY:-/opt/pdg-bot/bot.py}"
  [[ -f "$sb" && -f "$botpy" ]] || return 0

  local probe
  if ! probe="$(python3 - "$botpy" "$sb" "$rs" <<'PY'
import importlib.util
import json
import os
import sys
from pathlib import Path

spec = importlib.util.spec_from_file_location("pdg_bot_direct_probe", sys.argv[1])
sys.path.insert(0, str(Path(sys.argv[1]).resolve().parent))
bot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bot)
cfg = json.load(open(sys.argv[2], encoding="utf-8"))
model_changed = bot._normalize_default_direct_tag(cfg)
meta_changed = False
if bot._direct_anchor_tag(cfg) == bot.DEFAULT_DIRECT_TAG and os.path.isfile(sys.argv[3]):
    meta = json.load(open(sys.argv[3], encoding="utf-8"))
    if not isinstance(meta, dict):
        raise SystemExit("rulesets metadata top level is not an object")
    meta_changed = bot._normalize_default_direct_meta(meta)
print("migrate" if model_changed or meta_changed else "unchanged")
PY
  )"; then
    c_y "  direct 锚点 jp→JP 前置检查失败，未改动任何文件"
    return 1
  fi
  [[ "$probe" == migrate ]] || return 0

  local wd="" rc=0 step="" core_restarted=0
  local applied=() g target name
  mkdir -p "$statedir" 2>/dev/null || return 1
  wd="$(mktemp -d "$statedir/directtag.XXXXXX" 2>/dev/null)" || {
    c_y "  direct 锚点 jp→JP: 无法创建事务目录，未改动任何文件"; return 1; }
  chmod 700 "$wd"

  # 三个事务目标只接受单链接普通文件；metadata 可以原本不存在。
  for g in "$sb:model" "$mh:mihomo" "$rs:meta"; do
    target="${g%%:*}"; name="${g##*:}"
    if [[ -L "$target" || ( -e "$target" && ! -f "$target" ) ]]; then
      c_y "  direct 锚点 jp→JP: $target 不是受控普通文件，未改动任何文件"
      rm -rf "$wd"; return 1
    fi
    [[ -e "$target" ]] || { echo 0 >"$wd/existed-$name"; continue; }
    [[ "$(stat -c '%h' "$target" 2>/dev/null)" == 1 ]] || {
      c_y "  direct 锚点 jp→JP: $target 是硬链接或无法读取 stat，未改动任何文件"
      rm -rf "$wd"; return 1; }
    echo 1 >"$wd/existed-$name"
    cp --preserve=mode,ownership "$target" "$wd/before-$name" 2>/dev/null \
      && cmp -s "$target" "$wd/before-$name" || {
        c_y "  direct 锚点 jp→JP: 保存 $name before-image 失败，未改动任何文件"
        rm -rf "$wd"; return 1; }
  done
  [[ "$(cat "$wd/existed-model")" == 1 && "$(cat "$wd/existed-mihomo")" == 1 ]] || {
    c_y "  direct 锚点 jp→JP: model 或 Mihomo 配置缺失，未改动任何文件"
    rm -rf "$wd"; return 1; }

  # 从 before-image 生成全部候选；Mihomo 必须按候选 metadata 渲染，不能偷读旧引用。
  if ! python3 - "$botpy" "$wd/before-model" "$wd/before-meta" \
      "$wd/candidate-model" "$wd/candidate-meta" "$wd/candidate-mihomo" \
      "$(cat "$wd/existed-meta")" <<'PY'
import importlib.util
import json
import sys
from pathlib import Path

botpy, model_in, meta_in, model_out, meta_out, mihomo_out, meta_exists = sys.argv[1:]
sys.path.insert(0, str(Path(botpy).resolve().parent))
spec = importlib.util.spec_from_file_location("pdg_bot_direct_migrate", botpy)
bot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bot)

cfg = json.load(open(model_in, encoding="utf-8"))
model_changed = bot._normalize_default_direct_tag(cfg)
if not model_changed and bot._direct_anchor_tag(cfg) != bot.DEFAULT_DIRECT_TAG:
    raise SystemExit("candidate no longer contains a recognized default direct anchor")
model_data = bot._model_bytes(cfg)
staged = {"model": model_data}
meta_changed = False
if meta_exists == "1":
    meta = json.load(open(meta_in, encoding="utf-8"))
    if not isinstance(meta, dict):
        raise SystemExit("rulesets metadata top level is not an object")
    meta_changed = bot._normalize_default_direct_meta(meta)
    meta_data = json.dumps(meta, ensure_ascii=False, indent=2).encode("utf-8")
    staged["rs_meta"] = meta_data
    open(meta_out, "wb").write(meta_data)
if not model_changed and not meta_changed:
    raise SystemExit("candidate contains no legacy direct references")
open(model_out, "wb").write(model_data)
open(mihomo_out, "wb").write(bot._mihomo_derive(staged))
PY
  then
    c_y "  direct 锚点 jp→JP: 候选生成或无损转换检查失败，未改动任何文件"
    rm -rf "$wd"; return 1
  fi
  chmod 600 "$wd"/candidate-model "$wd"/candidate-mihomo
  [[ "$(cat "$wd/existed-meta")" != 1 ]] || chmod 600 "$wd/candidate-meta"
  if command -v mihomo >/dev/null 2>&1 \
     && ! mihomo -t -d /etc/mihomo -f "$wd/candidate-mihomo" >/dev/null 2>&1; then
    c_y "  direct 锚点 jp→JP: 候选 Mihomo 配置校验失败，未改动任何文件"
    rm -rf "$wd"; return 1
  fi

  _directtag_restore(){
    local bad=() item path before
    for item in model meta mihomo; do
      [[ " ${applied[*]} " == *" $item "* ]] || continue
      case "$item" in
        model) path="$sb";; meta) path="$rs";; mihomo) path="$mh";;
      esac
      before="$wd/before-$item"
      if [[ "$(cat "$wd/existed-$item" 2>/dev/null)" == 1 ]]; then
        _pdg_atomic_restore_file "$before" "$path" 2>/dev/null \
          && cmp -s "$before" "$path" || bad+=("$item 未还原")
      else
        rm -f "$path" 2>/dev/null
        [[ ! -e "$path" ]] || bad+=("$item 本应不存在")
      fi
    done
    if [[ "$core_restarted" == 1 ]]; then
      systemctl restart "$(_pdg_core_svc)" >/dev/null 2>&1 \
        && _core_kernel_stable "$(_pdg_core_svc)" >/dev/null 2>&1 \
        || bad+=("Mihomo 未恢复稳定运行")
    fi
    if [[ ${#bad[@]} -ne 0 ]]; then
      c_y "  ⚠️ direct 锚点迁移回滚不完整: ${bad[*]}"
      c_y "     before-image 保留在 $wd"
      return 1
    fi
    rm -rf "$wd"
    return 0
  }

  _directtag_put(){
    local candidate="$1" path="$2" item="$3"
    # 候选继承目标原 mode/owner，再走同目录原子替换。
    chmod --reference="$wd/before-$item" "$candidate" 2>/dev/null \
      && chown --reference="$wd/before-$item" "$candidate" 2>/dev/null || return 1
    # 原子替换可能已完成、却在目录 fsync 时返回失败；先记账，任何失败都按 before-image 回滚。
    applied+=("$item")
    _pdg_atomic_restore_file "$candidate" "$path" 2>/dev/null || return 1
    cmp -s "$candidate" "$path"
  }

  step=model
  _directtag_put "$wd/candidate-model" "$sb" model || rc=1
  if [[ $rc == 0 && "$(cat "$wd/existed-meta")" == 1 ]]; then
    step=metadata
    _directtag_put "$wd/candidate-meta" "$rs" meta || rc=1
  fi
  if [[ $rc == 0 ]]; then
    step="Mihomo 配置"
    _directtag_put "$wd/candidate-mihomo" "$mh" mihomo || rc=1
  fi
  if [[ $rc == 0 ]]; then
    step="Mihomo 重启"
    core_restarted=1
    systemctl reset-failed "$(_pdg_core_svc)" >/dev/null 2>&1 || true
    systemctl restart "$(_pdg_core_svc)" >/dev/null 2>&1 \
      && _core_kernel_stable "$(_pdg_core_svc)" >/dev/null 2>&1 || rc=1
  fi
  if [[ $rc != 0 ]]; then
    c_y "  direct 锚点 jp→JP 在「$step」失败，开始回滚"
    _directtag_restore || return 1
    return 1
  fi

  rm -rf "$wd"
  c_g "  默认 direct 锚点及全部引用已迁移: jp → JP"
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

# 规则集 target=direct 的 MosDNS 接口：独立 ruleset_direct 聚合并入 geosite_cn，同时让显式
# custom_hijack 单域名覆盖在 CN/宽泛 direct 规则集之前进入 fake/SNI 序列。只改本项目标准
# 形态；自定义配置不猜。配置备份、文件创建、重启核验与失败还原在本函数内闭合。
migrate_ruleset_phone_direct(){
  local mc=/etc/mosdns/config.yaml
  local agg=/etc/mosdns/rules/ruleset_direct.txt
  local hijagg=/etc/mosdns/rules/ruleset_hijack.txt
  local state_root=/var/lib/privdns-gateway/migrations
  local journal="$state_root/ruleset-dns-v1"
  local preparing="$state_root/.ruleset-dns-v1.preparing"
  local work="" config_ready=0 agg_pre=0 hijagg_pre=0 mc_mode=""
  [[ -e "$mc" || -L "$mc" ]] || return 0
  [[ -f "$mc" && ! -L "$mc" ]] \
    || { c_y "  ⛔ [规则集手机直连] MosDNS 配置不是普通文件，拒绝迁移。"; return 1; }
  mc_mode="$(stat -c '%a' "$mc" 2>/dev/null)"
  [[ "$mc_mode" =~ ^[0-7]{3,4}$ ]] \
    || { c_y "  ⛔ [规则集手机直连] 无法读取 MosDNS 配置权限。"; return 1; }
  install -d -o root -g root -m700 "$state_root" \
    || { c_y "  ⛔ [规则集手机直连] 无法建立 root-only 迁移状态目录。"; return 1; }
  if [[ -e "$journal" || -L "$journal" ]]; then
    c_y "  [规则集手机直连] 检测到未完成提交，先按持久 before-image 恢复。"
    _pdg_recover_ruleset_migration_journal \
      "$journal" "$mc" "$agg" "$hijagg" \
      || { c_y "  ⛔ [规则集手机直连] 未完成提交恢复失败，拒绝继续。"; return 1; }
  fi
  # preparing 尚未发布为 journal 时绝不会开始改 live 文件；中断后可验证并丢弃。
  if [[ -e "$preparing" || -L "$preparing" ]]; then
    _pdg_sync_ruleset_migration_path "$preparing" \
      && rm -rf -- "$preparing" \
      && _pdg_sync_parent_dir "$preparing" \
      || { c_y "  ⛔ [规则集手机直连] 遗留准备目录不可信，拒绝继续。"; return 1; }
  fi
  # 已有新版接口也不能直接返回：早期迁移可能只创建了空聚合，必须从当前 metadata/source
  # 重新派生，才不会让现有代理规则集在 DNS 阶段被宽泛 CN 规则提前放行。
  if _pdg_ruleset_direct_interface_ready_file "$mc"; then
    config_ready=1
  else
    grep -q 'tag: internal_sequence' "$mc" \
      && grep -q 'tag: geosite_cn' "$mc" \
      && grep -q 'tag: force_hijack_seq' "$mc" \
      || { c_y "  [规则集手机直连] MosDNS 是自定义形态，未猜测改写；target=direct 会拒绝直到接口就绪。"; return 0; }
  fi
  if [[ -L "$agg" || ( -e "$agg" && ! -f "$agg" ) ]]; then
    c_y "  ⛔ [规则集手机直连] 聚合目标不是普通文件，拒绝迁移。"; return 1
  fi
  if [[ -L "$hijagg" || ( -e "$hijagg" && ! -f "$hijagg" ) ]]; then
    c_y "  ⛔ [规则集劫持] 聚合目标不是普通文件，拒绝迁移。"; return 1
  fi
  [[ -f "$agg" ]] && agg_pre=1
  [[ -f "$hijagg" ]] && hijagg_pre=1
  install -d -o root -g root -m700 "$preparing" \
    || { c_y "  [规则集手机直连] 无法创建持久迁移工作目录，未改动。"; return 1; }
  work="$preparing"
  if ! _pdg_capture_ruleset_migration_before \
         "$work" "$mc" "$agg" "$hijagg" "$agg_pre" "$hijagg_pre" \
     || ! cp -a "$work/config.before" "$work/config.candidate" 2>/dev/null \
     || ! cmp -s "$work/config.before" "$work/config.candidate"; then
    c_y "  [规则集手机直连] 三文件 before-image 捕获失败，未改动。"
    rm -rf -- "$work"; return 1
  fi
  if [[ "$agg_pre" != 1 ]]; then
    install -o root -g root -m600 /dev/null "$work/direct.absent" \
      || { rm -rf -- "$work"; return 1; }
  fi
  if [[ "$hijagg_pre" != 1 ]]; then
    install -o root -g root -m600 /dev/null "$work/hijack.absent" \
      || { rm -rf -- "$work"; return 1; }
  fi
  if [[ "$config_ready" != 1 ]] \
     && ! python3 - "$work/config.candidate" "$agg" "$hijagg" <<'RSDIRECTPY'
import os
import re
import stat
import sys
import tempfile

mc, agg, hijagg = sys.argv[1:]
s = open(mc, encoding="utf-8").read()

def ensure_domain_set_file(text, tag, path):
    pattern = re.compile(
        r"(?m)(^  - tag:\s*" + re.escape(tag)
        + r"\s*$\n(?:(?!^  - tag:)[\s\S])*?"
        + r"^[ \t]*args:\s*\{\s*files:\s*\[)([^\]]*)(\])"
    )
    matches = list(pattern.finditer(text))
    if len(matches) != 1:
        raise SystemExit(tag + " shape unknown")
    match = matches[0]
    # `# "...path..."` 是注释，不是 files 元素；若注释出现在同一行，重写时一并去掉。
    files = match.group(2).split("#", 1)[0].rstrip()
    loaded = path in re.findall(r'"([^"\r\n]+)"', files)
    if loaded:
        return text
    separator = "," if files.strip() else ""
    files += separator + '"' + path + '"'
    return text[:match.start(2)] + files + text[match.end(2):]

if "  - tag: explicit_hijack\n" not in s:
    marker = "  - tag: hijack_set\n"
    if s.count(marker) != 1:
        raise SystemExit("hijack_set shape unknown")
    plugin = (
        "  - tag: explicit_hijack\n"
        "    type: domain_set\n"
        '    args: { files: ["/etc/mosdns/rules/custom_hijack.txt",'
        '"/etc/mosdns/rules/ruleset_hijack.txt"] }\n'
    )
    s = s.replace(marker, plugin + marker, 1)

s = ensure_domain_set_file(s, "geosite_cn", agg)
s = ensure_domain_set_file(
    s, "explicit_hijack", "/etc/mosdns/rules/custom_hijack.txt"
)
s = ensure_domain_set_file(s, "explicit_hijack", hijagg)

marker = "      - matches: qname $geosite_cn\n"
if s.count(marker) < 1:
    raise SystemExit("geosite_cn sequence shape unknown")
rule = (
    "      - matches: qname $explicit_hijack\n"
    "        exec: goto force_hijack_seq\n"
)
active_s = "\n".join(line.split("#", 1)[0] for line in s.splitlines())
if "qname $explicit_hijack" in active_s and rule not in s:
    raise SystemExit("explicit_hijack sequence shape unknown")
if rule in s:
    if s.count(rule) != 1:
        raise SystemExit("duplicate explicit_hijack sequence")
    # 旧迁移只检查“存在”，可能把显式代理规则留在宽泛 direct 后面；移除标准块后按
    # 当前 geosite_cn 的首条规则重新插入，错误顺序可自愈。
    s = s.replace(rule, "", 1)
s = s.replace(marker, rule + marker, 1)

st = os.lstat(mc)
if not stat.S_ISREG(st.st_mode):
    raise SystemExit("mosdns config is not regular")
directory = os.path.dirname(mc)
fd, tmp = tempfile.mkstemp(prefix=".pdg-rsdirect.", dir=directory)
try:
    if hasattr(os, "fchmod"):
        os.fchmod(fd, stat.S_IMODE(st.st_mode))
    if hasattr(os, "fchown"):
        os.fchown(fd, st.st_uid, st.st_gid)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        fd = -1
        stream.write(s)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(tmp, stat.S_IMODE(st.st_mode))
    os.replace(tmp, mc)
    if os.name != "nt":
        dfd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
finally:
    if fd >= 0:
        os.close(fd)
    try:
        os.unlink(tmp)
    except FileNotFoundError:
        pass
RSDIRECTPY
  then
    c_y "  [规则集手机直连] 配置候选生成失败，正在还原三文件 before-image。"
    if _pdg_restore_ruleset_migration_before \
         "$work" "$mc" "$agg" "$hijagg" "$agg_pre" "$hijagg_pre"; then
      rm -rf -- "$work"
      c_y "  [规则集手机直连] 生成失败，磁盘配置已还原；MosDNS 运行态未重启。"
      return 1
    fi
    c_y "  ⛔ [规则集手机直连] 生成失败且还原不完整；before-image 保留在 $work"
    return 1
  fi

  # 从当前 metadata + 所有受管 source JSON 纯派生两份候选。不能先落空文件再宣布
  # 迁移成功，否则已有 proxy/direct 规则集要等到下一次 refresh 才有正确 DNS 语义。
  if ! _pdg_ruleset_aggregate_candidates \
         "$work/config.candidate" "$work/direct.candidate" \
         "$work/hijack.candidate" "$work/hijack.transition" "$hijagg" \
     || ! _pdg_ruleset_direct_interface_ready_file "$work/config.candidate"; then
    c_y "  [规则集手机直连] 双聚合/配置候选生成失败；live 文件尚未改动。"
    rm -rf -- "$work"
    return 1
  fi

  # 候选与 before-image 全部持久化后，原子发布 journal；只有发布成功才允许触碰
  # live 文件。断电后下一次 migrate 会先从该目录幂等恢复三文件。
  if ! _pdg_sync_ruleset_migration_path "$work" \
     || ! mv "$preparing" "$journal" \
     || ! _pdg_sync_parent_dir "$journal"; then
    c_y "  ⛔ [规则集手机直连] 持久恢复 journal 发布失败，拒绝提交 live 文件。"
    return 1
  fi
  work="$journal"

  # 过渡劫持先取 old∪candidate：出口 target 双向变化的中间窗口最多保守走网关，
  # 不会因 direct/hijack 两文件尚未同步而误直连。config 仍最后切换。
  if ! install -d -m755 /etc/mosdns/rules \
     || ! _pdg_atomic_install_file "$work/hijack.transition" "$hijagg" 644 \
     || ! _pdg_atomic_install_file "$work/direct.candidate" "$agg" 644 \
     || ! _pdg_atomic_install_file "$work/hijack.candidate" "$hijagg" 644 \
     || ! _pdg_atomic_install_file "$work/config.candidate" "$mc" "$mc_mode"; then
    c_y "  [规则集手机直连] 三文件提交失败，正在按持久 journal 还原。"
    if _pdg_restore_ruleset_migration_before \
         "$work" "$mc" "$agg" "$hijagg" "$agg_pre" "$hijagg_pre"; then
      rm -rf -- "$work"
      _pdg_sync_parent_dir "$work" || true
      return 1
    fi
    c_y "  ⛔ [规则集手机直连] 提交失败且还原不完整；journal 保留在 $work"
    return 1
  fi

  # 提交后仍须调用 Bot 的同一严格接口判据。
  if ! _pdg_ruleset_direct_interface_ready_file "$mc"; then
    c_y "  [规则集手机直连] 严格接口校验失败，正在还原三文件 before-image；未重启 MosDNS。"
    if _pdg_restore_ruleset_migration_before \
         "$work" "$mc" "$agg" "$hijagg" "$agg_pre" "$hijagg_pre"; then
      rm -rf -- "$work"
      _pdg_sync_parent_dir "$work" || true
      return 1
    fi
    c_y "  ⛔ [规则集手机直连] 严格校验失败且还原不完整；before-image 保留在 $work"
    return 1
  fi
  if systemctl restart mosdns 2>/dev/null && _core_kernel_stable mosdns; then
    if ! rm -rf -- "$work" || ! _pdg_sync_parent_dir "$work"; then
      c_y "  ⛔ [规则集手机直连] 新配置已稳定，但 journal 清理未持久确认。"
      return 1
    fi
    c_g "  已从当前规则集重建 direct/hijack DNS 聚合，并建立显式代理优先级。"
    return 0
  fi
  c_y "  [规则集手机直连] MosDNS 重启后未稳定，正在还原三文件 before-image。"
  if _pdg_restore_ruleset_migration_before \
       "$work" "$mc" "$agg" "$hijagg" "$agg_pre" "$hijagg_pre" \
     && systemctl restart mosdns 2>/dev/null \
     && _core_kernel_stable mosdns; then
    if ! rm -rf -- "$work" || ! _pdg_sync_parent_dir "$work"; then
      c_y "  ⛔ [规则集手机直连] 旧配置已稳定，但 journal 清理未持久确认。"
      return 1
    fi
    c_y "  [规则集手机直连] 新接口未提交；旧配置已还原并确认稳定。"
    return 0
  fi
  c_y "  ⛔ [规则集手机直连] 旧配置还原后 MosDNS 仍未稳定；before-image 保留在 $work"
  return 1
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

_pdg_install_dataplane_bundle(){
  # Install bot + converter + strict profile parser as one validated version
  # set.  Renames are per-file atomic; a mid-set failure restores every file
  # already touched before returning.
  local source_root="$1" dst=/opt/pdg-bot wd name src target restore_name
  wd="$(mktemp -d)" || return 1
  mkdir -p "$dst" || { rm -rf "$wd"; return 1; }
  for name in bot.py sb2mihomo.py pdgprofile.py; do
    case "$name" in
      bot.py) src="$source_root/pdg-bot.py";;
      *) src="$source_root/$name";;
    esac
    [[ -f "$src" ]] || { rm -rf "$wd"; return 1; }
    cp "$src" "$wd/$name" || { rm -rf "$wd"; return 1; }
    if [[ -e "$dst/$name" ]]; then
      cp -a "$dst/$name" "$wd/$name.before" || { rm -rf "$wd"; return 1; }
      : >"$wd/$name.existed"
    fi
  done
  PYTHONPYCACHEPREFIX="$wd/pycache" python3 -m py_compile \
    "$wd/bot.py" "$wd/sb2mihomo.py" "$wd/pdgprofile.py" \
    || { rm -rf "$wd"; return 1; }
  for name in bot.py sb2mihomo.py pdgprofile.py; do
    if ! _pdg_atomic_install_file "$wd/$name" "$dst/$name" 755; then
      for restore_name in bot.py sb2mihomo.py pdgprofile.py; do
        target="$dst/$restore_name"
        if [[ -e "$wd/$restore_name.existed" ]]; then
          _pdg_atomic_install_file \
            "$wd/$restore_name.before" "$target" 755 || true
        else
          rm -f "$target"
        fi
      done
      rm -rf "$wd"; return 1
    fi
  done
  rm -rf "$wd"
}

_pdg_restart_restore_before(){
  local wd="$1" qhelper nftexe failed=0
  qhelper="$(_pdg_quic_helper)" || return 1
  # Restore dependencies before the on-disk core config. The running Mihomo
  # process still has its previous in-memory config, so route -> nft -> config
  # avoids presenting an old config with a new route tuple if rollback stalls.
  if [[ -e "$wd/had-state" ]]; then
    bash "$qhelper" rollback-state "$wd/state.before" >/dev/null 2>&1 \
      || failed=1
  else
    bash "$qhelper" rollback-state - >/dev/null 2>&1 || failed=1
  fi
  nftexe="$(_pdg_nft_bin)"
  if [[ -e "$wd/had-nft" ]]; then
    # shellcheck source=lib/nfttxn.sh
    if source "$REPO_DIR/lib/nfttxn.sh" 2>/dev/null; then
      pdg_nft_atomic_install "$wd/nft.before" /etc/nftables.conf "$nftexe" \
        && "$nftexe" -f /etc/nftables.conf || failed=1
    else
      failed=1
    fi
  else
    rm -f /etc/nftables.conf || failed=1
    [[ -n "$nftexe" ]] && "$nftexe" delete table inet pdg 2>/dev/null || true
  fi
  if [[ -e "$wd/had-config" ]]; then
    _pdg_atomic_install_file "$wd/config.before" /etc/mihomo/config.yaml 600 \
      || failed=1
  else
    rm -f /etc/mihomo/config.yaml || failed=1
  fi
  return "$failed"
}

_pdg_dataplane_mode_readonly(){
  local tool="$1" mode="" marker=""
  # Strictly parse the managed structure and validate every present data-plane
  # value before any migration writes a marker.  Missing keys are a legacy
  # state and receive resolver defaults; malformed/duplicate keys are not.
  python3 - "$tool" "$PROFILE_ENV" <<'PY' >/dev/null || return 1
import importlib.util
import sys
from pathlib import Path
tool, profile = sys.argv[1:]
sys.path.insert(0, str(Path(tool).resolve().parent))
spec = importlib.util.spec_from_file_location("pdgprofile_preflight", tool)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
mod.resolve(profile, environ={})
PY
  marker="$(cat /etc/privdns-gateway/firewall-mode 2>/dev/null)"
  if mode="$(_pdg_profile_get_from "$tool" PDG_FIREWALL_MODE 2>/dev/null)"; then
    [[ "$mode" == managed || "$mode" == external ]] || return 1
    if [[ -n "$marker" && "$marker" != "$mode" ]]; then
      echo "firewall-mode state/profile 冲突或 marker 非法" >&2
      return 1
    fi
    printf '%s\n' "$mode"
    return 0
  fi
  if [[ "$marker" == managed || "$marker" == external ]]; then
    printf '%s\n' "$marker"
  elif [[ -n "$marker" ]]; then
    echo "firewall-mode marker 非法" >&2
    return 1
  elif grep -q 'mode=external' /etc/nftables.conf 2>/dev/null; then
    printf 'external\n'
  elif grep -q 'mode=managed' /etc/nftables.conf 2>/dev/null \
    || grep -qE 'table inet (pdg|filter)' /etc/nftables.conf 2>/dev/null; then
    printf 'managed\n'
  else
    echo "无法从可信现场证据确定 firewall mode，拒绝默认 managed" >&2
    return 1
  fi
}

_pdg_dataplane_nft_preflight(){
  local mode="$1" scan_out scan_rc
  [[ -f "$REPO_DIR/deploy/bot/nftscan.py" ]] \
    || { echo "checked-out nftables 扫描器不存在" >&2; return 1; }
  scan_out="$(python3 "$REPO_DIR/deploy/bot/nftscan.py" \
    --mode "$mode" /etc/nftables.conf 2>&1)"; scan_rc=$?
  case "$scan_rc" in
    0)
      echo "检测到自定义 input base chain，与 PDG 的 policy drop 不兼容 → 迁移前置检查中止:"
      printf '%s\n' "$scan_out" | sed 's/^/    /'
      return 1;;
    1) return 0;;
    2)
      echo "无法确认 input 链冲突 → 迁移前置检查中止:"
      printf '%s\n' "$scan_out" | sed 's/^/    /'
      return 1;;
    *)
      echo "nftables 迁移前置扫描器异常退出 $scan_rc:"
      printf '%s\n' "$scan_out" | sed 's/^/    /'
      return 1;;
  esac
}

migrate_dataplane_profile(){
  local tool mode="" marker="" cidr="" sshp="" key value
  # An update may be running with an old /opt runtime bundle.  Migration must
  # consume one coherent checked-out bundle, never import old bot/sb2mihomo
  # before copying the new files.
  tool="$REPO_DIR/deploy/bot/pdgprofile.py"
  [[ -f "$tool" && -f "$REPO_DIR/deploy/bot/pdg-bot.py" \
     && -f "$REPO_DIR/deploy/bot/sb2mihomo.py" ]] \
    || { echo "checked-out data-plane bundle 不完整"; return 1; }

  mode="$(_pdg_dataplane_mode_readonly "$tool")" || return 1
  _pdg_dataplane_nft_preflight "$mode" || return 1

  install -d -m700 /etc/privdns-gateway || return 1
  _profile_set PDG_FIREWALL_MODE "$mode" || return 1
  if [[ -e /etc/privdns-gateway/firewall-mode ]]; then
    marker="$(cat /etc/privdns-gateway/firewall-mode 2>/dev/null)"
    [[ "$marker" == "$mode" ]] || {
      echo "firewall-mode state/profile 冲突" >&2; return 1; }
  else
    local mt
    mt="$(mktemp /etc/privdns-gateway/.firewall-mode.XXXXXX)" || return 1
    printf '%s\n' "$mode" >"$mt" && chmod 600 "$mt" \
      && mv -f "$mt" /etc/privdns-gateway/firewall-mode || { rm -f "$mt"; return 1; }
  fi

  cidr="$(_pdg_profile_get PDG_INTERNAL_CIDR 2>/dev/null)" || true
  if [[ -z "$cidr" ]]; then
    cidr="$(python3 -c 'import sys;sys.path.insert(0,"/opt/pdg-bot");import checks;print(checks._internal_cidr())' 2>/dev/null)"
    [[ -n "$cidr" ]] || cidr="$(grep -oE 'ip saddr [0-9./]+' /etc/nftables.conf 2>/dev/null | head -1 | awk '{print $3}')"
    [[ -n "$cidr" ]] || { echo "无法迁移 PDG_INTERNAL_CIDR"; return 1; }
    _profile_set PDG_INTERNAL_CIDR "$cidr" || return 1
  fi
  sshp="$(_pdg_profile_get PDG_SSH_PORT 2>/dev/null)" || true
  if [[ -z "$sshp" ]]; then
    sshp="$(ss -lntpH 2>/dev/null | awk '/sshd/{n=split($4,a,":"); print a[n]; exit}')"
    sshp="${sshp:-22}"
    _profile_set PDG_SSH_PORT "$sshp" || return 1
  fi
  _plat_write_profile "$(_pdg_platform)" || return 1

  # Resolve the whole group before writing any one of it. Invalid/duplicate
  # existing keys abort; missing keys receive this fork's explicit defaults.
  local lines
  lines="$(python3 "$tool" --profile "$PROFILE_ENV" --profile-only \
    --platform "$(_pdg_platform)" --ssh-port "$sshp" lines)" || return 1
  while IFS='=' read -r key value; do
    [[ -n "$key" ]] || continue
    _profile_set "$key" "$value" || return 1
  done <<<"$lines"

  # Deploy source helper + boot unit as hard lifecycle prerequisites.
  install -d -m755 /usr/local/libexec /opt/pdg-bot || return 1
  _pdg_install_dataplane_bundle "$REPO_DIR/deploy/bot" || return 1
  install -m755 "$REPO_DIR/deploy/firewall/pdg-quic-routing.sh" \
    /usr/local/libexec/pdg-quic-routing.sh || return 1
  install -m644 "$REPO_DIR/deploy/firewall/pdg-quic-routing.service" \
    /etc/systemd/system/pdg-quic-routing.service || return 1
  # shellcheck source=lib/units.sh
  source "$REPO_DIR/lib/units.sh" || return 1
  pdg_write_unit pdg_unit_mihomo /etc/systemd/system/mihomo.service || return 1
  systemctl daemon-reload || return 1
  systemctl enable pdg-quic-routing >/dev/null 2>&1 || return 1

  local mwd mcand
  mwd="$(mktemp -d)" || return 1; mcand="$mwd/config.yaml"
  if ! _pdg_render_mihomo_candidate "$mcand" "$REPO_DIR/deploy/bot"; then
    rm -rf "$mwd"; return 1
  fi
  if command -v mihomo >/dev/null 2>&1 \
    && ! mihomo -t -d /etc/mihomo -f "$mcand" >/dev/null 2>&1; then
    rm -rf "$mwd"; return 1
  fi
  if ! _pdg_atomic_install_file "$mcand" /etc/mihomo/config.yaml 600 \
    || ! _switchcore_nft mihomo "$REPO_DIR"; then
    rm -rf "$mwd"; return 1
  fi
  rm -rf "$mwd"
  systemctl enable --now pdg-quic-routing >/dev/null 2>&1 || return 1
  /usr/local/libexec/pdg-quic-routing.sh status >/dev/null 2>&1 || return 1
  systemctl restart mihomo >/dev/null 2>&1 || return 1
  [[ "$(systemctl is-active pdg-quic-routing 2>/dev/null)" == active \
     && "$(systemctl is-active mihomo 2>/dev/null)" == active ]] || return 1
}

run_all_migrations(){
  local rc=0 tool preflight_mode
  # Hard gate before even platform/backend marker migrations: a conflict,
  # unreadable live ruleset, or corrupt managed profile must be zero-write.
  tool="$REPO_DIR/deploy/bot/pdgprofile.py"
  [[ -f "$tool" ]] || return 1
  preflight_mode="$(_pdg_dataplane_mode_readonly "$tool")" || return 1
  _pdg_dataplane_nft_preflight "$preflight_mode" || return 1
  migrate_platform_marker || true          # 先统一平台判定源(后续平台相关迁移据此走)
  migrate_backend_marker || true           # 再把内核标记落地(别再靠默认值兜底)
  # 数据面前置迁移负责在任何写入前完成 mode-aware nft 冲突扫描；失败后继续跑
  # best-effort 迁移会破坏其“冲突现场零改动”保证，因此这里立即返回。
  migrate_dataplane_profile || return 1
  migrate_default_direct_tag || return 1
  migrate_botenv || true; migrate_firewall_to_pdg || true; migrate_mosdns_concurrent || true
  migrate_mosdns_unlock || true; migrate_fw_gms || true
  migrate_mosdns_ratelimit || true; migrate_lowmem || true; migrate_mihomo_safepaths || true
  migrate_deploy_botfiles || true; migrate_deploy_units || true
  migrate_mosdns_hijack_shape || true
  migrate_custom_hijack || true
  migrate_mosdns_mitm || true
  migrate_ruleset_phone_direct || rc=1
  migrate_pdg_mitm_service || true
  migrate_android_cleanup || true
  # iOS GMS 清理**失败必须传出**: 它会动 model + 内核配置 + 防火墙三样, 失败即现网可能与
  # 期望形态不一致(它自己会完整回滚, 但回滚不完整时更要让上层知道)。以前是 `|| true`,
  # 于是 cmd_update / cmd_migrate / cmd_platform 全都收不到这条失败。
  migrate_ios_gms_cleanup || rc=1
  # MosDNS stock v5.3.4 与修补版共用上游版本号，必须在新版脚本进程内按精确
  # flavor/provenance 更新；失败必须传给 update 触发其精确快照回滚。
  migrate_mosdns_patched_binary || rc=1
  # 内核迁移放最后: 上面的 config.json / mosdns / 防火墙 迁移都先按老路子跑完(它们只动数据模型
  # 与 nft, 与内核无关), 这里再把**最终形态的** config.json 转 mihomo 并移除 sing-box 运行时。
  # 唯一"失败必须传出"的迁移 —— 失败即让 __migrate 返回非0,
  # cmd_update 据此回滚到更新前快照(其余迁移都是幂等自愈, 失败 best-effort 吞掉不挡后续)。
  migrate_drop_singbox || rc=1
  return $rc
}

# 迁移到 mihomo 时渲染并应用 mihomo 的 nft 入站模型(REDIRECT→7893)。出口/分流/证书/DoT/mosdns
# 全不动(model 共用)。$1 目前恒为 mihomo(唯一内核), 保留形参以兼容 _activate_mihomo_core 调用。
# 找出**除 table inet pdg 之外**挂在 `hook input` 上的 base chain。
# 为什么这条是硬门槛: PDG 的 input chain 是 `policy drop`, 而 nftables 里同一 hook 上的多个
# base chain **都会执行** —— 任一条判 drop, 包就没了。于是用户自己的 input chain 里对 10443 /
# WireGuard 的 accept 会被 PDG 这条 drop 架空: 配置文本还在, 端口实际已经不通, 而迁移还报成功。
# 这种"看着保留、其实失效"比直接报错危险得多, 故一律中止, 交由用户手工合并。
# 检测同时看**配置文件**与**当前运行 ruleset**(两边都可能只有一侧有), 宁可保守中止。
# 判据本身放在 deploy/bot/nftscan.py —— 迁移前置门与 doctor 共用同一份, 免得两处正则各写
# 一遍慢慢漂移(一边判冲突一边判干净, 比都不判还糟)。
# stdout: 冲突描述(每行一条)。返回 0=有冲突, 1=确认没有, 2=读不到运行 ruleset 无法确认。
_pdg_nft_foreign_input_chains(){
  local conf="${1:-/etc/nftables.conf}" scan
  for scan in "${REPO_DIR:-/opt/privdns-gateway}/deploy/bot/nftscan.py" /opt/pdg-bot/nftscan.py; do
    [[ -f "$scan" ]] || continue
    python3 "$scan" "$conf"
    return $?
  done
  # 判据脚本都不在 → 不能假装现场干净(那正是这道门要挡的事), 按"无法确认"处理
  echo "找不到 nftscan.py(判据脚本缺失), 无法确认 input 链冲突"
  return 2
}

# 把渲染好的 pdg 表块**合并**进现网 nftables.conf: 只替换本项目管理区(table inet pdg 的
# 声明/delete/表体), 其余内容逐字节保留。$1=渲染好的块文件 $2=目标 conf $3=输出文件。
# 无法证明能安全合并(pdg 块括号不配平 / 文件里有 flush ruleset 又还有别的表)→ 返回非 0,
# 调用方必须在改动运行环境**之前**中止 —— 整文件覆盖会把用户的 VPN/NAT/转发/开放端口抹掉。
_pdg_nft_splice(){
  local m mode="${4:-}"
  for m in "${REPO_DIR:-/opt/privdns-gateway}/deploy/bot/nftmerge.py" /opt/pdg-bot/nftmerge.py; do
    [[ -f "$m" ]] || continue
    if [[ -n "$mode" ]]; then python3 "$m" --mode "$mode" "$1" "$2" "$3"
    else python3 "$m" "$1" "$2" "$3"; fi
    return $?
  done
  echo "找不到 nftmerge.py(合并脚本缺失), 拒绝合并防火墙配置" >&2
  return 1
}

_pdg_switchcore_restore_nft_before(){
  local wd="$1" bak="$2" nftexe="$3" had_live="$4"
  local live_restore="$5" livebak="$6"
  local failed=0 now="$wd/pdg.live.after-restore"
  local nft_target="${PDG_NFT_CONF:-/etc/nftables.conf}"
  if [[ -e "$bak" ]]; then
    pdg_nft_atomic_install "$bak" "$nft_target" "$nftexe" || failed=1
    [[ "$failed" == 0 ]] && cmp -s "$bak" "$nft_target" || failed=1
  else
    rm -f "$nft_target" || failed=1
    [[ ! -e "$nft_target" ]] || failed=1
  fi
  if [[ "$had_live" == 1 ]]; then
    "$nftexe" -f "$live_restore" >/dev/null 2>&1 || failed=1
    "$nftexe" list table inet pdg >"$now" 2>/dev/null || failed=1
    cmp -s "$livebak" "$now" || failed=1
  else
    if ! "$nftexe" delete table inet pdg >/dev/null 2>&1; then
      # ENOENT is acceptable only after a read-back proof of absence.
      local tables=""
      tables="$("$nftexe" list tables 2>/dev/null)" || failed=1
      if [[ "$failed" == 0 ]] && grep -Eq \
          '^[[:space:]]*table[[:space:]]+inet[[:space:]]+pdg([[:space:]]|$)' \
          <<<"$tables"; then failed=1; fi
    fi
    local tables_after=""
    tables_after="$("$nftexe" list tables 2>/dev/null)" || failed=1
    if [[ "$failed" == 0 ]] && grep -Eq \
        '^[[:space:]]*table[[:space:]]+inet[[:space:]]+pdg([[:space:]]|$)' \
        <<<"$tables_after"; then failed=1; fi
  fi
  return "$failed"
}

_switchcore_nft(){   # Render/apply the complete profile-owned data plane.
  local target="$1" source_repo="${2:-}" sshp icidr mode tool qhelper nftexe
  [[ "$target" == mihomo ]] || { echo "内部错误: _switchcore_nft 只支持 mihomo(收到 $target)"; return 1; }
  if [[ -n "$source_repo" ]]; then
    tool="$source_repo/deploy/bot/pdgprofile.py"
    qhelper="$source_repo/deploy/firewall/pdg-quic-routing.sh"
    [[ -f "$tool" && -f "$qhelper" ]] \
      || { echo "checked-out profile/QUIC helper bundle 不完整"; return 1; }
  else
    tool="$(_pdg_profile_tool)" || { echo "缺 pdgprofile.py"; return 1; }
    qhelper="$(_pdg_quic_helper)" || { echo "缺 QUIC routing helper"; return 1; }
  fi
  if [[ -n "$source_repo" ]]; then
    mode="$(_pdg_profile_get_from "$tool" PDG_FIREWALL_MODE)" \
      || { echo "profile 防火墙模式缺失/重复"; return 1; }
    local state_mode=""
    [[ ! -e /etc/privdns-gateway/firewall-mode ]] \
      || state_mode="$(cat /etc/privdns-gateway/firewall-mode 2>/dev/null)"
    [[ -z "$state_mode" || "$state_mode" == "$mode" ]] \
      || { echo "firewall mode state/profile 冲突"; return 1; }
    sshp="$(_pdg_profile_get_from "$tool" PDG_SSH_PORT)" \
      || { echo "profile 缺 PDG_SSH_PORT"; return 1; }
    icidr="$(_pdg_profile_get_from "$tool" PDG_INTERNAL_CIDR)" \
      || { echo "profile 缺 PDG_INTERNAL_CIDR"; return 1; }
  else
    mode="$(_pdg_firewall_mode)" \
      || { echo "profile 防火墙模式缺失/重复/冲突"; return 1; }
    sshp="$(_pdg_profile_get PDG_SSH_PORT)" \
      || { echo "profile 缺 PDG_SSH_PORT"; return 1; }
    icidr="$(_pdg_profile_get PDG_INTERNAL_CIDR)" \
      || { echo "profile 缺 PDG_INTERNAL_CIDR"; return 1; }
  fi
  [[ -f "$REPO_DIR/deploy/firewall/nftables-mihomo.conf" ]] || { echo "缺 nftables-mihomo.conf(先 pdg update)"; return 1; }
  # 兜底(调用方本应已在更早处拦下): 别的 input base chain 与 PDG 的 policy drop 不兼容,
  # 在写文件/执行 nft 之前中止, 免得"文本保留、端口失效"。
  local _fic2 _frc2
  _fic2="$(python3 "$REPO_DIR/deploy/bot/nftscan.py" --mode "$mode" \
    /etc/nftables.conf)"; _frc2=$?
  if [[ "$_frc2" == 0 ]]; then
    echo "检测到自定义 input base chain, 与 PDG 的 policy drop 不兼容 → 未改动防火墙:"
    printf '%s\n' "$_fic2" | sed 's/^/    /'
    return 1
  fi
  if [[ "$_frc2" == 2 ]]; then     # 读不到运行 ruleset: 不能假装干净就往下写规则
    echo "无法确认 input 链冲突 → 未改动防火墙:"
    printf '%s\n' "$_fic2" | sed 's/^/    /'
    return 1
  fi
  local wd rendered merged bak rc qbak qbefore="-" livebak live_restore had_live=0
  wd="$(mktemp -d)" || { echo "无法创建临时目录"; return 1; }
  rendered="$wd/pdg.nft"; merged="$wd/merged.conf"; bak="$wd/nftables.conf.bak"
  livebak="$wd/pdg.live.before"; live_restore="$wd/pdg.live.restore"
  python3 "$tool" --profile "$PROFILE_ENV" --profile-only \
    --platform "$(_pdg_platform)" --ssh-port "$sshp" --listener-preflight render-nft \
    --template "$REPO_DIR/deploy/firewall/nftables-mihomo.conf" \
    --internal-cidr "$icidr" --firewall-mode "$mode" >"$rendered" \
    || { rm -rf "$wd"; echo "按 profile 渲染 nft 失败"; return 1; }
  # 备份必须先成立(逐字节校验): 后面任何一步失败都要靠它把现网原样放回去
  if [[ -e /etc/nftables.conf ]]; then
    if ! cp -a /etc/nftables.conf "$bak" 2>/dev/null || ! cmp -s /etc/nftables.conf "$bak"; then
      rm -rf "$wd"; echo "备份 /etc/nftables.conf 失败(磁盘满?), 未改动防火墙"; return 1
    fi
  fi
  # 只替换本项目管理区(table inet pdg), 用户的额外表/VPN/NAT/转发/开放端口原样保留。
  # 合并不了(块不配平 / flush ruleset 与别的表共存)→ 在改动运行环境之前就中止。
  if ! _pdg_nft_splice "$rendered" /etc/nftables.conf "$merged" "$mode"; then
    rm -rf "$wd"
    echo "无法安全合并防火墙配置 → 未改动 /etc/nftables.conf(见上方冲突位置)"
    echo "  请把本项目所需规则手工并入 table inet pdg 后重试, 或先备份并清理冲突配置。"
    return 1
  fi
  nftexe="$(_pdg_nft_bin)"; [[ -n "$nftexe" ]] \
    || { rm -rf "$wd"; echo "找不到 nft，拒绝未校验写入"; return 1; }
  if "$nftexe" list table inet pdg >"$livebak" 2>/dev/null; then
    had_live=1
    {
      printf 'table inet pdg\n'
      printf 'delete table inet pdg\n'
      cat "$livebak"
    } >"$live_restore" || { rm -rf "$wd"; return 1; }
    "$nftexe" -c -f "$live_restore" >/dev/null 2>&1 \
      || { rm -rf "$wd"; echo "无法构造 live nft before-image"; return 1; }
  fi
  PDG_PROFILE="$PROFILE_ENV" PDG_PROFILE_TOOL="$tool" bash "$qhelper" preflight \
    || { rm -rf "$wd"; echo "QUIC routing 预检失败，未写 nft"; return 1; }
  qbak="$wd/quic-routing.state.before"
  if [[ -e /etc/privdns-gateway/quic-routing.state ]]; then
    if ! cp -a /etc/privdns-gateway/quic-routing.state "$qbak" 2>/dev/null \
      || ! cmp -s /etc/privdns-gateway/quic-routing.state "$qbak"; then
      rm -rf "$wd"; echo "QUIC routing state 备份失败，未写 nft"; return 1
    fi
    qbefore="$qbak"
  fi
  # shellcheck source=lib/nftbin.sh
  source "$REPO_DIR/lib/nftbin.sh" 2>/dev/null || { rm -rf "$wd"; return 1; }
  # shellcheck source=lib/nfttxn.sh
  source "$REPO_DIR/lib/nfttxn.sh" 2>/dev/null || { rm -rf "$wd"; return 1; }
  if ! pdg_nft_atomic_install "$merged" /etc/nftables.conf "$nftexe"; then
    rm -rf "$wd"; echo "原子安装 nftables.conf 失败"; return 1
  fi
  if ! "$nftexe" -f /etc/nftables.conf; then
    rc=1
    if _pdg_switchcore_restore_nft_before \
        "$wd" "$bak" "$nftexe" "$had_live" "$live_restore" "$livebak"; then
      echo "应用新防火墙失败 → 已验证还原 persistent/live nft before-image"
    else
      echo "应用新防火墙失败，且 persistent/live nft before-image 恢复不完整，必须人工复核" >&2
    fi
    rm -rf "$wd"; return "$rc"
  fi
  # Runtime nft is now known-good. The routing helper is internally
  # rollback-safe; if it cannot apply/status, restore old nft persistent+live.
  if ! PDG_PROFILE="$PROFILE_ENV" PDG_PROFILE_TOOL="$tool" bash "$qhelper" apply \
    || ! PDG_PROFILE="$PROFILE_ENV" PDG_PROFILE_TOOL="$tool" bash "$qhelper" status \
       >/dev/null; then
    local qrb=0
    PDG_PROFILE_TOOL="$tool" bash "$qhelper" rollback-state "$qbefore" \
      >/dev/null 2>&1 || qrb=1
    local nrb=0
    _pdg_switchcore_restore_nft_before \
      "$wd" "$bak" "$nftexe" "$had_live" "$live_restore" "$livebak" || nrb=1
    if [[ "$qrb" == 0 && "$nrb" == 0 ]]; then
      echo "QUIC routing apply/status 失败，已验证恢复旧 route state 与 persistent/live nft"
    else
      echo "QUIC routing apply/status 失败；before-image 回滚不完整(route=$qrb nft=$nrb)，必须人工复核" >&2
    fi
    rm -rf "$wd"; return 1
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
  _restore_sc_nft(){
    local nx; nx="$(_pdg_nft_bin)"
    # shellcheck source=lib/nfttxn.sh
    source "$REPO_DIR/lib/nfttxn.sh" 2>/dev/null || return 1
    [[ -f /etc/nftables.conf.scbak ]] || return 0
    pdg_nft_atomic_install /etc/nftables.conf.scbak /etc/nftables.conf "$nx" \
      && "$nx" -f /etc/nftables.conf
  }

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
  _switchcore_nft mihomo || { printf '%s\n' "${prev_backend:-singbox}" > /etc/privdns-gateway/backend; echo "❌ nft 应用失败, 已回滚"; return 1; }
  if ! _core_kernel_activate mihomo sing-box; then
    c_y "mihomo 启动/自启核验失败 → 回滚"
    printf '%s\n' "${prev_backend:-singbox}" > /etc/privdns-gateway/backend
    _restore_sc_nft >/dev/null 2>&1 || c_y "旧 nft 原子恢复失败，请立即检查"
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
  # 前置硬门槛: 现场若还有别的 input base chain, PDG 的 policy drop 会把它们的放行架空
  # (配置看着还在、端口实际不通)。必须在**动任何东西之前**中止 —— 下核、翻标记、渲染配置、
  # 写 unit、改 nft、切服务, 一个都还没做。
  local _fic _frc
  _fic="$(_pdg_nft_foreign_input_chains /etc/nftables.conf)"; _frc=$?
  # 2 = 读不到运行中的 ruleset(非 root / nft 不可用): 内存里的冲突链没进视野, 不能当成干净。
  # 迁移本来就要写 nft 规则, 这台机器上迟早也过不去 —— 早停一步, 现场还没被动过。
  if [[ "$_frc" == 2 ]]; then
    c_y "无法确认现场是否存在其它 input base chain → 中止迁移(现场未做任何改动)。"
    printf '%s\n' "$_fic" | sed 's/^/    /'
    c_y "  怎么办: 用 root 重试 sudo pdg update; 若本机确无 nftables, 请先装好 nftables 再迁移。"
    return 1
  fi
  if [[ "$_frc" == 0 ]]; then
    c_y "检测到自定义 input base chain, 无法保证与 PDG 默认拒绝策略(policy drop)兼容 → 中止迁移。"
    printf '%s\n' "$_fic" | sed 's/^/    /'
    c_y "  原因: nftables 同一 hook 上的多个 base chain 都会执行, 任一条 drop 包就没了 ——"
    c_y "        PDG 的 input chain 是 policy drop, 会把上面这些表里的放行(如自定义端口/VPN)架空,"
    c_y "        表面上配置都在, 实际端口不通。这种失效比直接报错更难排查, 故不自动处理。"
    c_y "  怎么办: 把上述表里需要的放行规则并入 table inet pdg 的 input chain(或改用非 input hook),"
    c_y "          再重试 sudo pdg update。现场未做任何改动, sing-box 仍在正常运行。"
    return 1
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
# profile.env 的 PDG_PLATFORM 与 platform 文件必须同步 —— 后者丢了(备份恢复/手工清理)时
# _pdg_platform 会回退去读 profile.env, 两处不一致就会在下一次迁移里把平台判反。
_plat_write_profile(){
  local target="$1" tool tmp
  [[ "$target" == ios || "$target" == android ]] || return 1
  tool="$REPO_DIR/deploy/bot/pdgprofile.py"
  [[ -f "$tool" ]] || tool="$(_pdg_profile_tool)" || return 1
  mkdir -p "$(dirname "$PROFILE_ENV")" 2>/dev/null || true
  tmp="$(mktemp "${PROFILE_ENV}.XXXXXX" 2>/dev/null)" || return 1
  if ! python3 "$tool" --profile "$PROFILE_ENV" \
      retarget-platform "$target" >"$tmp"; then
    rm -f "$tmp" 2>/dev/null
    return 1
  fi
  mv -f "$tmp" "$PROFILE_ENV" 2>/dev/null \
    || { rm -f "$tmp" 2>/dev/null; return 1; }
}

# 部署 iOS 专属组件(幂等)。probe81 / 描述文件模板 / MITM 模块 —— 缺一样 doctor 就会报
# "pdg-probe81 未运行 / :81 无响应", 而以前 `pdg platform ios` 只写个标记就说"已确认"。
# iOS 平台必须存在的文件(源 → 目标)。切平台是**事务**, 这里一个都不能少。
_PLAT_IOS_REQUIRED=(
  "deploy/ios/probe81.py|/opt/pdg-bot/probe81.py|755"
  "deploy/ios/pdg-dot-ondemand.mobileconfig.tmpl|/opt/pdg-bot/pdg-dot.mobileconfig.tmpl|644"
  "deploy/bot/mitm_ca.py|/opt/pdg-bot/mitm_ca.py|755"
  "deploy/bot/mitm_server.py|/opt/pdg-bot/mitm_server.py|755"
  "deploy/bot/mitm_wloc.py|/opt/pdg-bot/mitm_wloc.py|755"
  "deploy/ios/pdg-probe81.service|/etc/systemd/system/pdg-probe81.service|644"
)

_plat_deploy_ios(){
  # 严格模式: 每个必需文件自己装、自己查, 不走 migrate_deploy_botfiles ——
  # 那是**幂等迁移**的语义(`install … || true`, 装不上就当没这回事, 下轮再补), 放在平台切换
  # 这种一次性事务里就成了洞: 注入 mitm_server.py 安装失败后命令照样 RC=0、platform=ios,
  # 而机器上既没有 mitm_server.py 也没有 pdg-mitm.service —— 一个半残的 iOS 现场。
  local ent src dst mode
  install -d -m755 /opt/pdg-bot || { echo "  创建 /opt/pdg-bot 失败"; return 1; }
  for ent in "${_PLAT_IOS_REQUIRED[@]}"; do
    IFS='|' read -r src dst mode <<< "$ent"
    if ! install -m"$mode" "$REPO_DIR/$src" "$dst" 2>/dev/null; then
      echo "  部署失败: $src → $dst"; return 1
    fi
    [[ -s "$dst" ]] || { echo "  部署后文件为空/不存在: $dst"; return 1; }
  done
  systemctl daemon-reload >/dev/null 2>&1 || { echo "  systemctl daemon-reload 失败"; return 1; }
  systemctl reset-failed pdg-probe81 >/dev/null 2>&1 || true
  systemctl enable --now pdg-probe81 >/dev/null 2>&1 || { echo "  启用 pdg-probe81 失败"; return 1; }
  # pdg-mitm unit 也照严格口径写(migrate_pdg_mitm_service 是幂等迁移, 失败同样是吞掉的)
  # shellcheck source=lib/units.sh
  source "$REPO_DIR/lib/units.sh" 2>/dev/null || { echo "  读不到 lib/units.sh"; return 1; }
  pdg_write_unit pdg_unit_pdg_mitm /etc/systemd/system/pdg-mitm.service \
    || { echo "  写 pdg-mitm.service 失败"; return 1; }
  systemctl daemon-reload >/dev/null 2>&1 || { echo "  systemctl daemon-reload 失败"; return 1; }
  systemctl reset-failed pdg-mitm >/dev/null 2>&1 || true
  systemctl enable --now pdg-mitm >/dev/null 2>&1 || { echo "  启用 pdg-mitm 失败"; return 1; }
  return 0
}

# 切换成功前的复核: 目标平台**该有的**在、**该没有的**不在。
# 部署那步逐个查过返回值了, 这里再看一遍最终现场 —— 中间任何一步把文件又弄没了(比如某条
# 幂等迁移顺手清理), 也能在返回 0 之前发现。
_plat_verify(){
  local p="$1" f miss=() extra=()
  if [[ "$p" == ios ]]; then
    local ent dst
    for ent in "${_PLAT_IOS_REQUIRED[@]}"; do
      dst="$(cut -d'|' -f2 <<< "$ent")"
      [[ -s "$dst" ]] || miss+=("$dst")
    done
    [[ -s /etc/systemd/system/pdg-mitm.service ]] || miss+=("/etc/systemd/system/pdg-mitm.service")
    [[ "$(systemctl is-active pdg-probe81 2>/dev/null)" == active ]] || miss+=("pdg-probe81(未运行)")
    [[ "$(systemctl is-active pdg-mitm 2>/dev/null)" == active ]] || miss+=("pdg-mitm(未运行)")
  else
    for f in /opt/pdg-bot/probe81.py /opt/pdg-bot/pdg-dot.mobileconfig.tmpl \
             /opt/pdg-bot/mitm_ca.py /opt/pdg-bot/mitm_server.py /opt/pdg-bot/mitm_wloc.py \
             /etc/systemd/system/pdg-probe81.service /etc/systemd/system/pdg-mitm.service; do
      [[ -e "$f" ]] && extra+=("$f")
    done
    [[ "$(systemctl is-active pdg-probe81 2>/dev/null)" == active ]] && extra+=("pdg-probe81(仍在运行)")
    [[ "$(systemctl is-active pdg-mitm 2>/dev/null)" == active ]] && extra+=("pdg-mitm(仍在运行)")
  fi
  if [[ ${#miss[@]} -gt 0 ]]; then
    echo "❌ 切到 $p 后这些必需项缺失: ${miss[*]}"; return 1
  fi
  if [[ ${#extra[@]} -gt 0 ]]; then
    echo "❌ 切到 $p 后这些 iOS 专属残留没清掉: ${extra[*]}"; return 1
  fi
  return 0
}

# 切平台: 全局锁 + 快照 + 就地备份, 任一步失败恢复原平台与原配置并返回非 0。
# 以前这里只写个标记就 run_all_migrations 并恒返回 0: Android→iOS 缺 probe81/描述文件模板,
# iOS→Android 的 nft 里 GMS 5228-5230 回不来、mihomo 配置里 MITM-OUT 还留着, 而命令还说"已确认"。
cmd_platform(){
  need_root platform
  local p="${1:-}" cur; cur="$(_pdg_platform)"
  if [[ "$p" != ios && "$p" != android ]]; then
    echo "用法: pdg platform <ios|android>"
    echo "  当前: $cur$( [[ -e /etc/privdns-gateway/platform.guessed ]] && echo "  ⚠️ 推测值, 未确认" )"
    echo "  确认后才会执行该平台的组件部署/清理(推测状态下一律不做破坏性清理)。"
    return 1
  fi
  _lock
  c_g "切换平台: $cur → $p"
  # 1) 先留快照。拿不到就别开始 —— 后面要改 nft、删/装 unit、重渲内核, 没有回退手段不能动手。
  cmd_snapshot >/dev/null 2>&1 || { echo "❌ 快照失败 → 中止切换(未改动任何东西)"; return 1; }
  # 2) 就地备份直接会被改写的几样(快照是整体回退, 这些用于精确还原)
  local wd; wd="$(mktemp -d)" || { echo "❌ 无法创建临时目录"; return 1; }
  local f
  for f in /etc/privdns-gateway/platform /etc/privdns-gateway/profile.env \
           /etc/privdns-gateway/mitm.json /etc/nftables.conf /etc/mihomo/config.yaml \
           /etc/mosdns/rules/mitm_hijack.txt; do
    if [[ ( -e "$f" || -L "$f" ) ]] \
       && ! cp -a "$f" "$wd/$(basename "$f")" 2>/dev/null; then
      echo "❌ 无法备份 $f → 中止切换(未改动任何东西)"
      rm -rf "$wd"
      return 1
    fi
  done
  # 2b) 平台专属文件也要能原样回去: 装上去的要删掉, 清掉的要放回来。
  # 只还原配置不管这些文件的话, 一次失败的 Android→iOS 会在盘上留下 probe81/描述文件模板/
  # MITM 模块和两个 unit —— 平台明明已经回滚成 android, 现场却是半个 iOS。
  # 备份**内容**而不只是记在不在: 文件本来就有(版本旧一点)时, install 会把它改写掉。
  local _PLAT_FILES=(
    /opt/pdg-bot/probe81.py
    /opt/pdg-bot/pdg-dot.mobileconfig.tmpl
    /opt/pdg-bot/mitm_ca.py
    /opt/pdg-bot/mitm_server.py
    /opt/pdg-bot/mitm_wloc.py
    /etc/systemd/system/pdg-probe81.service
    /etc/systemd/system/pdg-mitm.service
  )
  if ! mkdir -p "$wd/plat"; then
    echo "❌ 无法创建平台专属文件备份目录 → 中止切换(未改动任何东西)"
    rm -rf "$wd"
    return 1
  fi
  local _pf _key
  for _pf in "${_PLAT_FILES[@]}"; do
    _key="${_pf//\//_}"
    if [[ ( -e "$_pf" || -L "$_pf" ) ]] \
       && ! cp -a "$_pf" "$wd/plat/$_key" 2>/dev/null; then
      echo "❌ 无法备份平台专属文件 $_pf → 中止切换(未改动任何东西)"
      rm -rf "$wd"
      return 1
    fi
  done
  # 服务的启用/运行状态同样记下来(回滚后不能留下一个"unit 已删但还标着 enabled"的现场)
  # 只取第一行并在空值时兜底: systemctl 这些子命令是"既打印状态又用退出码表态", 拿
  # `cmd || echo disabled` 兜底会打印两遍, 多出来的那行会被下面的 read 当成新记录读走。
  local _psvc _pstate _pen _pac; _pstate=""
  for _psvc in pdg-probe81 pdg-mitm; do
    _pen="$(systemctl is-enabled "$_psvc" 2>/dev/null | head -1)"
    _pac="$(systemctl is-active  "$_psvc" 2>/dev/null | head -1)"
    _pstate="$_pstate$_psvc|${_pen:-disabled}|${_pac:-inactive}"$'\n'
  done
  _plat_rollback(){
    local g
    for g in platform profile.env mitm.json nftables.conf config.yaml mitm_hijack.txt; do
      case "$g" in
        platform|profile.env|mitm.json)
          if [[ -e "$wd/$g" ]]; then
            cp -a "$wd/$g" "/etc/privdns-gateway/$g"
          else
            rm -f "/etc/privdns-gateway/$g"
          fi;;
        nftables.conf) if [[ -e "$wd/$g" ]]; then
          local pnx; pnx="$(_pdg_nft_bin)"
          # shellcheck source=lib/nfttxn.sh
          source "$REPO_DIR/lib/nfttxn.sh" 2>/dev/null \
            && pdg_nft_atomic_install "$wd/$g" /etc/nftables.conf "$pnx" \
            && "$pnx" -f /etc/nftables.conf >/dev/null 2>&1 || true
        fi;;
        config.yaml)
          if [[ -e "$wd/$g" ]]; then cp -a "$wd/$g" /etc/mihomo/config.yaml
          else rm -f /etc/mihomo/config.yaml
          fi;;
        mitm_hijack.txt)
          if [[ -e "$wd/$g" ]]; then cp -a "$wd/$g" /etc/mosdns/rules/mitm_hijack.txt
          else rm -f /etc/mosdns/rules/mitm_hijack.txt
          fi;;
      esac
    done
    # 平台专属文件: 有备份的放回去, 本来不存在的删掉(这次新装的)
    local pf key
    for pf in "${_PLAT_FILES[@]}"; do
      key="${pf//\//_}"
      if [[ -e "$wd/plat/$key" || -L "$wd/plat/$key" ]]; then
        install -d "$(dirname "$pf")" 2>/dev/null || true
        cp -a "$wd/plat/$key" "$pf" 2>/dev/null || true
      else
        rm -f "$pf" 2>/dev/null || true
      fi
    done
    systemctl daemon-reload 2>/dev/null || true
    # 服务状态回到切换前: unit 已经不在了就只停不启
    local svc en ac
    while IFS='|' read -r svc en ac; do
      [[ -n "$svc" ]] || continue
      if [[ -e "/etc/systemd/system/$svc.service" ]] && [[ "$en" == enabled || "$ac" == active ]]; then
        systemctl reset-failed "$svc" >/dev/null 2>&1 || true
        if [[ "$ac" == active ]]; then
          systemctl enable --now "$svc" >/dev/null 2>&1 || true
        else
          systemctl enable "$svc" >/dev/null 2>&1 || true      # 切换前就是"开机启动但没在跑"
        fi
      else
        systemctl disable --now "$svc" >/dev/null 2>&1 || true
      fi
    done <<< "$_pstate"
    [[ -x /usr/local/libexec/pdg-quic-routing.sh ]] \
      && /usr/local/libexec/pdg-quic-routing.sh apply >/dev/null 2>&1 \
      && /usr/local/libexec/pdg-quic-routing.sh status >/dev/null 2>&1 || true
    systemctl restart "$(_pdg_core_svc)" mosdns >/dev/null 2>&1 || true
    c_y "已恢复到原平台 $cur 与原配置(含平台专属文件与服务状态; 快照仍在, 必要时可 sudo pdg rollback)。"
  }
  # 3) 落平台标记(platform 文件 + profile.env 同步)
  install -d -m700 /etc/privdns-gateway
  printf '%s\n' "$p" > /etc/privdns-gateway/platform || { _plat_rollback; rm -rf "$wd"; return 1; }
  rm -f /etc/privdns-gateway/platform.guessed
  _plat_write_profile "$p" || { c_y "profile.env 写入失败"; _plat_rollback; rm -rf "$wd"; return 1; }

  # 4) 按目标平台部署 / 清理组件
  if [[ "$p" == ios ]]; then
    if ! _plat_deploy_ios; then
      echo "❌ iOS 组件部署失败(probe81 / 描述文件模板 / pdg-probe81 服务)"
      _plat_rollback; rm -rf "$wd"; return 1
    fi
  else
    migrate_android_cleanup                     # 安全休眠 WLOC + 移除 iOS unit/模块/模板(保留地点与 CA)
  fi

  # 5) 防火墙按目标平台重建(Android 有 GMS 5228-5230, iOS 没有)。与迁移同一实现: 渲染 → 合并
  #    (用户其它表逐字节保留)→ nft -c → 应用, 任一步失败它自己会把现网还原。
  if ! _switchcore_nft mihomo; then
    echo "❌ 防火墙按新平台重建失败"
    _plat_rollback; rm -rf "$wd"; return 1
  fi

  # 6) Generate and validate before atomically installing the core candidate.
  local pcand="$wd/mihomo.candidate"
  if ! _pdg_render_mihomo_candidate "$pcand"; then
    echo "❌ 重新渲染 mihomo candidate 失败"
    _plat_rollback; rm -rf "$wd"; return 1
  fi
  if command -v mihomo >/dev/null 2>&1 && ! mihomo -t -d /etc/mihomo -f "$pcand" >/dev/null 2>&1; then
    echo "❌ 新平台的 mihomo 配置校验(mihomo -t)未过"
    _plat_rollback; rm -rf "$wd"; return 1
  fi
  _pdg_atomic_install_file "$pcand" /etc/mihomo/config.yaml 600 \
    || { echo "❌ Mihomo candidate 原子落盘失败"; _plat_rollback; rm -rf "$wd"; return 1; }
  systemctl restart "$(_pdg_core_svc)" >/dev/null 2>&1 || true
  systemctl restart mosdns >/dev/null 2>&1 || true

  # 7) 校验: nft 配置、核心服务、平台必需服务
  # nft 的位置与扫描器同一份判据(_pdg_nft_bin): `command -v nft` 只看 PATH, 而 nft 装在
  # /usr/sbin —— PATH 里没有 sbin 时这条校验会被整条跳过, 等于不校验就放行。
  local _nftexe; _nftexe="$(_pdg_nft_bin)"
  if [[ -n "$_nftexe" ]] && ! "$_nftexe" -c -f /etc/nftables.conf >/dev/null 2>&1; then
    echo "❌ 切换后的 nftables 配置校验未过"
    _plat_rollback; rm -rf "$wd"; return 1
  fi
  /usr/local/libexec/pdg-quic-routing.sh status >/dev/null 2>&1 || {
    echo "❌ 切换后的 QUIC routing/profile 不一致"
    _plat_rollback; rm -rf "$wd"; return 1
  }
  if [[ "$(_pdg_bot_cred)" == partial ]]; then
    echo "❌ Bot 凭据只配了一项(token 与允许 id 必须成对)—— 这是配置错误, 先用 pdg-set-token"
    echo "   补齐或把两项都留空(彻底禁用 bot), 再切平台。"
    _plat_rollback; rm -rf "$wd"; return 1
  fi
  local svc bad=()
  # 必需服务集按凭据状态算: 没配 bot 的机器不该因为 pdg-bot 没跑而切不了平台
  for svc in $(_pdg_required_svcs); do
    _core_kernel_stable "$svc" || bad+=("$svc")
  done
  if [[ ${#bad[@]} -gt 0 ]]; then
    echo "❌ 切换后这些服务未稳定运行: ${bad[*]}"
    _plat_rollback; rm -rf "$wd"; return 1
  fi
  # 8) 返回 0 之前复核现场: 目标平台该有的都在、该没有的都清干净了
  if ! _plat_verify "$p"; then
    _plat_rollback; rm -rf "$wd"; return 1
  fi
  # 关键迁移必须在**删掉回滚材料、宣布成功之前**跑完: 它失败就走 _plat_rollback,
  # 而 _plat_rollback 依赖 $wd 里的材料 —— 顺序颠倒的话就只能 best-effort 了。
  if ! migrate_ios_gms_cleanup; then
    echo "❌ iOS GMS 残留清理失败(详见上方), 平台切换回退"
    _plat_rollback; rm -rf "$wd"; return 1
  fi
  rm -rf "$wd"
  run_all_migrations || true                    # 其余平台无关的幂等迁移照常跑(GMS 那步已单独跑过)
  c_g "平台已确认: $cur → $p"
  if [[ -x /opt/pdg-bot/doctor.py ]] || [[ -f /opt/pdg-bot/doctor.py ]]; then
    python3 /opt/pdg-bot/doctor.py || c_y "自检有未通过项(见上), 平台切换本身已完成。"
  fi
  return 0
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

# 显式迁移: 先上锁、先快照, 再跑幂等迁移, 并记一笔审计(source=cli, op=migrate)。
# 边界说明(不夸大): 迁移内部仍是各自的就地改写 + 局部还原, 尚未逐文件走事务核心的
# before-image —— 那属于 5.1B。这里保证的是"迁移前一定有可回滚的快照, 且不会在用户
# 不知情时发生", 失败时明确指出用哪一份快照回退。
cmd_migrate(){
  need_root migrate; _lock
  c_g "迁移前留快照…"
  if ! cmd_snapshot >/dev/null 2>&1 || [[ -z "$_PDG_SNAP_CREATED" ]]; then
    c_y "❌ 快照失败, 拒绝在无法回滚的前提下迁移。"; return 1
  fi
  local snap="$_PDG_SNAP_CREATED" rc=0
  run_all_migrations || rc=$?
  if [[ $rc == 0 ]]; then
    _tx_audit cli migrate COMMITTED "snapshot=$snap"
    c_g "✅ 迁移完成(快照: $snap)"
    return 0
  fi
  _tx_audit cli migrate ROLLBACK_FAILED "snapshot=$snap"
  c_y "❌ 迁移失败。快照仍在: $snap"
  c_y "   需要回退时: sudo pdg rollback --dir $snap"
  return 1
}

# 往事务审计里补一条记录 —— CLI 侧那些尚未逐文件事务化的操作, 至少要记在同一本账上。
_tx_audit(){
  local m
  for m in "$REPO_DIR/deploy/bot/pdgtx.py" /opt/pdg-bot/pdgtx.py; do
    [[ -f "$m" ]] || continue
    python3 - "$m" "$1" "$2" "$3" "${4:-}" <<'TXAUDIT' 2>/dev/null || true
import importlib.util, json, os, sys, time
spec = importlib.util.spec_from_file_location("pdgtx", sys.argv[1])
tx = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tx)
rec = {"ts": time.time(), "txid": tx.new_txid(), "source": sys.argv[2], "op": sys.argv[3],
       "mode": "normal", "state": sys.argv[4], "targets": [], "services": [], "error": "",
       "note": tx.redact(sys.argv[5]), "schema_version": tx.SCHEMA_VERSION}
try:
    os.makedirs(os.path.dirname(tx.AUDIT), mode=0o700, exist_ok=True)
    with open(tx.AUDIT, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
except OSError:
    pass
TXAUDIT
    return 0
  done
}

# pdg tx: 查看/恢复事务。list/show 是只读的(不取写锁); recover 自己在核心里取同一把锁。
cmd_tx(){
  need_root tx
  local m
  for m in "$REPO_DIR/deploy/bot/pdgtx.py" /opt/pdg-bot/pdgtx.py; do
    [[ -f "$m" ]] && { python3 "$m" "$@"; return $?; }
  done
  echo "❌ 找不到 pdgtx.py(事务核心缺失)"; return 1
}

# 5.1: **取消命令分派前的隐藏迁移**。
# 以前这里对所有管理类命令(含 update)先跑一遍 run_all_migrations —— 那发生在 _lock 之前、
# 也在 cmd_update 打快照之前: 迁移会改 unit / nft / mosdns, 于是"更新失败回滚"只能回到
# **已经被迁移改过**的现网, 而用户以为回到了操作前。菜单、restart 这类命令更不该在用户
# 不知情时改配置。
# 现在迁移只有两个入口, 都在锁与快照之后: cmd_update 装好新脚本后调用的 `pdg __migrate`,
# 以及用户显式运行的 `sudo pdg migrate`(先上锁、先快照, 并记一笔审计)。

case "${1:-menu}" in
  menu|"")       menu;;
  __migrate)     need_root __migrate; run_all_migrations;;   # 内部: cmd_update 装好新脚本后据此跑"新版"迁移
  migrate)       cmd_migrate;;
  tx)            shift || true; cmd_tx "$@";;
  status|st)     cmd_status;;
  doctor|dr)     shift || true; cmd_doctor "${1:-}";;
  update|up)     shift || true; cmd_update "${1:-}";;
  migrate-fw)    need_root migrate-fw; migrate_firewall_to_pdg;;
  snapshot|snap) cmd_snapshot;;
  rollback)
    shift || true
    if [[ $# -gt 0 ]]; then cmd_rollback "$@"; else cmd_rollback 0; fi
    ;;
  token)         cmd_token;;
  web)           shift || true; cmd_web "${1:-status}" "${@:2}";;
  restart)       cmd_restart;;
  log|logs)      shift || true; cmd_log "${1:-40}";;
  traffic|tr)    cmd_traffic;;
  ios)           cmd_ios;;
  report)        shift || true; cmd_report "$@";;
  detect-cidr|cidr) shift || true; cmd_detect_cidr "${1:-}";;
  platform)      shift || true; cmd_platform "${1:-}";;
  hijack-mode)   shift || true; cmd_hijack_mode "${1:-}";;
  uninstall|rm)  shift || true; cmd_uninstall "${1:-}";;
  *) echo "用法: pdg [menu|status|doctor [--json|--deep]|update [--dry-run]|snapshot|rollback [n]|web <setup|enable|disable|status|password>|token|restart|log [n]|traffic|ios(仅 iOS)|report [--redact-ip|--full]|detect-cidr|platform <ios|android>|hijack-mode <all|gfw>|migrate|migrate-fw|tx <list|show|recover|abort>|uninstall [--purge]]";;
esac
