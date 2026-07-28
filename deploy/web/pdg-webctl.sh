#!/usr/bin/env bash
# Lifecycle wrapper for the optional, default-disabled PDG Web management UI.
set -euo pipefail

CONFIG=/etc/privdns-gateway/web.json
SETUP=/opt/pdg-web/pdg-web-setup.py
UNIT=/etc/systemd/system/pdg-web.service
FIREWALL_MODE_FILE=/etc/privdns-gateway/firewall-mode
PROFILE_ENV=/etc/privdns-gateway/profile.env
ACTIVE_BACKUP=""
KEEP_BACKUP=0

die(){ echo "[x] $*" >&2; exit 1; }
need_root(){ [[ $EUID -eq 0 ]] || die "请用 root 运行: sudo pdg web $*"; }
have_config(){ [[ -f "$CONFIG" && ! -L "$CONFIG" ]]; }

cleanup(){
  if [[ -n "$ACTIVE_BACKUP" && "$KEEP_BACKUP" != 1 ]]; then
    rm -f -- "$ACTIVE_BACKUP"
  fi
}
trap cleanup EXIT

firewall_mode(){
  local mode="" values="" count=0
  if [[ -r "$FIREWALL_MODE_FILE" && ! -L "$FIREWALL_MODE_FILE" ]]; then
    IFS= read -r mode <"$FIREWALL_MODE_FILE" || true
  elif [[ -r "$PROFILE_ENV" && ! -L "$PROFILE_ENV" ]]; then
    values="$(sed -n 's/^[[:space:]]*PDG_FIREWALL_MODE=//p' "$PROFILE_ENV")"
    count="$(printf '%s\n' "$values" | grep -c . || true)"
    [[ "$count" == 1 ]] && mode="$(printf '%s\n' "$values")"
  fi
  case "$mode" in
    managed|external) printf '%s\n' "$mode" ;;
    *) printf '%s\n' unknown ;;
  esac
}

guidance(){
  local mode
  mode="$(firewall_mode)"
  python3 - "$CONFIG" "$mode" <<'PY'
import ipaddress
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    config = json.load(stream)
mode = sys.argv[2]
listen = str(ipaddress.ip_address(config["listen"]))
interface = "[%s]" % listen if ipaddress.ip_address(listen).version == 6 else listen
port = config["port"]
trusted = ", ".join(config["trusted_cidrs"])
host = config["allowed_hosts"][0]
print("服务接口: %s:%d" % (interface, port))
print("HTTPS Host: %s" % host)
print("可信来源 CIDR: %s" % trusted)
if ipaddress.ip_address(listen).is_loopback:
    print("访问方式: 仅本机监听；官方推荐路径是 SSH 隧道。")
    print("   Web 只按 socket 地址鉴权且忽略 X-Forwarded-For；若另设反向代理，代理本身必须独立执行来源 ACL。")
elif mode == "external":
    print("访问方式: external 模式直连该服务接口；外部防火墙须只允许上述 CIDR 到达 TCP/%d。" % port)
elif mode == "managed":
    print("访问方式: 当前为 managed input policy；非 loopback Web 入口不会被本项目自动接入。")
    print("   官方受支持路径是改回 loopback + SSH 隧道；否则须由管理员显式集成该 service interface。")
else:
    print("访问方式: 防火墙模式未知；在管理员确认 input policy 前不要暴露该接口。")
print("⚠️ pdg web 从不修改 nftables、云安全组或整机 input policy。")
if not ipaddress.ip_address(listen).is_loopback:
    print("   服务接口声明必须使用上面报告的 TCP/%d 和可信 CIDR，不能硬编码示例端口。" % port)
PY
}

validate(){
  have_config || die "尚未配置 $CONFIG；先运行 sudo pdg web setup"
  [[ -x "$SETUP" ]] || die "缺少 $SETUP；请先运行 sudo pdg update"
  python3 "$SETUP" --validate-only
}

config_is_valid(){
  have_config && [[ -x "$SETUP" ]] \
    && python3 "$SETUP" --validate-only >/dev/null 2>&1
}

web_stable(){
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

prepare_active_backup(){
  ACTIVE_BACKUP=""
  systemctl is-active --quiet pdg-web 2>/dev/null || return 0
  have_config || die "pdg-web 正在运行但现有配置缺失或不是普通文件；拒绝覆盖"
  ACTIVE_BACKUP="$(mktemp /etc/privdns-gateway/.web.json.before.XXXXXX)" \
    || die "无法创建现有 Web 配置的 root-only 临时备份"
  if ! install -o root -g root -m 0600 "$CONFIG" "$ACTIVE_BACKUP"; then
    rm -f -- "$ACTIVE_BACKUP"
    ACTIVE_BACKUP=""
    die "无法备份现有 Web 配置；未执行修改"
  fi
}

restore_active_backup(){
  local restore_tmp
  [[ -n "$ACTIVE_BACKUP" && -f "$ACTIVE_BACKUP" ]] || return 1
  restore_tmp="$(mktemp /etc/privdns-gateway/.web.json.restore.XXXXXX)" \
    || { KEEP_BACKUP=1; return 1; }
  if ! install -o root -g root -m 0600 "$ACTIVE_BACKUP" "$restore_tmp" \
     || ! mv -f -- "$restore_tmp" "$CONFIG"; then
    rm -f -- "$restore_tmp"
    KEEP_BACKUP=1
    return 1
  fi
  systemctl reset-failed pdg-web >/dev/null 2>&1 || true
  if systemctl restart pdg-web >/dev/null 2>&1 && web_stable; then
    rm -f -- "$ACTIVE_BACKUP"
    ACTIVE_BACKUP=""
    return 0
  fi
  KEEP_BACKUP=1
  return 1
}

restart_or_restore(){
  if systemctl restart pdg-web >/dev/null 2>&1 && web_stable; then
    rm -f -- "$ACTIVE_BACKUP"
    ACTIVE_BACKUP=""
    return 0
  fi
  if restore_active_backup; then
    die "新配置未能稳定启动；已原子还原旧配置并确认 pdg-web 恢复运行"
  fi
  die "新配置未能稳定启动，旧配置还原或服务恢复也失败；请立即检查 journalctl -u pdg-web"
}

rollback_failed_enable(){
  local rollback_failed=0
  systemctl disable --now pdg-web >/dev/null 2>&1 || true
  if systemctl is-active --quiet pdg-web 2>/dev/null; then
    rollback_failed=1
  fi
  if systemctl is-enabled --quiet pdg-web 2>/dev/null; then
    rollback_failed=1
  fi
  [[ "$rollback_failed" == 0 ]]
}

cmd="${1:-status}"
shift || true
case "$cmd" in
  setup)
    need_root setup
    [[ -x "$SETUP" ]] || die "缺少 $SETUP；请先安装/更新 PrivDNS Gateway"
    was_active=0
    systemctl is-active --quiet pdg-web 2>/dev/null && was_active=1
    [[ "$was_active" == 1 ]] && prepare_active_backup
    if ! python3 "$SETUP" "$@"; then
      if [[ "$was_active" == 1 ]] && restore_active_backup; then
        die "Web setup 未完成；已原子还原旧配置并确认 pdg-web 恢复运行"
      fi
      [[ "$was_active" == 1 ]] \
        && die "Web setup 未完成，旧配置还原或服务恢复也失败；请立即检查 journalctl -u pdg-web"
      die "Web setup 未完成；没有运行中的旧实例需要恢复"
    fi
    [[ "$was_active" == 1 ]] && restart_or_restore
    guidance
    ;;
  enable)
    need_root enable
    [[ -f "$UNIT" ]] || die "缺少 $UNIT；请先运行 sudo pdg update"
    validate
    systemctl daemon-reload
    if ! systemctl enable --now pdg-web >/dev/null 2>&1 \
       || ! web_stable; then
      rollback_failed_enable \
        || die "pdg-web 启动失败，且未能恢复 disabled/inactive；请立即检查 systemctl status pdg-web"
      die "pdg-web 启动失败；已恢复 disabled/inactive，请看 journalctl -u pdg-web"
    fi
    echo "✅ pdg-web 已启用并确认运行。"
    guidance
    ;;
  disable)
    need_root disable
    systemctl disable --now pdg-web 2>/dev/null || true
    if systemctl is-active --quiet pdg-web 2>/dev/null; then
      die "pdg-web 仍在运行，拒绝宣称已禁用"
    fi
    if systemctl is-enabled --quiet pdg-web 2>/dev/null; then
      die "pdg-web 仍被设为开机启动，拒绝宣称已禁用"
    fi
    echo "✅ pdg-web 已禁用；root-only 配置保留。"
    if config_is_valid; then
      guidance
    elif have_config; then
      echo "⚠️ 保留的 Web 配置无效；修复前不要重新启用。"
    fi
    ;;
  status)
    if [[ $EUID -ne 0 ]]; then
      echo "配置: unreadable/unknown（root-only；请用 sudo pdg web status 查看）"
    elif config_is_valid; then
      echo "配置: valid ($CONFIG)"
      guidance
    elif have_config; then
      echo "配置: INVALID ($CONFIG)"
    else
      echo "配置: absent（默认禁用；运行 sudo pdg web setup）"
    fi
    enabled_state="$(systemctl is-enabled pdg-web 2>/dev/null || true)"
    active_state="$(systemctl is-active pdg-web 2>/dev/null || true)"
    echo "启用: ${enabled_state:-disabled}"
    echo "运行: ${active_state:-inactive}"
    ;;
  password)
    need_root password
    validate
    was_active=0
    systemctl is-active --quiet pdg-web 2>/dev/null && was_active=1
    [[ "$was_active" == 1 ]] && prepare_active_backup
    if ! python3 "$SETUP" --password-only "$@"; then
      if [[ "$was_active" == 1 ]] && restore_active_backup; then
        die "密码更新未完成；已原子还原旧配置并确认 pdg-web 恢复运行"
      fi
      [[ "$was_active" == 1 ]] \
        && die "密码更新未完成，旧配置还原或服务恢复也失败；请立即检查 journalctl -u pdg-web"
      die "密码更新未完成；没有运行中的旧实例需要恢复"
    fi
    [[ "$was_active" == 1 ]] && restart_or_restore
    echo "✅ 密码已更新；所有旧会话均已失效。"
    ;;
  *)
    die "用法: pdg web setup|enable|disable|status|password"
    ;;
esac
