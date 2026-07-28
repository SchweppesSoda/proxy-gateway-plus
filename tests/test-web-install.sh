#!/usr/bin/env bash
# Static lifecycle regressions for the optional, default-disabled PDG Web UI.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
pass=0 fail=0
ok(){ echo "[OK]   $1"; pass=$((pass + 1)); }
bad(){ echo "[FAIL] $1"; fail=$((fail + 1)); }
has(){ grep -qF "$2" "$ROOT/$1"; }

required=(
  deploy/web/pdg-web.py
  deploy/web/pdgcontrol.py
  deploy/web/pdg-web-setup.py
  deploy/web/pdgwebconfig.py
  deploy/web/pdg-webctl.sh
  deploy/web/pdg-web.service
  deploy/web/static/index.html
  deploy/web/static/app.js
  deploy/web/static/style.css
  deploy/web/static/manifest.webmanifest
  deploy/web/static/icon.svg
)
missing=()
for path in "${required[@]}"; do
  [[ -f "$ROOT/$path" ]] || missing+=("$path")
done
[[ ${#missing[@]} -eq 0 ]] \
  && ok "Web 发布清单完整" \
  || bad "缺少 Web 发布文件: ${missing[*]}"

syntax_ok=1
for path in install.sh uninstall.sh deploy/bot/pdg.sh \
            deploy/cert/99-reload-cert.deploy-hook.sh deploy/web/pdg-webctl.sh; do
  bash -n "$ROOT/$path" || syntax_ok=0
done
[[ "$syntax_ok" == 1 ]] && ok "相关 shell 脚本通过 bash -n" || bad "shell 语法错误"

install_ok=1
for path in pdg-web.py pdgcontrol.py pdg-web-setup.py pdgwebconfig.py index.html app.js style.css \
            manifest.webmanifest icon.svg pdg-webctl.sh pdg-web.service; do
  grep -qF "deploy/web/${path}" "$ROOT/install.sh" \
    || grep -qF "deploy/web/static/${path}" "$ROOT/install.sh" \
    || install_ok=0
done
has install.sh "_dir_txn_record /etc/mosdns /etc/sing-box /etc/mihomo /opt/pdg-bot /opt/pdg-web" \
  || install_ok=0
[[ "$install_ok" == 1 ]] \
  && ok "install 事务清单部署 Web 代码、静态资源、ctl 和 unit" \
  || bad "install Web 清单或目录事务不完整"

if grep -Eq '^[[:space:]]*systemctl[[:space:]]+(enable[[:space:]]+--now|start)[[:space:]]+pdg-web([[:space:]]|$)' \
     "$ROOT/install.sh"; then
  bad "install 不得自动启用/启动 pdg-web"
else
  ok "install 保持 pdg-web 默认 disabled/inactive"
fi

install_state_ok=1
for marker in \
  "WEB_WAS_ENABLED=0; WEB_WAS_ACTIVE=0" \
  "systemctl is-enabled --quiet pdg-web" \
  "systemctl is-active --quiet pdg-web" \
  'if [[ "$WEB_WAS_ENABLED" == 1 || "$WEB_WAS_ACTIVE" == 1 ]]' \
  'if [[ "$WEB_WAS_ACTIVE" == 1 ]]' \
  "_web_service_stable" \
  "_restore_web_service_state" \
  'chown root:root "$CERT_DIR/fullchain.pem" "$CERT_DIR/privkey.pem"' \
  '[[ "$WEB_WAS_ACTIVE" == 1 ]] && PLAT_SVCS+=(pdg-web)'; do
  grep -qF "$marker" "$ROOT/install.sh" || install_state_ok=0
done
[[ "$install_state_ok" == 1 ]] \
  && ok "覆盖安装捕获 Web 状态、校验后条件重启，并纳入稳定门和失败还原" \
  || bad "覆盖安装的 Web 状态保持/稳定回滚契约不完整"

unit="$ROOT/deploy/web/pdg-web.service"
unit_ok=1
for exact in \
  "ConditionPathExists=/etc/privdns-gateway/web.json" \
  "User=root" "Group=root" "UMask=0077" \
  "ExecStart=/usr/bin/python3 /opt/pdg-web/pdg-web.py" \
  "Restart=on-failure" "NoNewPrivileges=true" "PrivateTmp=true"; do
  grep -qxF "$exact" "$unit" || unit_ok=0
done
[[ "$unit_ok" == 1 ]] && ok "systemd unit 契约与必要加固完整" || bad "systemd unit 契约缺失"

ctl="$ROOT/deploy/web/pdg-webctl.sh"
ctl_ok=1
for command in setup enable disable status password; do
  grep -qE "^[[:space:]]*${command}\\)" "$ctl" || ctl_ok=0
done
grep -qF "systemctl enable --now pdg-web" "$ctl" || ctl_ok=0
grep -qF "systemctl disable --now pdg-web" "$ctl" || ctl_ok=0
grep -qF "从不修改 nftables、云安全组或整机 input policy" "$ctl" || ctl_ok=0
grep -qF "restore_active_backup" "$ctl" || ctl_ok=0
grep -qF "rollback_failed_enable" "$ctl" || ctl_ok=0
grep -qF "Web 只按 socket 地址鉴权且忽略 X-Forwarded-For" "$ctl" || ctl_ok=0
grep -qF "external 模式直连该服务接口" "$ctl" || ctl_ok=0
grep -qF "当前为 managed input policy" "$ctl" || ctl_ok=0
grep -qF "unreadable/unknown" "$ctl" || ctl_ok=0
[[ "$ctl_ok" == 1 ]] && ok "pdg web 生命周期命令齐全并输出边界提示" || bad "pdg-webctl 契约不完整"

if bash "$ROOT/tests/test-webctl-failure.sh"; then
  ok "setup 子进程晚失败时还原旧 active 配置；还原失败时保留 root-only 证据"
else
  bad "pdg-webctl setup 晚失败恢复测试失败"
fi

if grep -Eq '^[[:space:]]*(sudo[[:space:]]+)?(nft|iptables|ip6tables|ufw|firewall-cmd)([[:space:]]|$)' \
     "$ROOT"/deploy/web/pdg-web-setup.py "$ROOT"/deploy/web/pdg-webctl.sh; then
  bad "Web setup/ctl 不得执行防火墙命令"
else
  ok "Web setup/ctl 不修改主机或云防火墙"
fi

inventory_ok=1
for exact in \
  "opt/pdg-web/pdg-web.py" "opt/pdg-web/pdgcontrol.py" \
  "opt/pdg-web/pdg-web-setup.py" "opt/pdg-web/pdgwebconfig.py" \
  "opt/pdg-web/static/manifest.webmanifest" \
  "usr/local/bin/pdg-webctl" "etc/systemd/system/pdg-web.service"; do
  grep -qF "$exact" "$ROOT/deploy/bot/pdg.sh" || inventory_ok=0
done
grep -qF "python3 /opt/pdg-web/pdg-web-setup.py --validate-only" \
  "$ROOT/deploy/bot/pdg.sh" || inventory_ok=0
[[ "$inventory_ok" == 1 ]] \
  && ok "update/snapshot/rollback 清单跟踪 Web 且更新时校验配置" \
  || bad "update/snapshot/rollback Web 清单不完整"

purge_line="$(grep -nF 'if [[ "${1:-}" == "--purge" ]]' "$ROOT/uninstall.sh" | head -n1 | cut -d: -f1)"
config_remove_line="$(grep -nF 'rm -f /etc/privdns-gateway/web.json' "$ROOT/uninstall.sh" | head -n1 | cut -d: -f1)"
if has uninstall.sh "rm -rf /opt/pdg-web" \
   && has uninstall.sh "rm -f /usr/local/bin/pdg-webctl" \
   && [[ -n "$purge_line" && -n "$config_remove_line" ]] \
   && (( config_remove_line > purge_line )); then
  ok "普通卸载移除 Web 代码并保留配置，purge 才移除认证配置"
else
  bad "uninstall 的 Web 保留/purge 语义错误"
fi

hook="$ROOT/deploy/cert/99-reload-cert.deploy-hook.sh"
if grep -qF '[[ -f /etc/privdns-gateway/web.json && ! -L /etc/privdns-gateway/web.json ]] || return 0' "$hook" \
   && grep -qF 'systemctl is-active --quiet pdg-web' "$hook" \
   && grep -qF 'systemctl restart pdg-web' "$hook" \
   && grep -qF 'chown root:root "$CERT_DIR/fullchain.pem" "$CERT_DIR/privkey.pem"' "$hook"; then
  ok "证书 hook 只重启已配置且 active 的 pdg-web"
else
  bad "证书 hook 的 pdg-web 条件重载契约缺失"
fi

echo "────────────────────────────────────────"
echo "通过 $pass, 失败 $fail"
[[ "$fail" == 0 ]]
