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
  deploy/web/pdg-web-job.py
  deploy/web/pdgcontrol.py
  deploy/web/pdgconfigio.py
  deploy/web/pdg-web-setup.py
  deploy/web/pdgwebconfig.py
  deploy/web/pdg-webctl.sh
  deploy/web/pdg-web.service
  deploy/web/static/index.html
  deploy/web/static/theme.js
  deploy/web/static/app.js
  deploy/web/static/style.css
  deploy/web/static/manifest.webmanifest
  deploy/web/static/icon.svg
  deploy/web/static/templates/mihomo-import.example.yaml
  deploy/web/static/templates/mosdns-import.example.yaml
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
for path in pdg-web.py pdg-web-job.py pdgcontrol.py pdgconfigio.py pdg-web-setup.py pdgwebconfig.py index.html theme.js app.js style.css \
            manifest.webmanifest icon.svg pdg-webctl.sh pdg-web.service; do
  grep -qF "deploy/web/${path}" "$ROOT/install.sh" \
    || grep -qF "deploy/web/static/${path}" "$ROOT/install.sh" \
    || install_ok=0
done
for template in mihomo-import.example.yaml mosdns-import.example.yaml; do
  grep -qF "deploy/web/static/templates/${template}" "$ROOT/install.sh" || install_ok=0
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
  "opt/pdg-web/pdg-web.py" "opt/pdg-web/pdg-web-job.py" "opt/pdg-web/pdgcontrol.py" \
  "opt/pdg-web/pdgconfigio.py" \
  "opt/pdg-web/pdg-web-setup.py" "opt/pdg-web/pdgwebconfig.py" \
  "opt/pdg-web/static/theme.js" \
  "opt/pdg-web/static/manifest.webmanifest" \
  "opt/pdg-web/static/templates/mihomo-import.example.yaml" \
  "opt/pdg-web/static/templates/mosdns-import.example.yaml" \
  "usr/local/bin/pdg-webctl" "etc/systemd/system/pdg-web.service"; do
  grep -qF "$exact" "$ROOT/deploy/bot/pdg.sh" || inventory_ok=0
done
for exact in \
  "opt/pdg-web/static/templates/mihomo-import.example.yaml" \
  "opt/pdg-web/static/templates/mosdns-import.example.yaml"; do
  [[ "$(grep -cF "$exact" "$ROOT/deploy/bot/pdg.sh")" -ge 2 ]] \
    || inventory_ok=0
done
for template in mihomo-import.example.yaml mosdns-import.example.yaml; do
  grep -qF "deploy/web/static/templates/${template}" \
    "$ROOT/deploy/bot/pdg.sh" || inventory_ok=0
done
grep -qF "rmdir /opt/pdg-web/static/templates /opt/pdg-web/static /opt/pdg-web" \
  "$ROOT/deploy/bot/pdg.sh" || inventory_ok=0
grep -qF "python3 /opt/pdg-web/pdg-web-setup.py --validate-only" \
  "$ROOT/deploy/bot/pdg.sh" || inventory_ok=0
grep -qF "apt-get install -y -qq python3-yaml" "$ROOT/deploy/bot/pdg.sh" \
  || inventory_ok=0
grep -qF "python3 -c 'import yaml'" "$ROOT/deploy/bot/pdg.sh" \
  || inventory_ok=0
grep -qF "python3-yaml" "$ROOT/install.sh" || inventory_ok=0
grep -qF "/var/lib/privdns-gateway/web-imports" "$ROOT/uninstall.sh" \
  || inventory_ok=0
[[ "$inventory_ok" == 1 ]] \
  && ok "update/snapshot/rollback 清单跟踪 Web 且更新时校验配置" \
  || bad "update/snapshot/rollback Web 清单不完整"

template_contract_ok=1
template_python="$(command -v python3 || command -v python || true)"
if [[ -n "$template_python" ]]; then
  "$template_python" - "$ROOT/deploy/singbox/config.json.tmpl" \
    "$ROOT/deploy/mosdns/config.yaml" \
    "$ROOT/deploy/web/static/templates/mosdns-import.example.yaml" <<'PY' \
    || template_contract_ok=0
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    model = json.load(stream)
assert model["_pdg"] == {
    "schema": 3,
    "policy-groups": [],
    "mihomo": {
        "proxy-providers": {},
        "rule-providers": {},
        "advanced": {},
        "managed-files": {},
    },
}
assert model["outbounds"] == [{"type": "direct", "tag": "JP"}]
assert model["route"]["final"] == "JP"
with open(sys.argv[2], encoding="utf-8") as stream:
    managed_mosdns = stream.read()
with open(sys.argv[3], encoding="utf-8") as stream:
    import_example = stream.read()
assert import_example[import_example.index("log:\n"):] == managed_mosdns
PY
else
  template_contract_ok=0
fi
mihomo_template="$ROOT/deploy/web/static/templates/mihomo-import.example.yaml"
for marker in proxies: proxy-providers: proxy-groups: rule-providers: rules: \
              dns: tun: sniffer:; do
  grep -qxF "$marker" "$mihomo_template" || template_contract_ok=0
done
grep -qE '^mixed-port:[[:space:]]+[0-9]+' "$mihomo_template" \
  || template_contract_ok=0
grep -qF "They are ignored" "$mihomo_template" || template_contract_ok=0
mosdns_template="$ROOT/deploy/web/static/templates/mosdns-import.example.yaml"
for marker in remote_upstream local_upstream unlock_upstream geosite_unlock \
              geosite_cn npn_clients hijack_set explicit_hijack force_hijack \
              ecs_china ecs_neutral has_resp client_limiter lazy_cache \
              force_hijack_seq internal_sequence main_sequence \
              udp_server tcp_server dot_server; do
  grep -qF -- "- tag: $marker" "$mosdns_template" || template_contract_ok=0
done
for placeholder in __SERVER_IP__ __INTERNAL_CIDR__ __CERT_DIR__ \
                   __HIJACK_SET_FILE__ __MOSDNS_CACHE__; do
  grep -qF "$placeholder" "$mosdns_template" || template_contract_ok=0
done
[[ "$template_contract_ok" == 1 ]] \
  && ok "模型 v3 与 Mihomo/MosDNS 导入模板结构完整" \
  || bad "模型 v3 或导入模板结构不完整"

aggregate_inventory_ok=1
for exact in \
  "etc/mosdns/rules/ruleset_direct.txt" \
  "etc/mosdns/rules/ruleset_hijack.txt"; do
  grep -qF "$exact" "$ROOT/deploy/bot/pdg.sh" || aggregate_inventory_ok=0
done
grep -qF ': > /etc/mosdns/rules/ruleset_hijack.txt' \
  "$ROOT/install.sh" || aggregate_inventory_ok=0
grep -qF 'p="$rsdirect_member" -v q="$rshijack_member"' \
  "$ROOT/deploy/bot/pdg.sh" || aggregate_inventory_ok=0
grep -qF 'python3 - "$work/config.candidate" "$agg" "$hijagg"' \
  "$ROOT/deploy/bot/pdg.sh" || aggregate_inventory_ok=0
grep -qF 's = ensure_domain_set_file(s, "explicit_hijack", hijagg)' \
  "$ROOT/deploy/bot/pdg.sh" || aggregate_inventory_ok=0
[[ "$aggregate_inventory_ok" == 1 ]] \
  && ok "快照回滚与安装清单同时跟踪并重建 direct/hijack 规则集 DNS 聚合" \
  || bad "规则集 DNS 聚合生命周期清单不完整"

capture_source="$(awk '
  /^_pdg_capture_ruleset_migration_before\(\)\{/ { active=1 }
  active { print }
  active && /^}$/ { exit }
' "$ROOT/deploy/bot/pdg.sh")"
capture_root="$(mktemp -d)"
capture_ok=1
if [[ -z "$capture_source" || -z "$capture_root" ]]; then
  capture_ok=0
else
  eval "$capture_source"
  printf 'config-before\n' >"$capture_root/config"
  mkdir "$capture_root/absent" "$capture_root/present"
  _pdg_capture_ruleset_migration_before \
    "$capture_root/absent" "$capture_root/config" \
    "$capture_root/direct" "$capture_root/hijack" 0 0 \
    || capture_ok=0
  [[ -f "$capture_root/absent/config.before" \
     && ! -e "$capture_root/absent/direct.before" \
     && ! -e "$capture_root/absent/hijack.before" ]] || capture_ok=0
  printf 'direct-before\n' >"$capture_root/direct"
  printf 'hijack-before\n' >"$capture_root/hijack"
  _pdg_capture_ruleset_migration_before \
    "$capture_root/present" "$capture_root/config" \
    "$capture_root/direct" "$capture_root/hijack" 1 1 \
    || capture_ok=0
  cmp -s "$capture_root/config" "$capture_root/present/config.before" \
    || capture_ok=0
  cmp -s "$capture_root/direct" "$capture_root/present/direct.before" \
    || capture_ok=0
  cmp -s "$capture_root/hijack" "$capture_root/present/hijack.before" \
    || capture_ok=0
  restore_source="$(awk '
    /^_pdg_restore_ruleset_migration_before\(\)\{/ { active=1 }
    active { print }
    active && /^}$/ { exit }
  ' "$ROOT/deploy/bot/pdg.sh")"
  eval "$restore_source"
  _pdg_atomic_restore_file(){ cp "$1" "$2"; }
  printf 'changed-config\n' >"$capture_root/config"
  printf 'changed-direct\n' >"$capture_root/direct"
  printf 'changed-hijack\n' >"$capture_root/hijack"
  _pdg_restore_ruleset_migration_before \
    "$capture_root/present" "$capture_root/config" \
    "$capture_root/direct" "$capture_root/hijack" 1 1 \
    || capture_ok=0
  cmp -s "$capture_root/config" "$capture_root/present/config.before" \
    || capture_ok=0
  cmp -s "$capture_root/direct" "$capture_root/present/direct.before" \
    || capture_ok=0
  cmp -s "$capture_root/hijack" "$capture_root/present/hijack.before" \
    || capture_ok=0
  printf 'changed-direct\n' >"$capture_root/direct"
  printf 'changed-hijack\n' >"$capture_root/hijack"
  _pdg_restore_ruleset_migration_before \
    "$capture_root/absent" "$capture_root/config" \
    "$capture_root/direct" "$capture_root/hijack" 0 0 \
    || capture_ok=0
  [[ ! -e "$capture_root/direct" && ! -L "$capture_root/direct" \
     && ! -e "$capture_root/hijack" && ! -L "$capture_root/hijack" ]] \
    || capture_ok=0
fi
[[ -n "$capture_root" && -d "$capture_root" ]] && rm -rf -- "$capture_root"
[[ "$capture_ok" == 1 ]] \
  && ok "规则集迁移对 aggregate 缺失/已存在均真实捕获并恢复三文件 before-image" \
  || bad "规则集迁移 before-image 捕获/恢复执行失败"

atomic_source="$(awk '
  /^_pdg_atomic_install_file\(\)\{/ { active=1 }
  active { print }
  active && /^}$/ { exit }
' "$ROOT/deploy/bot/pdg.sh")"
if grep -qF 'out.flush()' <<<"$atomic_source" \
   && grep -qF 'os.fsync(out.fileno())' <<<"$atomic_source" \
   && grep -qF 'os.replace(temporary, target)' <<<"$atomic_source" \
   && grep -qF 'os.fsync(directory_fd)' <<<"$atomic_source"; then
  ok "原子文件安装在 replace 前 fsync 数据、replace 后 fsync 父目录"
else
  bad "原子文件安装缺少 durable data/metadata fsync"
fi

if grep -qF "secrets.token_hex(4)" "$ROOT/deploy/bot/pdg.sh" \
   && grep -qF 'mkdir -m700 "$d"' "$ROOT/deploy/bot/pdg.sh" \
   && grep -qF 'PDG_WEB_JOB_STATE_DIR' "$ROOT/deploy/web/pdg-web-job.py" \
   && grep -qF 'install -d -o root -g root -m700 /var/lib/privdns-gateway/web-jobs' \
      "$ROOT/install.sh"; then
  ok "快照使用排他随机稳定 ID，Web 维护任务状态持久化到 root-only 目录"
else
  bad "快照稳定 ID 或维护任务持久化契约缺失"
fi

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

# A pre-v1.9 updater (including v1.6.4) runs from its already-loaded old shell, but invokes the newly
# installed `pdg __migrate`.  Therefore the new migration itself must install
# every dependency/file unknown to v1.8 and must propagate failure.
migration_source="$(awk '
  /^migrate_web_config_io\(\)\{/ { active=1 }
  active { print }
  active && /^}$/ { exit }
' "$ROOT/deploy/bot/pdg.sh")"
run_migrations_source="$(awk '
  /^run_all_migrations\(\)\{/ { active=1 }
  active { print }
  active && /^}$/ { exit }
' "$ROOT/deploy/bot/pdg.sh")"
if [[ -n "$migration_source" ]] \
   && grep -qF 'apt-get install -y -qq python3-yaml' <<<"$migration_source" \
   && grep -qF "python3 -c 'import yaml'" <<<"$migration_source" \
   && grep -qF '/var/lib/privdns-gateway/web-imports /etc/mihomo/providers' <<<"$migration_source" \
   && grep -qF '/opt/pdg-bot/pdgmodel.py' <<<"$migration_source" \
   && grep -qF '/opt/pdg-web/pdgconfigio.py' <<<"$migration_source" \
   && grep -qF 'mihomo-import.example.yaml' <<<"$migration_source" \
   && grep -qF 'mosdns-import.example.yaml' <<<"$migration_source" \
   && grep -qF 'python3 -m py_compile /opt/pdg-bot/pdgmodel.py /opt/pdg-web/pdgconfigio.py || return 1' <<<"$migration_source" \
   && grep -qF 'migrate_web_config_io || rc=1' <<<"$run_migrations_source" \
   && ! grep -Eq 'migrate_web_config_io[[:space:]]*\|\|[[:space:]]*true' <<<"$run_migrations_source"; then
  ok "pre-v1.9 旧 updater（含 v1.6.4）经新版 __migrate 硬安装并校验 ConfigIO/PyYAML/模板"
else
  bad "pre-v1.9→v1.9 ConfigIO 自举迁移不完整或错误吞掉失败"
fi

cleanup_source="$(awk '
  /^_pdg_clear_web_import_staging\(\)\{/ { active=1 }
  active { print }
  active && /^}$/ { exit }
' "$ROOT/deploy/bot/pdg.sh")"
cleanup_root="$(mktemp -d)"
cleanup_ok=1
if [[ -z "$cleanup_source" ]]; then
  cleanup_ok=0
else
  eval "$cleanup_source"
  mkdir -p "$cleanup_root/root/var/lib/privdns-gateway/web-imports"
  printf 'secret\n' >"$cleanup_root/root/var/lib/privdns-gateway/web-imports/imp-test.upload"
  printf 'keep\n' >"$cleanup_root/root/var/lib/privdns-gateway/keep"
  PDG_ROOT_PREFIX="$cleanup_root/root" _pdg_clear_web_import_staging \
    || cleanup_ok=0
  [[ ! -e "$cleanup_root/root/var/lib/privdns-gateway/web-imports" \
     && "$(cat "$cleanup_root/root/var/lib/privdns-gateway/keep" 2>/dev/null)" == keep ]] \
    || cleanup_ok=0

  mkdir -p "$cleanup_root/root/var/lib/privdns-gateway/elsewhere"
  printf 'do-not-follow\n' >"$cleanup_root/root/var/lib/privdns-gateway/elsewhere/secret"
  if ln -s "$cleanup_root/root/var/lib/privdns-gateway/elsewhere" \
      "$cleanup_root/root/var/lib/privdns-gateway/web-imports" 2>/dev/null \
      && [[ -L "$cleanup_root/root/var/lib/privdns-gateway/web-imports" ]]; then
    if PDG_ROOT_PREFIX="$cleanup_root/root" _pdg_clear_web_import_staging; then
      cleanup_ok=0
    fi
  elif ! grep -qF '[[ -d "$parent" && ! -L "$parent" ]]' <<<"$cleanup_source" \
       || ! grep -qF 'readlink -f -- "$staging"' <<<"$cleanup_source"; then
    # Windows Git Bash may not grant symlink creation; keep the executable
    # boundary check on POSIX and require both no-follow guards statically.
    cleanup_ok=0
  fi
  [[ "$(cat "$cleanup_root/root/var/lib/privdns-gateway/elsewhere/secret" 2>/dev/null)" \
      == do-not-follow ]] || cleanup_ok=0
fi
rm -rf -- "$cleanup_root"
if [[ "$cleanup_ok" == 1 ]] \
   && grep -qF 'if [[ ! -e "$tree/opt/pdg-web/pdgconfigio.py" ]]' \
      "$ROOT/deploy/bot/pdg.sh"; then
  ok "回滚到旧 Web 快照会在停服后清空精确 root-only import staging，拒绝 symlink"
else
  bad "旧快照回滚未安全清理 ConfigIO staging"
fi

echo "────────────────────────────────────────"
echo "通过 $pass, 失败 $fail"
[[ "$fail" == 0 ]]
