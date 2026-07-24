#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# systemd unit 单一事实源。install.sh(装机)与 pdg 的 sing-box→mihomo 迁移都从这里
# 生成内核 / pdg-mitm 的 unit, 杜绝两处手写漂移 —— 历史坑: 换核时生成的
# mihomo.service 漏了 Environment=SAFE_PATHS, 与装机版不一致。
#
# 各函数把 unit 内容打到 stdout, 由调用方重定向落盘, 例:
#   pdg_unit_mihomo > /etc/systemd/system/mihomo.service
# 或用 pdg_write_unit 一步写入并 chmod 644。
# ─────────────────────────────────────────────────────────────────────────────

pdg_unit_mihomo(){ cat <<'EOF'
[Unit]
Description=mihomo (PrivDNS Gateway core)
After=network-online.target mosdns.service
Wants=network-online.target
[Service]
ExecStart=/usr/local/bin/mihomo -d /etc/mihomo -f /etc/mihomo/config.yaml
Environment=SAFE_PATHS=/etc/sing-box/ui/dist
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
EOF
}

pdg_unit_pdg_mitm(){ cat <<'EOF'
[Unit]
Description=pdg-mitm (PrivDNS Gateway MITM plugins)
After=network-online.target
Wants=network-online.target
[Service]
ExecStart=/usr/bin/python3 /opt/pdg-bot/mitm_server.py 7894
Restart=on-failure
RestartSec=3
[Install]
WantedBy=multi-user.target
EOF
}

# 内核 svc 名 → 对应 unit 生成函数(mihomo 为唯一内核; 保留此壳以便将来扩展/调用方不改)。
pdg_unit_for_core_svc(){
  case "$1" in
    mihomo)   pdg_unit_mihomo ;;
    *) return 1 ;;
  esac
}

# 写入 unit 并置 644(幂等)。$1=生成函数名 $2=目标路径。
pdg_write_unit(){
  local fn="$1" path="$2"
  "$fn" > "$path" && chmod 644 "$path"
}
