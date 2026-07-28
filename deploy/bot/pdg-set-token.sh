#!/usr/bin/env bash
# 设置/更新 PrivDNS Gateway 的 Telegram bot token 与允许的 user id, 然后启用并重启 bot。
# 安装后可随时跑: sudo pdg-set-token
# token / id 只写进 /etc/privdns-gateway/bot.env (600), 不进 systemd unit、不进版本库。
# (可见粘贴 + 格式校验, 规避静默粘贴被吃字符 / sed 转义问题)
set -uo pipefail
[[ $EUID -eq 0 ]] || { echo "请用 root 运行: sudo pdg-set-token"; exit 1; }
SVC=/etc/systemd/system/pdg-bot.service
ENVD=/etc/privdns-gateway
ENVF="$ENVD/bot.env"
[[ -f "$SVC" ]] || { echo "没找到 $SVC —— 先装好 PrivDNS Gateway"; exit 1; }

printf '\e[?2004l'   # 关掉括号粘贴, 防混入转义字符
read -rp "Telegram bot token (留空回车=返回): " T
T="${T//[$'\r\n\t ']/}"
[[ -n "$T" ]] || { echo "已取消, 返回。"; exit 0; }
printf %s "$T" | grep -qE '^[0-9]+:[A-Za-z0-9_-]+$' \
  || { echo "❌ token 格式不对(当前长度 ${#T}), 应形如 数字:字母, 未改动。"; exit 1; }

read -rp "允许的 Telegram user id (你自己的; 多个用逗号): " A
A="${A//[$'\r\n\t ']/}"
[[ "$A" =~ ^[0-9]+(,[0-9]+)*$ ]] || { echo "❌ user id 只能是数字(可逗号分隔), 未改动。"; exit 1; }

# 写入受限的 bot.env(目录 700 / 文件 600)
install -d -m700 "$ENVD"
( umask 077; printf 'PDG_BOT_TOKEN=%s\nPDG_BOT_ALLOWED=%s\n' "$T" "$A" > "$ENVF" )
chmod 600 "$ENVF"

# 兼容旧 unit: 去掉曾写在 unit 里的明文 token 行, 并确保引用 bot.env
if grep -qE '^Environment=PDG_BOT_(TOKEN|ALLOWED)=' "$SVC"; then
  sed -i -E '/^Environment=PDG_BOT_(TOKEN|ALLOWED)=/d' "$SVC"
fi
if ! grep -q '^EnvironmentFile=-\?/etc/privdns-gateway/bot.env' "$SVC"; then
  sed -i -E 's#^\[Service\]#[Service]\nEnvironmentFile=-/etc/privdns-gateway/bot.env#' "$SVC"
fi
chmod 644 "$SVC"

systemctl daemon-reload
systemctl enable --now pdg-bot >/dev/null 2>&1
sleep 2
echo "→ pdg-bot: $(systemctl is-active pdg-bot)"
journalctl -u pdg-bot -n 3 --no-pager -o cat
echo "看到 active + 'pdg-bot v3 started' 且无 401 就成了。Telegram 发 /start 试试。"
