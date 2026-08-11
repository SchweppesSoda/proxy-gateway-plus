#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# 端到端: 真跑 `pdg update`。造一个带两个 tag 的**真 git 仓库**当发布源, 让 cmd_update
# 走完整条路: 取 tag → reset → 装文件 → __migrate → 内核 → 校验门 → doctor → 成功/回滚。
#
# 单测(test-update-faults.sh)是把 cmd_update 抽出来打桩跑的; 这里跑的是**装在机器上的
# 那份脚本**对着真仓库、真快照目录、真 doctor 做的事 —— 快照能不能建、回滚能不能真的把
# 文件换回去, 只有这么跑才看得出来。
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail
E2E_ROOT="${E2E_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
# shellcheck source=tests/e2e-lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/e2e-lib.sh"
e2e_enter "$@"

command -v git >/dev/null 2>&1 || e2e_skip "无 git"
e2e_stub_system
e2e_seed_install
# 这是带 ready Bot 凭据的已安装老机器：pdg update 只会刷新既有 unit，
# 不会为从未安装 Bot 的机器凭空创建它。保留旧 sing-box 依赖，顺带让
# migrate_deploy_units 覆盖真实的 legacy → mihomo unit 更新路径。
cat > /etc/systemd/system/pdg-bot.service <<'BOTU'
[Unit]
Description=PrivDNS Gateway Telegram bot
After=network-online.target sing-box.service mosdns.service
Wants=network-online.target

[Service]
EnvironmentFile=-/etc/privdns-gateway/bot.env
Environment=PDG_CERT=/etc/mosdns/certs/fullchain.pem
ExecStart=/usr/bin/python3 /opt/pdg-bot/bot.py
Restart=on-failure

[Install]
WantedBy=multi-user.target
BOTU
chmod 644 /etc/systemd/system/pdg-bot.service
e2e_seed_mosdns all
e2e_seed_singbox_model
e2e_seed_nft singbox
printf 'android\n' > /etc/privdns-gateway/platform
printf 'singbox\n' > /etc/privdns-gateway/backend
mkdir -p /var/lib/privdns-gateway
e2e_seed_cert || e2e_skip "无 openssl, 造不出占位证书"

# 内核二进制打桩: update 里的 _update_core_binary 会比对版本, 让它认为"已是钉死版本"
. "$E2E_ROOT/lib/versions.sh"
cat > /usr/local/bin/mihomo <<S
#!/bin/sh
case "\$1" in -v|version) echo "Mihomo Meta $MIHOMO_VER linux amd64";; -t) exit 0;; esac
exit 0
S
chmod 755 /usr/local/bin/mihomo
# 现场是"仍在跑 sing-box 的老机器"(backend=singbox + 二进制/unit 都在): 这次 update 应当
# 由 migrate_drop_singbox 自动迁到 mihomo 并把 sing-box 运行时清掉。
printf '#!/bin/sh\nexit 0\n' > /usr/local/bin/sing-box; chmod 755 /usr/local/bin/sing-box
# 老版装机真正生成的 unit 形态 —— 归属判定据此认出"这是本项目装的"才会去清理它
# (随手写的 `[Unit]` 桩不具备该特征, 会被当成第三方 sing-box 保留, 那是另一条分支)
cat > /etc/systemd/system/sing-box.service <<'SBU'
[Unit]
Description=sing-box
After=network-online.target
Wants=network-online.target
[Service]
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
SBU

# ── 造发布源: 真 git 仓库, 两个 tag(v9.9.8 当前 / v9.9.9 新版) ────────────────
# 连 origin 都是真的(本地裸仓库): pdg update 里的 `git fetch --tags origin main` 照跑不误,
# 于是"取 tag"这段也在覆盖范围内, 且全程离线 —— 不打桩、不碰 GitHub。
REPO=/opt/privdns-gateway
ORIGIN=/tmp/e2e-origin.git
rm -rf "$REPO/.git" "$ORIGIN"            # e2e_seed_install 拷进来的是开发机/CI 的 .git, 弃用
git -C "$REPO" init -q -b main
git -C "$REPO" config user.email t@t; git -C "$REPO" config user.name t
git -C "$REPO" config commit.gpgsign false
git -C "$REPO" add -A >/dev/null 2>&1
git -C "$REPO" commit -qm base >/dev/null 2>&1
git -C "$REPO" tag v9.9.8
# 新版本: 往 bot 模块里塞个可辨识标记, 用来验证"文件真的被换成了新版"
echo "# NEWVERSION-MARKER" >> "$REPO/deploy/bot/checks.py"
git -C "$REPO" add -A >/dev/null 2>&1
git -C "$REPO" commit -qm newver >/dev/null 2>&1
git -C "$REPO" tag v9.9.9
git clone -q --bare "$REPO" "$ORIGIN"
git -C "$REPO" remote add origin "$ORIGIN"
git -C "$REPO" tag -d v9.9.9 >/dev/null  # 本地先没有新 tag → 逼 update 真去 origin 取
git -C "$REPO" checkout -q v9.9.8
{ [[ "$(git -C "$REPO" describe --tags)" == v9.9.8 ]] && [[ -z "$(git -C "$REPO" tag -l v9.9.9)" ]]; } \
  && ok "发布源就位: 工作仓库停在 v9.9.8, 新 tag v9.9.9 只在 origin 上(要靠 fetch 才拿得到)" \
  || bad "发布源没造对: $(git -C "$REPO" describe --tags), tags=$(git -C "$REPO" tag -l)"
# 本地伪造的更高 tag 绝不能参与 release 选择；它不在 origin 上。
git -C "$REPO" tag v99.0.0

# ── 1. 正常更新: 应装上新版文件并显示成功 ════════════════════════════════════
echo; echo "── 1. 正常更新 ──"
out=$(bash /usr/local/bin/pdg update --target v9.9.9 2>&1); rc=$?
{ [[ "$rc" == 0 ]] && grep -q '✅ 已更新' <<<"$out"; } \
  && ok "pdg update 成功走完(取 tag→装文件→迁移→内核→校验门→doctor)" \
  || bad "更新失败 rc=$rc: $(tail -5 <<<"$out")"
grep -q 'NEWVERSION-MARKER' /opt/pdg-bot/checks.py \
  && ok "新版文件真的装到了 /opt/pdg-bot(不是只动了 git)" || bad "部署文件仍是旧版"
[[ "$(git -C "$REPO" rev-parse v99.0.0^{commit})" != "$(git -C "$REPO" rev-parse HEAD)" ]] \
  && ok "精确 target 忽略本地更高 poison tag" || bad "更新错误落到了本地 poison tag"
[[ "$(git -C "$REPO" describe --tags 2>/dev/null)" == v9.9.9 ]] \
  && ok "仓库已切到最新发布 tag v9.9.9" || bad "仓库 tag=$(git -C "$REPO" describe --tags 2>/dev/null)"
snaps=$(find /var/lib/privdns-gateway/backups -name snap.tar.gz 2>/dev/null | wc -l)
[[ "$snaps" -ge 1 ]] && ok "更新前留下了快照($snaps 份)" || bad "没有快照"
# v1.6.0: 这台老机器原本跑 sing-box, update 应顺带把它迁到 mihomo 并清掉 sing-box 运行时
[[ "$(cat /etc/privdns-gateway/backend 2>/dev/null)" == mihomo ]] \
  && ok "旧 sing-box 机器: update 后 backend 已迁为 mihomo" \
  || bad "backend=$(cat /etc/privdns-gateway/backend 2>/dev/null)"
{ [[ ! -e /usr/local/bin/sing-box ]] && [[ ! -e /etc/systemd/system/sing-box.service ]]; } \
  && ok "旧 sing-box 机器: update 后 sing-box 二进制/unit 已移除" || bad "sing-box 运行时仍残留"
grep -q '出口/分流/证书/DoT 不动' <<<"$out" \
  && ok "迁移明确声明不动出口/分流/证书/DoT" || bad "迁移未声明数据保全"

# ── 2. doctor 判失败 → 必须回滚且不显示成功 ═════════════════════════════════
echo; echo "── 2. doctor 报 fail → 回滚 ──"
git -C "$REPO" checkout -q v9.9.8                     # 退回旧版, 好再更新一次
rm -rf /opt/pdg-bot; mkdir -p /opt/pdg-bot
for f in "$E2E_ROOT"/deploy/bot/*.py; do install -m755 "$f" /opt/pdg-bot/; done
install -m755 "$E2E_ROOT/deploy/bot/pdg-bot.py" /opt/pdg-bot/bot.py
# 注入只会由 doctor 判定的故障：Bot 凭据只配置一半。这样不会削弱或抢先触发
# Mihomo/QUIC 的更新前置硬门，能精确覆盖“新版已部署，doctor fail 后回滚”。
printf 'PDG_BOT_TOKEN=123456:AAaa\n' > /etc/privdns-gateway/bot.env
chmod 600 /etc/privdns-gateway/bot.env
before=$(sha256sum /opt/pdg-bot/checks.py | cut -d' ' -f1)
out=$(bash /usr/local/bin/pdg update 2>&1); rc=$?
{ [[ "$rc" != 0 ]] && ! grep -q '✅ 已更新' <<<"$out"; } \
  && ok "doctor 有 fail → 返回非0 且不显示'已更新'" || bad "rc=$rc 却报了成功"
grep -q '自检发现' <<<"$out" && ok "明确说明是自检失败并回滚" || bad "没说回滚原因: $(tail -3 <<<"$out")"
grep -q 'Bot 凭据' <<<"$out" && ok "故障确由 doctor 的 Bot 凭据检查发现" || bad "doctor 未点名注入项"
[[ "$(sha256sum /opt/pdg-bot/checks.py | cut -d' ' -f1)" == "$before" ]] \
  && ok "回滚把部署文件真的换回了更新前那份(按 sha 比对)" || bad "回滚后文件不是更新前的"
grep -q 'NEWVERSION-MARKER' /opt/pdg-bot/checks.py \
  && bad "回滚后仍残留新版标记(说明没换回去)" || ok "回滚后无新版残留"
rm -f /etc/privdns-gateway/bot.env

# ── 3. --dry-run 只看不动 ════════════════════════════════════════════════════
echo; echo "── 3. --dry-run ──"
b1=$(sha256sum /opt/pdg-bot/checks.py | cut -d' ' -f1)
out=$(bash /usr/local/bin/pdg update --dry-run 2>&1); rc=$?
{ [[ "$rc" == 0 ]] && [[ "$(sha256sum /opt/pdg-bot/checks.py | cut -d' ' -f1)" == "$b1" ]]; } \
  && ok "--dry-run 不动任何部署文件" || bad "dry-run 改了文件"
grep -qE '当前|最新发布' <<<"$out" && ok "--dry-run 打印当前/最新版本对照" || bad "dry-run 输出不含版本对照"

# ── 4. 快照 → 手工回滚: 配置真的被换回去 ═════════════════════════════════════
echo; echo "── 4. snapshot + rollback ──"
printf 'MARK=before-snapshot\n' >> /etc/privdns-gateway/profile.env
bash /usr/local/bin/pdg snapshot >/dev/null 2>&1
printf 'MARK=after-snapshot\n' >> /etc/privdns-gateway/profile.env
out=$(bash /usr/local/bin/pdg rollback 0 2>&1); rc=$?
{ [[ "$rc" == 0 ]] && grep -q '✅ 已回滚' <<<"$out"; } \
  && ok "pdg rollback 0 成功" || bad "回滚失败 rc=$rc: $(tail -3 <<<"$out")"
{ grep -q 'before-snapshot' /etc/privdns-gateway/profile.env \
  && ! grep -q 'after-snapshot' /etc/privdns-gateway/profile.env; } \
  && ok "配置被换回快照时刻的内容(快照后的改动已消失)" || bad "配置没回到快照状态"

e2e_summary
