#!/usr/bin/env bash
# 更新 geosite 规则库: 下载 geosite.dat → 解析到**临时目录** → 经统一配置事务落盘 → 重载 mosdns。
# 依赖本机能解析 DNS (resolv.conf 指向 127.0.0.1=mosdns)。
#
# 5.1 之前这里是直接把解析结果写进 /etc/mosdns/rules(非原子: 一个文件写到一半就是坏的),
# 然后 `systemctl restart mosdns` 且**不检查它有没有起来** —— 而这条路径每天 04:30 由 timer
# 自动跑, 既不上锁(可与 Bot/CLI 的写操作对撞), 出事也没有任何回退材料。
# 现在: 解析进临时目录 → 逐个 stage 进事务 → 事务在锁内校验、落盘、重启并观察 mosdns;
# 任一步不成立就整批回到旧规则库, 现网 DNS 不受影响。
set -euo pipefail

BOOTSTRAP=0
case "${1:-}" in
  "") ;;
  --bootstrap) BOOTSTRAP=1 ;;
  *) echo "用法: $0 [--bootstrap]" >&2; exit 2 ;;
esac

# `--bootstrap` 只给 install.sh 的首装窗口使用。默认 live updater 绝不能因为
# mosdns 已损坏/没启动就降级提交，否则定时任务会在无法证明新库可加载时覆盖现网。
# marker 同时绑定本脚本的直接父进程，遗留 marker 或手工调用均不能冒充正在运行的安装器。
if [[ "$BOOTSTRAP" == 1 ]]; then
  marker="/etc/privdns-gateway/.installing-rules"
  [[ -f "$marker" && ! -L "$marker" ]] \
    || { echo "bootstrap 拒绝: 找不到首装 marker"; exit 1; }
  marker_meta="$(stat -c '%u:%a' "$marker" 2>/dev/null)" \
    || { echo "bootstrap 拒绝: 查不到首装 marker 属性"; exit 1; }
  [[ "$marker_meta" == 0:600 ]] \
    || { echo "bootstrap 拒绝: 首装 marker 必须是 root:600"; exit 1; }
  marker_pid="$(cat "$marker" 2>/dev/null || true)"
  [[ "$marker_pid" =~ ^[1-9][0-9]*$ && "$marker_pid" == "$PPID" ]] \
    || { echo "bootstrap 拒绝: 首装 marker 不属于当前父安装进程"; exit 1; }
  load_state="$(systemctl show mosdns.service -p LoadState --value 2>/dev/null)" \
    || { echo "bootstrap 拒绝: 查不到 mosdns LoadState"; exit 1; }
  active_state="$(systemctl show mosdns.service -p ActiveState --value 2>/dev/null)" \
    || { echo "bootstrap 拒绝: 查不到 mosdns ActiveState"; exit 1; }
  [[ "$load_state" == loaded && "$active_state" == inactive ]] \
    || { echo "bootstrap 拒绝: mosdns 必须是 loaded/inactive（当前 $load_state/$active_state）"; exit 1; }
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

curl -fsSL -o "$WORK/geosite.dat" \
  https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat
mkdir -p "$WORK/rules"
python3 /opt/pdg-bot/parse-geosite.py "$WORK/geosite.dat" "$WORK/rules"

# parser 过去即使上游缺了某个类别也会造出同名空文件，因此“*.txt 数量 > 0”并不能
# 证明候选库完整。这里只接受固定四类，并要求每类都有内容；拒绝把上游格式漂移误当空规则库。
expected=(
  "geosite_cn.txt"
  "geosite_geolocation-!cn.txt"
  "geosite_apple.txt"
  "geosite_gfw.txt"
)
files=()
for leaf in "${expected[@]}"; do
  f="$WORK/rules/$leaf"
  [[ -s "$f" ]] || { echo "geosite 候选缺失或为空: $leaf, 保留旧库"; exit 1; }
  files+=("$f")
done

TX=""
for m in /opt/privdns-gateway/deploy/bot/pdgtx.py /opt/pdg-bot/pdgtx.py; do
  [[ -f "$m" ]] && { TX="$m"; break; }
done
[[ -n "$TX" ]] || { echo "找不到事务核心 pdgtx.py, 拒绝直接改现网规则库"; exit 1; }

tx_mode=normal
tx_source=scheduler
tx_op=geosite_update
if [[ "$BOOTSTRAP" == 1 ]]; then
  # 首装时服务尚未启动，normal 的“操作前必须健康”硬门理应不成立。repair 仅允许在
  # 降级基线上保存完整 before-image 后原子落盘；这里刻意不声明 restart 动作，随后
  # install.sh 会首次启动并走自己的服务稳定硬门。默认 live 路径仍是 normal+restart。
  tx_mode=repair
  tx_source=installer
  tx_op=geosite_bootstrap
fi

ID="$(python3 "$TX" new --source "$tx_source" --op "$tx_op" --mode "$tx_mode")"
for f in "${files[@]}"; do
  python3 "$TX" stage --tx "$ID" --target "mosdns_rule:$(basename "$f")" --file "$f"
done
if [[ "$BOOTSTRAP" == 1 ]]; then
  # guard 在事务全局锁内再次证明 exact inactive，避免外层 systemctl 检查与 apply
  # 两个进程之间的 TOCTOU。这里绝不启动服务：managed 防火墙尚未应用，提前监听公网
  # 53/853 会制造短暂的开放递归窗口。
  python3 "$TX" guard --tx "$ID" --unit mosdns --expect inactive
else
  python3 "$TX" service --tx "$ID" --action restart:mosdns
fi

if python3 "$TX" apply --tx "$ID" >/dev/null; then
  if [[ "$BOOTSTRAP" == 1 ]]; then
    # 提交后仍须精确保持 loaded/inactive。若并发 actor 启动了服务，保守地令整个 install
    # 失败并由外层目录事务撤销本次规则；不能把“磁盘新库、运行时旧库”当成功。
    post_load="$(systemctl show mosdns.service -p LoadState --value 2>/dev/null)" \
      || { echo "bootstrap 提交后查不到 mosdns LoadState" >&2; exit 1; }
    post_active="$(systemctl show mosdns.service -p ActiveState --value 2>/dev/null)" \
      || { echo "bootstrap 提交后查不到 mosdns ActiveState" >&2; exit 1; }
    [[ "$post_load" == loaded && "$post_active" == inactive ]] \
      || { echo "bootstrap 提交后 mosdns 不再是 loaded/inactive（当前 $post_load/$post_active）" >&2; exit 1; }
    echo "geosite 规则库已完成首装离线落盘 (事务 $ID, ${#files[@]} 个文件)"
  else
    echo "geosite 规则库已更新并重载 mosdns (事务 $ID, ${#files[@]} 个文件)"
  fi
  exit 0
fi
echo "geosite 更新未提交(事务 $ID): 旧规则库仍在使用, mosdns 未受影响" >&2
exit 1
