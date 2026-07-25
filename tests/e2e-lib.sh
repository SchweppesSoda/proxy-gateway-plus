#!/usr/bin/env bash
# shellcheck shell=bash
# ─────────────────────────────────────────────────────────────────────────────
# 端到端沙盒骨架。用 user+mount namespace + overlayfs 把 /etc /opt /usr/local/bin 覆盖掉,
# 于是可以在**真实绝对路径**上跑真正的 install/migrate/update/switch-core, 而宿主毫发无损
# (所有写入落在 overlay 的 upperdir)。
#
# 为什么要有这层: 现有回归都在函数级别打桩, 跨组件的接缝没人看着 —— 而实践中查出来的 bug
# (GMS 重复插入、backend 标记从不落地、分流规则不进 mosdns)全是接缝问题, 单测全绿照样漏。
#
# 用法(每个 e2e 脚本开头):
#     source "$(dirname "$0")/e2e-lib.sh"
#     e2e_enter "$@"          # 不支持则以 0 退出(跳过); 支持则重入 namespace 并挂好 overlay
#     ... 测试主体(此时已是 namespace 内 root) ...
#     e2e_summary
# ─────────────────────────────────────────────────────────────────────────────

E2E_PASS=0; E2E_FAIL=0
ok(){ echo "[OK]   $1"; E2E_PASS=$((E2E_PASS+1)); }
bad(){ echo "[FAIL] $1"; E2E_FAIL=$((E2E_FAIL+1)); }
e2e_summary(){ echo "────────────────────────────────────────"; echo "通过 $E2E_PASS, 失败 $E2E_FAIL"; [[ "$E2E_FAIL" == 0 ]]; }
e2e_skip(){ echo "[SKIP] $1"; echo "────────────────────────────────────────"; echo "通过 0, 失败 0(已跳过)"; exit 0; }

# 沙盒里的仓库文件未必归当前 uid(CI 容器 job: 工作区归 runner uid, 容器内是 root),
# git 会以 "dubious ownership" 拒绝一切操作 —— update 那条 e2e 连 tag 都读不到。
# safe.directory 属"受保护配置": 经 -c / GIT_CONFIG_* 环境变量设置会被 git 故意忽略,
# 只认 system/global。所以写沙盒里的 /etc/gitconfig —— 本地是 overlay, CI 是一次性容器,
# 两边都碰不到开发机的真实配置。
_e2e_git_safe(){ grep -q 'directory = \*' /etc/gitconfig 2>/dev/null || printf '[safe]\n\tdirectory = *\n' >> /etc/gitconfig 2>/dev/null || true; }

# 把机器清回"什么都没装过"的状态。namespace 模式下 overlay 本来就干净, 这里主要给容器模式
# (CI 里多个脚本共用一个容器)用: 二进制、unit、归属/后端标记、快照、仓库副本、服务桩一个不留。
e2e_reset_box(){
  systemctl disable --now pdg-bot pdg-probe81 pdg-mitm mosdns mihomo sing-box >/dev/null 2>&1 || true
  # sing-box 是**必须**清掉的那个: 装机会把来源不明的 sing-box 判成第三方冲突而中止,
  # 跨版本回滚用例正好留一份在这。mihomo / mosdns 反过来要**留着** —— 它们是从网上下的
  # 真内核(几十 MB), 每个脚本重下一遍既慢又会在没网时把用例整条 skip 掉(假绿)。
  rm -f /usr/local/bin/sing-box \
        /usr/local/bin/pdg /usr/local/bin/pdg-set-token \
        /usr/local/bin/proxy-gateway-open-cert-http.sh \
        /usr/local/bin/proxy-gateway-restore-firewall.sh 2>/dev/null || true
  rm -f /etc/systemd/system/{pdg-bot,pdg-probe81,pdg-mitm,mosdns,mihomo,sing-box,pdg-rules-update,pdg-health}.service \
        /etc/systemd/system/{pdg-rules-update,pdg-health}.timer \
        /etc/systemd/journald.conf.d/50-pdg.conf 2>/dev/null || true
  rm -rf /etc/privdns-gateway /etc/mosdns /etc/mihomo /etc/sing-box /opt/pdg-bot \
         /opt/privdns-gateway /var/lib/privdns-gateway 2>/dev/null || true
  rm -f /etc/nftables.conf.pdg-orig /etc/resolv.conf.pdg-orig 2>/dev/null || true
  rm -rf /tmp/e2e-svc /tmp/e2e-nft-ruleset /tmp/e2e-calls.log /tmp/e2e-inject \
         /tmp/e2e-origin.git /tmp/e2e-xver-origin.git /tmp/e2e-cli-origin.git \
         /tmp/e2e-empty-origin.git 2>/dev/null || true
  # 前一个脚本装的**桩命令**同样是"上一个脚本留下的状态": e2e-install 会留一个假 curl
  # (下载什么都写 "stub" 几个字节), 下一个脚本想取真内核时就只能拿到一个坏档而整条 skip。
  # 每个脚本都会自己造它需要的桩(e2e_stub_system / 各自的 setup), 进场清掉是安全的。
  rm -f /usr/local/bin/{systemctl,nft,curl,tcpdump,apt-get,dpkg,certbot,vnstat,ss,tar} 2>/dev/null || true
  # 真内核二进制留着(几十 MB, 每个脚本重下一遍既慢又会在没网时把用例整条 skip 成假绿);
  # 但**桩**版本要清 —— 拿 `-t` 恒 0 的假 mihomo 当内核, 配置校验类用例会静默失效。
  if command -v mihomo >/dev/null 2>&1 && ! e2e_mihomo_is_real; then
    rm -f /usr/local/bin/mihomo 2>/dev/null || true
  fi
  if [[ -f /usr/local/bin/mosdns ]] && [[ "$(stat -c %s /usr/local/bin/mosdns 2>/dev/null || echo 0)" -lt 1000000 ]]; then
    rm -f /usr/local/bin/mosdns 2>/dev/null || true      # 小于 1MB = 桩, 不是真 mosdns
  fi
  mkdir -p /var/lib/privdns-gateway /etc/mosdns/rules /etc/sing-box /etc/mihomo \
           /etc/privdns-gateway /etc/systemd/system /etc/systemd/journald.conf.d /tmp/e2e-svc 2>/dev/null || true
  : > /etc/nftables.conf
  # 清 bash 的命令哈希: 上面刚跑过 mihomo(能力探测)又把它删了, 不清的话后续 `command -v mihomo`
  # 仍会命中缓存里的旧路径, 于是"没有就造个桩"的分支被跳过, 装机改走下载 → 撞上假 curl → SHA 失败。
  hash -r 2>/dev/null || true
}

# 重入 namespace: 外层建 overlay 目录并 unshare, 内层挂载
e2e_enter(){
  # 已经身处一次性隔离环境且是 root(CI 的容器 job) → 直接跑, 不必再自建 namespace。
  # GitHub runner(ubuntu-24.04)用 AppArmor 禁掉了非特权用户命名空间, unshare -rm 不可用,
  # 所以 CI 走容器这条路; 本地开发机则走 namespace, 两边跑的是同一份测试主体。
  if [[ "${PDG_E2E_ISOLATED:-}" == 1 && "$(id -u)" == 0 ]]; then
    # 容器是一次性的, 但**同一个容器里顺序跑多个脚本**时它并不是一次性的: 前一个脚本留下的
    # /usr/local/bin/sing-box 会让下一个脚本的装机路径判成"机器上已有第三方 sing-box"而中止。
    # 进场先把现场清干净 —— 每个 E2E 都必须自带完整前提, 不许指望上一个脚本留下的状态。
    e2e_reset_box
    _e2e_git_safe
    return 0
  fi
  if [[ "${PDG_E2E_INNER:-}" == 1 ]]; then
    mount -t overlay overlay -o "lowerdir=/etc,upperdir=$E2E_OVL/eu,workdir=$E2E_OVL/ew" /etc \
      || { echo "[SKIP] overlay /etc 挂不上"; exit 0; }
    mount -t overlay overlay -o "lowerdir=/usr/local/bin,upperdir=$E2E_OVL/bu,workdir=$E2E_OVL/bw" /usr/local/bin
    mount -t overlay overlay -o "lowerdir=/opt,upperdir=$E2E_OVL/ou,workdir=$E2E_OVL/ow" /opt
    mount -t tmpfs tmpfs /run 2>/dev/null || true            # pdg 的 flock 落在 /run(宿主归真 root)
    # 快照目录在 /var/lib/privdns-gateway; 宿主 /var/lib 归真 root, 不覆盖就建不了快照,
    # 而"快照失败即中止更新"是有意设计 → 不覆盖的话整条 update 路径根本走不到。
    mount -t overlay overlay -o "lowerdir=/var/lib,upperdir=$E2E_OVL/vu,workdir=$E2E_OVL/vw" /var/lib \
      2>/dev/null || mount -t tmpfs tmpfs /var/lib 2>/dev/null || true
    mkdir -p /var/lib/privdns-gateway 2>/dev/null || true
    _e2e_git_safe
    return 0
  fi
  unshare -rm true 2>/dev/null || e2e_skip "本环境不支持 unshare -rm(需用户+挂载命名空间)"
  E2E_OVL="$(mktemp -d)"
  # 宿主 /etc 里归真 root 的路径在 userns 里映射成 nobody, 改不动 → 先在 upperdir 里建好(归本人)
  mkdir -p "$E2E_OVL"/{eu,ew,bu,bw,ou,ow,vu,vw}
  mkdir -p "$E2E_OVL"/eu/{mosdns/rules,sing-box,mihomo,privdns-gateway,systemd/system,systemd/journald.conf.d}
  : > "$E2E_OVL"/eu/nftables.conf
  local rc=0
  PDG_E2E_INNER=1 E2E_OVL="$E2E_OVL" E2E_ROOT="$E2E_ROOT" \
    unshare -rm bash "$0" "$@" || rc=$?
  # overlay 的 workdir 归 namespace 内的 root, 外层删不掉 → 再进一次 namespace 清理
  unshare -rm bash -c 'rm -rf "$1"' _ "$E2E_OVL" 2>/dev/null || rm -rf "$E2E_OVL" 2>/dev/null
  exit "$rc"
}

# ── 打桩: 沙盒里没有 systemd / netlink ──────────────────────────────────────
e2e_stub_system(){
  mkdir -p /tmp/e2e-svc
  # 有状态的假 systemd: 记录每个 unit 的 active/enabled。切核纪律(旧核必须真的 inactive
  # 且 disabled)只有靠状态机才验得出来 —— 无脑回 active 的桩会把 activate 判成失败。
  cat > /usr/local/bin/systemctl <<'S'
#!/bin/sh
D=/tmp/e2e-svc; mkdir -p "$D"
echo "systemctl $*" >> /tmp/e2e-calls.log
verb="$1"; shift
now=0; [ "$1" = "--now" ] && { now=1; shift; }
case "$verb" in
  daemon-reload|reset-failed|preset|mask|unmask) exit 0;;
  enable)  for u in "$@"; do echo 1 > "$D/${u}.en"
             # .fail 标记 = 这个 unit "起得来但立刻崩" → 起完仍是 inactive
             if [ "$now" = 1 ]; then [ -f "$D/${u}.fail" ] && echo 0 > "$D/${u}.ac" || echo 1 > "$D/${u}.ac"; fi
           done; exit 0;;
  disable) for u in "$@"; do echo 0 > "$D/${u}.en"; [ "$now" = 1 ] && echo 0 > "$D/${u}.ac"; done; exit 0;;
  start|restart) for u in "$@"; do
                   [ -f "$D/${u}.fail" ] && echo 0 > "$D/${u}.ac" || echo 1 > "$D/${u}.ac"
                 done; exit 0;;
  stop)    for u in "$@"; do echo 0 > "$D/${u}.ac"; done; exit 0;;
  is-active)
      u="$1"; v=$(cat "$D/${u}.ac" 2>/dev/null)
      # 没记录过的: 有 unit 文件就当它在跑(模拟装好即运行), 否则 inactive
      [ -z "$v" ] && { [ -f "/etc/systemd/system/${u}.service" ] && v=1 || v=0; }
      [ "$v" = 1 ] && { echo active; exit 0; }; echo inactive; exit 3;;
  is-enabled)
      u="$1"; v=$(cat "$D/${u}.en" 2>/dev/null)
      [ -z "$v" ] && { [ -f "/etc/systemd/system/${u}.service" ] && v=1 || v=0; }
      [ "$v" = 1 ] && { echo enabled; exit 0; }; echo disabled; exit 1;;
  show)   echo 0; exit 0;;
esac
exit 0
S
  cat > /usr/local/bin/nft <<'S'
#!/bin/sh
echo "nft $*" >> /tmp/e2e-calls.log
exit 0
S
  chmod 755 /usr/local/bin/systemctl /usr/local/bin/nft
  : > /tmp/e2e-calls.log
}

# 把某 unit 置为"当前不在跑"(供故障注入)。注意: 之后任何 restart 都会把它拉回 active,
# 要模拟"启动后立刻崩溃"请用 e2e_svc_crash。
e2e_svc_fail(){ mkdir -p /tmp/e2e-svc; echo 0 > "/tmp/e2e-svc/$1.ac"; }

# "起得来但立刻崩": restart 返回 0, 但服务随即变回 inactive —— 真实现场里最常见的失败形态,
# 也正是"只看 systemctl 返回值"这种写法看不出来的那种。
e2e_svc_crash(){ mkdir -p /tmp/e2e-svc; : > "/tmp/e2e-svc/$1.fail"; echo 0 > "/tmp/e2e-svc/$1.ac"; }
e2e_svc_heal(){ rm -f "/tmp/e2e-svc/$1.fail"; echo 1 > "/tmp/e2e-svc/$1.ac"; }

# PATH 上那个 mihomo 是不是**真内核**: 正反两份配置都要判对。串行跑时它很可能是上一个脚本
# 留下的桩(`-t` 恒 0), 拿它当内核用, "配置不合法就不许重启"这类用例会静默失效。
e2e_mihomo_is_real(){
  command -v mihomo >/dev/null 2>&1 || return 1
  local d rc_good rc_bad; d="$(mktemp -d)" || return 1
  printf '{"log-level":"silent","mixed-port":17899,"proxies":[],"rules":["MATCH,DIRECT"]}\n' > "$d/good.yaml"
  printf '{"proxies":[{"name":"x","type":"definitely-not-a-real-protocol","server":"1.1.1.1","port":1}],"rules":["MATCH,DIRECT"]}\n' > "$d/bad.yaml"
  mihomo -t -d "$d" -f "$d/good.yaml" >/dev/null 2>&1; rc_good=$?
  mihomo -t -d "$d" -f "$d/bad.yaml"  >/dev/null 2>&1; rc_bad=$?
  rm -rf "$d"
  [[ "$rc_good" == 0 && "$rc_bad" != 0 ]]
}

# 取真内核二进制(钉死版本); 拿不到回非 0, 调用方据此跳过
e2e_fetch_mihomo(){
  e2e_mihomo_is_real && return 0
  rm -f /usr/local/bin/mihomo 2>/dev/null || true      # 桩要换成真的
  # shellcheck source=/dev/null
  . "$E2E_ROOT/lib/versions.sh"
  curl -fsSL --retry 2 -m 120 \
    "https://github.com/MetaCubeX/mihomo/releases/download/${MIHOMO_VER}/mihomo-linux-amd64-${MIHOMO_VER}.gz" \
    -o /tmp/m.gz 2>/dev/null || return 1
  gunzip -c /tmp/m.gz > /usr/local/bin/mihomo 2>/dev/null || return 1
  chmod 755 /usr/local/bin/mihomo
}
e2e_fetch_mosdns(){
  command -v mosdns >/dev/null 2>&1 && return 0
  # shellcheck source=/dev/null
  . "$E2E_ROOT/lib/versions.sh"
  curl -fsSL --retry 2 -m 120 \
    "https://github.com/IrineSistiana/mosdns/releases/download/${MOSDNS_VER}/mosdns-linux-amd64.zip" \
    -o /tmp/mos.zip 2>/dev/null || return 1
  (cd /tmp && unzip -qo mos.zip mosdns) 2>/dev/null || return 1
  install -m755 /tmp/mosdns /usr/local/bin/mosdns 2>/dev/null || return 1
}

# ── 造现场 ──────────────────────────────────────────────────────────────────
E2E_SIP=203.0.113.1
E2E_CIDR=127.0.0.0/8

# 装好 bot 模块 + 仓库 + pdg 脚本
e2e_seed_install(){
  mkdir -p /opt/pdg-bot /etc/mosdns/rules /etc/privdns-gateway
  cp -a "$E2E_ROOT" /opt/privdns-gateway
  install -m755 "$E2E_ROOT/deploy/bot/pdg.sh" /usr/local/bin/pdg
  local f; for f in "$E2E_ROOT"/deploy/bot/*.py; do install -m755 "$f" /opt/pdg-bot/; done
  install -m755 "$E2E_ROOT/deploy/bot/pdg-bot.py" /opt/pdg-bot/bot.py
  printf 'PDG_BOT_TOKEN=x\nPDG_BOT_ALLOWED=1\n' > /etc/privdns-gateway/bot.env
}

# 渲染 mosdns 配置 + 规则文件。$1=劫持模式(all|gfw)
e2e_seed_mosdns(){
  local mode="${1:-all}" f
  for f in geosite_cn geosite_apple custom_direct custom_hijack unlock mitm_hijack \
           geosite_gfw 'geosite_geolocation-!cn'; do : > "/etc/mosdns/rules/$f.txt"; done
  printf 'domain:baidu.com\n' > /etc/mosdns/rules/geosite_cn.txt
  printf 'domain:blocked.test\n' > /etc/mosdns/rules/geosite_gfw.txt
  sed -e "s|__SERVER_IP__|$E2E_SIP|g" -e "s|__INTERNAL_CIDR__|$E2E_CIDR|g" \
      -e 's|__CERT_DIR__|/etc/mosdns/certs|g' -e 's|__SSH_PORT__|22|g' \
      -e 's|__MOSDNS_CACHE__|1024|g' -e 's|__HIJACK_SET_FILE__|geosite_geolocation-!cn.txt|g' \
      "$E2E_ROOT/deploy/mosdns/config.yaml" > /etc/mosdns/config.yaml
  # shellcheck source=/dev/null
  . "$E2E_ROOT/lib/mosdns.sh"
  local setf; [[ "$mode" == gfw ]] && setf=geosite_gfw.txt || setf='geosite_geolocation-!cn.txt'
  _mosdns_hijack_shape "$mode" /etc/mosdns/config.yaml "$setf" >/dev/null
  printf 'PDG_LOWMEM=0\nPDG_HIJACK_MODE=%s\n' "$mode" > /etc/privdns-gateway/profile.env
}

# 渲染真实防火墙配置(switch-core 要从中提取 SSH 端口)。$1=内核(singbox|mihomo)
# v1.6.0: 只剩 mihomo 一套模板($1 保留但已无意义, 调用方不必改)。
e2e_seed_nft(){
  sed -e "s|__SSH_PORT__|22|g" -e "s|__INTERNAL_CIDR__|$E2E_CIDR|g" -e "s|__SERVER_IP__|$E2E_SIP|g" \
      "$E2E_ROOT/deploy/firewall/nftables-mihomo.conf" > /etc/nftables.conf
}

e2e_seed_singbox_model(){
  sed -e "s|__SERVER_IP__|$E2E_SIP|g" -e "s|__INTERNAL_CIDR__|$E2E_CIDR|g" -e 's|__SSH_PORT__|22|g' \
      "$E2E_ROOT/deploy/singbox/config.json.tmpl" > /etc/sing-box/config.json
}

# 自签占位证书(装机时 PDG_SKIP_CERT 也是这么做的)。没有它 doctor 的证书项必 fail,
# 而 update 的校验门见 fail 就回滚 —— 整条更新路径根本走不完。
e2e_seed_cert(){
  command -v openssl >/dev/null 2>&1 || return 1
  mkdir -p /etc/mosdns/certs
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout /etc/mosdns/certs/privkey.pem -out /etc/mosdns/certs/fullchain.pem \
    -subj "/CN=dot.e2e.test" >/dev/null 2>&1 || return 1
  chmod 600 /etc/mosdns/certs/privkey.pem
  echo dot.e2e.test > /opt/pdg-bot/dot-domain
}

# 起真 mosdns 在 127.0.0.1:15353(上游指向死端口, 保证快速失败且不外连)
e2e_mosdns_start(){
  local cfg=/tmp/e2e-mos.yaml
  sed -e 's#0.0.0.0:53#127.0.0.1:15353#g' \
      -e 's#^\([[:space:]]*\)args: {.*1\.1\.1\.1.*}#\1args: { concurrent: 1, upstreams: [ {addr: "udp://127.0.0.1:15999"} ] }#' \
      -e 's#^\([[:space:]]*\)args: {.*223\.5\.5\.5.*}#\1args: { concurrent: 1, upstreams: [ {addr: "udp://127.0.0.1:15999"} ] }#' \
      -e 's#^\([[:space:]]*\)args: {.*22\.22\.22\.22.*}#\1args: { concurrent: 1, upstreams: [ {addr: "udp://127.0.0.1:15999"} ] }#' \
      -e '/- tag: dot_server/,$d' /etc/mosdns/config.yaml > "$cfg"
  mosdns start -c "$cfg" -d /tmp >/tmp/e2e-mos.log 2>&1 &
  echo $! > /tmp/e2e-mos.pid
  local _i; for _i in $(seq 1 50); do
    dig +short +time=1 +tries=1 @127.0.0.1 -p 15353 probe.ready A >/dev/null 2>&1 && return 0
    sleep 0.1
  done
  return 0
}
e2e_mosdns_stop(){ [[ -f /tmp/e2e-mos.pid ]] && kill "$(cat /tmp/e2e-mos.pid)" 2>/dev/null; rm -f /tmp/e2e-mos.pid; sleep 0.2; }
e2e_q(){ dig +short +time=2 +tries=1 @127.0.0.1 -p 15353 "$1" A 2>/dev/null | head -1; }
