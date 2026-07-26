#!/bin/bash
# certbot deploy-hook (装到 /etc/letsencrypt/renewal-hooks/deploy/)。
# 续期/签发后把证书拷到 mosdns(853 DoT) 读取的位置并重载 mosdns。
# 选哪张证书: 优先 certbot 注入的 RENEWED_LINEAGE; 否则 /opt/pdg-bot/dot-domain 指定的活动域名; 再否则最近的 live。
set -e
# 活动 DoT 域名优先 (/opt/pdg-bot/dot-domain): 多域名时, 即便续期的是另一张证书,
# 也只把"当前生效域名"的证书部署给 mosdns, 否则旧域名续期会把活动证书覆盖掉 → DoT 不匹配。
DOMAIN_FILE=/opt/pdg-bot/dot-domain
ACTIVE=""
[[ -f "$DOMAIN_FILE" ]] && ACTIVE="$(head -n1 "$DOMAIN_FILE" | tr -d '[:space:]')"
if [[ -n "$ACTIVE" ]] && [[ -d "/etc/letsencrypt/live/$ACTIVE" ]]; then
    LIVE_DIR="/etc/letsencrypt/live/$ACTIVE"
elif [[ -n "${RENEWED_LINEAGE:-}" ]]; then
    LIVE_DIR="$RENEWED_LINEAGE"
else
    LIVE_DIR=$(find /etc/letsencrypt/live -maxdepth 1 -type d ! -path /etc/letsencrypt/live | sort | head -n1)
fi
[[ -z "$LIVE_DIR" ]] && { echo "[!] no LE live dir"; exit 1; }

# DoT 证书目录 (mosdns dot_server 读这里)。默认 /etc/mosdns/certs; 旧机可用 PDG_CERT_DIR 覆盖。
# 续期后把新证书部署到生产: 走统一配置事务(与 Bot 的 set_dot_domain 同一条路径)——
# 两个文件 + mosdns 重启要么一起成, 要么一起回到旧证书。
#
# **fail-closed**: 只要事务核心在, 从 new/stage/service 到 apply 的任何一步失败(含 python3
# 不可用), 都直接中止, **绝不退回直接 cp**。旧写法在"事务准备失败"时会 fall through 去逐个
# 覆盖生产证书 —— 那正好绕过了事务, 而且发生在最不该冒险的时刻(准备阶段都出问题了)。
# 生产证书宁可停在旧的(DoT 照常工作, certbot 下次续期还会再来一次), 也不要一份没人验证过的。
TX=""
for m in /opt/privdns-gateway/deploy/bot/pdgtx.py /opt/pdg-bot/pdgtx.py; do
    [[ -f "$m" ]] && { TX="$m"; break; }
done

if [[ -n "$TX" ]]; then
    if ! command -v python3 >/dev/null 2>&1; then
        echo "[x] 事务核心在但没有 python3: 拒绝绕过事务直接覆盖证书。生产仍用原证书。" >&2
        exit 1
    fi
    ID="$(python3 "$TX" new --source certbot --op cert_renew 2>/dev/null)" || ID=""
    if [[ -z "$ID" ]]; then
        echo "[x] 无法开启配置事务: 未改动生产证书。" >&2
        exit 1
    fi
    if ! python3 "$TX" stage --tx "$ID" --target cert_fullchain --file "$LIVE_DIR/fullchain.pem"; then
        echo "[x] 暂存证书失败(事务 $ID): 未改动生产证书。" >&2; exit 1
    fi
    if ! python3 "$TX" stage --tx "$ID" --target cert_privkey --file "$LIVE_DIR/privkey.pem"; then
        echo "[x] 暂存私钥失败(事务 $ID): 未改动生产证书。" >&2; exit 1
    fi
    if ! python3 "$TX" service --tx "$ID" --action restart:mosdns; then
        echo "[x] 登记服务动作失败(事务 $ID): 未改动生产证书。" >&2; exit 1
    fi
    if python3 "$TX" apply --tx "$ID" >/dev/null; then
        echo "新证书已部署并重载 mosdns (事务 $ID)"
        exit 0
    fi
    echo "[x] 新证书部署失败, 生产仍在使用原来的证书(事务 $ID)" >&2
    exit 1
fi

# legacy: 只有**事务核心文件完全不存在**(v1.6.2 之前的老机器)才走到这里。
CERT_DIR="${PDG_CERT_DIR:-/etc/mosdns/certs}"
echo "[!] legacy 路径: 本机没有事务核心(pdgtx.py), 直接部署证书(无事务保护)"
mkdir -p "$CERT_DIR"
cp "$LIVE_DIR/fullchain.pem" "$CERT_DIR/fullchain.pem"
cp "$LIVE_DIR/privkey.pem"   "$CERT_DIR/privkey.pem"
chmod 644 "$CERT_DIR/fullchain.pem"
chmod 600 "$CERT_DIR/privkey.pem"

systemctl is-active --quiet mosdns && systemctl restart mosdns
exit 0
