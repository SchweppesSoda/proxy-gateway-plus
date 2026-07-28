#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# 出站 schema 校验: 走**真实生产链路** —— parse_link 生成的各协议出站(sing-box JSON 数据模型)
# → sb2mihomo 渲染 → 用**项目锁定版** mihomo(lib/versions.sh 的 MIHOMO_VER, 钉死 SHA256)跑 `mihomo -t`。
# 为什么单独做: test-parse-links.py 只验"解析出的 dict 字段对不对", 但这些字段能不能真的渲染成
# 内核认的配置是另一回事, 且常随版本小变 —— 必须拿锁定版内核真校验才算数。CI 可跑。
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
# shellcheck source=lib/versions.sh
source "$ROOT/lib/versions.sh"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
fail(){ echo "[FAIL] $*" >&2; exit 1; }

case "$(uname -m)" in
  x86_64) ARCH=amd64 ;; aarch64|arm64) ARCH=arm64 ;;
  *) fail "不支持的架构: $(uname -m)" ;;
esac

# 必须用锁定版(不是 PATH 上可能漂移的版本)→ 下载 MIHOMO_VER 并校验 SHA256
echo "[*] 下载锁定版 mihomo $MIHOMO_VER ($ARCH)…"
curl -fsSL "https://github.com/MetaCubeX/mihomo/releases/download/${MIHOMO_VER}/mihomo-linux-${ARCH}-${MIHOMO_VER}.gz" \
     -o "$WORK/m.gz" || fail "mihomo 下载失败"
pdg_verify_sha256 "$WORK/m.gz" "${PDG_SHA256[mihomo-$ARCH]:-}" "mihomo $MIHOMO_VER ($ARCH)" \
  || fail "mihomo SHA256 校验失败"
gunzip -c "$WORK/m.gz" > "$WORK/mihomo" || fail "mihomo 解压失败"
chmod 755 "$WORK/mihomo"
MH="$WORK/mihomo"
echo "[*] $("$MH" -v | head -1)"

# 用 parse_link 拼各协议出站 → 写最小 config(占位但字段合法的值)
python3 - "$ROOT" "$WORK/cfg.json" "$ZASHBOARD_VER" <<'PY'
import base64, json, sys, os, importlib.util
root, out, zash_ver = sys.argv[1:4]
spec = importlib.util.spec_from_file_location("b", os.path.join(root, "deploy/bot/pdg-bot.py"))
b = importlib.util.module_from_spec(spec)
try:
    spec.loader.exec_module(b)
except SystemExit:
    pass
U = "11111111-2222-3333-4444-555555555555"
ss2022 = base64.b64encode(b"0123456789abcdef").decode()                 # 2022-blake3-aes-128-gcm 需 16B 密钥
ssui = base64.urlsafe_b64encode(b"aes-256-gcm:pw").decode().rstrip("=")
vm = base64.b64encode(json.dumps({"v": "2", "ps": "VM", "add": "vm.example.com", "port": "443",
     "id": U, "aid": "0", "net": "ws", "tls": "tls", "host": "vm.example.com", "path": "/p"}).encode()).decode()
links = [
    "ss://%s@1.2.3.4:8388#SS" % ssui,
    'HK = ss, 2.2.2.2, 11111, encrypt-method=2022-blake3-aes-128-gcm, password="%s"' % ss2022,
    "vmess://" + vm,
    "trojan://pw@t.example.com:443?sni=t.example.com#TROJAN",
    "vless://%s@r.example.com:443?security=reality&pbk=jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0"
    "&sid=ab12&fp=chrome&flow=xtls-rprx-vision&sni=www.microsoft.com#REALITY" % U,
    "vless://%s@g.example.com:443?security=tls&type=grpc&serviceName=mygrpc&sni=g.example.com#GRPC" % U,
    "hysteria2://hp@h2.example.com:8443?sni=h2.example.com&obfs=salamander&obfs-password=ob#HY2",
    "tuic://%s:tp@tuic.example.com:443?sni=tuic.example.com&congestion_control=bbr&alpn=h3#TUIC" % U,
    "anytls://ap@a.example.com:443?sni=a.example.com#ANYTLS",
    "socks5://u:p@1.2.3.4:1080#SOCKS",
    "http://u:p@1.2.3.4:8080#HTTP",
]
obs = [b.parse_link(x) for x in links]
print("[*] 出站类型:", [o["type"] for o in obs])
# 数据模型仍是 sing-box JSON(bot 的唯一数据源), 再经 sb2mihomo 渲染成内核吃的配置
model = {"log": {"level": "error"},
         "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": 12345}],
         "outbounds": obs + [{"type": "direct", "tag": "direct"}],
         "route": {"final": "direct"},
         "experimental": {"clash_api": {
             "external_controller": "0.0.0.0:9090", "secret": "schema-test",
             "external_ui": "/etc/sing-box/ui/dist",
             "external_ui_download_url": f"https://github.com/Zephyruso/zashboard/releases/download/{zash_ver}/dist-no-fonts.zip"}}}
sys.path.insert(0, os.path.join(root, "deploy/bot"))
import sb2mihomo
cfg, meta = sb2mihomo.singbox_to_mihomo(model, redir_port=7893)
bad = (meta or {}).get("unknown_proxies") or []
if bad:                                    # 每个协议都必须能转换, 不能静默丢
    print("[FAIL] 这些出站 sb2mihomo 转换不了:", ", ".join(map(str, bad)), file=sys.stderr)
    sys.exit(1)
json.dump(cfg, open(out, "w"), ensure_ascii=False)   # JSON 即合法 YAML
PY
[ -f "$WORK/cfg.json" ] || fail "拼 config 失败(parse_link / sb2mihomo 出错?)"

echo "[*] mihomo -t(锁定版 $MIHOMO_VER)…"
"$MH" -t -d "$WORK" -f "$WORK/cfg.json" \
  || fail "mihomo -t 不过: parse_link→sb2mihomo 产出的配置与锁定版 $MIHOMO_VER 不符"
echo "✅ 各协议出站 + 面板 clash_api 经 sb2mihomo 在锁定版 mihomo $MIHOMO_VER 下校验通过"
