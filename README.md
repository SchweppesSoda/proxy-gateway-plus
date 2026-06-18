# proxy-gateway-plus

面向 5G NPN / 私网蜂窝出口场景的智能 DNS + SNI/QUIC 透明反代网关。

核心路径只处理**正常走 DNS/DoT 的域名流量**：客户端把 DNS over TLS 指向 VPS1，VPS1 根据规则返回真实地址或自身地址。RethinkDNS、WireGuard、SOCKS5 都是附加兜底项，用来处理裸 IP、自带 DoH/DoQ、私有 UDP、特定 App 等不正常走 DoT 的流量。

## 核心组件

| 组件 | 端口/协议 | 作用 |
|---|---|---|
| dnsdist | TCP/UDP 53, TCP 853 | DNS/DoT 策略调度、缓存、限速 |
| sniproxy | TCP 80/443 | HTTP/HTTPS SNI/Host 透明反代 |
| quic-proxy | UDP 443 | QUIC v1 Initial SNI 解析与 UDP 转发 |
| china-dns-race-proxy | 127.0.0.1:5301 TCP/UDP | ChinaList 国内 DNS 上游并发竞速 |
| WireGuard | 可选 | RethinkDNS 裸 IP / TCP / UDP 兜底 |
| sing-box SOCKS5 | 可选 | RethinkDNS SOCKS5 备用兜底或调试 |

原项目不是 SOCKS/VPN 协议。它的主路径是：

```text
Android/RethinkDNS DNS -> VPS1 dnsdist
  ChinaList -> 返回真实国内 IPv4，客户端直连
  GFWList -> 返回 VPS1 IPv4，进入 sniproxy/quic-proxy
  其他域名 -> 按安装时策略 direct/proxy 处理
```

RethinkDNS 兜底路径是附加路径（add-on fallback），不参与正常 DoT 规则判断：

```text
异常连接 / 裸 IP / 私有 UDP / 自带 DoH
  -> RethinkDNS VPNService 捕获
  -> WireGuard 或 SOCKS5
  -> VPS1 或可选 VPS2 出口
```

## 规则来源

- GFWList: `https://github.com/gfwlist/gfwlist/raw/master/gfwlist.txt`
- ChinaList: `https://github.com/felixonmars/dnsmasq-china-list/raw/master/accelerated-domains.china.conf`

GFWList 上游文件本身是 Base64 编码，直接打开会像乱码。`update-rules.sh` 会先把它解码成文本规则，再抽取 `||domain^`、URL、裸域名等格式里的域名并写入 dnsdist 的 `SuffixMatchNode`。

安装后会创建 weekly systemd timer：

```text
update-dnsdist-rules.timer
OnCalendar=Sun *-*-* 03:00:00
```

也可以在菜单里手动更新规则。

## 自定义分流

内置策略：

```text
ChinaList -> direct
GFWList   -> proxy
其他域名 -> 安装时选择 direct 或 proxy
```

本地覆盖文件：

```text
/etc/dnsdist/gfwlist-extra-local.txt
/etc/dnsdist/proxy-extra-local.txt
/etc/dnsdist/direct-extra-local.txt
/etc/dnsdist/custom-proxy-lists.txt
/etc/dnsdist/custom-direct-lists.txt
```

`gfwlist-extra-local.txt` 兼容原项目，用来手动补充 GFWList。`proxy-extra-local.txt` 和 `direct-extra-local.txt` 每行一个域名。`custom-*-lists.txt` 每行一个远程列表 URL，远程列表支持常见裸域名、Adblock、dnsmasq `server=/domain/`、`address=/domain/` 风格。

本地域名文件建议使用最简单的一行一个域名：

```text
example.com
google.com
youtube.com
```

远程列表内容可解析这些格式：

```text
example.com
*.example.com
||example.com^
|https://example.com/path
|http://example.com/path
server=/example.com/1.1.1.1
address=/example.com/1.2.3.4
```

当前不解析 Clash/Surge/Loon 的策略行、关键字、IP 段或正则，例如：

```text
DOMAIN-SUFFIX,example.com,Proxy
DOMAIN-KEYWORD,google,Proxy
IP-CIDR,1.2.3.0/24,Proxy
/regex/
0.0.0.0 example.com
```

解析时会去掉行尾 `#` 注释、首尾空白、末尾点号，并把 `www.example.com` 归一成 `example.com`。

海外 DNS 仍支持原项目变量：

```text
OVERSEAS_DNS            旧兼容变量，等同 PRIVATE_OVERSEAS_DNS
PRIVATE_OVERSEAS_DNS    172.22.0.0/16 私网客户端默认海外 DNS
PUBLIC_OVERSEAS_DNS     非私网 DoT 客户端默认海外 DNS
SNIPROXY_DNS            sniproxy 后端解析器
```

安装时会把 `SNIPROXY_DNS` 写入 `/etc/sniproxy.conf` 的 resolver，并保持 `mode ipv4_only`，避免反代后端解析优先走 IPv6。

## 小内存模式

原模板里有 3 组 `newPacketCache(500000)`。本项目改成可配置 cache size，默认小内存模式：

```text
默认 cache size: 200000
可选: 50000 / 100000 / 200000 / 500000 / 自定义
```

这只控制 dnsdist packet cache 条目数；GFWList / ChinaList 仍会加载到 dnsdist 的 `SuffixMatchNode`。

## 交互安装

### 远程使用

推荐在 VPS 上下载单个 `install.sh` 后运行。脚本发现当前目录缺少模板、Go 源码和辅助脚本时，会自动下载公开仓库 tarball、解压到临时目录，并切换到完整脚本继续显示交互菜单。

```bash
sudo -i
curl -fL -o proxy-gateway-install.sh https://raw.githubusercontent.com/SchweppesSoda/proxy-gateway-plus/main/install.sh
bash proxy-gateway-install.sh
```

如果不想使用自举下载，也可以手动下载完整仓库后运行：

```bash
sudo -i
workdir="$(mktemp -d)"
cd "$workdir"
curl -fL -o proxy-gateway-plus.tar.gz https://github.com/SchweppesSoda/proxy-gateway-plus/archive/refs/heads/main.tar.gz
tar -xzf proxy-gateway-plus.tar.gz
cd proxy-gateway-plus-main
chmod +x install.sh update-rules.sh renew-hook.sh
./install.sh
```

如果 VPS 已安装 `git`，也可以克隆公开仓库后运行：

```bash
git clone https://github.com/SchweppesSoda/proxy-gateway-plus.git
cd proxy-gateway-plus
sudo ./install.sh
```

上传仓库文件到 VPS 后运行：

```bash
chmod +x install.sh
./install.sh
```

安装时会先让你输入用于 DoT 和证书的域名。这个域名不绑定 ClouDNS，可以使用 Cloudflare、阿里云、腾讯云、Namecheap、ClouDNS 或任意 DNS 服务商；只要把该域名的 A 记录解析到 VPS 公网 IP，脚本验证通过后就会继续证书步骤。脚本会先检查本机 `/etc/letsencrypt/live/` 里是否已有覆盖当前域名且未临近过期的 existing certificate；有的话直接复制给 dnsdist 使用，不会重新申请。找不到可复用证书时才调用 certbot 申请。

主菜单：

```text
  1) 安装核心 DNS + SNI/QUIC 网关
  2) 配置 DNS 分流策略
  3) 管理自定义分流列表
  4) 添加 RethinkDNS WireGuard 兜底入口
  5) 添加 RethinkDNS SOCKS5 兜底入口
  6) 配置 VPS1 转发到 VPS2 SNI/QUIC 后端
  7) 安装 VPS2 SNI/QUIC 后端
  8) 安装可选 VPS2 SOCKS5 出口
  9) 立即更新 DNS 规则
 10) 查看状态
 11) 续期证书
 12) 重新生成 iOS 描述文件
 13) 清空 DNS 设置
 14) 卸载
  0) 退出
```

脚本交互输入优先从 `/dev/tty` 读取，适配 `curl` 下载后本地执行的场景。需要 root 的安装建议先下载脚本再运行，不建议直接在线管道执行。

## RethinkDNS 附加项

WireGuard 使用原生 `wireguard-tools` + `wg-quick`，推荐用于裸 IP、TCP、UDP、QUIC、游戏或私有协议兜底。脚本会生成：

```text
/etc/wireguard/pgw-rdns.conf
/opt/proxy-gateway/wireguard/rethinkdns-client.conf
```

SOCKS5 使用 sing-box。脚本会优先复用已存在的 sing-box，尤其是 argosbx 常见路径：

```text
$HOME/agsbx/sing-box
$HOME/agsbx/sb.json
/root/agsbx/sing-box
/root/agsbx/sb.json
$HOME/bin/agsbx
```

找到后默认选项是备份并追加 `proxy-gateway-socks-in` inbound。新建独立 `proxy-gateway-socks.service` 只是复用失败或用户明确选择时的兜底。

SOCKS5 默认：

```text
监听: 0.0.0.0:1080
用户名: pgw
密码: 随机生成
来源限制: 172.22.0.0/16 或用户输入 CIDR
```

VPS2 出口是可选项。VPS2 只安装 SOCKS5 出口时，脚本默认使用 additive 防火墙模式，只追加 proxy-gateway 自有链，不清空整机防火墙；如选择 `managed-exclusive` 专用机器模式，才会接管整机防火墙。

## VPS1 转发到 VPS2 SNI/QUIC 后端

如果不希望 VPS1 本机跑 `sniproxy` / `quic-proxy`，可以把 VPS1 作为入口，转发到 VPS2 后端：

```text
客户端 -> VPS1:80/443/TCP 或 443/UDP
VPS1 DNAT + MASQUERADE -> VPS2:80/443/TCP 或 443/UDP
VPS2 sniproxy/quic-proxy -> 真实网站
```

配置步骤：

```bash
./install.sh --vps2-backend   # 在 VPS2 上执行，安装 sniproxy/quic-proxy
./install.sh --vps1-forward   # 在 VPS1 上执行，输入 VPS2 IP 和客户端 CIDR
```

VPS1 forward 模式会停止并禁用本机 `sniproxy` / `quic-proxy`，避免和 DNAT 入口抢占 80/443/TCP、443/UDP。DNS 仍然返回 VPS1，客户端不会拿到 VPS2 IP。

UDP/QUIC 使用内核 NAT + conntrack，不使用 `socat`。VPS1 会对转发到 VPS2 的 TCP/UDP 流量做 MASQUERADE，因此 VPS2 看到的来源是 VPS1，回包会稳定回到 VPS1，再由 VPS1 返回客户端。

防火墙模式：

```text
FIREWALL_MODE=additive           默认，只追加 proxy-gateway 自有链
FIREWALL_MODE=managed-exclusive  专用机器模式，接管整机防火墙
FIREWALL_MODE=disabled           不改防火墙，只输出提示
```

脚本会在写防火墙规则前检测实际 SSH 端口：优先 `sshd -T`，再读 `/etc/ssh/sshd_config` 和 `/etc/ssh/sshd_config.d/*.conf`，再查正在监听的 `sshd`，最后保留当前 SSH 会话端口。检测失败时才默认保留 TCP/22，也可以用 `SSH_PORTS=22,2222` 手动指定。

## 客户端配置

Android 系统私人 DNS 或 RethinkDNS DNS 设置指向安装生成的域名：

```text
tls://<domain>:853
```

iOS 描述文件默认由 VPS1 的 `8111` 端口提供：

```text
http://<domain>:8111/ios-dot.mobileconfig
```

RethinkDNS 中建议：

```text
正常 DNS: VPS1 DoT
异常/裸 IP/TCP/UDP fallback: WireGuard
简单 TCP 调试或备用: SOCKS5
```

## 安全边界

- 默认防火墙模式是 `additive`，脚本只追加/刷新 `proxy-gateway` 自有规则，不清空整机防火墙、不修改默认 policy。
- 选择 `managed-exclusive` 时才会接管整机防火墙；该模式会先检测并保留实际 SSH 端口，不再硬编码只放行 22。
- DNS 53、DoT 853、80/443 SNI/QUIC 反代端口的最终暴露面取决于当前防火墙模式和已有系统规则；脚本自有规则会把 80/443/TCP 和 443/UDP 限制到 `172.22.0.0/16` 或用户配置的 CIDR。
- SOCKS5 默认强制用户名密码，并且防火墙限制来源 CIDR。
- WireGuard/SOCKS5/VPS2 都不是主路径，只有用户在菜单中启用才安装。
- 公开仓库不包含任何密钥；安装时生成的密码、WireGuard 私钥和证书只保存在目标服务器。

## 维护命令

```bash
./install.sh --status
./install.sh --update-rules
./install.sh --renew-cert
./install.sh --clear-settings
./install.sh --vps1-forward
./install.sh --vps2-backend
./install.sh -ios
./install.sh --uninstall
```

## 验证

```bash
bash -n install.sh update-rules.sh renew-hook.sh tests/*.sh
```

PowerShell 策略测试位于 `tests/*.ps1`。
