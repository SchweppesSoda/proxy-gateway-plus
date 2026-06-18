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

`gfwlist-extra-local.txt` 兼容原项目，用来手动补充 GFWList。`proxy-extra-local.txt` 和 `direct-extra-local.txt` 每行一个域名。`custom-*-lists.txt` 每行一个远程列表 URL，支持常见裸域名、Adblock、dnsmasq `server=/domain/`、`address=/domain/` 风格。

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

主菜单：

```text
  1) 安装核心 DNS + SNI/QUIC 网关
  2) 配置 DNS 分流策略
  3) 管理自定义分流列表
  4) 添加 RethinkDNS WireGuard 兜底入口
  5) 添加 RethinkDNS SOCKS5 兜底入口
  6) 安装可选 VPS2 SOCKS5 出口
  7) 立即更新 DNS 规则
  8) 查看状态
  9) 续期证书
 10) 重新生成 iOS 描述文件
 11) 卸载
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

VPS2 出口是可选项。VPS2 只安装 SOCKS5 出口时，脚本使用 SOCKS-only 防火墙，只放行 SSH 和来自 VPS1 的 SOCKS5。

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

- DNS 53 仅允许 `172.22.0.0/16`，DoT 853 可对外但按来源分流。
- 80/443 SNI/QUIC 反代端口默认只允许 `172.22.0.0/16`。
- SOCKS5 默认强制用户名密码，并且防火墙限制来源 CIDR。
- WireGuard/SOCKS5/VPS2 都不是主路径，只有用户在菜单中启用才安装。
- 公开仓库不包含任何密钥；安装时生成的密码、WireGuard 私钥和证书只保存在目标服务器。

## 维护命令

```bash
./install.sh --status
./install.sh --update-rules
./install.sh --renew-cert
./install.sh -ios
./install.sh --uninstall
```

## 验证

```bash
bash -n install.sh update-rules.sh renew-hook.sh tests/*.sh
```

PowerShell 策略测试位于 `tests/*.ps1`。
