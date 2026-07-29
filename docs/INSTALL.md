# 安装 / 部署细节

## 0. 前提清单

- 墙外 VPS:**Debian 12+ / Ubuntu 22+**,root,**1 vCPU / 512MB+ 即可**(常驻 ~90MB)。
- 运营商**内网卡**:手机移动流量经私网到达 VPS,源 IP 是固定私有段。
- 一个**域名**,且你能改它的 DNS 记录(给 DoT 用)。
- 可选的 **Telegram bot**(找 @BotFather 建,拿 token)和你自己的 **user id**(找 @userinfobot);
  token 安装时可以留空,之后用 `sudo pdg-set-token` 配置。

## 1. 先把 DNS 准备好(这一步留给你)

给一个子域(如 `dot.example.com`)加一条 **A 记录指向你 VPS 的公网 IP**。

- **Cloudflare**:必须用「**仅 DNS / 灰云**」,**不要开橙云代理**(代理不覆盖 853 端口,会导致 DoT 连不上)。
- 其它 DNS 商:普通 A 记录即可。
- 等生效(`dig +short dot.example.com` 能返回你的 IP)再装。

## 2. 跑安装

派生仓库目前还没有兼容的 `v*` 发布 tag。首次派生版本发布前,请克隆当前默认分支并
显式跳过发布 tag 自举:

```bash
git clone https://github.com/SchweppesSoda/proxy-gateway-plus.git
cd proxy-gateway-plus
sudo PDG_TAG_BOOTSTRAPPED=1 ./install.sh
```

`PDG_TAG_BOOTSTRAPPED=1` 只用于这段首次发布前的开发验证。创建首个派生 `v*` tag 后,
标准入口脚本会自动切到最新发布 tag,不安装 main 上未发布的中间提交。

> MosDNS 使用 v5.3.4 no-session-ticket 修补 flavor。当前没有自有长期 release asset，
> 所以还须先在本机/KFC 构建并通过 `PDG_MOSDNS_ARTIFACT` 与显式 SHA256 交给安装器；
> 不会回退安装官方 stock v5.3.4，也不在 VPS 临时安装 Go。见
> [MosDNS 修补版构建与部署](MOSDNS-PATCHED-BUILD.md)。

过程中:

1. **自动检测公网 IP**(可改)。
2. **自动检测 SSH 端口**(可改)——⚠️ 防火墙会按它放行,改错会把自己关门外。
3. **自动识别内网卡段**:脚本抓包 ~40 秒,期间用手机(走内网卡/蜂窝)打开 `http://<你的IP>` 或 ping 它一下,脚本据此推断 CIDR。
   没抓到可手填。
4. 填 **bot token / 你的 TG id / DoT 域名**。
5. 确认 A 记录已生效后,脚本用 **certbot standalone** 签证书(此时会临时占用 80 口)。
6. 下载 geosite、起服务、应用防火墙。

## 3. 装完

见 [README](../README.md#装完之后):手机设私密 DNS、bot 加出口/分流、iOS 下发描述文件。

默认路由是「**国内直连 / 其余国际从 VPS 直出**」。要把国际流量走你的落地节点,在 bot 里加出口再把 `final` 或具体规则指过去。

## 可选 Web 管理面（默认禁用）

安装器只把 Web 代码、systemd 单元和控制命令部署到机器，不创建认证配置、不启动服务，
也不改任何防火墙。需要时显式执行：

```bash
sudo pdg web setup
sudo pdg web enable
sudo pdg web status
```

setup 默认建议 `127.0.0.1:9091`，但监听地址和端口都可配置；它会交互读取访问域名、可信
CIDR、证书/私钥和管理员密码。密码不会出现在 argv 或环境变量中，配置写入
`/etc/privdns-gateway/web.json`，父目录为 `root:root 0700`、文件为 `root:root 0600`。
服务只提供 HTTPS，并精确校验 Host、Origin 和客户端来源；会话最长 8 小时。证书和私钥
最终目标必须是 root 拥有的普通文件，私钥为 owner-only 权限；允许 certbot
`/etc/letsencrypt/live/...` 的 root-owned 链接，但链接链和解析后的全部父目录必须由 root
控制且不可被 group/world 写入。setup 会拒绝尚未生效、已过期、域名不匹配或私钥不匹配的
证书。正在运行的 Web 在 setup/password 后若无法稳定重启，会原子还原旧配置并验证旧服务
恢复。

Web 支持修改已有规则集 target，以及在保留 tag、顺序和全部引用的前提下原位替换普通节点
连接参数。出口延迟由 Mihomo Clash API 探测；域名诊断分别报告 DNS 实测证据与配置规则
推演，网关出口推演不等同于真实数据包出口验证。回滚按带随机后缀的稳定快照 ID 精确选择，
回滚和软件更新使用持久异步任务，浏览器断连后可重连查看状态。软件更新任务实际执行时调用
`pdg update` 并跟随届时最新发布版，不锁定提交任务时预检到的 tag。

推荐保持 loopback 监听并使用 SSH 隧道，例如：

```bash
ssh -L 9091:127.0.0.1:9091 -p <实际SSH端口> root@<VPS>
```

若证书签给 `pdg.example.com`，浏览器打开 `https://127.0.0.1:9091` 会因证书名称不匹配。
应在管理电脑的 hosts 中让 `pdg.example.com` 指向 `127.0.0.1`，打开
`https://pdg.example.com:9091`；也可以使用证书覆盖、仅可信网络可达的私有域名入口。
setup 会自动保留 `127.0.0.1/32` 和 `::1/128`，但 Host（非 443 时包含端口）仍须精确匹配。

Web 只信任 TCP socket 的真实对端地址并忽略 `X-Forwarded-For`。loopback 反向代理会让
Web 看到 `127.0.0.1`，所以代理若存在，必须自行执行真实客户端来源 ACL；默认支持路径仍是
SSH 隧道。

绑定非 loopback 地址直连只适用于 `PDG_FIREWALL_MODE=external`，外部防火墙/管理员应读取
`pdg web enable/status` 输出的**实际 service interface 和可信 CIDR**并显式接入。
`managed` 的 `inet pdg input policy drop` 不会由 Web 自动修改或放行该入口，官方路径是
改回 loopback + SSH 隧道，除非管理员明确完成策略集成。`pdg web` 在两种模式都不写
nftables、云安全组或整机 input policy，也不能把示例 9091 当成固定公网端口。修改密码用
`sudo pdg web password`，停用但保留配置用 `sudo pdg web disable`。普通卸载保留该配置；
只有 `--purge` 才删除。

## 排障

| 现象 | 排查 |
|---|---|
| 证书签发失败 | A 记录没生效?80 口被云厂商安全组挡了?`dig +short 域名` 对不对 |
| 手机没 DNS | 私密 DNS 主机名填对了吗?手机确实走内网卡?`systemctl status mosdns` |
| 代理域名打不开 | `systemctl status mihomo`;出口加了吗、密码对不对(bot「🚦 测出口」)|
| 内网卡段填错 | 改 `/etc/mosdns/config.yaml` 的 `npn_clients` 和 `/etc/nftables.conf`,`systemctl restart mosdns && nft -f /etc/nftables.conf` |
| bot 不理你 | Bot 只处理私聊;再看 `systemctl status pdg-bot`、token / user id(`/etc/privdns-gateway/bot.env`)|
| Web 无法打开 | `sudo pdg web status`;检查可信 CIDR、精确 HTTPS Host/Origin、证书有效期；直连只在 `external` 下检查外部 service interface，`managed` 使用 loopback + SSH 隧道 |
| 恢复备份报"成员过多/过大" | 规则集多的机器会撞上默认上限,见下方"恢复备份的解包限额" |

日志:`journalctl -u mosdns -u mihomo -u pdg-bot -u pdg-web -n 50`。

### 恢复备份的解包限额

备份包是外部输入(谁都能往 bot 发一个文件),所以解包有数量/体积上限,压缩炸弹一律拒整包。
规则集特别多的机器可能会撞上默认值 —— 在 `/etc/privdns-gateway/bot.env` 里调,然后
`systemctl restart pdg-bot`:

| 变量 | 默认 | 可调范围 |
|---|---|---|
| `PDG_RESTORE_MAX_MEMBERS` | 512 个 | 16 ~ 20000 |
| `PDG_RESTORE_MAX_FILE_BYTES` | 8 MiB | 64 KiB ~ 512 MiB |
| `PDG_RESTORE_MAX_TOTAL_BYTES` | 64 MiB | 1 MiB ~ 可用磁盘的一半 |

越界的值会被夹回区间(写 0 或天文数字并不能把这道防线关掉),写成非数字则按默认值处理;
两种情况都会在 `journalctl -u pdg-bot` 里留一行说明。总量上限的天花板跟着 `/etc/sing-box`
所在文件系统的可用空间走 —— 盘大就能调高,盘小也不至于被一个备份写满(问不到磁盘信息时
退回 2 GiB)。

## 非交互 / 自动化安装

预置环境变量 + `PDG_NONINTERACTIVE=1` 即可无人值守(适合脚本化/复刻):

```bash
sudo PDG_NONINTERACTIVE=1 \
     PDG_SERVER_IP=203.0.113.10 \
     PDG_SSH_PORT=22 \
     PDG_INTERNAL_CIDR=172.22.0.0/16 \
     PDG_FIREWALL_MODE=managed \
     PDG_QUIC_MODE=tproxy \
     PDG_HIJACK_TLS_TCP_PORTS=443,5228,5229,5230 \
     PDG_HIJACK_HTTP_TCP_PORTS=80 \
     PDG_BOT_TOKEN=123456:xxxx \
     PDG_ALLOWED=11111111 \
     PDG_DOT_DOMAIN=dot.example.com \
     ./install.sh
```

- 缺省项会自动探测(公网 IP / SSH 端口)或用默认值。
- `PDG_SKIP_CERT=1`:跳过 certbot,生成**自签占位证书**(先把服务跑起来,之后用 bot「🌐 DoT 自定义域名」补正式证书)。
- 安装会**自动关闭 systemd-resolved**(它占 `127.0.0.53:53`,与 mosdns 的 `0.0.0.0:53` 冲突)。
- `PDG_HIJACK_TLS_TCP_PORTS` 与 `PDG_HIJACK_HTTP_TCP_PORTS` 是完整十进制端口集合,
  不是增量追加。Android TLS 默认 `443,5228,5229,5230`,iOS TLS 默认 `443`,HTTP
  默认 `80`;安装器会拒绝空值、范围、重叠、本机监听冲突和重复 profile 键。
- `PDG_QUIC_MODE=tproxy` 是默认值;显式 `reject` 才关闭 Mihomo 原生 QUIC TPROXY。

> 本仓库的 install.sh 已在全新 Debian 12 上实跑验证(mosdns/mihomo/bot/防火墙全部起来、DNS 劫持分流正确)。

## 直连例外与非标准 TCP 端口

MosDNS 在劫持模式下会把代理域名 A 记录改写为网关 IP。遇到非标准端口故障时,不要先加端口:

1. 如果域名本应直连,在 bot「📑 分流管理」中把它指到 `direct`。Bot 会通过配置事务写入
   `/etc/mosdns/rules/custom_direct.txt` 并清理冲突的自定义劫持,手机重新查询后取得真实 IP。
   规则集也可使用 literal `direct`: `DOMAIN`→`full:`、`DOMAIN-SUFFIX`→`domain:`、
   `DOMAIN-KEYWORD`→`keyword:`，在同一 `pdgtx` 事务中派生到独立
   `/etc/mosdns/rules/ruleset_direct.txt`。这表示 MosDNS 返回真实地址、手机本地直连且不经
   VPS；含任何 `IP-CIDR/IP-CIDR6` 或 `.mrs/.srs` 的规则集会明确拒绝。默认 direct-type
   出口 `JP` 则是流量已到 VPS 后由 VPS 本机直出，两者不要混淆。显式单域名代理规则比宽泛
   direct 规则集优先。
   指向非 literal-direct 出口的可展开 source 规则集会把域名项聚合到
   `/etc/mosdns/rules/ruleset_hijack.txt`，由 MosDNS 在国内直连判断前强制劫持，避免目标
   域名取得真实地址后绕过 VPS。二进制 `.mrs` 不在 DNS 层展开，也不会猜测其中域名；可能
   命中时域名诊断会明确返回未知。
2. 只有域名确实需要代理时,才把原始目的端口加入对应完整集合。例如测试服务使用 TLS
   `:10443`,可在新部署参数中使用 `PDG_HIJACK_TLS_TCP_PORTS=443,10443`。Android 若仍需
   GMS/FCM,还要保留 `5228-5230`。
3. 扩展前确认该端口不与 SSH、DNS、Mihomo API 等本机监听冲突,并确认网关或所选出口能访问
   目标端口。安装器会把同一端口模型同时渲染到 nft source-scoped REDIRECT 和 Mihomo sniffer。

## 数据面端口与开放责任

TCP 代理流量按 `PDG_HIJACK_*_TCP_PORTS` 从内网卡来源段 REDIRECT 到单个 Mihomo
`:7893`。UDP/443 默认 TPROXY 到同一进程的 `:7895`;没有第二 Mihomo、TUN 或第二透明
监听器。

| 端口或集合 | 协议 | 用途 |
|---|---|---|
| `PDG_SSH_PORT` | tcp | SSH 管理;默认示例为 22,以实际 sshd 为准 |
| 53 | tcp+udp | MosDNS 明文 DNS |
| 853 | tcp | DoT 手机入口 |
| `PDG_HIJACK_HTTP_TCP_PORTS` | tcp | HTTP 原始目的端口集合,source-scoped REDIRECT → `:7893` |
| `PDG_HIJACK_TLS_TCP_PORTS` | tcp | TLS 原始目的端口集合,source-scoped REDIRECT → `:7893` |
| 5228-5230 | tcp | 仅 Android：默认包含在 TLS 集合中的 GMS/FCM 目的端口 |
| 443 | udp | 默认 native QUIC TPROXY → `:7895`;`reject` 模式不创建该 TPROXY 链 |
| 81 | tcp | 仅 iOS:OnDemand 探测端点,任意 GET 返回 HTTP 200 |
| 7893 | tcp | Mihomo redir listener,由透明数据面使用 |
| 7895 | udp | 默认 Mihomo native TPROXY listener |
| 8445 | tcp | 手机 Telegram 可选 SOCKS5 入口 |
| 9090 | tcp | Mihomo clash_api；通常仅本机，临时观测/控制面板开启时供内网卡来源访问 |
| Web 配置端口（setup 默认 9091） | tcp | 可选 HTTPS 管理面;默认禁用,来源由 trusted CIDR 限制 |
| 8443 | tcp | `pdg ios` 下发描述文件时临时使用 |

开放责任取决于防火墙模式:

- `PDG_FIREWALL_MODE=managed`（默认）:项目维护 `inet pdg` input hook 与 `policy drop`;
  SSH 按实际端口放行,应用入口只允许内网卡来源段。面板临时监听公网地址时仍只允许该来源段。
- `PDG_FIREWALL_MODE=external`:项目保留 source-scoped REDIRECT / TPROXY 数据面,但移除
  整个 input block,不声明任何公网开放端口。主机 input policy、云安全组和 ACME 临时放行均由
  `vps-toolkit` 或管理员负责。

两种模式都要求云安全组和上层防火墙与服务入口一致。Let's Encrypt HTTP-01 还要求签发或
续期期间公网能到达 TCP/80;source-scoped REDIRECT 不会截获非内网卡来源的 ACME 请求。
网关出站需能访问 Telegram API、DNS 上游、各落地节点和 GitHub;本仓库不接管整机 output policy。
证书成功续期后,deploy hook 会在 pdg-web 已配置且正在运行时重启并确认服务;没有 Web 配置
或服务未运行时不会顺带启用它。

本仓库提供非交互安装、显式迁移、更新、快照/回滚、状态和 doctor 等标准幂等接口。SSH 加固、
其他应用和跨主机发布属于 `vps-toolkit` 的整机编排范围;上层应调用这些接口而不是维护另一套
MosDNS、Mihomo 或 nft 模板。

## 版本注意

- **流量内核 mihomo(clash.meta)**,版本由 `lib/versions.sh` 钉死、`pdg update` 随发布版安装并逐字节 SHA256 校验。
- mosdns v5.x。

> **为什么不用 sing-box**:sing-box 1.13 移除了本网关依赖的 `sniff_override_destination`(其新写法 `action: sniff` 不覆盖目标地址、会流量回环),只能钉死在 1.12.x 死胡同。因此 v1.6.0 起彻底改用 mihomo(`sniffer.override-destination` 无版本天花板)。旧的 sing-box 机器 `sudo pdg update` 时会自动迁移到 mihomo。

## 升级

- 日常升级用 `sudo pdg update`:**更新到最新发布 tag**(只跟 `v*` tag、不拉 main 上未发布的中间提交)+ 校验门 + 失败自动回滚到更新前快照,不动出口/分流/证书。版本号(`pdg status` / bot『🔄 更新』)用 `git describe` 显示,如 `v1.1.0`。
- **不要**用 `install.sh` 在已有部署上覆盖升级——它会拒绝并提示走 `pdg update`(确要覆盖重装才 `sudo PDG_FORCE_REINSTALL=1 ./install.sh`,会先打快照)。

### 旧版升上来的一次性防火墙迁移

早期版本的防火墙是 `flush ruleset` + `table inet filter`;新版改用独立表 **`inet pdg`**(不再清掉 Docker/fail2ban 等其它表)。

- `pdg update` 在更新前先上锁并留快照,装入新脚本后再调用幂等迁移;失败由更新事务回滚。
  不升级代码时可显式执行 `sudo pdg migrate`（全部迁移）或 `sudo pdg migrate-fw`。
- `status`、`doctor`、`log`、`traffic`、`report`、菜单和普通 `restart` 都不会暗中修改配置或
  触发迁移。
- 迁移会识别旧 SSH 端口、内网卡段和目标 `managed|external` 意图,渲染
  `deploy/firewall/nftables-mihomo.conf`,经候选检查后只替换 owned `inet pdg` 块。
- **改过的 foreign/malformed 同名表不会被猜测重建**:扫描器会 fail closed,原配置保持不变。
  请先备份并人工解决冲突,不要直接复制标准模板覆盖整机规则。

## 流媒体/服务解锁(WDA,可选)

如果你的 VPS 厂商提供 **SmartDNS 解锁(WDA)** 服务,可在 bot『🌐 DNS 上游』用两个按钮整体切换:

- **🛬 解锁走落地出口**(默认):Netflix/Disney+/AI 等走各自分流出口(hk/tw)。
- **🔓 解锁走 WDA**:这些服务整体 → **本机(JP)直出** + 经解锁 DNS 解析到中继。中继是干净 IP,能避开 Netflix 对机房裸 IP 的代理封锁。

**开 WDA 前必须先在解锁服务商后台,把本机公网 IP 加白授权**(解锁按 IP 授权;多台网关要**每台 IP 各自加白**)。没授权就点 🔓,bot 会**自检后拦下并提示**(避免解锁服务拿不到中继、流媒体反而挂)。

- 解锁地区取决于你在厂商面板选的平台(VPS 在日本→选 JP 平台→日本区)。
- 解锁 DNS 默认对接 `22.22.22.22`(本项目所用厂商)。换别家解锁服务需同步改 `deploy/mosdns/config.yaml` 的 `unlock_upstream` 与 `deploy/bot/pdg-bot.py` 的 `UNLOCK_DNS`。
- 某个服务在 WDA 下不灵,点 🛬 整体切回落地即可(目前是整体开关,非按服务)。

## 卸载

```bash
sudo ./uninstall.sh           # 停服务、删 systemd 单元(留配置/证书/二进制)
sudo ./uninstall.sh --purge   # 连 Web 认证配置及其它网关配置一起删
```
