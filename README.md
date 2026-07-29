# proxy-gateway-plus

proxy-gateway-plus 基于 PrivDNS Gateway，是一个使用系统私密 DNS（DoT）的域名分流网关。手机端只需配置 DoT，网关根据域名决定直连，或把流量交给指定出口。手机不需要安装 VPN、Clash 或 sing-box 客户端。

> 第一次部署可参考图文教程：[docs/QUICKSTART.md](docs/QUICKSTART.md)。
>
> 当前根架构派生自 Misaka 的 PrivDNS Gateway 固定提交
> `eff3668c5873a7fce6b2c1663056b7d7bf1a7beb`；导入基线与同步规则见
> [UPSTREAM_BASE.md](UPSTREAM_BASE.md)，导入前的旧架构保存在
> [`legacy/current-architecture/`](legacy/current-architecture/)。

## 1. 项目简介

手机把系统 DNS 指向网关的 DoT 域名后，域名解析统一由网关处理：

- 国内域名返回真实 IP，手机直连。
- 需要走代理的域名，网关把 A 记录改写成网关自己的 IP，流量因此回到网关；网关嗅探 SNI/Host，再按域名把连接交给对应出口，或从本机直出。

手机上只有一条私密 DNS 设置，没有客户端，也没有 tun。出口、分流规则、故障组、DoT 域名等都在 Telegram Bot 或 `pdg` 命令里管理。

## 2. 工作原理

```
手机（Android 私密 DNS / iOS 描述文件）
   │  DoT :853
   ▼
MosDNS
   ├─ 直连域名：返回真实 IP ────────────────────────→ 手机直连
   └─ 代理域名：A 改写为网关 IP，AAAA / HTTPS 置空
                     │
          ┌──────────┴─────────────────────────┐
          │ TCP（配置的 HTTP/TLS 目的端口）     │ UDP/443（默认）
          ▼                                    ▼
   nft source-scoped REDIRECT → :7893   nft TPROXY → :7895
          └──────────────┬─────────────────────┘
                         ▼
                单个 Mihomo（clash.meta）
                         │ SNI / Host / QUIC 嗅探与规则
                         ▼
                 指定出口 / 故障组 / 本机直出
```

- DNS 层使用 MosDNS：只对安装时识别的内网卡来源段执行直连、劫持以及 AAAA / HTTPS
  抑制策略，其他来源的 DNS 查询走普通解析分支。
- TCP 数据面由 nftables 按来源段和目的端口执行 `REDIRECT`，统一进入 Mihomo
  `redir-port :7893`。默认端口按手机平台生成，也可以通过严格校验的 profile 扩展。
- UDP/443 默认使用 Mihomo 原生 `tproxy-port :7895`；同一台机器只运行一个 Mihomo，
  没有 TUN、第二内核或第二透明代理进程。
- REDIRECT / TPROXY 都限定内网卡来源段，不会把公网访问同端口的流量无差别送进 Mihomo。

## 3. 使用前提

本项目依赖一个特定拓扑，不是通用代理工具：

- 一台墙外 VPS，同时作为网关和 DNS。
- 一张运营商内网卡（定向内网 SIM）。手机的移动流量经运营商私网到达 VPS，来源 IP 是固定私有段（例如 `172.x`）。网关用这个私有源段区分「需要劫持的查询」和其他来源。没有这种内网卡时，DNS 劫持会影响到所有查询来源，不适用本项目。
- 一个可以自行修改解析记录的域名，用于 DoT 并签发 Let's Encrypt 证书。
- 一个 Telegram Bot，用于管理出口和分流。
- 一个或多个落地节点用于出国际流量（可选；默认其余国际从 VPS 直出）。

## 4. 安装

Debian 12+ / Ubuntu 22+，需要 root。派生仓库目前还没有兼容的 `v*` 发布 tag；
首次派生版本发布前，请克隆当前默认分支并显式跳过发布 tag 自举：

```bash
git clone https://github.com/SchweppesSoda/proxy-gateway-plus.git
cd proxy-gateway-plus
sudo env \
  PDG_MOSDNS_ARTIFACT=/absolute/path/mosdns-v5.3.4-pdg-notickets.1 \
  PDG_MOSDNS_ARTIFACT_SHA256=<lib/versions.sh 中当前架构的 mosdns-pdg pin> \
  PDG_TAG_BOOTSTRAPPED=1 \
  ./install.sh
```

`PDG_TAG_BOOTSTRAPPED=1` 只用于这段首次发布前的开发验证。创建首个派生 `v*` tag 后，
标准入口脚本会自动切到最新发布 tag，不安装 main 上未发布的中间提交。

MosDNS 使用本项目的 v5.3.4 no-session-ticket 修补 flavor，stock v5.3.4 不会被接受。
当前尚未发布自有长期 release asset；开发部署须先在可信构建机上可复现构建 raw binary，
通过可信通道把 binary 与预先取得的仓库 pin 交给安装器。不能在目标机下载后再“现算现信”，
VPS 也不安装 Go。完整步骤见
[MosDNS 修补版构建与部署](docs/MOSDNS-PATCHED-BUILD.md)。

已经安装 stock MosDNS 或其他非项目 flavor 的机器在执行更新时，同样须显式提供产物：

```bash
sudo env \
  PDG_MOSDNS_ARTIFACT=/absolute/path/mosdns-v5.3.4-pdg-notickets.1 \
  PDG_MOSDNS_ARTIFACT_SHA256=<lib/versions.sh 中当前架构的 mosdns-pdg pin> \
  pdg update
```

路径必须是普通文件而不是符号链接。产物 SHA256 必须与 `lib/versions.sh` 中对应架构的
`mosdns-pdg-*` pin 完全一致；SHA、build marker 或 provenance 任一不符，安装和更新都会
中止，绝不回退 stock。GitHub Actions 的短期 candidate artifact 也不是长期安装 URL。

安装会部署 mosdns、mihomo 内核、管理 Bot、防火墙和证书，自动识别公网 IP 和内网卡来源段，再交互填写 DoT 域名（Bot token 可以留空，装完后随时用 `sudo pdg-set-token` 设置并启用）。域名的 A 记录需要你自己指向本机，脚本会等你确认后再签发证书。

更多安装细节见 [docs/INSTALL.md](docs/INSTALL.md)。卸载：`sudo ./uninstall.sh`（加 `--purge` 连配置一起删除）。

### Android DoT 与 TLS 1.3 会话恢复

在本项目实测的 Android 私密 DNS 链路上，stock MosDNS v5.3.4 存在 TLS 1.3
会话恢复兼容性故障：首次完整握手和 DoT 查询可以成功，服务端随后签发 session ticket；
Android 在后续连接提供该 SSLSession、服务端接受恢复后，客户端不再完成握手和 DNS
查询。此时包括 Google 和本应境内直连的网站在内，都会因尚未取得 DNS 结果而显示
`ERR_NAME_NOT_RESOLVED`，流量根本没有进入 Mihomo，因此不是出口路由或域名 SNI
规则导致的故障。

抓包确认 ClientHello 的 SNI 和证书域名正确。独立双连接探针在 stock 上得到
`has_ticket=true`、`session_reused=true`，修补版则均为 `false`，两次真实 DoT
查询都正常返回。上游 v5.3.4 的 `tcp_server` 使用 Go 默认 `tls.Config`，本项目只增加
`SessionTicketsDisabled=true`；TLS 1.3、证书校验和其他 DNS 逻辑保持不变。这是目标
链路的兼容性约束，不表示 Android 或 TLS 1.3 通常不能使用会话恢复。

修补版使用精确 marker `v5.3.4-pdg-notickets.1`。构建信任锚集中在
`lib/versions.sh`，包括上游 commit、patch SHA256、Go 1.24.9 和 amd64/arm64 raw
binary SHA256；`tools/build-mosdns-patched.sh` 与 GitHub Actions 使用同一构建契约，
CI 对每个架构构建两次并逐字节比较。

部署后运行 `sudo pdg doctor --deep`：常规检查验证精确 marker、钉死 hash/provenance；
深度检查使用系统 CA 验证证书链与 DNS SAN，并完成两次真实 DoT 查询。第二次握手若出现
`session_reused=true` 即判失败。安装证明写入、服务重启或稳定门失败时，会同时恢复旧
MosDNS binary 和 attestation。

## 5. 手机平台选择

一台网关对应一个手机号，平台是每台机器的固定属性，装机时确定（`PDG_PLATFORM=ios` 或 `android`；不指定则安装时询问）。平台决定客户端接入方式和是否提供 iOS 专属功能：

- Android：手机在系统「私密 DNS」里直接填 DoT 域名。不安装 iOS 描述文件、pdg-probe81、MITM/WLOC 相关组件。
- iOS：通过 iOS 描述文件接入，另外安装 pdg-probe81（`:81` 探测）和 MITM/WLOC 组件。

## 6. 流量内核（mihomo）

流量层统一使用 Mihomo（clash.meta）。TCP 从 source-scoped nft REDIRECT 进入
`:7893`，UDP/443 默认从原生 TPROXY 进入同一进程的 `:7895`；Mihomo 再按嗅探到的
SNI / Host / QUIC 与规则选择出口。提供 clash_api，可按需临时开启观测面板。内核版本由
`pdg update` 随项目发布版指定并校验后安装。

> 早期版本曾支持 sing-box / mihomo 二选一。sing-box 1.13 移除了本网关依赖的 `sniff_override_destination`、被钉死在 1.12.x 死胡同，因此 **v1.6.0 起已彻底移除 sing-box 运行时**，mihomo 成为唯一内核。旧的 sing-box 机器执行 `sudo pdg update` 时会自动迁移到 mihomo（出口、分流、证书、DoT 全部保留；若有 mihomo 无法转换的出口，更新会中止并回滚，提示先在 Bot 里处理该出口）。

### 直连例外与非标准端口

先判断域名究竟应该直连还是经过网关：

- 本应直连的网站若因劫持模式而拿到网关 IP，应在 Bot「📑 分流管理」里把域名指向
  `direct`。Bot 会事务化写入 MosDNS 的 `custom_direct.txt` 并撤销冲突的自定义劫持，
  手机随后取得真实 IP。不要为了修复这种漏分流而扩展劫持端口。
- 规则集的目标也可写 literal `direct`：Bot 将可无损展开的 `DOMAIN`、`DOMAIN-SUFFIX`、
  `DOMAIN-KEYWORD` 在同一配置事务中派生到独立
  `/etc/mosdns/rules/ruleset_direct.txt`，MosDNS 返回真实地址，手机不经 VPS。含
  `IP-CIDR/IP-CIDR6` 的规则集以及 `.mrs/.srs` 无法在 DNS 层兑现完整语义，会被明确拒绝。
  内建 direct-type 出口（默认 `JP`）含义不同：流量已经到达 VPS，再由 VPS 本机直出。
  旧版默认 tag `jp` 会在 `pdg update` / `pdg migrate` 的受锁迁移中连同分流规则、故障组、
  默认出口、规则集元数据和派生 Mihomo 配置一起改为 `JP`；自定义 direct tag 不会被猜测改名。
- 指向非 literal-direct 出口的可展开 source 规则集，会将其中的域名项事务派生到
  `/etc/mosdns/rules/ruleset_hijack.txt`。MosDNS 在宽泛国内直连判断前先匹配该集合，避免
  本应送入 Mihomo 的国内域名取得真实地址后绕过 VPS。编译后的二进制 `.mrs` 不做 DNS
  展开，也不会猜测其中域名；诊断遇到可能由它命中的域名时会明确给出未知，而不是伪报出口。
- 显式单域名代理规则优先于宽泛手机直连规则集。例如 `example.com` 在 direct 规则集中时，
  仍可将 `api.example.com` 显式指向 `hk`；MosDNS 会先匹配 `custom_hijack.txt` 并送入代理。
- 只有确实需要代理、且业务使用非标准 HTTP/TLS 端口时，才扩展
  `PDG_HIJACK_HTTP_TCP_PORTS` 或 `PDG_HIJACK_TLS_TCP_PORTS`。例如代理一个使用
  TLS `:10443` 的测试服务，可以在非交互安装参数里使用
  `PDG_HIJACK_TLS_TCP_PORTS=443,10443`。变量表示完整端口集合而不是“追加值”，应保留
  当前平台需要的默认端口，并先确认端口不与 SSH、DNS、Mihomo API 等本机监听冲突。

安装器将这两个 TCP 端口集合同时持久化并渲染到 nft 与 Mihomo sniffer；任一非法、
重叠、重复 profile 键或本机监听冲突都会 fail closed。扩展端口前还应确认网关或所选出口
能够访问目标的该端口，否则透明接管只会把流量送入一条不可达的网关出站路径。

### QUIC 与防火墙模式

- `PDG_QUIC_MODE=tproxy` 是默认值：内网卡来源的 UDP/443 经 nft TPROXY、fwmark 与
  专用 policy route 进入 Mihomo `:7895`，sniffer 同时启用 QUIC。
- `PDG_QUIC_MODE=reject` 不创建 QUIC TPROXY 链，也不让 Mihomo 监听 `:7895`。在
  `managed` 防火墙模式下，网关拒绝内网卡来源 UDP/443，使支持的客户端回落 TCP；
  在 `external` 模式下是否拒绝由外部防火墙决定。
- `PDG_FIREWALL_MODE=managed` 由本项目维护带 `policy drop` 的 source-aware input
  链；`external` 只保留本项目自有、source-scoped 的 REDIRECT / TPROXY 数据面，
  不创建 input hook，不声明主机公网开放端口，也不替代云安全组或外部防火墙。

## 7. 手机接入

- Android：系统「设置 → 网络 → 私密 DNS」选「指定的 DNS 服务提供商主机名」，填 DoT 域名（例如 `dot.example.com`）。
- iOS：在 Bot「📱 客户端 → iOS 描述文件」生成并安装描述文件；不使用 Bot 时，`sudo pdg ios`（仅 iOS 平台可用）会在终端打出二维码，手机走内网卡扫码后在 Safari 里安装。Wi-Fi 与蜂窝是否启用私密 DNS 由 `:81` 探测自动判定（能连到网关才启用），生成时还可指定强制直连的 Wi-Fi 名单（SSID）。

## 8. Telegram Bot 使用

给 Bot 发 `/start` 进入菜单，常用功能：

- 📤 出口管理：添加、删除、改名、排序出口，设置默认出口，新建/编辑故障切换组。
  - 可直接粘贴的链接：`ss://`、`vmess://`、`vless://`（含 reality）、`trojan://`、`hysteria2://`、`tuic://`、`anytls://`、`socks5://`、`http://`，以及 Surge 的 `名字 = ss, …` 行。
  - shadowtls、ssh、hysteria（v1）、wireguard（endpoint）等出站不在直接支持之列：它们需要手写数据模型 `/etc/sing-box/config.json`，且 mihomo 未必能转换（渲染失败会被拒绝，不会静默丢弃）。
- 📑 分流管理：把域名、`.list` / `.txt` 等规则集指到出口；默认其余国际走 VPS 直出。
- 🔀 故障切换组：按探测延迟选择出口，并在出口不可用时切换。
- 📱 客户端：Android 显示私密 DNS 主机名；iOS 显示 iOS 描述文件入口。两个平台都提供「🌐 DoT 自定义域名」和「✈️ Telegram 出口」。
- 🛠 运维：重启服务、更新规则库、备份/恢复、DNS 上游、TFO、观测面板；iOS 平台另有「🍏 位置改写（WLOC）」。

Telegram 出口（Bot 内置 SOCKS5，端口 8445）用于给手机上的 Telegram 单独指定出口，在客户端菜单里配置。

### 可选 Web 管理面（默认禁用）

安装和更新会部署 Web 管理面代码，但不会创建认证配置，也不会启用或启动服务。首次使用：

```bash
sudo pdg web setup       # 交互填写监听地址、端口、域名、可信 CIDR 和管理员密码
sudo pdg web enable      # 校验配置和证书后显式启用
sudo pdg web status
```

其他生命周期命令为 `sudo pdg web disable` 和 `sudo pdg web password`。配置保存在
`/etc/privdns-gateway/web.json`，目录和文件分别强制为 `root:root 0700`、`root:root 0600`；
密码只保存为至少 600,000 次 PBKDF2-SHA256 派生值，会话密钥随机生成。服务只接受配置中
精确列出的 HTTPS Host、Origin 和可信来源 CIDR，生产访问不提供明文 HTTP 降级。Telegram
Bot 同样只处理私聊；它的 Zashboard 观测面板仍是 10/30 分钟的临时诊断入口，不是这个常驻
管理面。

Web 可直接修改已有规则集的 target；这里的 literal `direct` 仍表示手机取得真实 DNS
结果并在本地直连、不经过 VPS，而 direct-type `JP` 表示连接先到 VPS、再由 VPS 本机直出。
普通节点可原位更新连接参数，保留原 tag、列表顺序和全部引用，无需删掉重建。出口延迟通过
Mihomo Clash API 探测；域名诊断分别呈现 DNS 实测证据与配置规则推演，网关出口推演不冒充
真实数据包的出口验证。

Web 的本机快照使用带随机后缀的稳定 ID 精确选择，不会因新快照插入而改变回滚目标。回滚和
软件更新由持久化异步任务执行，浏览器断连或重新打开后仍可按任务记录继续查看状态；同一时间
只运行一个维护任务。软件更新任务在实际执行时调用 `pdg update` 并跟随届时最新发布版，提交
任务时不会锁定预检看到的 tag。配置回滚恢复 live nft/profile 后，还会显式 enable 并
restart 恢复前为 active/exited 的 `pdg-quic-routing` oneshot，再运行 helper status 验证；
任一步失败都报告未完全回滚，不会只凭 unit 为 active 就判定成功。

setup 要求证书和私钥最终指向由 root 拥有的普通文件，私钥必须保持 owner-only 权限；允许
certbot 常见的 `/etc/letsencrypt/live/...` root-owned 符号链接，但整条链接链及解析后的
父目录必须由 root 控制且不可被 group/world 写入。证书必须已生效、尚未过期、覆盖访问
域名并与私钥匹配。若 Web 原本正在运行，setup/password 写入新配置后会等待服务稳定；
重启或绑定失败时会原子还原旧配置并确认旧服务恢复，不会打印认证材料。

默认监听 `127.0.0.1:9091`，推荐通过 SSH 隧道访问。证书签给域名时，直接打开
`https://127.0.0.1:9091` 会因证书名称不匹配而失败；建立隧道后，应在管理电脑的 hosts
中把配置域名临时指到 `127.0.0.1`，再打开 `https://配置域名:9091`，或者使用一个证书名称
一致、仅可信网络可达的私有域名入口。setup 会始终把精确 loopback CIDR 加进可信来源，
浏览器 Host（包括非 443 端口）仍须与配置完全一致。

Web 按 TCP socket 的真实对端地址校验可信 CIDR，并忽略 `X-Forwarded-For`。因此 loopback
反向代理会让 Web 只看到 `127.0.0.1`，不能靠 Web 自身限制真实客户端；如另设反向代理，
代理必须独立执行来源 ACL。默认支持路径仍是 loopback + SSH 隧道。

若改为非 loopback 直连，`pdg web` 只报告实际 service interface 和可信 CIDR，绝不会改
nftables、云安全组或整机 input policy。非 loopback 入口只在
`PDG_FIREWALL_MODE=external` 下由外部防火墙/管理员负责接入；默认 `managed` 的
`inet pdg input policy drop` 不会自动放行 Web，官方路径仍是 loopback + SSH 隧道，除非
管理员明确把所报告接口集成进整机策略。任何编排都不能把示例 9091 或某台机器的端口硬编码
进仓库。

## 9. 日常管理命令

```bash
sudo pdg            # 进管理菜单
sudo pdg status     # 状态
sudo pdg doctor     # 自检（只读）；--deep 含 DoT chain/SAN 与两次握手会话恢复检查
sudo pdg update     # 更新（更新前自动快照，失败自动回滚；--dry-run 查看待更新）
sudo pdg snapshot   # 手动留一份配置快照
sudo pdg rollback   # 回滚到最近快照
sudo pdg token      # 设置 / 更换 Bot token
sudo pdg web status # 可选 Web 管理面；setup|enable|disable|status|password
sudo pdg restart    # 重启服务
sudo pdg log [n]    # 查看日志
sudo pdg traffic    # 网卡流量（vnstat）
sudo pdg ios        # 仅 iOS：在终端打出 iOS 描述文件二维码
sudo pdg report     # 脱敏诊断报告；--redact-ip 连 IP/域名一起隐藏；--full 不脱敏
sudo pdg detect-cidr           # 重新识别内网卡来源段，与现配不符可写回并重启
sudo pdg hijack-mode <all|gfw>          # 切换劫持模式
sudo pdg uninstall [--purge]            # 卸载（--purge 连配置删）
```

`pdg update` 只跟随项目的 `v*` 发布 tag，不安装 main 上未发布的中间提交；更新会同时安装该发布版指定并校验过的内核版本。健康自检每 10 分钟自动运行，服务异常、DNS 不应答、证书临近到期会通过 Telegram 通知。生命周期（安装、更新、卸载、token、状态）主要用 `pdg` 命令管理；出口、分流、DNS 上游等运行时配置可在 Telegram Bot 或可选 PDG Web 中管理。首版 Web 覆盖出口与默认出口、故障组、单域名规则、规则集、DNS 上游、TFO、状态/日志/流量查看、服务重启、规则库更新、本机配置快照与回滚，以及软件更新；概览页自检按失败、警告和正常项分组展示，不再把全部结果挤成一段文本。Web 的本机快照不是可下载的完整配置备份包；DoT 域名和证书签发、配置包备份/恢复、iOS 描述文件、WLOC、平台切换、安装/卸载和 Bot token 管理仍仅通过 SSH 下的 `pdg` 或 Telegram Bot 完成。

## 10. iOS 位置改写（WLOC，可选）

WLOC 只修改 Apple 网络定位响应中的坐标，不修改 GPS 数据。它把 `gs-loc.apple.com` 的定位查询转发给 Apple，取回真实响应后只替换其中的坐标。适用于依赖网络定位的场景；连续 GPS 定位（导航、打车等）不适用，户外 GPS 信号较强时也会覆盖它。WLOC 仅 iOS 平台提供。

首次使用顺序：

1. 在 Bot「🛠 运维 → 🍏 位置改写」里「➕ 添加地点」（发送「`名称 纬度,经度`」，例如 `上海 31.2304,121.4737`），然后「✅ 开启」。
2. 返回「📱 客户端 → iOS 描述文件」，重新生成并安装 iOS 描述文件。
3. 在「设置 → 通用 → 关于本机 → 证书信任设置」中，信任 PrivDNS Gateway MITM CA。

**切换地点的推荐顺序（全程用内网卡）：**

1. 控制中心把 Wi-Fi 点灰（不是在设置里关 Wi-Fi）
2. 在 Bot「📍 地点 / 切换」里点目标地点
3. 等 Bot 显示「WLOC 已热加载」
4. 设置 → 隐私与安全性 → 定位服务：关闭，等 2 秒后重新开启
5. 打开目标 App
6. iOS 26 如果一直没有发起新的 WLOC 请求，可能仍需重启手机

切换地点只原子更新 `mitm.json`；`pdg-mitm` 在下一次 WLOC 请求开始时读取当前配置，因此无需重启服务，进程不重启、DNS 也不会断。网关只能保证下一次请求使用新坐标，不能主动清除 iOS locationd 缓存。开关 WLOC（接管域名发生变化）才走完整事务。

Bot 在切换后会等最多 30 秒，看手机是否真的发来了新的 WLOC 请求：收到了就回报「已收到 iPhone 的新定位请求」，没收到就如实提示还没等到，并给出排查项。

**边界（网关做不到的部分）：** 网关只能保证**下一次** Apple 网络定位请求使用新坐标，无法让 iOS 清除 locationd 缓存，也无法强制手机立刻发起新请求。「网关已改写响应」不等于「手机显示的位置已经变了」——地图仍显示旧位置可能是 iOS 缓存或户外 GPS 覆盖。

长期无法定位时：设置 → 通用 → 传输或还原 iPhone → 还原 → 还原位置与隐私 → 重启手机

多个地点可以随时增删，开启状态下可切换。原理与配置见 [docs/design-mitm-plugins.md](docs/design-mitm-plugins.md)。

## 11. 项目组成

| 层 | 组件 | 说明 |
|---|---|---|
| DNS | mosdns v5.3.4 no-ticket 修补版 | 关闭 DoT session ticket/恢复；国内直连；代理域名 A 记录劫持到本机、AAAA / HTTPS 置空；按来源 IP 分支；ECS 处理；缓存；DoT（853）；可选 GFWList 劫持模式 |
| 流量 | mihomo（clash.meta） | 单进程；TCP source-scoped REDIRECT → `:7893`，UDP/443 默认 TPROXY → `:7895`；按域名规则支持多出口与故障组；提供 clash_api（观测面板） |
| 管理 | Telegram Bot + 可选 Web 管理面（Python 标准库） | 出口、分流、规则集、测速、流量、备份恢复、iOS 描述文件、自定义域名、WLOC；Web 默认禁用并使用独立 root-only 认证配置；事务管理的变更先校验候选并支持失败回滚 |
| 位置改写 | pdg-mitm（可选，iOS） | 自签 CA + 终止 TLS + 转发并替换 `gs-loc` 响应坐标 |
| 证书 | certbot standalone | Let's Encrypt，自动续期 |
| 防火墙 | nftables | `managed` 维护 source-aware input policy；`external` 不创建 input hook。两种模式的数据面均只按内网卡来源段透明接管 |

内核版本由 `pdg update` 随 PrivDNS Gateway 发布版指定并逐字节校验（SHA256）后安装。

**配置事务有明确边界。** 已接入统一配置事务入口的 Bot / `pdg` 变更，会先校验候选，
再原子落盘、按目标状态调整服务并观察健康门；这些事务管理的路径在失败时执行回滚，
进程被杀后可用 `sudo pdg tx recover <id>` 收尾，`sudo pdg doctor` 会点名未完成的事务。
这项保证不覆盖手工改文件、独立维护脚本或 `external` 模式下的主机 input policy /
公网暴露控制。非事务路径应先留快照，并用 `sudo pdg doctor`、`sudo pdg report` 与对应的
人工恢复步骤确认和修复状态。两个采用专门一致性机制的例子：

- **WLOC 切地点 / 改坐标**：只改一个文件（`mitm.json`）、一次原子替换、不动任何服务
  （pdg-mitm 在下一次 WLOC 请求开始时读当前配置），没有多组件半成功的可能，因此走快路径以保证
  切换在 1 秒内完成；它仍在同一把全局配置锁内，并写一条脱敏审计（只记操作与 generation 变化，
  不记地点名与经纬度）。
- **观测面板前端资源（zashboard）**：固定版本 + SHA256 校验 + 暂存目录 + 原子替换，属于静态
  缓存资源，不是 DNS/分流生产配置，因此不纳入配置事务。

## 12. 部署与整机编排边界

本仓库负责网关应用本身，提供可重复调用的标准部署入口：非交互 `install.sh`、`pdg update`、
显式迁移、快照/回滚、状态和 doctor。安装器与迁移脚本对自有配置采用 ownership marker、
候选校验、原子替换和幂等迁移，便于上层自动化复用。

SSH 加固、系统通用防火墙、其他应用、机器清单和跨主机发布等整机编排属于
`vps-toolkit`。上层编排应调用本仓库接口，不应把私有机器信息或一份平行的 MosDNS /
Mihomo / nft 模板复制进本仓库；使用 `PDG_FIREWALL_MODE=external` 时，上层还必须明确
承担主机 input policy 与公网暴露控制。Web 管理面需要直连时，上层还应读取其实际配置，
按所选端口和可信 CIDR 声明 service interface；直连入口要求
`PDG_FIREWALL_MODE=external`，仓库不会假定或硬编码一个公网管理端口。`managed` 模式的
默认支持路径是 loopback + SSH 隧道。

## 13. 文档

- [docs/QUICKSTART.md](docs/QUICKSTART.md) — 新手图文教程
- [docs/INSTALL.md](docs/INSTALL.md) — 安装细节 / DNS 配置 / 端口 / 版本说明
- [docs/MOSDNS-PATCHED-BUILD.md](docs/MOSDNS-PATCHED-BUILD.md) — MosDNS 修补版 provenance / 可复现构建 / KFC 部署
- [docs/TROUBLESHOOTING-PLAYBOOK.md](docs/TROUBLESHOOTING-PLAYBOOK.md) — 排障手册（症状 → 排查 → 修复）
- [docs/production-notes.md](docs/production-notes.md) — 实战记录与已知问题
- [docs/design-mitm-plugins.md](docs/design-mitm-plugins.md) — iOS 位置改写（WLOC）设计与原理
- [docs/RELEASE-CHECKLIST.md](docs/RELEASE-CHECKLIST.md) — 发版前检查清单
- [CHANGELOG.md](CHANGELOG.md) — 更新日志

## 14. 免责声明与 License

本项目仅供学习与合法网络管理用途。请遵守你所在地的法律法规，使用者自行承担责任，作者不对使用后果负责。

License：[MIT](LICENSE)
