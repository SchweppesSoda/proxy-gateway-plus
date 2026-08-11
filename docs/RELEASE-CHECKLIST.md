# 发版前检查清单

打 `v*` tag 前,在**一台 throwaway 机**(全新 Debian 12/13 或 Ubuntu 22/24)上把下面场景跑一遍。
单元测试(`tests/`)覆盖不到"装机 / 升级 / sing-box→mihomo 迁移"这类集成问题——本清单专门抓它们。

首次派生发布还要先创建并验证兼容的 `v*` tag；正式发布后安装文档必须使用标准 tag
自举入口，不能保留 `PDG_TAG_BOOTSTRAPPED=1` 开发绕过步骤。

> 本清单是照着真实翻过的车写的:v1.5.1(WLOC 开着时 `pdg update` 误回滚)、v1.5.2(从 v1.4.x 升级漏装 `sb2mihomo`/`mitm_*` → switch-core 报 ModuleNotFoundError)、v1.5.5(切 mihomo 后 TG 代理 :8445 没渲染)。这几个单测全绿、却都是部署才炸。

先按 `docs/MOSDNS-PATCHED-BUILD.md` 准备与 `lib/versions.sh` 架构 pin 一致的 raw
MosDNS 修补产物。装机用非交互 env(`PDG_SKIP_CERT=1` 自签占位,免签真证书):
```bash
PDG_NONINTERACTIVE=1 PDG_SERVER_IP=<公网IP> PDG_INTERNAL_CIDR=172.22.0.0/16 \
  PDG_SSH_PORT=22 PDG_SKIP_CERT=1 PDG_PLATFORM=<ios|android> \
  PDG_FIREWALL_MODE=<managed|external> PDG_QUIC_MODE=<tproxy|reject> \
  PDG_MOSDNS_ARTIFACT=<raw绝对路径> PDG_MOSDNS_ARTIFACT_SHA256=<仓库钉死SHA256> \
  bash install.sh
```

---

## ① 全新安装(两种平台)

至少跑 **iOS** 和 **Android** 两组(内核统一 mihomo)。装完:

- [ ] `pdg doctor` 全绿(无 🔴/🟡)。
- [ ] `mosdns version` 精确输出 `v5.3.4-pdg-notickets.1`;`pdg doctor --deep` 的
  「DoT 会话恢复」显示第二次真实 DoT 握手没有接受第一次 SSLSession。
- [ ] 必需服务 active:`systemctl is-active mosdns mihomo pdg-quic-routing`(iOS 追加
  `pdg-probe81` `pdg-mitm`)。Bot 凭据配齐时 `pdg-bot` active;两项都未配置时允许明确禁用,
  只配一项必须由 doctor 报配置错误。**Android 上 `pdg-probe81`/`pdg-mitm` 应不存在**
  (`systemctl is-enabled` 报 not-found),81/7894 不监听。**sing-box 二进制/服务都不应存在**。
- [ ] **平台专属模块只在对应平台**:iOS `ls /opt/pdg-bot/{mitm_ca,mitm_server,mitm_wloc}.py` 齐; **Android 这三个 + `probe81.py` + 描述文件模板都不应存在**。`sb2mihomo.py` 两平台都在。
- [ ] 平台门控对:**iOS** doctor 有「MITM 插件」「MITM结构」「平台=ios」无「GMS 推送」「iOS 探测」缺失;**Android** 反之(有 GMS、无 MITM/probe81)。
- [ ] **平台隔离(硬门控)**:**Android** bot「📱 客户端」无「iOS 描述文件」按钮;点旧消息里的 iOS/WLOC 按钮被拒;`sudo pdg ios` 友好拒绝(不装 qrencode、不开 8443)。**iOS** 有描述文件/WLOC。
- [ ] **iOS 无 GMS 残留**:`grep -c in-gms /etc/sing-box/config.json` = 0;`nft list ruleset | grep 5228` 无。
- [ ] **平台标记**:`cat /etc/privdns-gateway/platform` 为 ios/android;缺失时 `pdg status`/doctor 明确提示「按 Android 回退」而非静默。
- [ ] **单 Mihomo 数据面**:`/etc/mihomo/config.yaml` 有 `redir-port: 7893`;`tproxy` 模式
  另有 `tproxy-port: 7895` 和 QUIC sniffer,`reject` 模式不含后两项。
- [ ] **TCP 端口模型一致**:`inet pdg` 的 TLS/HTTP sets 与 Mihomo sniffer 使用同一组
  profile 端口;所有 REDIRECT 都同时含内网卡 `ip saddr` 和 `redirect to :7893`。
- [ ] **QUIC 模式一致**:`tproxy` 有 source-scoped UDP/443 TPROXY → `:7895`、owned
  fwmark policy rule/local route;`reject` 无这些状态。
- [ ] **防火墙模式一致**:`managed` 的 owned `inet pdg` 有 input hook 和 `policy drop`;
  `external` 无 input hook / input policy,但仍保留 source-scoped REDIRECT,并在 `tproxy`
  模式保留 source-scoped QUIC TPROXY。
- [ ] **PDG Web 配置 I/O**：保持默认 disabled/inactive；完成 loopback setup/enable 后，
  Mihomo/MosDNS 模板可下载。错误管理密码不能导出，重新验证正确密码后 PDG/Mihomo/MosDNS
  三类附件均可下载。分别上传两份示例模板执行预览，确认生产模型/config SHA 未变化；取消后
  暂存立即删除。再在 throwaway 机确认 Mihomo 的 merge/replace 与 MosDNS replace-only
  各完成一次，维护任务成功、`pdg-web`/`mihomo`/`mosdns` 稳定、`pdg-bot` 符合其凭据配置
  状态，且 `pdg doctor --deep` 通过。

## ② 从上一个发布版升级(最容易翻车)

先装**上一个** tag,再 `pdg update` 到本版——复现"旧脚本装新版"的时序滞后:
```bash
git -C /opt/privdns-gateway checkout <上一个tag>   # 或直接用旧 tag 装
pdg update                                          # 切到本版
```
- [ ] `pdg update` **成功、没触发回滚**(校验门过)。
- [ ] **新增的 bot 模块升级后就位**(`ls /opt/pdg-bot/sb2mihomo.py` 等)——靠 `migrate_deploy_botfiles` 自愈;缺了说明迁移没跑到。
- [ ] `pdg doctor` 全绿。
- [ ] **iOS + WLOC 开着**时再 `pdg update`:不因「pdg-mitm 未运行」误回滚(pdg-mitm 有被 `reset-failed`+重启)。

## ③ 从 sing-box 旧版升级 → 自动迁移到 mihomo(v1.6.0 关键路径)

先装一个**仍支持 sing-box 的旧 tag**(如 `PDG_CORE=singbox` 装 v1.5.x),确认在 sing-box 上跑通,再 `pdg update` 到本版,验证 `migrate_drop_singbox` 自动迁移:
```bash
pdg update     # __migrate 里自动 sing-box → mihomo
```
- [ ] `pdg update` 成功、不回滚;`cat /etc/privdns-gateway/backend` = `mihomo`。
- [ ] **sing-box 已彻底移除**:`systemctl is-enabled sing-box` 报 not-found、`ls /usr/local/bin/sing-box` 不存在。
- [ ] `systemctl is-active mihomo` = active;`pdg doctor` 全绿。
- [ ] **单内核入站正确**:`ss -lntup` 可见 Mihomo `:7893`;默认 `tproxy` 另见 UDP
  `:7895`;Telegram 代理启用时 `:8445` 有 Mihomo listener。原始目的端口由 nft
  REDIRECT / TPROXY 接管,不要求 Mihomo 分别监听 80/443/GMS 端口。
- [ ] **出口/分流全保留**:bot「🚦 测出口」每个出口都返回延迟、不报「超时/不通」;**direct 出口(JP)** 也通(它在 mihomo 里映射成内建 `DIRECT`)。
- [ ] **有不可转换出口时**:config.json 里放一个 mihomo 不支持的出站,`pdg update` 应**中止并回滚到旧 sing-box 版**(数据无损),报出该出口名。

## ④ WLOC(仅 iOS 装机)

- [ ] bot「🍏 位置改写」:加地点(点按钮 **和** 直接发「名称 纬度,经度」两种都试)、切换、开启。
- [ ] `systemctl is-active pdg-mitm` = active;`pdg doctor` 有「🟢 MITM 插件」。
- [ ] `/etc/mihomo/config.yaml`(mihomo)有 `MITM-OUT` + `DOMAIN-SUFFIX,gs-loc*` 规则;`mitm_hijack.txt` 有 gs-loc 两域名。
- [ ] (有真 iPhone 时)内网卡 + 控制中心关 WiFi + 定位服务关开 → 定位改到设定城市。

## ⑤ 卸载

```bash
bash uninstall.sh --purge
```
- [ ] 服务全 disable+删:`mosdns sing-box mihomo pdg-bot pdg-probe81 pdg-mitm`。
- [ ] `--purge` 后 `/etc/privdns-gateway`、`/etc/mihomo` 都删掉。

---

## 打 tag / 发布

所有场景都过,再:
```bash
git tag -a vX.Y.Z -m "vX.Y.Z"
git push origin HEAD:main
git push origin vX.Y.Z
gh release create vX.Y.Z --latest --title "vX.Y.Z" --notes ""
```

Release 发布成功后，从维护者本机使用私有 SSH alias 部署。当前 fork 的默认线上 alias 为
`kfc-pdg`；真实 IP、端口和 IdentityFile 只写在 `~/.ssh/config`，绝不进入仓库：

```bash
PDG_EXPECTED_VERSION=vX.Y.Z bash tools/deploy-release.sh
```

多台线上实例可把 alias 依次写在命令末尾。该入口会先验证远端同时存在
`/usr/local/bin/pdg`、`/opt/privdns-gateway`，且仓库 origin 为当前 GitHub fork，因此构建机、
测试机、普通代理机或其他 fork 不会被误当成线上 PDG；随后固定执行
`update --dry-run`、事务化更新、精确 tag、四项服务和
`pdg doctor --deep` 核验。任一步失败立即停止，不继续部署下一台。
