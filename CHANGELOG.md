# 变更记录 · Changelog

本文件记录 **TaskList Inspector** 的重要变更，格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)。
日期为提交日期；本项目尚未打 tag，条目按时间倒序排列。

## 2026-10-13

### 新增

签名库扩充至 **500+**：

- **终端安全 / EDR / XDR**
  - McAfee/Trellix：ENS（`mfeesp` / `mfefw` / `mfehcs` / `mfeatp` / `mfetp` / `mfeensppl` / `mfemactl` / `MFEConsole`）、Agent（`macmnsvc` / `macompatsvc` / `mctray` / `UpdaterUI`）、DLP/FRP（`fcag` / `fcags` / `fcagswd` / `fcom`）、Policy Auditor（`AuditManagerService`）、**XClient 终端代理（`xclient` / `xclientnotif` / `xclientppl`）**
  - VMware Carbon Black、Cybereason、Trellix/FireEye HX（`xagt`）
  - Palo Alto Cortex XDR 全组件（`cyserver` / `cytray` / `cyuserserver` / `cysandbox` / `tlaworker` / `xdrhealth` / `cortex-xdr-payload` 等）
- **服务器 / 邮件**
  - Microsoft Exchange Server 全套角色组件（`microsoft.exchange` / `msexchange` 前缀兜底，兼容截断名）、FIP-FS 内容扫描（`scanningprocess` / `fms` / `updateservice`）、搜索组件（`noderunner` / `ParserServer` / `hostcontrollerservice`）、合规审计（`ComplianceAuditService`）
  - IIS（`w3wp` / `inetinfo` / `WMSvc`）、MSMQ（`mqsvc`）、故障转移群集（`clussvc` / `RHS`）、WCF 激活宿主（`SMSvcHost`）
  - SQL Server 组件（SSIS / SSAS / PolyBase / 全文搜索 / Launchpad / VSS Writer / CEIP）
- **虚拟化 / 远程控制**
  - VMware Tools 组件（`vm3dservice` / `VGAuthService`）、VMware Remote Console（`vmrc`）、VMware Remote MKS（`vmware-remotemks`）
  - DameWare Mini Remote Control（`DWRCS` / `DWRCST`）、SCCM 远程控制（`CmRcService`）
  - Citrix Workspace 组件（`concentr` / `wfcrun32` / `SelfServicePlugin` / `Receiver` / `redirector` / `AnalyticsSrv` / `AOTListenerService`）
- **Windows 内置组件**
  `LogonUI` / `AggregatorHost` / `TabTip(32)` / `mmc` / `vds` / `msdtc` / `ServerManager` / `Memory Compression` / `LockApp(Host)` / 小组件 / `ShellHost` / `Windows 365` / `Work Folders` / `Microsoft.AAD.BrokerPlugin` / `MoUsoCoreWorker` / `MoNotificationUx` / `SearchProtocolHost` / `SearchFilterHost` / `sppsvc` / `SppExtComObj` 等
- **桌面 / 外设 / 音频**
  Realtek 音频服务、Waves MaxxAudio、Intelligo（`iGoSwServer`）、OEM 音频后台进程（`CLAudioBackgroundProcess`）、Intel IPF（`ipf_helper`）、Intel PresentMon（`PresentMonService`）
- **其它**
  Elastic OTel Collector（EDOT）、osquery 扩展（`osquery-extension`）、GLPI Agent、NXLog、Cisco Webex、Cisco Secure Client（`csc_ui`）、HID ActivClient（`acevents` / `ac.activclient.*`）、Crashpad（`crashpad_handler`）、Adobe Acrobat 组件（`acrotray` / `AdobeCollabSync`）

### 修复

- 主机画像：「终端防护」行不再截断为最多 5 项，检测到的全部 AV/EDR（例如 Elastic Defend）都会展示，避免重要 EDR 被 `…(共 N 项)` 隐藏
- 解析器：兜底解析跳过表头行（含带主机名前缀的 `Image Name … PID Services`），避免主机名被误当成进程
- 解析器：支持 `tasklist /svc` 的 `<名称> <PID> <服务列表>` 行，**服务名不再被误判为进程**
- 解析器：NetExec 透传 `tasklist` 时列被截断（`<名称> <PID> N/A`），`N/A` 曾被拆成伪进程 `A`
- 匹配：`tasklist` 会把超长进程名**截断为 25 字符**（如 `StartMenuExperienceHost.e`、`Microsoft.AAD.BrokerPlugi`、`elastic-otel-collector.ex`、`ac.activclient.gui.scagen`），现已能正确匹配

### 文档

- README 更新输入格式说明与签名覆盖范围；首页统计更新为 **500+ signatures**

## 2026-10-08

### 新增

- Palo Alto Cortex XDR 全部组件
- SQL Server 全套组件（Agent / Browser / CEIP / VSS Writer / SSIS / SSAS / Launchpad / 全文搜索 / PolyBase）
- Windows 内置组件（`LogonUI` / `AggregatorHost` / `TabTip(32)` / `mmc` / `vds` / `msdtc` / `ServerManager`）
- VMware Carbon Black、Trellix/FireEye HX、Cybereason、GLPI Agent

### 修复

- 解析器：`Image Name … PID` 表头（无 `Mem Usage` 列）现识别为 win-table
- 解析器：支持截断列 `<名称> <PID> N/A` 的行

## 2026-10-07

- 宣传素材：新增图标集（`icon.svg` 母版 + 多尺寸 PNG）

## 2026-09-30

- 新增 OG / Twitter 分享卡片
- 清洗示例数据、移除本地环境说明
- 首次发布：TaskList Inspector —— 中英双语在线进程分析工具

[Keep a Changelog]: https://keepachangelog.com/zh-CN/1.1.0/
