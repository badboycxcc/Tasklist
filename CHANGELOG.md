# 变更记录 · Changelog

本文件记录 **TaskList Inspector** 的重要变更，格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)。
日期为提交日期；本项目尚未打 tag，条目按时间倒序排列。

## 2026-11-05

### 新增

- **签名库 547 → 564 条**（按真实主机 `tasklist` 补漏，19 个此前落入「未识别」的进程全部识别）：
  - **Sophos 全家桶 12 个组件**：`SophosFileScanner`（文件扫描）、`SEDService`（Endpoint Defense / Intercept X 拦截核心）、`SSPService`（System Protection）、`SophosNtpService`（Network Threat Protection）、`SophosNetFilter`（网络过滤）、`SophosFIMService`（文件完整性监控）、`SophosHealth`（端点健康上报）、`SophosFS`（文件防护）、`McsAgent` / `McsClient`（**Management Communications System**，与 Sophos Central 通信）；另加 `sophos*` 前缀兜底，未枚举到的 Sophos 组件也能归入终端防护
  - **其他终端防护**：`CsFalconUIHost`（CrowdStrike Falcon 界面宿主）、`ThreatSonar`（TeamT5 反勒索/EDR）、`intimesec`（奇安信天擎，原网神 Intime；并补 `qaxsafe` / `tianqing`）
  - **系统组件**：`UnistoreSvc_efe21` 这类带 `_xxxxx` 实例后缀的 Windows UWP/Unistack 服务（`UnistoreSvc` / `UdkUserSvc` / `UserDataSvc` / `CDPUserSvc` / `StateRepository`，前缀匹配）
  - **命令行工具**：`curl`（Windows 10+ 内置 / Linux 自带；提示核对调用方与下载内容）
  - **给出归属线索而非留白**：`UI.exe`（通用界面进程）、`sp3/sp4/sp6.exe`（规则化命名、未对应公开软件）归入「其他」并写明取路径+数字签名确认的方法
- 主机画像的「终端防护」一行现在能完整列出 Sophos / CrowdStrike / 天擎 / ThreatSonar 混合部署
- 自测新增 12 项回归断言（19 个进程零未识别、各组件归类、画像提示）
- 站点文案同步为「签名库 564 条」，资源版本号 `?v=1.6.7`

### 说明

- `McsAgent/McsClient` 按 Sophos Management Communications System 归类；若现场确认是其他产品的同名进程，用 `Get-Process McsAgent | Select Path` 看路径即可区分
- `sp3/sp4/sp6` 与 `UI.exe` 这类无法从进程名定性的，建议取：
  `Get-Process sp3 | Select-Object Path, Company, Product, Description` 与
  `Get-AuthenticodeSignature C:\path\sp3.exe | Format-List`，拿到签名主体后再回填签名库（`assets/js/signatures.js` 追加一条即可）

## 2026-11-04-fix

### 修复 / 增强（按真实 fscan v2.x 输出对齐）

- **SNMP 模块**：`[!] SNMP 10.3.12.113:161 community: public | HP ETHERNET MULTI-ENVIRONMENT` → 解析出 161/udp、community、设备描述；`public/private` 团体字生成 high 弱点项「SNMP 默认团体字」，其它团体字记 medium；HP/KYOCERA/京瓷/JetDirect 等设备描述识别为「网络打印机 / 一体机」
- **SMBGhost**：`[!] SMB Ghost 10.3.96.218:445 CVE-2020-0796 漏洞存在` → 归一成 `CVE-2020-0796 (SMBGhost)`，记 critical 弱点
- **噪声行**：`端口扫描中（900线程） ● 100.0% [====] (15561/15561) …`、`[完成] 扫描完成: … (耗时: 1.6m)`、`root@poc:~/.log#` 统一忽略，不再污染「未识别行」
- 兜底规则：任何行里出现 `CVE-xxxx-xxxx / MSxx-xxx / CNVD-xxxx / SMBGhost / BlueKeep / EternalBlue / poc-yaml-*` 都按漏洞命中处理（不再要求行首就是漏洞编号）

- **支持 fscan v2.x 的 `[*]` 结果行**：以前 `[*] 10.0.0.5:445 smb [Product:..] Banner:(..)`、`[*] https://10.0.0.5 code:401 len:0`、`[*] 端口开放 ip:port [http](HTTP探测)`、`[*] ip:port`（裸端口）全部被当成噪声丢掉，现在都能解析
- **新增模块行解析**：`SMBInfo`（系统 + 主机名 + SMBv1/v2）、`RDP`（`[OS:..., Build:..., Hostname:..., DNSDomain:..., FQDN:...]`）、`NetInfo`（主机名 + `-> 邻接 IP`）、`MySQL / MSSQL / PostgreSQL / LDAP / Telnet / Rsync / SSH服务识别成功` 等
- **修复 `[OS:Windows...]` 被误判成弱口令**：真实结果里 10 台 RDP 主机曾被解析成 `rdp [OS:Windows` 口令；现在结构化字段（`OS:/Build:/Hostname:/Product:/Banner:`、含括号的文本）一律不参与口令判定
- **系统版本判定改为「显式 Server 版本 → 构建号 → 客户端标签」**：`Windows 10 (Build 20348)` 正确判为 **Server 2022**、`(Build 17763)` → **2019**、`(Build 9200)` → **2012/8**、`(Build 26100)` → **11 24H2**；构建号 9200/9600 归到 Server 2012/2012R2（EOL 2023-10-10）
- **新增 Web 字段解析**：`code:/len:/title:/server:/[tags]` 拆成独立字段，`[*]` 探测行与 `[+]` 信息行按 URL 自动合并；端口表新增「产品/版本」（`[Product:OpenSSH ||Version:7.2p2]`）
- **内网线索**：`NetInfo -> 10.0.1.41` 收进主机的「邻接 IP」，跨网段自动标记 ↗，Markdown 报告单独成节
- **新增 SMBv1 弱点项**：`SMBInfo ... SMBv1` → high（MS17-010/永恒之蓝攻击面），统计卡单列「SMBv1 主机」
- **服务名不再被探测方式覆盖**：`[*] ip:3389 ssl` 显示为 `3389/rdp` 而不是 `3389/https`；`NetInfo` 不再把 135 标成 `netinfo`
- **剔除二进制垃圾 banner**：SMB 扩展字节、TLS 证书 dump（`DOWNGRD`/`not_defined_in_RFC`）不再进端口表
- **端口表扩充**：88/515/636/3268/3269/5060/8088/8090/10250(Kubelet)/10255，MySQL 5.x 判为 EOL 组件
- **新增「简单清单」复制（推荐日常用）**：`📋 复制机器清单`（按系统分组，一行一台：IP 主机名 系统）、`🔌 复制 IP 清单`（一行一台并带端口/服务）；纯文本、列对齐、中文按显示宽度补位；TXT 下载 = 这两份清单
- Markdown 报告保留为「⬇ Markdown 报告」下载，其中 IP / 端口 / 口令 / 证据均为代码格式
- **新增「📋 复制全部」**：一次复制 = 机器清单 + 服务清单 + IP 清单（与 `⬇ TXT` 下载内容逐字一致，单测已断言），工具栏重排为「复制全部 / 机器 / 服务 / IP ┃ Markdown / JSON / TXT」
- **新增「按服务分类」**：页面新增「🧩 按服务」标签页 + 「🧩 复制服务清单」按钮，按 **Web 服务 / SSH 服务 / 数据库服务 / 远程管理 / 文件共享 / 其它服务** 六类归组（一台主机可同时属于多类），每类只列对应端口；分类端口表见 `SERVICE_CATS`（可自行增删）
- 新增示例「fscan v2 示例」（脱敏真实输出）与 `test/fscan-selftest.js` 中 26 项 v2 断言（弱口令 0 误判、Build→版本、邻接 IP、Web 字段、代码格式导出）
- 新增 URL 参数：`?demo=v2`、`?view=os|ip|risk|ports`、`?expand=1`（展开全部折叠块，打印/截图用）

## 2026-11-04

### 新增

- **fscan 结果解析（新页面 `fscan.html` + `assets/js/fscan.js`）**：把 fscan 的散乱文本结果归一化成结构化数据，解决"结果太多看不出重点"的问题
  - **按操作系统分组**：从 SMB/NetBIOS banner、Web 标题（IIS、`Apache httpd 2.2.15 ((CentOS))`）、构建号（2600/3790/6002/7601/9600/17763/20348…）、IIS 版本（6.0/7.5/8.5→2003/2008R2/2012R2）、发行版字符串识别系统与版本；按官方支持终止日期判定 **EOL**（Windows XP/2003/Vista/7/2008/2008 R2/8/8.1/10/2012/2012 R2/2016/2019/2022、Ubuntu/CentOS/Debian/RHEL、ESXi 5.5–8.0），EOL 分组置顶并标注日期；仅有端口线索时按端口画像兜底为「Windows/Linux（端口推测）」
  - **按 IP 分组**：端口 + 服务 + Web 标题 + 弱口令 + 漏洞/未授权 + Web 资产 + 弱点清单，按风险分降序
  - **按弱点分组**：系统已 EOL → 弱口令（匿名账号单列）→ 未授权访问 → 已知漏洞（MS17-010/CVE/SMBGhost/BlueKeep/poc-yaml-*）→ 高危端口（76 条端口/服务/风险表）→ 组件版本过旧（Tomcat/ httpd / nginx / OpenSSH / OpenSSL 1.0.1 Heartbleed / PHP / IIS / vsftpd 2.3.4 后门 / ProFTPD / WebLogic / Struts2 / Shiro）→ 后台/敏感页面
  - **端口矩阵**：端口 → 命中主机数 → 可打点提示
  - **⚡ 优先关注**：critical/high 弱点排成一列，直接给打击顺序
  - **多格式容错**：`ip:port open`、`[+] ip:port<TAB>tag<TAB>msg`、`[+] MS17-010 ip port`、`[+] PocScan http://… poc-yaml-*`、`[+] http://… Title`、服务标签在前（`[+] SSH 1.2.3.4:22 root:123456`）均可解析；banner 图形、进度条、`[*]`/`[-]` 状态行自动忽略；**兼容 nmap 混排**（`Nmap scan report for` + `445/tcp open microsoft-ds`）
  - **未识别行单独收集**，便于确认是解析器漏规则还是 fscan 没扫到
  - 风险评分 0–100（EOL 40 / 弱口令 40 / 漏洞 40 / 未授权 25 / 高危端口 8 / 组件 6–25），≥70 严重、≥50 高、≥25 中
  - 导出 Markdown / JSON / TXT；`?demo=1` 载入示例、`?view=os|ip|risk|ports` 指定默认视图
- 新增 Node 自测 `test/fscan-selftest.js`（格式识别、OS/EOL 判定、凭据误判防护、nmap 混排、导出、边界用例）
- `index.html` 顶栏加入 fscan 解析入口；资源版本号提升至 `?v=1.6.1`

## 2026-10-28

### 新增

- **补齐一批桌面/驱动/接入类进程的识别**（此前全部落入「未识别」）：
  - 终端防护：`MpDefenderCoreService` / `DefenderSessionHelper` / `DefenderAiPlatformHost` 并入 Windows Defender；McAfee Security Scan Plus（`SSScheduler` / `McUICnt`）、Lavasoft Web Companion
  - VPN / 远程接入：Pulse Secure（Ivanti Secure Access）、OpenVPN Connect 组件（`agent_ovpnconnect_*` / `capiws` / `ovpnhelper_service`）、FortiClient 组件（`FortiSSLVPNdaemon` / `FortiSettings` / `FortiVPN` / `FortiTray` / `FCDBLog`）、LogMeIn Hamachi、SonicWall `SnwlVpn`、Sophos Connect（`charon-svc`）、LogMeIn（`LMIGuardianSvc`）
  - 虚拟化：Hyper-V `vmms` / `vmcompute`、VMware USB Arbitration Service
  - Windows 内置：`dasHost`、`LsaIso`（Credential Guard）、`WLanext`、`IpOverUsbSvc`、`UserOOBEBroker`
  - 厂商组件 / 工具：NVIDIA 容器与遥测（`NVDisplay.Container` / `nvcontainer` / `NvTelemetryContainer`）、GeForce Experience Web Helper、ASUS GPU Tweak、Kyocera `KDService`、Intel `OneApp.IGCC.WinService`、WD Discovery / WD Sync、Opera 浏览器助手、TortoiseSVN、Greenshot、`Video.UI`、`.NET ngen`；`jucheck` 并入 Java 更新程序
  - 归属未公开但仍单独归类（不再计入未识别，提示按路径与签名确认）：`kdd.exe`、`scvpn.exe`、`slservice.exe`、`gentask.exe`、通用 `scheduler.exe`
- 签名库增至 **547 条**

### 修复

- 解析器：兜底格式支持**含空格的进程名**（`WD Discovery.exe`、`NVIDIA Web Helper.exe`），不再被截断成 `Discovery.exe` / `Helper.exe`
- 解析器：支持粘贴界面芯片文本中的 `名称 ×N` 计数后缀（如 `WD Discovery.exe ×4`）与 `名称 PID` 行
- 缓存：`index.html` 资源版本号提升至 `?v=1.5.0`

## 2026-10-22

### 新增

- **Windows 服务名识别**：支持直接粘贴 `sc query` / 服务清单。160+ 个 Windows 内置服务名（`DcomLaunch`、`Appinfo`、`fdPHost`、`RSoPProv`、`vmic*` 等）归入「Windows 系统服务(服务名)」，不再显示为未识别进程
- **新增输入格式**：`sc query` / `sc queryex` 输出（只取 `SERVICE_NAME`，忽略 `DISPLAY_NAME`/`TYPE`/`STATE` 属性行）与 PowerShell `Get-Service` 表格（只取 Name 列），避免把属性值当成进程名
- 服务名专项归属：`Sense` → Defender for Endpoint、`W3SVC`/`WAS`/`IISADMIN`/`AppHostSvc` → IIS、`MSMQ` → MSMQ、`SNMPTRAP` → SNMP、`TermService`/`SessionEnv`/`UmRdpService` → RDP（画像提示 3389）、`VSS`/`VSSVC` → 卷影复制、`ssh-agent` → OpenSSH 认证代理
- 补充签名：Graylog Sidecar（含 `graylog-collector-*` 前缀）、Forefront AD 连接器、`perfmon.exe`、ESET `eguiProxy`

### 修复

- 分类：`elastic-otel-collector`（EDOT）由「运维 / 监控」改归**终端安全 / EDR**，与 Elastic Defend 一并计入「终端防护」画像
- 分类：`elastic-agent.exe` 由「运维 / 监控」改归**终端安全 / EDR**（部署 Elastic Defend 时即承载终端防护）
- 缓存：`index.html` 资源版本号提升至 `?v=1.4.0`

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

- 缓存：`index.html` 中的 JS/CSS 引用加上 `?v=` 版本查询串，避免 GitHub Pages 长缓存（约 4 小时）导致更新后页面仍用旧脚本
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
