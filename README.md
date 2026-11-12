# TaskList Inspector · 在线进程分析 (中/英双语)

> 面向渗透测试前期信息收集 / 资产盘点 / 应急响应的进程列表分析工具。
> 粘贴 `tasklist`、`ps aux` 等进程列表，自动识别目标主机上的 **浏览器、杀毒软件 / EDR、远程控制、隧道代理、数据库、Web 服务、开发工具** 等常见软件，并生成主机画像线索与可导出的分析报告。

> An online process-list analyzer for pentest recon, asset inventory and incident response — bilingual (中文 / English). Paste `tasklist` / `ps aux` / NetExec output to identify AV/EDR, browsers, remote tools, databases, web services and more.

> 🧭 姊妹工具 / Companion tool：**[Fscan Report Inspector](./fscan.html)** —— 把 fscan 的散乱结果按「操作系统 / IP / 弱点」重新组织，重点标记已停止支持的 Windows 与弱口令。/ Regroups messy fscan output by OS, IP and weakness.

🌐 线上地址 / Live：<https://tasklist.cxaqhq.cn> · 📦 仓库 / Repo：<https://github.com/badboycxcc/Tasklist> · 🧾 变更记录 / Changelog：[CHANGELOG.md](./CHANGELOG.md)

---

## ✨ 功能特性

- **多格式自动识别**
  - Windows：`tasklist` 默认表格 / `tasklist /fo csv` / `tasklist /fo list` / PowerShell `Get-Process`
  - Linux：`ps aux` / `ps -ef` / `top -bn1`
  - `tasklist /svc`：服务列里的服务名不会被当成进程，`N/A` 占位符也不会被误判成进程名 `A`
  - Windows 服务名清单（`sc query` / 服务列表）：160+ 个内置服务名会归入「Windows 系统服务(服务名)」；`Sense`(Defender for Endpoint)、`W3SVC`(IIS)、`MSMQ`、`TermService`(RDP)、`VSS`、`ssh-agent` 等服务名会给出具体归属
  - 名称截断容错：`tasklist` 会把超长进程名截断为 25 字符（如 `StartMenuExperienceHost.e`、`Microsoft.AAD.BrokerPlugi`、`elastic-otel-collector.ex`），解析器仍能正确匹配
  - 远程执行工具输出：NetExec / CrackMapExec（`nxc ... -x "tasklist"` 等）日志会自动剥离 `[协议 IP 端口 主机名]` 前缀并丢弃 `[+]` 状态行
  - 兜底：一行一个进程名，或简单的“名称 PID”列表
- **564 条软件签名库**：覆盖国内外杀软/EDR/XDR（火绒、360、Kaspersky、CrowdStrike、Palo Alto Cortex XDR、InTimeSec 集时安全 MDR、TeamT5 ThreatSonar、McAfee/Trellix（ENS/Agent/DLP/Policy Auditor/XClient）、VMware Carbon Black、Cybereason、Trellix/FireEye HX 等）、Microsoft Exchange Server 全套角色组件、IIS/MSMQ/故障转移群集、SQL Server 全套组件、Windows 内置组件、虚拟化/远程（VMware Tools/VMRC、DameWare、SCCM/Citrix 远程控制）、资产盘点 Agent（GLPI、osquery）、远程控制（TeamViewer、AnyDesk、向日葵、ToDesk…）、隧道代理（frp、ngrok…）、数据库、Web 服务、容器/编排、云厂商 Agent（阿里云/腾讯云）等
- **中英双语界面**：右上角一键切换 `中文 / EN`，识别名称、软件说明、主机画像与导出报告全部同步切换
- **命令行关键字识别**：对 `java` / `python` 等宿主进程，扫描完整命令行识别 Burp Suite、SQLMap、Metasploit、宝塔面板等
- **可疑启发式检测**：仿冒系统进程名（如 `svch0st.exe`、`scvhost.exe`）、双扩展名、非 ASCII 同形字、从临时/公共目录运行、UNC 路径运行
- **主机画像**：自动推断服务器角色、办公/开发终端、企业域环境、云主机、虚拟化等线索
- **报告导出**：复制 Markdown / 下载 Markdown、JSON、TXT
- **纯前端 · 零依赖 · 可离线**：无后端、无跟踪、无第三方库，数据全部在浏览器本地处理

## 🧭 fscan 结果解析（`fscan.html`）

fscan 的输出是一堆平铺的行（`ip:port open`、`[+] …`、弱口令、未授权、POC 命中），打完一个 C 段很难快速回答"**哪些机器是旧系统、谁开了什么服务、先打哪台**"。这个页面把它归一化成三个视图：

- **① 按操作系统分组**：从 SMB/NetBIOS banner、Web 标题（IIS/`Apache httpd 2.2.15 ((CentOS))`）、构建号（`7601`/`3790`/`17763`…）、IIS 版本、发行版字符串里识别 OS 与版本；按官方支持终止日期判定 **EOL**（XP/2003/Vista/7/2008/2008 R2/8/2012/2012 R2/10，以及 Ubuntu/CentOS/Debian/RHEL/ESXi），EOL 分组排在最前并标注日期；只有端口线索时给出「Windows/Linux（端口推测）」兜底
- **② 按 IP 分组**：每台主机的端口 + 服务 + Web 标题 + 弱口令 + 漏洞/未授权 + Web 资产 + 完整弱点清单，风险分从高到低排序
- **③ 按弱点分组**：系统已 EOL → 弱口令 → 未授权访问 → 已知漏洞（MS17-010 / CVE / SMBGhost / BlueKeep / poc-yaml-*）→ 高危端口 → 组件版本过旧（Tomcat/CVE-2017-12615、OpenSSL 1.0.1 Heartbleed、vsftpd 2.3.4 后门…）→ 后台/敏感页面
- **④ 按服务**：Web / SSH / 数据库 / 远程管理 / 文件共享 / 其它 六类分组，每类只显示该主机对应的端口
- **⑤ 端口矩阵**：每个端口命中多少台主机、可打点提示
- **⚡ 优先关注**：把 critical/high 的弱点排成一列，直接给"先打这里"
- **零配置兼容（v1.8 + v2.x）**：
  - v1.8：`ip:port open`、`[+] ip:port␉tag␉msg`、`[+] MS17-010 1.2.3.4 445`、`[+] PocScan http://… poc-yaml-*`、`[+] http://… Title`
  - v2.x：`[*] ip:port tag [Product:…||Version:…] Banner:(…)`、`[*] 端口开放 ip:port [http](HTTP探测)`、`[*] https://ip code:401 len:0`、`[*] ip:port`（裸端口）
  - 模块行：`SMBInfo`（系统+主机名+SMBv1/v2）、`RDP`（`[OS:, Build:, Hostname:, DNSDomain:, FQDN:]`）、`NetInfo`（主机名 + `-> 邻接 IP`）、`SNMP`（community + 设备型号，`public/private` 直接记为弱点）、`MySQL / MSSQL / PostgreSQL / LDAP / Telnet / Rsync / SSH服务识别成功`
  - 漏洞命中：`MS17-010` / `CVE-xxxx` / `SMB Ghost (CVE-2020-0796)` / `BlueKeep` / `poc-yaml-*`，行内任意位置出现即识别
  - 混排：`Nmap scan report for` + `445/tcp open microsoft-ds`；banner 图形、进度条、`[*]` 状态行、`插件扫描错误` 自动忽略
- **版本判定**：显式 `Server 20xx` → 构建号（`7601`/`9200`/`17763`/`20348`/`26100`…）→ 客户端标签；`Windows 10 (Build 20348)` 会正确判成 Server 2022
- **未识别行单独列出**：解析不了的行单独收集，方便反馈补规则，也便于确认"是解析器没认出来"而不是"fscan 没扫到"
- **两种「简单清单」一键复制**（纯文本、列对齐、无 Markdown 符号）：
  ```
  Windows 机器 (6)
  10.0.0.3    SRV-CORP3   Windows Server 2012
  10.0.0.23   SRV-APP8    Windows 7 SP1 / Server 2008 R2 SP1
  ```
  - `📋 复制全部`：一次复制三段（机器清单 + 服务清单 + IP 清单），**内容与 `⬇ TXT` 下载完全一致**，直接甩进群/文档
  - `📋 机器`：按系统分组，一行一台（IP 主机名 系统），组内按 IP 排序
  - `🔌 IP`：一行一台并带端口（`10.0.0.3  SRV-CORP3  Windows Server 2012  53/dns 80/http 445/smb 3389/rdp`）
  - `🧩 服务`：按服务分类分组 —— **Web / SSH / 数据库 / 远程管理 / 文件共享 / 其它**，每类只列该主机对应的端口（一台机器可同时出现在多类里）
  ```
  Web 服务 (12)
  10.0.0.3    SRV-CORP3   Windows Server 2012   80/http
  10.0.0.221  -           Rocky Linux             80/http 8000/http

  数据库服务 (3)
  10.0.0.4    -           Ubuntu 16.04           3306/mysql
  ```
  - 中文列宽按显示宽度对齐（CJK 按 2 列算），贴进聊天/文档不会错位
- 仍可下载完整 **Markdown 报告 / JSON / TXT**（TXT = 上面两份清单）

- **URL 参数**：`?demo=1` / `?demo=v2` / `?demo=nmap` 载入示例，`?view=os|ip|risk|ports` 指定视图，`?expand=1` 展开全部折叠块（打印/截图）

自测：`node test/fscan-selftest.js`（覆盖 v1.8 与 v2.x 两种输出）

## 🚀 本地使用

无需构建，直接双击 `index.html` 即可；或启动一个静态服务器：

```bash
cd tasklist
python3 -m http.server 8080
# 浏览器访问 http://localhost:8080
```

也可在本地运行自测脚本（需要 Node.js）验证解析与识别逻辑：

```bash
node test/selftest.js
```

## 📦 部署到 GitHub Pages 并绑定 tasklist.cxaqhq.cn

仓库地址：<https://github.com/badboycxcc/Tasklist>

> 提示：首次发布时按以下步骤推送即可；建议将本项目作为独立仓库维护。

### 1. 推送代码

```bash
cd tasklist
git init
git add .
git commit -m "feat: TaskList Inspector (bilingual)"
git branch -M main
git remote add origin https://github.com/badboycxcc/Tasklist.git
git push -u origin main
```

> 若仓库创建时已带有初始 `README`，先执行 `git pull --rebase origin main` 再推送。

### 2. 开启 GitHub Pages

1. 打开仓库 → **Settings → Pages**
2. **Build and deployment → Source** 选择 `Deploy from a branch`
3. Branch 选择 `main`，目录选择 `/ (root)`，保存
4. 等待 1~2 分钟，默认站点地址为 `https://badboycxcc.github.io/Tasklist/`

### 3. 绑定自定义域名

本仓库已包含 `CNAME` 文件（内容为 `tasklist.cxaqhq.cn`），并已放置 `.nojekyll`。

在 **Settings → Pages → Custom domain** 中确认填入 `tasklist.cxaqhq.cn` 并保存，
随后勾选 **Enforce HTTPS**（证书签发可能需要几分钟到半小时）。

### 4. 配置 DNS 解析（在 cxaqhq.cn 的域名服务商处）

| 记录类型 | 主机记录 | 记录值 |
| --- | --- | --- |
| CNAME | `tasklist` | `badboycxcc.github.io` |

> 注意：
> - 如果使用 Cloudflare 等代理，请先关闭小云朵（DNS only），等 GitHub 证书签发成功后再按需开启。
> - 若 GitHub 提示需要验证域名所有权，按提示在 DNS 添加它给出的 `TXT` 记录即可。

完成后访问 <https://tasklist.cxaqhq.cn> 即可。

## 📁 目录结构

```
tasklist/
├── index.html                 # 进程分析页(中英双语区块)
├── fscan.html                 # fscan 结果解析页(按系统/IP/弱点/端口)
├── favicon.svg                # 站点图标
├── CNAME                      # GitHub Pages 自定义域名
├── .nojekyll                  # 禁用 Jekyll 处理
├── assets/
│   ├── css/style.css          # 样式(深色安全工具风格 + 双语切换)
│   ├── css/fscan.css          # fscan 页增量样式(复用 style.css 的设计令牌)
│   └── js/
│       ├── signatures.js      # 软件签名库 + 类别定义 + 命令行关键字(核心可维护文件)
│       ├── signatures.en.js   # 英文翻译(签名名称/描述、厂商、命令行关键字)
│       ├── i18n.js            # 多语言框架(语言检测/切换/静态文本)
│       ├── samples.js         # 内置示例数据(Windows/Linux/NetExec)
│       ├── parser.js          # 多格式进程列表解析器(含 NetExec 前缀清洗)
│       ├── analyzer.js        # 匹配、可疑检测、画像生成
│       ├── app.js             # UI 渲染与报告导出
│       ├── fscan.js           # fscan 解析引擎(端口表/OS指纹/EOL/弱点评分/导出)
│       ├── fscan-samples.js   # fscan 示例数据(fscan 原始输出 + nmap 混排)
│       └── fscan-app.js       # fscan 页渲染与交互
├── test/
│   ├── selftest.js            # Node 自测脚本(含双语覆盖率校验)
│   └── fscan-selftest.js      # fscan 解析器自测(格式/OS/EOL/误判防护/导出)
├── CHANGELOG.md               # 变更记录
└── README.md
```

## 🧩 扩展签名库

在 `assets/js/signatures.js` 的 `SIGNATURES` 数组中按格式追加即可（无需改动其它代码）：

```js
// match: 归一化后的进程名(小写、不含 .exe); prefix: true 表示前缀匹配
{ match: ["yourproc"], prefix: true, name: "软件名称", vendor: "厂商", cat: "类别key", os: "w", desc: "说明文字" },
```

- `os`：`w` = Windows，`l` = Linux，`b` = 两者
- `cat`：见同文件 `CATEGORIES` 中的类别键（如 `av`、`remote`、`db`、`web`…）
- 命令行关键字：追加到 `CMD_KEYWORDS`
- 英文翻译：在 `assets/js/signatures.en.js` 中补一条 `"类别|名称": "英文描述"`；
  若中文名称本身需要英文化，用 `{ name: "English Name", desc: "..." }`；缺失时会回退显示中文描述

### ⚠️ 发版时记得更新资源版本号（缓存）

GitHub Pages 对 JS/CSS 设置了较长缓存（`max-age=14400`，约 4 小时），浏览器可能因此继续使用旧脚本。
`index.html` 中的 `<script>` / `<link>` 均带有版本查询串（当前 `?v=1.6.1`，`index.html` 与 `fscan.html` 需同步）。
**每次修改 `assets/` 下的 JS/CSS 后，请把 `index.html` 中所有 `?v=` 统一 +1（或改为新版本号）**，
这样浏览器会立即拉取新文件，避免"改了但页面没变"。

## 🧾 变更记录

完整历史见 **[CHANGELOG.md](./CHANGELOG.md)**。近期要点：

- **2026-11-04**：新增 **fscan 结果解析**（`fscan.html`）——按操作系统（含 EOL 判定）/ IP / 弱点三视图重组 fscan 结果，端口矩阵与「优先关注」清单，兼容 nmap 混排，可导出 Markdown/JSON/TXT
- **2026-10-28**：补齐 48 个桌面/驱动/接入类进程（Windows Defender 组件、McAfee Scan Plus、OpenVPN Connect / FortiClient / Pulse Secure / Hamachi / SonicWall / Sophos Connect、Hyper-V `vmms`/`vmcompute`、NVIDIA / WD Discovery / Kyocera / ASUS GPU Tweak 等）；兜底解析支持含空格进程名与 `名称 ×N` 计数后缀
- **2026-10-22**：新增 160+ Windows 内置服务名识别（`sc query` / 服务清单），`Sense`/`W3SVC`/`MSMQ`/`TermService`/`VSS`/`ssh-agent` 等服务名给出具体归属；Elastic Agent / EDOT 归入终端防护（EDR）；补充 Graylog Sidecar、Forefront AD 连接器、perfmon、ESET `eguiProxy`
- **2026-10-13**：签名库扩充至 **500+**（McAfee/Trellix 含 XClient、Exchange 全套角色组件、Citrix/DameWare/SCCM、VMware VMRC、Windows 内置组件、Realtek/Waves/Intelligo 音频、Intel IPF/PresentMon、Elastic OTel Collector 等）；解析器支持 `tasklist /svc` 服务列与 25 字符名称截断匹配
- **2026-10-08**：新增 Cortex XDR 全组件、SQL Server 组件、Windows 内置组件、GLPI Agent

## 🎨 宣传素材

图标与分享卡片素材位于 `assets/`，可直接引用线上地址（如 `https://tasklist.cxaqhq.cn/assets/icon-512.png`）：

| 文件 | 用途 |
| --- | --- |
| `assets/icon-1024.png` / `assets/icon-512.png` | 站点图标 / 平台头像（高清） |
| `assets/icon-256.png` / `icon-128.png` / `icon-64.png` | 列表图标、小尺寸场景 |
| `assets/icon-square-512.png` | 全出血方形版（平台裁剪为圆形头像时用） |
| `assets/og-image.png` | 链接分享卡片（1200×630） |
| `assets/icon.svg` / `icon-square.svg` / `og-image.svg` | 矢量母版（可自行改色、放缩） |

## 🇬🇧 English

**TaskList Inspector** is a pure client-side web tool that analyzes process lists (`tasklist` / `ps aux` / `ps -ef` / `top` / NetExec logs) to identify software running on Windows & Linux hosts — built for pentest recon, asset inventory and incident response. The UI is bilingual (中文 / English) — switch it in the top-right corner.

- **Inputs**: `tasklist` (table / CSV / list / **`/svc`**), PowerShell `Get-Process`, `ps aux`, `ps -ef`, `top -bn1`, NetExec/CrackMapExec logs (prefixed output auto-cleaned), plain name lists — plus tolerance for `N/A` placeholders and `tasklist`'s 25-character name truncation (`StartMenuExperienceHost.e`, `Microsoft.AAD.BrokerPlugi`, …)
- **564 signatures**: AV/EDR/XDR (incl. Cortex XDR, McAfee/Trellix ENS/Agent/DLP/XClient, Carbon Black, Cybereason, Trellix HX), full Microsoft Exchange role set, IIS/MSMQ/Failover Clustering, full SQL Server component set, Windows built-ins, virtualization/remote (VMware Tools/VMRC, DameWare, SCCM/Citrix), inventory agents (GLPI, osquery), remote control (incl. AnyDesk), tunnels, VPN/zero-trust, databases, web services, containers/K8s, dev tools, office/IM, cloud agents …
- **Command-line keyword scan**: spots Burp Suite, SQLMap, Metasploit, BT Panel and more inside java/python command lines
- **Suspicious heuristics**: typosquatted system processes (`svch0st.exe`), double extensions, non-ASCII homoglyphs, execution from temp/public directories, UNC paths
- **Host profiling** and **report export** (Markdown / JSON / TXT), 100% client-side, offline-ready

**Fscan Report Inspector** ([fscan.html](./fscan.html)) regroups messy fscan output into three views — by operating system (with end-of-life detection for Windows XP/2003/Vista/7/2008/2008 R2/8/2012/2012 R2/10 plus Ubuntu/CentOS/Debian/RHEL/ESXi), by IP (ports, services, web titles, credentials, vulnerabilities, risk score) and by weakness (EOL OS → weak credentials → unauthenticated access → known CVEs → high-risk ports → outdated components). Includes a port matrix, a "priority targets" list, nmap mixed-input tolerance, and Markdown/JSON/TXT export.

Deploy: push this folder to <https://github.com/badboycxcc/Tasklist>, enable Pages (`main` / root), set the custom domain `tasklist.cxaqhq.cn` (the `CNAME` file is included) and add a DNS record: `CNAME  tasklist → badboycxcc.github.io`.

**Changelog**: see [CHANGELOG.md](./CHANGELOG.md).

## ⚠️ 免责声明

本工具仅用于**已获授权**的安全测试、资产盘点与应急响应场景。使用者应确保对目标系统拥有合法授权，并对自身行为承担全部责任；严禁用于任何未经授权的用途。
