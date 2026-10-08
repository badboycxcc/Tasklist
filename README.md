# TaskList Inspector · 在线进程分析 (中/英双语)

> 面向渗透测试前期信息收集 / 资产盘点 / 应急响应的进程列表分析工具。
> 粘贴 `tasklist`、`ps aux` 等进程列表，自动识别目标主机上的 **浏览器、杀毒软件 / EDR、远程控制、隧道代理、数据库、Web 服务、开发工具** 等常见软件，并生成主机画像线索与可导出的分析报告。

> An online process-list analyzer for pentest recon, asset inventory and incident response — bilingual (中文 / English). Paste `tasklist` / `ps aux` / NetExec output to identify AV/EDR, browsers, remote tools, databases, web services and more.

🌐 线上地址 / Live：<https://tasklist.cxaqhq.cn> · 📦 仓库 / Repo：<https://github.com/badboycxcc/Tasklist>

---

## ✨ 功能特性

- **多格式自动识别**
  - Windows：`tasklist` 默认表格 / `tasklist /fo csv` / `tasklist /fo list` / PowerShell `Get-Process`
  - Linux：`ps aux` / `ps -ef` / `top -bn1`
  - 远程执行工具输出：NetExec / CrackMapExec（`nxc ... -x "tasklist"` 等）日志会自动剥离 `[协议 IP 端口 主机名]` 前缀并丢弃 `[+]` 状态行；列被截断为 `<名称> <PID> N/A` 的表格也能正确解析（`N/A` 不会被误判成进程名 `A`）
  - 兜底：一行一个进程名，或简单的“名称 PID”列表
- **440+ 软件签名库**：覆盖国内外杀软/EDR/XDR（火绒、360、Kaspersky、CrowdStrike、Palo Alto Cortex XDR、VMware Carbon Black、Cybereason、Trellix/FireEye HX 等）、SQL Server 全套组件、Windows 内置组件、资产盘点 Agent（GLPI）、远程控制（TeamViewer、AnyDesk、向日葵、ToDesk…）、穿透工具（frp、ngrok…）、数据库、Web 服务、容器/编排、云厂商 Agent（阿里云/腾讯云）等
- **中英双语界面**：右上角一键切换 `中文 / EN`，识别名称、软件说明、主机画像与导出报告全部同步切换
- **命令行关键字识别**：对 `java` / `python` 等宿主进程，扫描完整命令行识别 Burp Suite、SQLMap、Metasploit、宝塔面板等
- **可疑启发式检测**：仿冒系统进程名（如 `svch0st.exe`、`scvhost.exe`）、双扩展名、非 ASCII 同形字、从临时/公共目录运行、UNC 路径运行
- **主机画像**：自动推断服务器角色、办公/开发终端、企业域环境、云主机、虚拟化等线索
- **报告导出**：复制 Markdown / 下载 Markdown、JSON、TXT
- **纯前端 · 零依赖 · 可离线**：无后端、无跟踪、无第三方库，数据全部在浏览器本地处理

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
├── index.html                 # 页面主体(中英双语区块)
├── favicon.svg                # 站点图标
├── CNAME                      # GitHub Pages 自定义域名
├── .nojekyll                  # 禁用 Jekyll 处理
├── assets/
│   ├── css/style.css          # 样式(深色安全工具风格 + 双语切换)
│   └── js/
│       ├── signatures.js      # 软件签名库 + 类别定义 + 命令行关键字(核心可维护文件)
│       ├── signatures.en.js   # 英文翻译(签名名称/描述、厂商、命令行关键字)
│       ├── i18n.js            # 多语言框架(语言检测/切换/静态文本)
│       ├── samples.js         # 内置示例数据(Windows/Linux/NetExec)
│       ├── parser.js          # 多格式进程列表解析器(含 NetExec 前缀清洗)
│       ├── analyzer.js        # 匹配、可疑检测、画像生成
│       └── app.js             # UI 渲染与报告导出
├── test/
│   └── selftest.js            # Node 自测脚本(含双语覆盖率校验)
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

- **Inputs**: `tasklist` (table / CSV / list), PowerShell `Get-Process`, `ps aux`, `ps -ef`, `top -bn1`, NetExec/CrackMapExec logs (prefixed output auto-cleaned; truncated `<name> <PID> N/A` tables handled), plain name lists
- **440+ signatures**: AV/EDR/XDR (incl. Cortex XDR, Carbon Black, Cybereason, Trellix HX), full SQL Server component set, Windows built-ins, inventory agents (GLPI), remote control (incl. AnyDesk), tunnels, VPN/zero-trust, databases, web services, containers/K8s, dev tools, office/IM, cloud agents …
- **Command-line keyword scan**: spots Burp Suite, SQLMap, Metasploit, BT Panel and more inside java/python command lines
- **Suspicious heuristics**: typosquatted system processes (`svch0st.exe`), double extensions, non-ASCII homoglyphs, execution from temp/public directories, UNC paths
- **Host profiling** and **report export** (Markdown / JSON / TXT), 100% client-side, offline-ready

Deploy: push this folder to <https://github.com/badboycxcc/Tasklist>, enable Pages (`main` / root), set the custom domain `tasklist.cxaqhq.cn` (the `CNAME` file is included) and add a DNS record: `CNAME  tasklist → badboycxcc.github.io`.

## ⚠️ 免责声明

本工具仅用于**已获授权**的安全测试、资产盘点与应急响应场景。使用者应确保对目标系统拥有合法授权，并对自身行为承担全部责任；严禁用于任何未经授权的用途。
