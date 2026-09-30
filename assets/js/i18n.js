/*!
 * TaskList Inspector - 多语言(i18n)支持
 * ---------------------------------------------------------------
 * - 语言: "zh" (中文) / "en" (English)
 * - 优先级: URL 参数(?lang=en) > localStorage > 浏览器语言 > 默认 zh
 * - 页面静态文本: 使用 data-i18n / data-i18n-html / data-i18n-ph 属性
 * - 长文本区块: 使用 <div class="lang-zh"> / <div class="lang-en"> 双块切换(CSS)
 * - JS 动态文本: I18N.t(key, params), 切换语言时派发 "tli:lang" 事件
 */
(function (root) {
  "use strict";

  var STRINGS = {
    zh: {
      "meta.title": "TaskList Inspector · 在线进程分析 · 目标软件识别",
      "brand.sub": "在线进程分析",
      "lang.btn": "EN",
      "lang.title": "切换到 English",

      "sec.input": "① 粘贴进程列表",
      "lbl.platform": "平台",
      "opt.auto": "自动识别",
      "ph.input": "在此粘贴 tasklist、tasklist /fo csv、PowerShell Get-Process、ps aux、ps -ef、top 等命令的输出...\n\n提示：Windows 可执行 tasklist /v 或 tasklist /fo csv；Linux 可执行 ps auxf 获取更完整信息。",
      "btn.analyze": "开始分析 (Ctrl/⌘ + Enter)",
      "btn.sampleWin": "Windows 示例",
      "btn.sampleNix": "Linux 示例",
      "btn.sampleNxc": "nxc/CME 示例",
      "btn.clear": "清空",
      "meta.input": "输入: {lines} 行 · {kb} KB",
      "privacy": "🔒 所有分析均在浏览器本地完成，输入内容不会上传到任何服务器；页面无任何第三方依赖，也可下载后完全离线使用。",
      "sec.guide": "📖 支持的输入格式与使用建议",

      "sec.profile": "🎯 主机画像线索",
      "sec.findings": "🔎 关键发现",
      "sec.cmd": "⚡ 命令行关键字发现",
      "sec.sus": "⚠️ 可疑提示",
      "sec.tables": "📋 识别明细",
      "ph.filter": "筛选进程 / 软件名...",
      "btn.copy": "📋 复制报告",
      "btn.md": "⬇ 下载 Markdown",
      "btn.json": "⬇ 下载 JSON",
      "btn.txt": "⬇ 下载 TXT",
      "sec.unresolved": "❓ 未识别进程",

      "st.platform": "目标平台",
      "st.instances": "进程条目",
      "st.unique": "唯一进程名",
      "st.identified": "已识别",
      "st.av": "终端防护软件",
      "st.sus": "可疑提示",
      "st.rows": "条",
      "st.undetermined": "未判定",

      "mode.win-table": "tasklist 表格",
      "mode.win-csv": "tasklist CSV",
      "mode.win-list": "tasklist 列表",
      "mode.win-ps": "PowerShell Get-Process",
      "mode.nix-aux": "ps aux",
      "mode.nix-ef": "ps -ef",
      "mode.nix-top": "top 输出",
      "mode.generic": "通用解析",

      "th.proc": "进程",
      "th.pid": "PID 示例",
      "th.result": "识别结果",
      "th.match": "匹配",
      "th.desc": "说明 / 标记",
      "badge.name": "名称匹配",
      "badge.prefix": "前缀匹配",
      "badge.cmd": "命令行匹配",
      "badge.none": "未识别",
      "row.cmdKeyword": "命中命令行关键字",
      "tbl.procs": "{n} 个进程",
      "tbl.empty": "没有符合筛选条件的进程。",
      "fc.items": "{n} 项",
      "unresolved.count": "{n} 个",
      "unresolved.more": "… 等 {n} 项",

      "toast.empty": "请先粘贴进程列表, 或点击「Windows 示例 / Linux 示例」体验",
      "toast.sampleWin": "已载入 Windows 示例, 点击「开始分析」",
      "toast.sampleNix": "已载入 Linux 示例, 点击「开始分析」",
      "toast.sampleNxc": "已载入 NetExec/CME 带前缀输出示例, 点击「开始分析」",
      "toast.copied": "报告已复制到剪贴板",
      "toast.copyFail": "复制失败, 请手动选择文本",
      "cmd.hit": "命令行发现: ",
      "cmd.procSuffix": "(命令行)",
      "err.parse": "解析失败, 请检查输入格式",

      "parse.nxc": "已自动去除 NetExec / CrackMapExec 输出前缀(共处理 {n} 行), 并基于命令输出内容解析。",
      "err.noEntries": "未能从输入中解析出有效的进程条目。支持 tasklist(表格/CSV/列表)、PowerShell Get-Process、ps aux、ps -ef、top 等格式。",

      "vendor.cmd": "命令行关键字",
      "sep.list": "、",
      "sep.reason": "；",

      "pf.av": "🛡️ 终端防护: {list} —— 目标主机受安全软件/EDR 保护",
      "pf.tool": "⚔️ 安全测试工具痕迹: {list} —— 如非我方授权行动, 建议重点核实",
      "pf.remote": "🎛️ 远程控制/会话组件: {list} —— 可能存在运维远程通道, 注意横向移动面",
      "pf.tunnel": "🚇 隧道/代理: {list} —— 存在穿透/转发类工具, 可作为外联通道",
      "pf.vpn": "🔐 VPN/零信任客户端: {list} —— 企业远程接入环境",
      "pf.cloud": "☁️ 云环境线索: {list} —— 疑似云主机",
      "pf.container": "📦 容器/编排: {list} —— Docker/K8s 环境",
      "pf.server": "🖥️ 疑似服务器角色: {svc}",
      "pf.svc.web": "Web({list})",
      "pf.svc.db": "数据库({list})",
      "pf.mail": "✉️ 邮件服务: {list}",
      "pf.file": "📁 文件/共享服务: {list} —— 注意共享访问面",
      "pf.workspace": "💼 疑似办公/开发终端: {parts}",
      "pf.ws.browser": "浏览器({list})",
      "pf.ws.office": "办公({list})",
      "pf.ws.im": "通讯({list})",
      "pf.ws.dev": "开发({list})",
      "pf.domain": "🏢 企业集中管理/域线索: 存在 SCCM/域认证相关组件, 注意域环境关联影响",
      "pf.rdp": "🖱️ 存在 RDP 会话/服务组件, 可关注 3389 等远程桌面入口",
      "pf.winrm": "⌨️ 存在 WinRM 远程管理会话组件",
      "pf.guest": "💠 当前系统疑似运行在虚拟机/云主机中",
      "pf.host": "💠 本机可能作为虚拟化宿主机运行虚拟机",
      "pf.none": "未识别出明显特征软件, 可能为精简系统或非常见环境; 可尝试输入包含完整命令行的列表提升识别率。",
      "pf.more": "…(共 {n} 项)",
      "pf.sus": "⚠️ 可疑提示: {raw} — {reasons}",

      "sus.nonascii": "进程名包含非 ASCII 字符, 可能是同形字伪装",
      "sus.doubleext": "双扩展名进程名(常见伪装手法)",
      "sus.typosquat": "名称酷似系统关键进程 \"{name}\", 请核实是否为仿冒",
      "sus.tempdir": "命令行路径位于{dir}, 需确认来源",
      "sus.unc": "从 UNC 网络路径运行, 需确认来源",

      "p.userTemp": "用户临时目录",
      "p.sysTemp": "系统临时目录",
      "p.temp": "临时目录",
      "p.tmp": "临时目录",
      "p.downloads": "下载目录",
      "p.public": "公共目录",
      "p.tmpl": "/tmp 目录",
      "p.devshm": "/dev/shm 共享内存",
      "p.vartmp": "/var/tmp 目录",
      "p.runshm": "/run/shm",

      "rep.title": "# 进程分析报告",
      "rep.time": "- 分析时间: {t}",
      "rep.platform": "- 目标平台: {p}（{m}）",
      "rep.counts": "- 进程条目: {a} 条（去重后 {b} 个, 已识别 {c} 个）",
      "rep.tool": "- 生成工具: TaskList Inspector (tasklist.cxaqhq.cn)",
      "rep.profile": "## 主机画像线索",
      "rep.cmd": "## 命令行关键字发现",
      "rep.sus": "## 可疑提示",
      "rep.results": "## 识别结果",
      "rep.th": "| 进程 | PID 示例 | 识别结果 | 厂商 | 匹配 | 说明 |",
      "rep.sep": "| --- | --- | --- | --- | --- | --- |",
      "rep.match.name": "名称",
      "rep.match.prefix": "前缀",
      "rep.match.cmd": "命令行",
      "rep.unresolved": "## 未识别进程（{n} 个）",
      "rep.footer": "> 本报告由 TaskList Inspector 在浏览器本地生成, 仅供授权的安全测试、资产盘点与应急响应使用。"
    },

    en: {
      "meta.title": "TaskList Inspector · Online Process Analyzer",
      "brand.sub": "Process Analyzer",
      "lang.btn": "中文",
      "lang.title": "Switch to Chinese",

      "sec.input": "① Paste the process list",
      "lbl.platform": "Platform",
      "opt.auto": "Auto-detect",
      "ph.input": "Paste the output of tasklist, tasklist /fo csv, PowerShell Get-Process, ps aux, ps -ef, top, or NetExec logs...\n\nTip: on Windows run tasklist /v or tasklist /fo csv; on Linux run ps auxf for full command lines.",
      "btn.analyze": "Analyze (Ctrl/⌘ + Enter)",
      "btn.sampleWin": "Windows sample",
      "btn.sampleNix": "Linux sample",
      "btn.sampleNxc": "nxc/CME sample",
      "btn.clear": "Clear",
      "meta.input": "Input: {lines} lines · {kb} KB",
      "privacy": "🔒 Everything runs locally in your browser — input never leaves your machine. No third-party dependencies, works fully offline.",
      "sec.guide": "📖 Supported input formats & tips",

      "sec.profile": "🎯 Host profile clues",
      "sec.findings": "🔎 Key findings",
      "sec.cmd": "⚡ Command-line keyword hits",
      "sec.sus": "⚠️ Suspicious indicators",
      "sec.tables": "📋 Identification details",
      "ph.filter": "Filter process / software...",
      "btn.copy": "📋 Copy report",
      "btn.md": "⬇ Download Markdown",
      "btn.json": "⬇ Download JSON",
      "btn.txt": "⬇ Download TXT",
      "sec.unresolved": "❓ Unrecognized processes",

      "st.platform": "Platform",
      "st.instances": "Process rows",
      "st.unique": "Unique names",
      "st.identified": "Identified",
      "st.av": "AV / EDR",
      "st.sus": "Suspicious",
      "st.rows": "rows",
      "st.undetermined": "Undetermined",

      "mode.win-table": "tasklist table",
      "mode.win-csv": "tasklist CSV",
      "mode.win-list": "tasklist list",
      "mode.win-ps": "PowerShell Get-Process",
      "mode.nix-aux": "ps aux",
      "mode.nix-ef": "ps -ef",
      "mode.nix-top": "top output",
      "mode.generic": "generic parse",

      "th.proc": "Process",
      "th.pid": "Sample PIDs",
      "th.result": "Identification",
      "th.match": "Match",
      "th.desc": "Notes / flags",
      "badge.name": "name match",
      "badge.prefix": "prefix match",
      "badge.cmd": "cmdline match",
      "badge.none": "unmatched",
      "row.cmdKeyword": "command-line keyword hit",
      "tbl.procs": "{n} processes",
      "tbl.empty": "No processes match the current filter.",
      "fc.items": "{n} items",
      "unresolved.count": "{n} items",
      "unresolved.more": "… {n} items in total",

      "toast.empty": "Paste a process list first, or try a built-in sample.",
      "toast.sampleWin": "Windows sample loaded — click Analyze.",
      "toast.sampleNix": "Linux sample loaded — click Analyze.",
      "toast.sampleNxc": "NetExec/CME prefixed sample loaded — click Analyze.",
      "toast.copied": "Report copied to clipboard",
      "toast.copyFail": "Copy failed, please select the text manually",
      "cmd.hit": "Command-line hit: ",
      "cmd.procSuffix": " (cmdline)",
      "err.parse": "Parse failed, please check the input format",

      "parse.nxc": "Stripped NetExec / CrackMapExec log prefixes ({n} lines) and parsed the underlying command output.",
      "err.noEntries": "No valid process entries found. Supported: tasklist (table/CSV/list), PowerShell Get-Process, ps aux, ps -ef, top, NetExec logs, plain name lists.",

      "vendor.cmd": "command-line keyword",
      "sep.list": ", ",
      "sep.reason": "; ",

      "pf.av": "🛡️ Endpoint protection: {list} — host is protected by AV/EDR",
      "pf.tool": "⚔️ Security testing tool traces: {list} — verify if this is not from your authorized engagement",
      "pf.remote": "🎛️ Remote control / session components: {list} — possible remote admin channel, mind the lateral movement surface",
      "pf.tunnel": "🚇 Tunnel / proxy: {list} — tunneling or forwarding tools present, could serve as an egress channel",
      "pf.vpn": "🔐 VPN / zero-trust clients: {list} — corporate remote access environment",
      "pf.cloud": "☁️ Cloud environment clues: {list} — likely a cloud instance",
      "pf.container": "📦 Container / orchestration: {list} — Docker/K8s environment",
      "pf.server": "🖥️ Likely server role: {svc}",
      "pf.svc.web": "Web ({list})",
      "pf.svc.db": "database ({list})",
      "pf.mail": "✉️ Mail services: {list}",
      "pf.file": "📁 File / sharing services: {list} — watch the sharing attack surface",
      "pf.workspace": "💼 Likely office / developer workstation: {parts}",
      "pf.ws.browser": "browser ({list})",
      "pf.ws.office": "office ({list})",
      "pf.ws.im": "IM ({list})",
      "pf.ws.dev": "dev ({list})",
      "pf.domain": "🏢 Enterprise management / domain clues: SCCM or domain-auth components present",
      "pf.rdp": "🖱️ RDP session/service components present — remote desktop entry (e.g. 3389) worth checking",
      "pf.winrm": "⌨️ WinRM remote management session components present",
      "pf.guest": "💠 System appears to run inside a VM / cloud instance",
      "pf.host": "💠 Host may be running virtual machines (hypervisor role)",
      "pf.none": "No notable software identified — minimal system or uncommon environment. Provide full command lines to improve detection.",
      "pf.more": "… ({n} total)",
      "pf.sus": "⚠️ Suspicious: {raw} — {reasons}",

      "sus.nonascii": "Process name contains non-ASCII characters (possible homoglyph masquerading)",
      "sus.doubleext": "Double file extension in process name (common masquerading trick)",
      "sus.typosquat": "Name closely resembles critical system process \"{name}\" — verify authenticity",
      "sus.tempdir": "Command line path is under {dir} — verify origin",
      "sus.unc": "Running from a UNC network path — verify origin",

      "p.userTemp": "user temp directory",
      "p.sysTemp": "system temp directory",
      "p.temp": "a temp directory",
      "p.tmp": "a temp directory",
      "p.downloads": "the downloads directory",
      "p.public": "a public directory",
      "p.tmpl": "/tmp",
      "p.devshm": "/dev/shm shared memory",
      "p.vartmp": "/var/tmp",
      "p.runshm": "/run/shm",

      "rep.title": "# Process Analysis Report",
      "rep.time": "- Generated at: {t}",
      "rep.platform": "- Target platform: {p} ({m})",
      "rep.counts": "- Process rows: {a} (unique {b}, identified {c})",
      "rep.tool": "- Tool: TaskList Inspector (tasklist.cxaqhq.cn)",
      "rep.profile": "## Host profile clues",
      "rep.cmd": "## Command-line keyword hits",
      "rep.sus": "## Suspicious indicators",
      "rep.results": "## Identification results",
      "rep.th": "| Process | Sample PIDs | Identification | Vendor | Match | Notes |",
      "rep.sep": "| --- | --- | --- | --- | --- | --- |",
      "rep.match.name": "name",
      "rep.match.prefix": "prefix",
      "rep.match.cmd": "cmdline",
      "rep.unresolved": "## Unrecognized processes ({n})",
      "rep.footer": "> Generated locally in the browser by TaskList Inspector — for authorized security testing, asset inventory and incident response only."
    }
  };

  var lang = "zh";

  /* ---------- 语言检测(仅浏览器环境; Node 等环境默认中文) ---------- */
  function detect() {
    if (!root.document) return "zh"; // 非浏览器环境(如 Node 自测)
    try {
      var q = root.location && root.location.search ? root.location.search.match(/[?&]lang=(zh|en)(?:&|$)/) : null;
      if (q && q[1]) return q[1];
    } catch (e) {}
    try {
      var ls = root.localStorage ? root.localStorage.getItem("tli-lang") : null;
      if (ls === "zh" || ls === "en") return ls;
    } catch (e) {}
    var nav = "";
    try {
      nav = ((root.navigator && (root.navigator.language || root.navigator.userLanguage)) || "").toLowerCase();
    } catch (e) {}
    if (nav.indexOf("zh") === 0) return "zh";
    return nav ? "en" : "zh";
  }

  /* ---------- 翻译 ---------- */
  function t(key, params) {
    var dict = STRINGS[lang] || STRINGS.zh;
    var s = dict[key];
    if (s == null) s = STRINGS.zh[key];
    if (s == null) s = key;
    if (params) {
      s = s.replace(/\{(\w+)\}/g, function (m, k) {
        return params[k] != null ? String(params[k]) : m;
      });
    }
    return s;
  }

  /* ---------- 应用静态文本(data-i18n 等) ---------- */
  function applyStatic() {
    var doc = root.document;
    if (!doc) return;
    var html = doc.documentElement;
    html.className = "lang-" + lang;
    html.setAttribute("lang", lang === "zh" ? "zh-CN" : "en");
    doc.title = t("meta.title");

    var i, nodes;
    nodes = doc.querySelectorAll("[data-i18n]");
    for (i = 0; i < nodes.length; i++) nodes[i].textContent = t(nodes[i].getAttribute("data-i18n"));
    nodes = doc.querySelectorAll("[data-i18n-html]");
    for (i = 0; i < nodes.length; i++) nodes[i].innerHTML = t(nodes[i].getAttribute("data-i18n-html"));
    nodes = doc.querySelectorAll("[data-i18n-ph]");
    for (i = 0; i < nodes.length; i++) nodes[i].setAttribute("placeholder", t(nodes[i].getAttribute("data-i18n-ph")));
    nodes = doc.querySelectorAll("[data-i18n-title]");
    for (i = 0; i < nodes.length; i++) nodes[i].setAttribute("title", t(nodes[i].getAttribute("data-i18n-title")));
  }

  /* ---------- 切换语言 ---------- */
  function setLang(next, opts) {
    if (next !== "zh" && next !== "en") next = "zh";
    var changed = next !== lang;
    lang = next;
    try { if (root.document && root.localStorage) root.localStorage.setItem("tli-lang", lang); } catch (e) {}
    applyStatic();
    if (changed && !(opts && opts.silent)) {
      try {
        root.document.dispatchEvent(new CustomEvent("tli:lang", { detail: { lang: lang } }));
      } catch (e) {}
    }
  }

  function getLang() { return lang; }
  function isEn() { return lang === "en"; }

  lang = detect();
  applyStatic();

  root.I18N = { t: t, setLang: setLang, getLang: getLang, isEn: isEn, applyStatic: applyStatic, STRINGS: STRINGS };
  if (typeof module !== "undefined" && module.exports) module.exports = root.I18N;
})(typeof window !== "undefined" ? window : globalThis);
