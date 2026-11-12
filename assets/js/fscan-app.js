/*!
 * Fscan Report Inspector - 页面交互与渲染
 * ---------------------------------------------------------------
 * 四个视图: 按操作系统 / 按 IP / 按弱点 / 端口矩阵
 * 复用 assets/js/i18n.js 的语言状态(tli-lang), 但文案表自带一份,
 * 以免把终端进程分析用的长文案混进 i18n.js。
 */
(function () {
  "use strict";

  var FS = window.FscanParser;
  var $ = function (sel) { return document.querySelector(sel); };

  /* ============ 文案 ============ */
  var STR = {
    zh: {
      "meta.title": "Fscan Report Inspector · fscan 结果解析 · 按系统/端口/弱点分组",
      "brand.sub": "fscan 结果解析",
      "nav.back": "进程分析",
      "lang.btn": "EN",
      "lang.title": "切换到 English",

      "hero.h1": "fscan 结果解析 · 一眼看清系统、端口与弱点",
      "hero.lead": "粘贴 fscan 的扫描结果，自动归一化成三张表：按操作系统分组（谁还是 Windows 2008 / 7 / 2003）、按 IP 汇总（开了哪些端口、跑的什么服务）、按弱点排序（弱口令、未授权、高危端口、组件过旧）——先打谁一目了然。",
      "pill.1": "按 <b>操作系统</b> 分组",
      "pill.2": "按 <b>IP</b> 汇总端口服务",
      "pill.3": "按 <b>弱点</b> 排序（含 EOL 系统）",
      "pill.4": "纯浏览器本地 · <b>数据不上传</b>",

      "sec.input": "① 粘贴 fscan 结果",
      "ph.input": "粘贴 fscan 的输出（含 [+] 结果行、ip:port open 行、弱口令、未授权、POC 命中），也可以混入 nmap 结果...\n\n提示：fscan -o result.txt 后把文件内容整体粘进来即可；banner、进度条、[*] 状态行会自动忽略。",
      "btn.parse": "开始解析 (Ctrl/⌘ + Enter)",
      "btn.sample": "fscan 示例",
      "btn.sampleV2": "fscan v2 示例",
      "btn.sampleMixed": "nmap 混排示例",
      "btn.clear": "清空",
      "privacy": "🔒 解析全部在浏览器本地完成，输入内容不会上传；页面无第三方依赖，可下载后离线使用。",
      "meta.input": "输入: {lines} 行 · {kb} KB",

      "sec.priority": "⚡ 优先关注（按风险排序）",
      "hint.priority": "先打这里：EOL 系统 / 弱口令 / 未授权 / 已知漏洞",
      "sec.unknown": "❓ 未识别的原始行",
      "hint.unknown": "这些行没被解析（可复制反馈补规则），不影响其它结果",
      "sec.guide": "📖 支持的结果格式与解读口径",

      "tab.os": "🖥️ 按操作系统",
      "tab.ip": "🌐 按 IP",
      "tab.risk": "⚠️ 按弱点",
      "tab.svc": "🧩 按服务",
      "tab.ports": "🔌 端口矩阵",
      "ph.filter": "筛选 IP / 端口 / 服务 / 标题...",
      "btn.copyAll": "📋 复制全部",
      "btn.copy": "📋 机器",
      "btn.copySvc": "🧩 服务",
      "btn.copyIp": "🔌 IP",
      "btn.copyMd": "⬇ Markdown",
      "tt.copyAll": "机器清单 + 服务清单 + IP 清单(与 TXT 下载完全一致)",
      "tt.copy": "按系统分组, 一行一台: IP 主机名 系统",
      "tt.copySvc": "按服务分类: Web / SSH / 数据库 / 远程管理 / 文件共享 / 其它",
      "tt.copyIp": "一行一台并带端口/服务",
      "btn.md": "⬇ Markdown",
      "btn.json": "⬇ JSON",
      "btn.txt": "⬇ TXT",

      "st.hosts": "主机",
      "st.ports": "开放端口",
      "st.creds": "弱口令",
      "st.vulns": "未授权 / 漏洞",
      "st.eol": "系统已 EOL",
      "st.risk": "高危主机",
      "st.web": "Web 服务",
      "st.smb": "SMBv1 主机",
      "st.unit": "台",
      "st.item": "项",

      "th.ip": "IP",
      "th.host": "主机名",
      "th.os": "操作系统",
      "th.ports": "开放端口 / 服务",
      "th.score": "风险",
      "th.brief": "弱点摘要",
      "th.port": "端口",
      "th.service": "服务",
      "th.title": "标题 / 横幅",
      "th.level": "风险",
      "th.hosts": "主机数",
      "th.note": "说明",
      "th.detail": "详情",
      "th.product": "产品 / 版本",

      "kind.os-eol": "系统已停止支持",
      "kind.os-old": "系统版本偏旧",
      "kind.weak-pass": "弱口令",
      "kind.unauth": "未授权访问",
      "kind.vuln": "已知漏洞",
      "kind.danger-port": "高危端口",
      "kind.old-comp": "组件版本过旧",
      "kind.web-admin": "后台/敏感页面",
      "kind.smb-v1": "SMBv1 已启用",
      "kind.snmp-public": "SNMP 默认团体字",

      "lv.critical": "严重",
      "lv.high": "高",
      "lv.medium": "中",
      "lv.low": "低",
      "lv.info": "信息",

      "os.eol": "已 EOL {d}",
      "os.group": "{n} 台",
      "os.max": "最高风险 {s}",
      "os.none": "识别不出具体版本（fscan 未取到系统 banner）——可用 nxc smb / smbclient 补版本",

      "ip.creds": "弱口令",
      "ip.vulns": "漏洞 / 未授权",
      "ip.web": "Web 资产",
      "ip.peers": "邻接 / 内网线索 IP",
      "ip.meta": "主机线索",
      "ip.findings": "弱点清单",
      "ip.empty": "没有匹配的 IP。",
      "ip.expand": "展开",

      "risk.empty": "没有匹配的弱点。",
      "risk.evidence": "证据",

      "ports.empty": "没有匹配的端口。",
      "svc.empty": "没有匹配的服务。",
      "ports.top": "共 {n} 个不同端口",

      "note.parsed": "fscan {v} · 解析出 {e} 条结果 · 忽略 {i} 行噪声 / {b} 行空行 · {u} 行未识别",
      "note.noversion": "未识别 fscan 版本",
      "meta.count": "{hosts} 台主机 · {ports} 个端口记录",

      "toast.empty": "请先粘贴 fscan 结果",
      "toast.sample": "已填入示例结果",
      "toast.copied": "已复制: 按系统分组的机器清单",
      "toast.copiedIp": "已复制: 每台机器的端口清单",
      "toast.copiedSvc": "已复制: 按服务分类的清单",
      "toast.copiedAll": "已复制: 机器 + 服务 + IP 三份清单(与 TXT 一致)",
      "toast.copyFail": "复制失败，请手动选择文本",
      "toast.fail": "解析失败，请检查输入内容",

      "footer.warn": "⚠️ 本工具仅供授权的安全测试、资产盘点与应急响应使用。",
      "footer.local": "纯静态页面：无后端、无跟踪、无第三方依赖，数据全部在浏览器本地处理。"
    },
    en: {
      "meta.title": "Fscan Report Inspector · group fscan results by OS, IP and weakness",
      "brand.sub": "fscan parser",
      "nav.back": "Process analyzer",
      "lang.btn": "中文",
      "lang.title": "Switch to 中文",

      "hero.h1": "fscan results · system, ports and weaknesses at a glance",
      "hero.lead": "Paste fscan output and get three normalised views: grouped by operating system (who is still on Windows 2008 / 7 / 2003), grouped by IP (which ports are open, what is running), and ranked by weakness (weak credentials, unauthenticated access, risky ports, outdated components) — strike order becomes obvious.",
      "pill.1": "Group by <b>operating system</b>",
      "pill.2": "Per-IP <b>ports &amp; services</b>",
      "pill.3": "Ranked by <b>weakness</b> (incl. EOL)",
      "pill.4": "Runs locally · <b>no upload</b>",

      "sec.input": "① Paste fscan results",
      "ph.input": "Paste fscan output ([+] result lines, ip:port open lines, weak credentials, unauth, POC hits). nmap output can be mixed in...\n\nTip: run fscan -o result.txt and paste the whole file — banners, progress bars and [*] status lines are ignored.",
      "btn.parse": "Parse (Ctrl/⌘ + Enter)",
      "btn.sample": "fscan sample",
      "btn.sampleV2": "fscan v2 sample",
      "btn.sampleMixed": "nmap mixed sample",
      "btn.clear": "Clear",
      "privacy": "🔒 Everything is parsed in your browser; nothing is uploaded. No third-party dependencies, works offline.",
      "meta.input": "Input: {lines} lines · {kb} KB",

      "sec.priority": "⚡ Priority targets (ranked by risk)",
      "hint.priority": "Strike here first: EOL systems / weak creds / unauth / known vulns",
      "sec.unknown": "❓ Unparsed lines",
      "hint.unknown": "These lines were not parsed (feedback welcome) and do not affect other results",
      "sec.guide": "📖 Supported formats and scoring",

      "tab.os": "🖥️ By OS",
      "tab.ip": "🌐 By IP",
      "tab.risk": "⚠️ By weakness",
      "tab.svc": "🧩 By service",
      "tab.ports": "🔌 Port matrix",
      "ph.filter": "Filter IP / port / service / title...",
      "btn.copyAll": "📋 Copy all",
      "btn.copy": "📋 Hosts",
      "btn.copySvc": "🧩 Services",
      "btn.copyIp": "🔌 IPs",
      "btn.copyMd": "⬇ Markdown",
      "tt.copyAll": "Host list + service list + IP list (identical to the TXT download)",
      "tt.copy": "Grouped by OS, one host per line: IP hostname OS",
      "tt.copySvc": "Grouped by service: web / SSH / database / remote admin / file sharing / other",
      "tt.copyIp": "One host per line with ports/services",
      "btn.md": "⬇ Markdown",
      "btn.json": "⬇ JSON",
      "btn.txt": "⬇ TXT",

      "st.hosts": "Hosts",
      "st.ports": "Open ports",
      "st.creds": "Weak creds",
      "st.vulns": "Unauth / vulns",
      "st.eol": "EOL systems",
      "st.risk": "High-risk hosts",
      "st.web": "Web services",
      "st.smb": "SMBv1 hosts",
      "st.unit": "",
      "st.item": "",

      "th.ip": "IP",
      "th.host": "Hostname",
      "th.os": "Operating system",
      "th.ports": "Open ports / services",
      "th.score": "Risk",
      "th.brief": "Findings",
      "th.port": "Port",
      "th.service": "Service",
      "th.title": "Title / banner",
      "th.level": "Risk",
      "th.hosts": "Hosts",
      "th.note": "Note",
      "th.detail": "Detail",
      "th.product": "Product / version",

      "kind.os-eol": "Out-of-support OS",
      "kind.os-old": "Old OS version",
      "kind.weak-pass": "Weak credentials",
      "kind.unauth": "Unauthenticated access",
      "kind.vuln": "Known vulnerability",
      "kind.danger-port": "High-risk port",
      "kind.old-comp": "Outdated component",
      "kind.web-admin": "Admin/sensitive page",
      "kind.smb-v1": "SMBv1 enabled",
      "kind.snmp-public": "SNMP default community",

      "lv.critical": "critical",
      "lv.high": "high",
      "lv.medium": "medium",
      "lv.low": "low",
      "lv.info": "info",

      "os.eol": "EOL {d}",
      "os.group": "{n} hosts",
      "os.max": "max risk {s}",
      "os.none": "Version unknown (fscan did not capture an OS banner) — collect it with nxc smb / smbclient",

      "ip.creds": "Weak credentials",
      "ip.vulns": "Vulns / unauth",
      "ip.web": "Web assets",
      "ip.peers": "Adjacent / internal IPs",
      "ip.meta": "Host clues",
      "ip.findings": "Findings",
      "ip.empty": "No matching hosts.",
      "ip.expand": "expand",

      "risk.empty": "No matching findings.",
      "risk.evidence": "Evidence",

      "ports.empty": "No matching ports.",
      "svc.empty": "No matching services.",
      "ports.top": "{n} distinct ports",

      "note.parsed": "fscan {v} · {e} results parsed · {i} noise lines / {b} blank lines ignored · {u} unparsed",
      "note.noversion": "fscan version not detected",
      "meta.count": "{hosts} hosts · {ports} port records",

      "toast.empty": "Paste fscan results first",
      "toast.sample": "Sample loaded",
      "toast.copied": "Copied: hosts grouped by OS",
      "toast.copiedIp": "Copied: per-host port list",
      "toast.copiedSvc": "Copied: hosts grouped by service",
      "toast.copiedAll": "Copied: hosts + services + IPs (same as the TXT download)",
      "toast.copyFail": "Copy failed, please select the text manually",
      "toast.fail": "Parse failed — check the input",

      "footer.warn": "⚠️ For authorized security testing, asset inventory and incident response only.",
      "footer.local": "Pure static page: no backend, no tracking, no third-party dependencies. All data stays in your browser."
    }
  };

  function lang() { return (window.I18N && window.I18N.getLang()) || "zh"; }
  function isEn() { return lang() === "en"; }
  function T(k, p) {
    var d = STR[lang()] || STR.zh;
    var s = d[k];
    if (s == null) s = STR.zh[k];
    if (s == null) s = k;
    if (p) {
      s = s.replace(/\{(\w+)\}/g, function (m, key) { return p[key] != null ? String(p[key]) : m; });
    }
    return s;
  }

  /* ============ DOM ============ */
  var els = {
    input: $("#fsInput"),
    btnParse: $("#fsBtnParse"),
    btnSample: $("#fsBtnSample"),
    btnSampleV2: $("#fsBtnSampleV2"),
    btnSampleMixed: $("#fsBtnSampleMixed"),
    btnClear: $("#fsBtnClear"),
    langBtn: $("#langBtn"),
    meta: $("#fsMeta"),
    results: $("#fsResults"),
    note: $("#fsNote"),
    stats: $("#fsStats"),
    priorityCard: $("#fsPriorityCard"),
    priority: $("#fsPriority"),
    tabs: $("#fsTabs"),
    filter: $("#fsFilter"),
    panelOs: $("#panelOs"),
    panelIp: $("#panelIp"),
    panelRisk: $("#panelRisk"),
    panelSvc: $("#panelSvc"),
    panelPorts: $("#panelPorts"),
    count: $("#fsCount"),
    unknownCard: $("#fsUnknownCard"),
    unknown: $("#fsUnknown"),
    copyAll: $("#fsCopyAll"),
    copy: $("#fsCopy"),
    copyIp: $("#fsCopyIp"),
    copySvc: $("#fsCopySvc"),
    md: $("#fsMd"),
    json: $("#fsJson"),
    txt: $("#fsTxt"),
    toast: $("#toast")
  };

  var state = { model: null, tab: "os", filter: "" };
  var EXPAND_ALL = /[?&]expand=1/.test(typeof location !== "undefined" ? location.search : "");

  /** ?expand=1: 展开所有折叠块(打印/截图/汇报用) */
  function expandAll(root) {
    if (!EXPAND_ALL || !root) return;
    var ds = root.querySelectorAll("details");
    for (var i = 0; i < ds.length; i++) ds[i].open = true;
  }

  /* ============ 工具 ============ */
  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (m) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[m];
    });
  }
  function lvName(lv) { return T("lv." + (lv || "info")); }
  function lvBadge(lv) {
    return '<span class="fs-lv lv-' + esc(lv || "info") + '">' + esc(lvName(lv)) + "</span>";
  }
  function kindName(k) { return T("kind." + k); }
  // 系统家族用文字标签而不是 emoji: 任何字体环境下都能看清
  function famBadge(fam) {
    var map = { windows: "WIN", linux: "LNX", unix: "UNIX", vmware: "ESXi", network: "NET", unknown: "?" };
    var f = map[fam] ? fam : "unknown";
    return '<span class="fs-fam fam-' + esc(f) + '">' + esc(map[fam] || "?") + "</span>";
  }
  function osLabel(os) { return os ? (isEn() ? os.nameEn : os.name) : "—"; }
  function fTitle(f) { return isEn() ? (f.titleEn || f.title) : f.title; }
  function fDetail(f) { return isEn() ? (f.detailEn || f.detail) : f.detail; }

  var toastTimer = null;
  function toast(msg, isErr) {
    els.toast.textContent = msg;
    els.toast.className = "show" + (isErr ? " err" : "");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { els.toast.className = ""; }, 2600);
  }

  /* ============ 静态文案 ============ */
  function applyStatic() {
    document.documentElement.className = "lang-" + lang();
    document.documentElement.lang = isEn() ? "en" : "zh-CN";
    document.title = T("meta.title");

    var nodes = document.querySelectorAll("[data-fs]");
    for (var i = 0; i < nodes.length; i++) nodes[i].textContent = T(nodes[i].getAttribute("data-fs"));
    nodes = document.querySelectorAll("[data-fs-html]");
    for (i = 0; i < nodes.length; i++) nodes[i].innerHTML = T(nodes[i].getAttribute("data-fs-html"));
    nodes = document.querySelectorAll("[data-fs-ph]");
    for (i = 0; i < nodes.length; i++) nodes[i].setAttribute("placeholder", T(nodes[i].getAttribute("data-fs-ph")));
    nodes = document.querySelectorAll("[data-fs-title]");
    for (i = 0; i < nodes.length; i++) nodes[i].setAttribute("title", T(nodes[i].getAttribute("data-fs-title")));
  }

  /* ============ 解析 ============ */
  function updateMeta() {
    var v = els.input.value;
    var lines = v ? v.split(/\r\n|\r|\n/).length : 0;
    els.meta.textContent = v ? T("meta.input", { lines: lines, kb: (v.length / 1024).toFixed(1) }) : "";
  }

  function parseNow(noScroll) {
    var text = els.input.value;
    if (!text.trim()) { toast(T("toast.empty"), true); return; }
    try {
      var parsed = FS.parse(text);
      var model = FS.analyze(parsed);
      model.parsedNote = { ignored: parsed.ignored, blank: parsed.blank, total: parsed.total };
      state.model = model;
      state.filter = "";
      els.filter.value = "";
      renderAll();
      els.results.classList.remove("hidden");
      if (!noScroll) els.results.scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (e) {
      if (window.console) console.error(e);
      toast(T("toast.fail"), true);
    }
  }

  /* ============ 渲染 ============ */
  function renderAll() {
    renderNote();
    renderStats();
    renderPriority();
    renderPanels();
    renderUnknown();
    els.count.textContent = T("meta.count", { hosts: state.model.stats.hosts, ports: state.model.stats.ports });
  }

  function renderNote() {
    var m = state.model;
    var n = m.parsedNote || {};
    var ver = m.version ? "fscan " + m.version : T("note.noversion");
    var html = '<div>🧾 ' + esc(T("note.parsed", {
      v: m.version || "?",
      e: m.entries,
      i: n.ignored || 0,
      b: n.blank || 0,
      u: m.unknown.length
    })) + "</div>";
    if (!m.version) html = '<div>ℹ️ ' + esc(ver) + "</div>" + html;
    els.note.innerHTML = html;
    els.note.classList.remove("hidden");
  }

  function renderStats() {
    var s = state.model.stats;
    var highHosts = state.model.hosts.filter(function (h) { return h.level === "critical" || h.level === "high"; }).length;
    var cells = [
      ["st.hosts", s.hosts, "v-cyan", ""],
      ["st.ports", s.ports, "", ""],
      ["st.creds", s.creds, s.creds ? "v-red" : "", ""],
      ["st.vulns", s.vulns, s.vulns ? "v-red" : "", ""],
      ["st.eol", s.eolHosts, s.eolHosts ? "v-yellow" : "", ""],
      ["st.risk", highHosts, highHosts ? "v-red" : "", ""],
      ["st.web", s.web, "", ""],
      ["st.smb", s.smbV1, s.smbV1 ? "v-red" : "", ""]
    ];
    var html = "";
    for (var i = 0; i < cells.length; i++) {
      html += '<div class="stat ' + cells[i][2] + '"><div class="k">' + esc(T(cells[i][0])) +
        '</div><div class="v">' + cells[i][1] + "</div></div>";
    }
    els.stats.innerHTML = html;
  }

  /* ---- 优先关注 ---- */
  function renderPriority() {
    var list = state.model.findings.filter(function (f) {
      return f.level === "critical" || f.level === "high";
    }).slice(0, 10);
    if (!list.length) { els.priorityCard.classList.add("hidden"); return; }
    var html = "";
    for (var i = 0; i < list.length; i++) {
      var f = list[i];
      html += '<div class="fs-pri lv-' + esc(f.level) + '">';
      html += lvBadge(f.level);
      html += '<code class="fs-pri-ip">' + esc(f.ip) + (f.port ? ":" + f.port : "") + "</code>";
      html += '<span class="fs-pri-kind">' + esc(kindName(f.kind)) + "</span>";
      html += '<span class="fs-pri-title">' + esc(fTitle(f)) + "</span>";
      html += '<span class="fs-pri-detail">' + esc(fDetail(f)) + "</span>";
      html += "</div>";
    }
    els.priority.innerHTML = html;
    els.priorityCard.classList.remove("hidden");
  }

  function renderPanels() {
    if (state.tab === "os") renderOs();
    else if (state.tab === "ip") renderIp();
    else if (state.tab === "risk") renderRisk();
    else if (state.tab === "svc") renderSvc();
    else renderPorts();
    els.panelOs.classList.toggle("hidden", state.tab !== "os");
    els.panelIp.classList.toggle("hidden", state.tab !== "ip");
    els.panelRisk.classList.toggle("hidden", state.tab !== "risk");
    els.panelSvc.classList.toggle("hidden", state.tab !== "svc");
    els.panelPorts.classList.toggle("hidden", state.tab !== "ports");
  }

  function hostHay(h) {
    var parts = [h.ip, h.hostname, h.os ? h.os.name : "", h.os ? h.os.nameEn : ""];
    for (var i = 0; i < h.ports.length; i++) {
      parts.push(h.ports[i].port, h.ports[i].service, h.ports[i].label, h.ports[i].title, h.ports[i].msgs.join(" "));
    }
    for (i = 0; i < h.web.length; i++) parts.push(h.web[i].url, h.web[i].title);
    return parts.join(" ").toLowerCase();
  }

  function filteredHosts() {
    var f = state.filter;
    if (!f) return state.model.hosts;
    return state.model.hosts.filter(function (h) { return hostHay(h).indexOf(f) !== -1; });
  }

  function portsLine(h, limit) {
    var n = limit || 14;
    var html = "";
    for (var i = 0; i < h.ports.length && i < n; i++) {
      var p = h.ports[i];
      html += '<span class="fs-port lv-' + esc(p.level) + '" title="' + esc((p.title || p.msgs[0] || p.label) || "") + '">' +
        p.port + '<i>' + esc(p.service || "?") + "</i></span>";
    }
    if (h.ports.length > n) html += '<span class="fs-port more">+' + (h.ports.length - n) + "</span>";
    return html || '<span class="fs-dim">—</span>';
  }

  function briefOf(h, n) {
    var list = h.findings.slice(0, n || 3).map(function (f) {
      return '<span class="fs-brief lv-' + esc(f.level) + '">' + esc(fTitle(f)) + "</span>";
    });
    return list.join("") || '<span class="fs-dim">—</span>';
  }

  /* ---- 视图 1: 按操作系统 ---- */
  function renderOs() {
    var groups = state.model.osGroups;
    var hosts = filteredHosts();
    var allow = {};
    for (var i = 0; i < hosts.length; i++) allow[hosts[i].ip] = 1;

    var html = "";
    for (i = 0; i < groups.length; i++) {
      var g = groups[i];
      var list = g.hosts.filter(function (h) { return allow[h.ip]; });
      if (!list.length) continue;
      var open = g.eol || i === 0 ? " open" : "";
      html += '<details class="cat-section"' + open + ">";
      html += "<summary>" + famBadge(g.family) + " " + esc(isEn() ? g.nameEn : g.name);
      if (g.eol) html += ' <span class="fs-eol">' + esc(T("os.eol", { d: g.eolDate })) + "</span>";
      html += '<span class="cat-count">' + esc(T("os.group", { n: list.length })) +
        " · " + esc(T("os.max", { s: g.maxScore })) + "</span>";
      html += "</summary>";
      html += '<div class="table-wrap"><table class="proc-table">';
      html += "<thead><tr><th>" + T("th.ip") + "</th><th>" + T("th.host") + "</th><th>" + T("th.ports") +
        "</th><th>" + T("th.score") + "</th><th>" + T("th.brief") + "</th></tr></thead><tbody>";
      for (var j = 0; j < list.length; j++) {
        var h = list[j];
        html += "<tr>";
        html += '<td class="c-proc"><code>' + esc(h.ip) + "</code></td>";
        html += '<td class="c-pid">' + esc(h.hostname || "—") + "</td>";
        html += '<td class="fs-ports">' + portsLine(h) + "</td>";
        html += '<td><span class="fs-score lv-' + esc(h.level) + '">' + h.score + "</span></td>";
        html += '<td class="c-desc">' + briefOf(h) + "</td>";
        html += "</tr>";
      }
      html += "</tbody></table></div></details>";
    }
    if (!html) {
      html = '<p class="fs-dim">' + esc(T("ip.empty")) + "</p>";
    } else {
      var unk = state.model.stats.unknownOs;
      if (unk) html += '<p class="fs-tip">💡 ' + esc(T("os.none")) + "</p>";
    }
    els.panelOs.innerHTML = html;
    expandAll(panelOs);
  }

  /* ---- 视图 2: 按 IP ---- */
  function renderIp() {
    var hosts = filteredHosts();
    if (!hosts.length) { els.panelIp.innerHTML = '<p class="fs-dim">' + esc(T("ip.empty")) + "</p>"; return; }
    var html = "";
    for (var i = 0; i < hosts.length; i++) {
      var h = hosts[i];

      /* 摘要行 */
      html += '<details class="cat-section host-card">';
      html += '<summary><code class="fs-ip">' + esc(h.ip) + "</code>";
      if (h.hostname) html += '<span class="fs-hostname">' + esc(h.hostname) + "</span>";
      html += '<span class="fs-os">' + famBadge(h.os ? h.os.family : "unknown") + " " + esc(osLabel(h.os)) + "</span>";
      html += '<span class="fs-ports fs-ports-inline">' + portsLine(h, 10) + "</span>";
      html += '<span class="fs-score lv-' + esc(h.level) + '">' + h.score + "</span>";
      html += "</summary>";

      /* 主机线索 */
      var meta = [];
      if (h.domain) meta.push("域 " + h.domain);
      if (h.fqdn && h.fqdn !== h.hostname) meta.push(h.fqdn);
      if (h.smb) meta.push("SMB " + h.smb);
      if (h.os && h.os.eol) meta.push("EOL " + h.os.eolDate);
      if (meta.length) html += '<div class="fs-host-meta">' + esc(meta.join(" · ")) + "</div>";

      /* 邻接 / 内网 IP 线索 */
      if (h.peers.length) {
        html += '<div class="fs-block"><div class="fs-block-h">🕸️ ' + esc(T("ip.peers")) + "</div><div class=\"fs-chips\">";
        for (var q = 0; q < h.peers.length; q++) {
          var peer = h.peers[q];
          var cross = String(peer).split(".").slice(0, 3).join(".") !== String(h.ip).split(".").slice(0, 3).join(".");
          html += '<code class="fs-ip-chip' + (cross ? " cross" : "") + '">' + esc(peer) + (cross ? " ↗" : "") + "</code>";
        }
        html += "</div></div>";
      }

      /* 端口表 */
      if (h.ports.length) {
        html += '<div class="table-wrap"><table class="proc-table">';
        html += "<thead><tr><th>" + T("th.port") + "</th><th>" + T("th.service") + "</th><th>" +
          T("th.product") + "</th><th>" + T("th.title") + "</th><th>" + T("th.level") + "</th></tr></thead><tbody>";
        for (var j = 0; j < h.ports.length; j++) {
          var p = h.ports[j];
          var prod = [p.product, p.version].filter(Boolean).join(" ");
          var extra = p.title || p.banner || p.msgs.slice(0, 2).join(" · ");
          html += "<tr>";
          html += '<td class="c-proc"><code>' + p.port + "/" + esc(p.proto || "tcp") + "</code></td>";
          html += '<td class="c-id"><b>' + esc(p.service || "?") + '</b><div class="vendor">' + esc(p.label || "") + "</div></td>";
          html += '<td class="c-desc">' + (prod ? esc(prod) : '<span class="fs-dim">—</span>') + "</td>";
          html += '<td class="c-desc">' + (p.url
            ? '<a href="' + esc(p.url) + '" target="_blank" rel="noopener noreferrer">' + esc(extra || p.url) + "</a>"
            : esc(extra || "—")) + "</td>";
          html += "<td>" + lvBadge(p.level) + "</td>";
          html += "</tr>";
        }
        html += "</tbody></table></div>";
      }

      /* Web 资产 */
      if (h.web.length) {
        html += '<div class="fs-block"><div class="fs-block-h">🌐 ' + esc(T("ip.web")) + "</div>";
        for (j = 0; j < h.web.length; j++) {
          var w = h.web[j];
          html += '<div class="fs-web">';
          if (w.code) html += '<span class="fs-http lv-' + (w.code >= 500 ? "high" : w.code >= 400 ? "medium" : "low") + '">' + w.code + "</span>";
          html += '<a href="' + esc(w.url) + '" target="_blank" rel="noopener noreferrer">' + esc(w.url) + "</a>";
          html += '<span class="fs-web-title">' + esc(w.title || "—") + "</span>";
          if (w.server) html += '<span class="fs-dim">' + esc(w.server) + "</span>";
          if (w.tags && w.tags.length) {
            html += '<span class="fs-tags">';
            for (var tj = 0; tj < w.tags.length; tj++) html += '<i>' + esc(w.tags[tj]) + "</i>";
            html += "</span>";
          }
          html += "</div>";
        }
        html += "</div>";
      }

      /* 弱口令 */
      if (h.creds.length) {
        html += '<div class="fs-block"><div class="fs-block-h">🔑 ' + esc(T("ip.creds")) + "</div>";
        for (j = 0; j < h.creds.length; j++) {
          var c = h.creds[j];
          html += '<div class="fs-cred"><code>' + esc(c.user) + ":" + esc(c.pass) + "</code>" +
            '<span class="fs-dim">' + c.port + "/" + esc(c.service || PORT_SVC(c.port)) + "</span></div>";
        }
        html += "</div>";
      }

      /* 漏洞 / 未授权 */
      if (h.vulns.length) {
        html += '<div class="fs-block"><div class="fs-block-h">💥 ' + esc(T("ip.vulns")) + "</div>";
        for (j = 0; j < h.vulns.length; j++) {
          var v = h.vulns[j];
          html += '<div class="fs-vuln">' + lvBadge(v.level) + "<code>" + esc(v.name) + "</code>" +
            '<span class="fs-dim">' + (v.port || "") + " " + esc(v.msg || "") + "</span></div>";
        }
        html += "</div>";
      }

      /* 弱点清单 */
      if (h.findings.length) {
        html += '<div class="fs-block"><div class="fs-block-h">⚠️ ' + esc(T("ip.findings")) + "</div>";
        for (j = 0; j < h.findings.length; j++) {
          var f = h.findings[j];
          html += '<div class="fs-finding">' + lvBadge(f.level) +
            '<span class="fs-f-kind">' + esc(kindName(f.kind)) + "</span>" +
            '<span class="fs-f-title">' + esc(fTitle(f)) + "</span>" +
            '<span class="fs-f-detail">' + esc(fDetail(f)) + "</span></div>";
        }
        html += "</div>";
      }

      html += "</details>";
    }
    els.panelIp.innerHTML = html;
    expandAll(panelIp);
  }

  function PORT_SVC(port) {
    var m = FS.PORT_MAP[port];
    return m ? m.s : "?";
  }

  /* ---- 视图 3: 按弱点 ---- */
  var KIND_ORDER = ["os-eol", "weak-pass", "unauth", "vuln", "smb-v1", "snmp-public", "danger-port", "old-comp", "web-admin", "os-old"];

  function renderRisk() {
    var f = state.filter;
    var list = state.model.findings.filter(function (x) {
      if (!f) return true;
      return (x.ip + " " + (x.port || "") + " " + fTitle(x) + " " + fDetail(x) + " " + x.kind).toLowerCase().indexOf(f) !== -1;
    });
    if (!list.length) { els.panelRisk.innerHTML = '<p class="fs-dim">' + esc(T("risk.empty")) + "</p>"; return; }

    var byKind = {};
    for (var i = 0; i < list.length; i++) {
      var k = list[i].kind;
      if (!byKind[k]) byKind[k] = [];
      byKind[k].push(list[i]);
    }
    var kinds = Object.keys(byKind);
    kinds.sort(function (a, b) {
      var ia = KIND_ORDER.indexOf(a), ib = KIND_ORDER.indexOf(b);
      if (ia === -1) ia = 99;
      if (ib === -1) ib = 99;
      return ia - ib || byKind[b].length - byKind[a].length;
    });

    var html = "";
    for (i = 0; i < kinds.length; i++) {
      var kk = kinds[i];
      var arr = byKind[kk];
      var worst = arr.reduce(function (m, x) {
        return FS.LEVEL_RANK[x.level] > FS.LEVEL_RANK[m] ? x.level : m;
      }, "info");
      html += '<details class="cat-section fs-risk-group" open>';
      html += "<summary>" + lvBadge(worst) + " " + esc(kindName(kk)) +
        '<span class="cat-count">' + arr.length + " " + esc(T("st.item")) + "</span></summary>";
      html += '<div class="fs-risk-list">';
      var cap = 400;
      for (var j = 0; j < arr.length && j < cap; j++) {
        var x = arr[j];
        html += '<div class="fs-risk-item lv-' + esc(x.level) + '">';
        html += lvBadge(x.level);
        html += '<code class="fs-risk-ip">' + esc(x.ip) + (x.port ? ":" + x.port : "") + "</code>";
        html += '<div class="fs-risk-body"><div class="fs-risk-title">' + esc(fTitle(x)) + "</div>";
        html += '<div class="fs-risk-detail">' + esc(fDetail(x)) + "</div>";
        if (x.evidence) html += '<div class="fs-risk-ev">' + esc(T("risk.evidence")) + ": <code>" + esc(String(x.evidence).slice(0, 200)) + "</code></div>";
        html += "</div></div>";
      }
      if (arr.length > cap) {
        html += '<div class="fs-risk-more">… 还有 ' + (arr.length - cap) + ' 项，用上面的筛选框缩小范围</div>';
      }
      html += "</div></details>";
    }
    els.panelRisk.innerHTML = html;
  }

  /* ---- 视图 4: 按服务 ---- */
  function renderSvc() {
    var groups = FS.serviceGroups(state.model);
    var f = state.filter;
    if (f) {
      groups = groups.map(function (g) {
        var items = g.items.filter(function (it) {
          var hay = (it.host.ip + " " + (it.host.hostname || "") + " " + it.host.os.name + " " +
            it.ports.map(function (p) { return p.port + "/" + p.service; }).join(" ") + " " + g.label).toLowerCase();
          return hay.indexOf(f) !== -1;
        });
        return items.length ? { key: g.key, label: g.label, labelEn: g.labelEn, items: items } : null;
      }).filter(Boolean);
    }
    if (!groups.length) { els.panelSvc.innerHTML = '<p class="fs-dim">' + esc(T("svc.empty")) + "</p>"; return; }

    var html = "";
    for (var g = 0; g < groups.length; g++) {
      var gr = groups[g];
      html += '<details class="cat-section" open>';
      html += "<summary><span class='fs-svc-tag svc-" + esc(gr.key) + "'>" + esc(isEn() ? gr.labelEn : gr.label) + "</span>" +
        '<span class="cat-count">' + gr.items.length + " " + esc(T("st.unit")) + "</span></summary>";
      html += '<div class="table-wrap"><table class="proc-table">';
      html += "<thead><tr><th>" + T("th.ip") + "</th><th>" + T("th.host") + "</th><th>" + T("th.os") +
        "</th><th>" + T("th.ports") + "</th><th>" + T("th.score") + "</th></tr></thead><tbody>";
      for (var i = 0; i < gr.items.length; i++) {
        var it = gr.items[i], h = it.host;
        var chips = it.ports.map(function (p) {
          return '<span class="fs-port lv-' + esc(p.level) + '">' + p.port + "<i>" + esc(p.service || "?") + "</i></span>";
        }).join("");
        html += "<tr>";
        html += '<td class="c-proc"><code>' + esc(h.ip) + "</code></td>";
        html += '<td class="c-pid">' + esc(h.hostname || "—") + "</td>";
        html += '<td class="fs-os">' + famBadge(h.os ? h.os.family : "unknown") + " " + esc(osLabel(h.os)) + "</td>";
        html += '<td class="fs-ports">' + chips + "</td>";
        html += '<td><span class="fs-score lv-' + esc(h.level) + '">' + h.score + "</span></td>";
        html += "</tr>";
      }
      html += "</tbody></table></div></details>";
    }
    els.panelSvc.innerHTML = html;
    expandAll(els.panelSvc);
  }

  /* ---- 视图 5: 端口矩阵 ---- */
  function renderPorts() {
    var f = state.filter;
    var rows = state.model.portMatrix.filter(function (p) {
      if (!f) return true;
      var hay = p.port + " " + p.service + " " + p.label + " " + p.note + " " + p.hosts.map(function (h) { return h.ip; }).join(" ");
      return hay.toLowerCase().indexOf(f) !== -1;
    });
    if (!rows.length) { els.panelPorts.innerHTML = '<p class="fs-dim">' + esc(T("ports.empty")) + "</p>"; return; }

    var html = '<p class="fs-tip">' + esc(T("ports.top", { n: rows.length })) + "</p>";
    html += '<div class="table-wrap"><table class="proc-table">';
    html += "<thead><tr><th>" + T("th.port") + "</th><th>" + T("th.service") + "<th>" + T("th.level") +
      "</th><th>" + T("th.hosts") + "</th><th>" + T("th.note") + "</th></tr></thead><tbody>";
    for (var i = 0; i < rows.length; i++) {
      var p = rows[i];
      html += "<tr>";
      html += '<td class="c-proc"><code>' + p.port + "</code></td>";
      html += '<td class="c-id"><b>' + esc(p.label) + '</b><div class="vendor">' + esc(p.service) + "</div></td>";
      html += "<td>" + lvBadge(p.level) + "</td>";
      html += '<td class="fs-ports">' + p.hosts.slice(0, 20).map(function (h) {
        return '<code class="fs-ip-chip">' + esc(h.ip) + "</code>";
      }).join("") + (p.hosts.length > 20 ? '<span class="fs-port more">+' + (p.hosts.length - 20) + "</span>" : "") + "</td>";
      html += '<td class="c-desc">' + esc(isEn() ? p.noteEn : p.note) + "</td>";
      html += "</tr>";
    }
    html += "</tbody></table></div>";
    els.panelPorts.innerHTML = html;
    expandAll(panelPorts);
  }

  function renderUnknown() {
    var list = state.model.unknown;
    if (!list.length) { els.unknownCard.classList.add("hidden"); return; }
    var html = "";
    for (var i = 0; i < list.length && i < 60; i++) {
      html += '<span class="chip-dim" title="' + esc(list[i]) + '">' + esc(list[i].slice(0, 90)) + "</span>";
    }
    if (list.length > 60) html += '<span class="chip-dim">+ ' + (list.length - 60) + "</span>";
    els.unknown.innerHTML = html;
    els.unknownCard.classList.remove("hidden");
  }

  /* ============ 导出 ============ */
  function nowStr() {
    var d = new Date();
    function p(n) { return (n < 10 ? "0" : "") + n; }
    return d.getFullYear() + "-" + p(d.getMonth() + 1) + "-" + p(d.getDate()) + "-" + p(d.getHours()) + p(d.getMinutes());
  }

  function download(filename, text, mime) {
    var blob = new Blob([text], { type: mime || "text/plain;charset=utf-8" });
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    setTimeout(function () {
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }, 150);
  }

  function copyText(text, okKey) {
    function fallback() {
      var ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand("copy"); toast(T(okKey)); }
      catch (e) { toast(T("toast.copyFail"), true); }
      document.body.removeChild(ta);
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () { toast(T(okKey)); }, fallback);
    } else {
      fallback();
    }
  }

  /** 按系统分组的机器清单: 一行一台(IP 主机名 系统) */
  function copyReport() {
    copyText(FS.toSimpleList(state.model, lang()), "toast.copied");
  }

  /** 每台机器一行: IP 主机名 系统 端口/服务 */
  function copyIpList() {
    copyText(FS.toSimpleIpList(state.model, lang()), "toast.copiedIp");
  }

  /** 全部清单: 与 TXT 下载内容完全一致 */
  function copyAll() {
    copyText(FS.toTxtList(state.model, lang()), "toast.copiedAll");
  }

  /** 按服务分类: Web / SSH / 数据库 / 远程管理 / 文件共享 / 其它 */
  function copyServiceList() {
    copyText(FS.toServiceList(state.model, lang()), "toast.copiedSvc");
  }

  /* ============ 事件 ============ */
  function switchTab(tab) {
    state.tab = tab;
    var btns = els.tabs.querySelectorAll(".fs-tab");
    for (var i = 0; i < btns.length; i++) btns[i].classList.toggle("active", btns[i].getAttribute("data-tab") === tab);
    if (state.model) renderPanels();
  }

  function init() {
    applyStatic();
    updateMeta();

    els.btnParse.addEventListener("click", function () { parseNow(); });
    els.btnSample.addEventListener("click", function () {
      els.input.value = window.FSCAN_SAMPLES.fscan;
      updateMeta();
      toast(T("toast.sample"));
    });
    els.btnSampleV2.addEventListener("click", function () {
      els.input.value = window.FSCAN_SAMPLES.v2;
      updateMeta();
      toast(T("toast.sample"));
    });
    els.btnSampleMixed.addEventListener("click", function () {
      els.input.value = window.FSCAN_SAMPLES.mixed;
      updateMeta();
      toast(T("toast.sample"));
    });
    els.btnClear.addEventListener("click", function () {
      els.input.value = "";
      state.model = null;
      els.results.classList.add("hidden");
      updateMeta();
    });
    els.input.addEventListener("input", updateMeta);
    els.input.addEventListener("keydown", function (e) {
      if ((e.ctrlKey || e.metaKey) && e.key === "Enter") { e.preventDefault(); parseNow(); }
    });

    els.tabs.addEventListener("click", function (e) {
      var btn = e.target.closest ? e.target.closest(".fs-tab") : null;
      if (btn) switchTab(btn.getAttribute("data-tab"));
    });

    els.filter.addEventListener("input", function () {
      state.filter = els.filter.value.trim().toLowerCase();
      if (state.model) renderPanels();
    });

    els.copyAll.addEventListener("click", copyAll);
    els.copy.addEventListener("click", copyReport);
    els.copyIp.addEventListener("click", copyIpList);
    els.copySvc.addEventListener("click", copyServiceList);
    els.md.addEventListener("click", function () {
      download("fscan-report-" + nowStr() + ".md", FS.toMarkdown(state.model, lang()), "text/markdown;charset=utf-8");
    });
    els.json.addEventListener("click", function () {
      download("fscan-report-" + nowStr() + ".json", FS.toJson(state.model), "application/json;charset=utf-8");
    });
    els.txt.addEventListener("click", function () {
      var txt = FS.toTxtList(state.model, lang());
      download("fscan-list-" + nowStr() + ".txt", txt, "text/plain;charset=utf-8");
    });

    els.langBtn.addEventListener("click", function () {
      if (window.I18N) window.I18N.setLang(isEn() ? "zh" : "en");
      else return;
    });
    document.addEventListener("tli:lang", function () {
      applyStatic();
      updateMeta();
      if (state.model) renderAll();
    });

    // ?demo=1 直接载入示例并解析; ?view=os|ip|risk|ports 指定默认视图(便于分享/自测)
    try {
      var dm = (location.search.match(/[?&]demo=(1|v2|nmap|misc)/) || [])[1];
      if (dm && window.FSCAN_SAMPLES) {
        els.input.value = dm === "v2" ? window.FSCAN_SAMPLES.v2
          : dm === "nmap" ? window.FSCAN_SAMPLES.mixed
          : dm === "misc" ? window.FSCAN_SAMPLES.misc
          : window.FSCAN_SAMPLES.fscan;
        updateMeta();
        parseNow(true);
      }
      var v = (location.search.match(/[?&]view=(os|ip|risk|svc|ports)/) || [])[1];
      if (v) switchTab(v);
    } catch (e) {}
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
