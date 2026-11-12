/*!
 * Fscan Report Inspector - 自测脚本 (Node.js)
 * 运行: node test/fscan-selftest.js
 */
"use strict";

var path = require("path");
function req(name) { return require(path.join(__dirname, "../assets/js/", name)); }
var F = req("fscan.js");
var SAMPLES = req("fscan-samples.js");

var failed = 0;
function assert(cond, msg) {
  if (cond) {
    console.log("  ✓ " + msg);
  } else {
    failed++;
    console.error("  ✗ ASSERT FAIL: " + msg);
  }
}

/* 1. 端口表 / 规则表完整性 */
console.log("== 规则表校验 ==");
var badPort = [], badRule = [];
Object.keys(F.PORT_MAP).forEach(function (p) {
  var e = F.PORT_MAP[p];
  if (!e.s || !e.n || !e.lv) badPort.push(p);
  if (e.lv !== "high" && e.lv !== "medium" && e.lv !== "low" && e.lv !== "info") badPort.push(p + "(lv)");
});
assert(badPort.length === 0, "PORT_MAP 每项都有 service/name/level" + (badPort.length ? " (问题: " + badPort.join(",") + ")" : ""));
F.COMP_RULES.forEach(function (r) { if (!r.id || !r.re || !r.name) badRule.push(r.id || r.name); });
assert(badRule.length === 0, "COMP_RULES 字段完整" + (badRule.length ? " (问题: " + badRule.join(",") + ")" : ""));
assert(Object.keys(F.PORT_MAP).length > 60, "端口表条目 > 60 (实际 " + Object.keys(F.PORT_MAP).length + ")");

/* 2. 解析 fscan 示例 */
console.log("\n== fscan 示例解析 ==");
var parsed = F.parse(SAMPLES.fscan);
assert(parsed.version === "1.8.4", "识别 fscan 版本 (实际: " + parsed.version + ")");
assert(parsed.entries.length > 25, "解析出 " + parsed.entries.length + " 条结果 (>25)");
assert(parsed.unknown.length === 1, "只有 1 行未识别 (实际: " + parsed.unknown.length + " -> " + JSON.stringify(parsed.unknown) + ")");
assert(parsed.unknown[0].indexOf("ICMP") !== -1, "未识别行是 ICMP 存活提示");
assert(parsed.blank >= 1, "空行单独计数 (blank=" + parsed.blank + ")");

var kinds = {};
parsed.entries.forEach(function (e) { kinds[e.t] = (kinds[e.t] || 0) + 1; });
assert(kinds.open >= 15, "open 端口行解析 " + kinds.open + " 条");
assert(kinds.cred === 6, "弱口令行解析 6 条 (实际: " + kinds.cred + ")");
assert(kinds.unauth === 3, "未授权行解析 3 条 (实际: " + kinds.unauth + ")");
assert(kinds.vuln >= 2, "漏洞命中行解析 " + kinds.vuln + " 条");
assert(kinds.web >= 2, "Web 标题行解析 " + kinds.web + " 条");

var sshCred = parsed.entries.filter(function (e) { return e.t === "cred" && e.port === 22 && e.user === "root"; })[0];
assert(sshCred && sshCred.pass === "123456", "ssh root:123456 提取到用户名口令");
var ms17 = parsed.entries.filter(function (e) { return e.t === "vuln" && /MS17-010/.test(e.name); })[0];
assert(ms17 && ms17.ip === "192.168.10.5" && ms17.port === 445, "MS17-010 命中归属到 192.168.10.5:445");
var poc = parsed.entries.filter(function (e) { return e.t === "vuln" && /poc-yaml/.test(e.name); })[0];
assert(poc && poc.port === 8080, "PocScan 行取到真实 POC 名与端口 (实际: " + (poc && poc.name) + ")");
var webE = parsed.entries.filter(function (e) { return e.t === "web"; })[0];
assert(webE && /^https?:\/\//.test(webE.url), "Web 标题行取到 URL");

/* 3. 分析结果 */
console.log("\n== 分析与分组 ==");
var model = F.analyze(parsed);
assert(model.stats.hosts === 10, "识别出 10 台主机 (实际: " + model.stats.hosts + ")");
assert(model.stats.creds === 6, "弱口令总数 6 (实际: " + model.stats.creds + ")");
assert(model.stats.eolHosts === 2, "EOL 系统 2 台 (2003 + 2008 R2, 实际: " + model.stats.eolHosts + ")");

var h5 = model.hosts.filter(function (h) { return h.ip === "192.168.10.5"; })[0];
assert(!!h5, "192.168.10.5 在主机列表");
assert(h5.os.key === "win-2008r2", "2008 R2 正则识别正确 (实际: " + h5.os.key + ")");
assert(h5.os.eol === true && h5.os.eolDate === "2020-01-14", "2008 R2 判定为已 EOL(2020-01-14)");
assert(h5.ports.length === 4, "192.168.10.5 开放 4 个端口 (实际: " + h5.ports.length + ")");
assert(h5.hostname === "FILESRV-01", "从 WORKGROUP\\FILESRV-01 取到主机名 (实际: " + h5.hostname + ")");
assert(h5.vulns.some(function (v) { return v.name === "MS17-010"; }), "192.168.10.5 记录 MS17-010");
assert(h5.score >= 70 && h5.level === "critical", "高风险主机评分 >=70 且判为 critical (实际 " + h5.score + "/" + h5.level + ")");

var h12 = model.hosts.filter(function (h) { return h.ip === "192.168.10.12"; })[0];
assert(h12.os.key === "win-2003", "Windows Server 2003 识别 (实际: " + h12.os.key + ")");
assert(h12.os.eol === true, "Server 2003 已 EOL");
assert(h12.creds.some(function (c) { return c.user === "administrator" && c.port === 5985; }), "winrm administrator 口令提取");

var h7 = model.hosts.filter(function (h) { return h.ip === "192.168.10.7"; })[0];
assert(h7.os.family === "linux" && h7.os.inferred === true, "只有端口线索的主机推断为 Linux(推测) (实际: " + h7.os.name + ")");
assert(h7.vulns.some(function (v) { return v.kind === "unauth" && v.port === 6379; }), "Redis 未授权记录为 unauth");

var h9 = model.hosts.filter(function (h) { return h.ip === "192.168.10.9"; })[0];
var anonF = h9.findings.filter(function (f) { return f.kind === "weak-pass" && /anonymous/.test(f.title); })[0];
assert(anonF && anonF.level === "high", "匿名账号(FTP anonymous)单独标 high");

var h8 = model.hosts.filter(function (h) { return h.ip === "192.168.10.8"; })[0];
assert(h8.ports[0].title && /IIS/.test(h8.ports[0].title), "IIS Web 标题挂到 8080 端口上");
assert(h8.findings.some(function (f) { return f.kind === "vuln"; }), "PocScan 命中进入弱点清单");

/* 4. 分组与端口矩阵 */
console.log("\n== 分组视图 ==");
assert(model.osGroups.length >= 5, "操作系统分组 " + model.osGroups.length + " 组");
assert(model.osGroups[0].eol === true, "EOL 分组排在最前 (实际: " + model.osGroups[0].name + ")");
var winGroups = model.osGroups.filter(function (g) { return g.family === "windows"; });
assert(winGroups.length === 4, "Windows 分 4 组(2008R2/2003/仅 IIS/端口推断) (实际: " + winGroups.length + ")");
var p445 = model.portMatrix.filter(function (p) { return p.port === 445; })[0];
assert(p445 && p445.hosts.length === 2, "端口矩阵: 445 命中 2 台 (实际: " + (p445 ? p445.hosts.length : "无") + ")");
assert(model.portMatrix[0].hosts.length >= 2, "端口矩阵按命中主机数排序");
assert(model.hosts[0].score >= model.hosts[model.hosts.length - 1].score, "主机按风险分降序");
var kindsOfFindings = {};
model.findings.forEach(function (f) { kindsOfFindings[f.kind] = (kindsOfFindings[f.kind] || 0) + 1; });
["os-eol", "weak-pass", "unauth", "vuln", "danger-port", "old-comp"].forEach(function (k) {
  assert(!!kindsOfFindings[k], "弱点类型存在: " + k);
});

/* 5. 误判防护 */
console.log("\n== 误判防护 ==");
var noCred = F.parse("[+] 1.2.3.4:80\thttp\thttp://1.2.3.4\tApache Tomcat/7.0.47\n[+] 1.2.3.4:80\thttp\thttp://1.2.3.4\tnginx/1.14.2");
assert(noCred.entries.every(function (e) { return e.t !== "cred"; }), "Tomcat/7.0.47、nginx/1.14.2 不会被当成用户名口令");
var comp = F.detectComponents("Apache Tomcat/7.0.47");
assert(comp.length === 1 && comp[0].level === "high", "Tomcat 7.x 判为组件过旧(high)");
var comp2 = F.detectComponents("OpenSSL/1.0.1e");
assert(comp2.length && comp2[0].level === "critical", "OpenSSL 1.0.1 判为 Heartbleed 高危");
var os2022 = F.detectOs("Windows Server 2022 Standard 20348");
assert(os2022.key === "win-2022" && os2022.eol === false, "Windows Server 2022 未 EOL (实际: " + os2022.key + "/" + os2022.eol + ")");
var osBuild = F.detectOs("Microsoft Windows 7601 Service Pack 1");
assert(osBuild.eol === true, "仅凭 build 7601 也能判定为已 EOL 版本");
var osIis = F.detectOs("Microsoft-IIS/7.5");
assert(osIis.key === "win-2008r2", "IIS/7.5 反推到 Server 2008 R2 (实际: " + osIis.key + ")");

/* 6. nmap 混排 */
console.log("\n== nmap 混排 ==");
var nm = F.run(SAMPLES.mixed);
assert(nm.stats.hosts === 3, "nmap 混排识别 3 台 (实际: " + nm.stats.hosts + ")");
var nm11 = nm.hosts.filter(function (h) { return h.ip === "10.0.0.11"; })[0];
assert(nm11 && nm11.ports.length === 3, "nmap 端口行按 Nmap scan report 归属 (实际: " + (nm11 ? nm11.ports.length : 0) + ")");
assert(nm11.os.key === "centos", "从 Apache httpd ((CentOS)) 识别出 CentOS (实际: " + nm11.os.key + ")");
assert(nm.unknown.length === 0, "nmap 混排无未识别行 (实际: " + nm.unknown.length + ")");
var esxi = nm.hosts.filter(function (h) { return h.ip === "10.0.0.13"; })[0];
assert(esxi.os.key === "esxi-6.0" && esxi.os.eol === true, "ESXi 6.0 识别并判定 EOL (实际: " + esxi.os.key + ")");

/* 7. fscan v2.x 真实输出(脱敏) */
console.log("\n== fscan v2.x 输出 ==");
var v2p = F.parse(SAMPLES.v2);
assert(v2p.entries.length > 50, "v2 解析出 " + v2p.entries.length + " 条结果 (>50)");
assert(v2p.unknown.length === 0, "v2 全部行都被识别 (未识别: " + JSON.stringify(v2p.unknown) + ")");

var v2 = F.analyze(v2p);
assert(v2.stats.hosts === 18, "v2 识别 18 台主机 (实际: " + v2.stats.hosts + ")");
assert(v2.stats.creds === 0, "v2 没有把 [OS:Windows...] 误判成弱口令 (实际: " + v2.stats.creds + ")");
assert(v2.stats.vulns === 0, "v2 没有伪造漏洞命中 (实际: " + v2.stats.vulns + ")");
assert(v2.stats.smbV1 === 2, "v2 识别 2 台 SMBv1 (实际: " + v2.stats.smbV1 + ")");

var h3 = v2.hosts.filter(function (h) { return h.ip === "10.0.0.3"; })[0];
assert(h3.os.key === "win-2012", "SMBInfo [Windows 8/Server 2012 (Build 9200)] → 2012 (实际: " + h3.os.key + ")");
assert(h3.hostname === "SRV-CORP3", "RDP 行取到主机名 (实际: " + h3.hostname + ")");
assert(h3.domain === "corp.example.local", "RDP 行取到域名 (实际: " + h3.domain + ")");
assert(h3.ports.filter(function (p) { return p.port === 3389; })[0].service === "rdp",
  "3389 的 ssl 探测不会盖掉 rdp 服务名");
assert(h3.peers.indexOf("10.0.1.41") !== -1, "NetInfo -> 10.0.1.41 收进邻接 IP");
assert(h3.findings.some(function (f) { return f.kind === "smb-v1"; }), "SMBv1 生成弱点项");

var h201 = v2.hosts.filter(function (h) { return h.ip === "10.0.0.201"; })[0];
assert(h201.os.key === "win-2022", "Build 20348 识别为 Server 2022 (实际: " + h201.os.key + ")");
assert(h201.smb === "SMBv2", "SMB 方言(SMBv2)已记录 (实际: " + h201.smb + ")");

var h23 = v2.hosts.filter(function (h) { return h.ip === "10.0.0.23"; })[0];
assert(h23.os.eol === true, "Build 7601 判定为已 EOL (实际: " + h23.os.name + ")");

var h4 = v2.hosts.filter(function (h) { return h.ip === "10.0.0.4"; })[0];
assert(h4.os.key === "ubuntu-16.04", "从 MySQL 版本串 0ubuntu0.16.04 取到 Ubuntu 16.04 (实际: " + h4.os.key + ")");
assert(h4.web.length >= 1 && h4.web[0].code === 200, "Web 行解析出状态码 (实际: " + JSON.stringify(h4.web[0] && h4.web[0].code) + ")");
assert(h4.web[0].title.indexOf("Apache2") !== -1, "Web 标题解析 (实际: " + (h4.web[0] && h4.web[0].title) + ")");
assert(h4.web[0].server.indexOf("Apache/2.4.18") !== -1, "Web server 字段解析 (实际: " + (h4.web[0] && h4.web[0].server) + ")");
assert(h4.components.some(function (c) { return c.id === "mysql" && c.level === "high"; }), "MySQL 5.7 判为组件过旧(high)");
assert(h4.ports.filter(function (p) { return p.port === 3306; })[0].product.indexOf("Genetec") !== -1,
  "端口表记下 [Product:...] 字段");

var cross = v2.peers.filter(function (p) { return p.cross; });
assert(cross.length >= 2, "跨网段邻接 IP 被标记 (" + cross.length + " 条)");

/* 8. 导出里的代码格式 */
var v2md = F.toMarkdown(v2, "zh");
assert(v2md.indexOf("内网 / 邻接 IP 线索") !== -1, "Markdown 含内网线索小节");
assert(v2md.indexOf("| `3389/tcp` | `rdp` |") !== -1, "Markdown 里端口/服务用反引号代码格式");
assert(v2md.indexOf("| `10.0.0.4` |") !== -1, "Markdown 里 IP 用反引号代码格式");
assert(v2md.indexOf("SMBv1") !== -1, "Markdown 含 SMBv1 弱点");

/* 8.5 纯文本清单(最简单的复制格式) */
console.log("\n== 纯文本清单 ==");
var simple = F.toSimpleList(v2, "zh");
assert(simple.indexOf("Windows 机器 (") === 0, "第一段是 Windows 机器分组 (实际: " + simple.split("\n")[0] + ")");
assert(/10\.0\.0\.3\s+SRV-CORP3\s+Windows Server 2012/.test(simple), "一行一台: IP 主机名 系统");
assert(simple.indexOf("10.0.0.113") < simple.indexOf("10.0.0.201"), "组内按 IP 数字排序");
assert(simple.indexOf("Linux 机器 (") !== -1 && simple.indexOf("未识别 (") !== -1, "Linux / 未识别 分组都存在");
assert(simple.indexOf("|") === -1 && simple.indexOf("#") === -1, "纯文本清单里没有 Markdown 符号");

var ipList = F.toSimpleIpList(v2, "zh");
assert(/10\.0\.0\.3\s+SRV-CORP3\s+Windows Server 2012\s+53\/dns 80\/http/.test(ipList), "IP 清单每行带端口/服务");
assert(ipList.split("\n").filter(Boolean).length === v2.stats.hosts, "IP 清单覆盖全部主机");

var simpleEn = F.toSimpleList(v2, "en");
assert(simpleEn.indexOf("Windows hosts (") === 0, "英文清单标题正确");

/* 8.6 按服务分类 */
console.log("\n== 按服务分类 ==");
var svc = F.serviceGroups(v2);
var keys = svc.map(function (g) { return g.key; });
assert(keys.indexOf("web") === 0, "第一个分类是 Web 服务 (实际: " + keys.join(",") + ")");
["web", "ssh", "db", "remote", "smb", "other"].forEach(function (k) {
  assert(keys.indexOf(k) !== -1, "分类存在: " + k);
});
var webG = svc.filter(function (g) { return g.key === "web"; })[0];
assert(webG.items.some(function (it) { return it.host.ip === "10.0.0.4" && it.ports.every(function (p) { return p.port === 80; }); }),
  "Web 分类里只列该主机的 Web 端口");
var dbG = svc.filter(function (g) { return g.key === "db"; })[0];
assert(dbG.items.some(function (it) { return it.host.ip === "10.0.0.4" && it.ports[0].port === 3306; }), "MySQL 主机进数据库分类");
var sshG = svc.filter(function (g) { return g.key === "ssh"; })[0];
assert(sshG.items.some(function (it) { return it.host.ip === "10.0.0.4"; }), "SSH 分类包含 22 端口主机");
var svcText = F.toServiceList(v2, "zh");
assert(svcText.indexOf("Web 服务 (") === 0, "服务清单首段是 Web 服务");
assert(/10\.0\.0\.4\s+-\s+Ubuntu 16\.04\s+3306\/mysql/.test(svcText), "服务清单行内含端口/服务");

/* 8.7 「复制全部」= TXT 内容 */
console.log("\n== 复制全部(同 TXT) ==");
var all = F.toTxtList(v2, "zh");
assert(all.indexOf("Windows 机器 (") === 0, "开头是机器清单");
assert(all.indexOf("Web 服务 (") !== -1 && all.indexOf("SSH 服务 (") !== -1, "中间是服务清单");
assert(all.indexOf("10.0.0.3    SRV-CORP3") !== -1, "结尾是 IP 清单(含端口)");
assert(all.split("------------------------------------------------------------").length === 3, "三段之间用分隔线隔开");
assert(all === F.toSimpleList(v2, "zh") + "\n" +
  "------------------------------------------------------------\n\n" +
  F.toServiceList(v2, "zh") + "\n" +
  "------------------------------------------------------------\n\n" +
  F.toSimpleIpList(v2, "zh"), "复制全部 与 TXT 下载内容完全一致");

/* 8.8 SNMP / SMBGhost / 进度条噪声 */
console.log("\n== SNMP / SMBGhost / 噪声 ==");
var mp = F.parse(SAMPLES.misc);
assert(mp.unknown.length === 0, "SNMP/SMBGhost/进度条全部处理掉, 无未识别行 (实际: " + JSON.stringify(mp.unknown) + ")");
assert(mp.ignored >= 2, "进度条 / [完成] / shell 提示符算噪声 (ignored=" + mp.ignored + ")");

var mm = F.analyze(mp);
var snmpHost = mm.hosts.filter(function (h) { return h.ip === "10.3.12.113"; })[0];
assert(snmpHost && snmpHost.ports[0].port === 161, "SNMP 行解析出 161 端口");
assert(snmpHost.ports[0].proto === "udp", "SNMP 端口标记为 udp");
assert(snmpHost.snmp.indexOf("public") !== -1, "community 记到主机上");
assert(snmpHost.findings.some(function (f) { return f.kind === "snmp-public" && f.level === "high"; }),
  "public 团体字生成 high 弱点项");
assert(snmpHost.os.name.indexOf("打印机") !== -1, "HP ETHERNET Multi-Environment 识别为网络打印机 (实际: " + snmpHost.os.name + ")");

var privHost = mm.hosts.filter(function (h) { return h.ip === "10.3.72.7"; })[0];
assert(privHost.findings.some(function (f) { return f.kind === "snmp-public"; }), "private 团体字同样告警");

var ghost = mm.hosts.filter(function (h) { return h.ip === "10.3.96.218"; })[0];
assert(ghost.vulns.some(function (v) { return /CVE-2020-0796/.test(v.name) && v.port === 445; }),
  "SMB Ghost 行归一成 CVE-2020-0796:445 (实际: " + JSON.stringify(ghost.vulns.map(function (v) { return v.name; })) + ")");
assert(ghost.findings.some(function (f) { return f.kind === "vuln" && f.level === "critical"; }), "CVE 命中记为 critical");

var kyo = mm.hosts.filter(function (h) { return h.ip === "10.3.96.28"; })[0];
assert(/KYOCERA/.test(kyo.evidence.join(" ")), "SNMP 设备描述(京瓷)进入证据");

var misTxt = F.toSimpleList(mm, "zh");
assert(misTxt.indexOf("网络设备 (") !== -1, "打印机归入网络设备分组");

/* 7. 边界 */
console.log("\n== 边界用例 ==");
var empty = F.run("");
assert(empty.stats.hosts === 0 && empty.findings.length === 0, "空输入不报错, 返回空结果");
var junk = F.run("这是一段普通文字, 没有任何扫描结果");
assert(junk.stats.hosts === 0 && junk.unknown.length === 1, "纯文本全部归入未识别行");
var ansi = F.parse("\u001b[32m[+] 1.2.3.4:22\tssh\troot:toor\u001b[0m");
assert(ansi.entries.length === 1 && ansi.entries[0].t === "cred", "ANSI 颜色码被剥离后仍能解析");
var tabs = F.parse("[+] 1.2.3.4:445\tsmb\tWindows 7 Professional 7601");
assert(tabs.entries[0].t === "svc", "Tab 分隔的结果行解析为服务行");
var spaceSep = F.parse("[+] 1.2.3.4:445 smb Windows 7 Professional 7601");
assert(spaceSep.entries[0].t === "svc", "空格分隔的结果行同样解析");
var tagFirst = F.parse("[+] SSH 1.2.3.4:22 root:123456");
assert(tagFirst.entries[0].t === "cred" && tagFirst.entries[0].port === 22, "服务标签在前的写法也支持");
var noPort = F.parse("[+] 1.2.3.4 MS17-010");
assert(noPort.entries[0].t === "vuln" && noPort.entries[0].port === 445, "仅给 IP 的 MS17-010 默认补 445");

/* 8. 导出 */
console.log("\n== 导出 ==");
var mdZh = F.toMarkdown(model, "zh");
assert(mdZh.indexOf("按操作系统划分") !== -1 && mdZh.indexOf("按弱点划分") !== -1, "中文 Markdown 含三张视图");
assert(mdZh.indexOf("MS17-010") !== -1, "中文 Markdown 含漏洞命中");
var mdEn = F.toMarkdown(model, "en");
assert(mdEn.indexOf("Grouped by operating system") !== -1, "英文 Markdown 标题正确");
assert(mdEn.indexOf("中文") === -1, "英文 Markdown 不含中文正文");
var json = JSON.parse(F.toJson(model));
assert(json.hosts.length === 10 && json.stats.hosts === 10, "JSON 导出主机数一致");
assert(json.osGroups.length === model.osGroups.length, "JSON 导出分组数一致");

console.log("\n" + (failed ? "❌ 共 " + failed + " 项失败" : "✅ 全部通过 (" + "fscan 解析器)"));
process.exitCode = failed ? 1 : 0;
