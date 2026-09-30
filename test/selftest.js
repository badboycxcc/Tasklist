/*!
 * TaskList Inspector - 自测脚本 (Node.js)
 * 运行: node test/selftest.js
 */
"use strict";

var path = require("path");
function req(name) { return require(path.join(__dirname, "../assets/js/", name)); }
var S = req("signatures.js");
var EN = req("signatures.en.js");
var I18N = req("i18n.js");
var P = req("parser.js");
var A = req("analyzer.js");
var SAMPLES = req("samples.js");

/* 自测以中文为基线(避免运行环境的语言设置干扰断言) */
I18N.setLang("zh", { silent: true });

var failed = 0;
function assert(cond, msg) {
  if (cond) {
    console.log("  ✓ " + msg);
  } else {
    failed++;
    console.error("  ✗ ASSERT FAIL: " + msg);
  }
}

/* 1. 校验签名库: match 全部小写、必备字段 */
console.log("== 签名库校验 ==");
console.log("  签名条数: " + S.SIGNATURES.length + ", 命令行关键字: " + S.CMD_KEYWORDS.length);
var badCase = [], badField = [], badCat = [];
for (var i = 0; i < S.SIGNATURES.length; i++) {
  var sig = S.SIGNATURES[i];
  for (var j = 0; j < sig.match.length; j++) {
    if (sig.match[j] !== sig.match[j].toLowerCase()) badCase.push(sig.name + " -> " + sig.match[j]);
  }
  if (!sig.name || !sig.cat || !sig.os || !sig.desc || !sig.match.length) badField.push(sig.name || "(无名条目#" + i + ")");
  if (!S.CATEGORIES[sig.cat]) badCat.push(sig.name + " -> " + sig.cat);
}
assert(badCase.length === 0, "match 均为小写" + (badCase.length ? " (问题: " + badCase.join(", ") + ")" : ""));
assert(badField.length === 0, "必备字段完整" + (badField.length ? " (问题: " + badField.join(", ") + ")" : ""));
assert(badCat.length === 0, "类别均在 CATEGORIES 中定义" + (badCat.length ? " (问题: " + badCat.join(", ") + ")" : ""));

/* 2. 解析器 */
console.log("\n== 解析器测试 ==");
var winParsed = P.parse(SAMPLES.windows, null);
assert(winParsed.platform === "w", "Windows 示例平台识别为 w");
assert(winParsed.mode === "win-table", "Windows 示例格式识别为 win-table (实际: " + winParsed.mode + ")");
assert(winParsed.entries.length === 33, "Windows 示例解析出 33 条 (实际: " + winParsed.entries.length + ")");
var idle = winParsed.entries.filter(function (e) { return e.raw === "System Idle Process"; });
assert(idle.length === 1 && idle[0].pid === "0", "含空格的进程名解析正确 (System Idle Process, PID 0)");

var nixParsed = P.parse(SAMPLES.linux, null);
assert(nixParsed.platform === "l", "Linux 示例平台识别为 l");
assert(nixParsed.mode === "nix-aux", "Linux 示例格式识别为 nix-aux (实际: " + nixParsed.mode + ")");
var nginxWorker = nixParsed.entries.filter(function (e) { return e.raw === "nginx"; });
assert(nginxWorker.length === 2, "nginx master/worker 均归一化为 nginx");

var efText = "UID        PID  PPID  C STIME TTY          TIME CMD\nroot         1     0  0 Aug12 ?        00:00:05 /sbin/init\nsshd       990     1  0 Aug12 ?        00:00:12 /usr/sbin/sshd -D";
var efParsed = P.parse(efText, null);
assert(efParsed.mode === "nix-ef", "ps -ef 格式识别 (实际: " + efParsed.mode + ")");
assert(efParsed.entries.length === 2, "ps -ef 解析出 2 条");

var psText = [
  "Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName",
  "-------  ------    -----      -----     ------     --  -- -----------",
  "    702      25    62716      84720     158.98  19108   1 chrome",
  "    451      12    28004      32908       3.50   1234   0 MsMpEng"
].join("\n");
var psParsed = P.parse(psText, "w");
assert(psParsed.mode === "win-ps", "PowerShell 输出格式识别 (实际: " + psParsed.mode + ")");
assert(psParsed.entries.length === 2, "PowerShell 输出解析出 2 条");

var simple = P.parse("chrome.exe\nexplorer.exe\nnginx", null);
assert(simple.entries.length === 3, "一行一个进程名的兜底解析 (实际: " + simple.entries.length + ")");

/* 3. Windows 分析 */
console.log("\n== Windows 示例分析 ==");
var winRes = A.analyze(winParsed);
assert(!!winRes.findings.av && winRes.findings.av.some(function (f) { return f.name.indexOf("Kaspersky") !== -1; }), "识别出 Kaspersky (avp.exe)");
assert(winRes.findings.av.some(function (f) { return f.name.indexOf("Defender") !== -1; }), "识别出 Windows Defender (MsMpEng.exe)");
assert(!!winRes.findings.browser && winRes.findings.browser.length >= 2, "识别出浏览器 (Chrome/Edge 等)");
assert(!!winRes.findings.remote && winRes.findings.remote.some(function (f) { return f.name.indexOf("ToDesk") !== -1; }), "识别出 ToDesk");
assert(!!winRes.findings.im && winRes.findings.im.some(function (f) { return f.name.indexOf("微信") !== -1; }), "识别出微信");
assert(!!winRes.findings.office && winRes.findings.office.some(function (f) { return f.name.indexOf("WPS") !== -1; }), "识别出 WPS");
assert(winRes.suspicious.some(function (s) { return s.raw === "svch0st.exe"; }), "启发式识别出仿冒进程 svch0st.exe");
assert(winRes.findings.remote.some(function (f) { return f.name.indexOf("RDP") !== -1; }), "识别出 RDP 会话组件 (rdpclip)");
var svcCount = winParsed.entries.filter(function (e) { return e.norm === "svchost"; }).length;
var svcGroup = winRes.groups.filter(function (g) { return g.norm === "svchost"; })[0];
assert(svcGroup && svcGroup.count === svcCount, "同名进程聚合正确 (svchost ×" + svcCount + ")");
console.log("  画像线索:");
winRes.profile.forEach(function (l) { console.log("    - " + l); });

/* 4. Linux 分析 */
console.log("\n== Linux 示例分析 ==");
var nixRes = A.analyze(nixParsed);
assert(!!nixRes.findings.tunnel && nixRes.findings.tunnel.some(function (f) { return f.name === "frp"; }), "识别出 frp 隧道 (./frps)");
assert(nixRes.findings.cloud.some(function (f) { return f.name.indexOf("阿里云盾") !== -1; }), "识别出阿里云盾 Agent");
assert(!!nixRes.findings.ops && nixRes.findings.ops.some(function (f) { return f.name.indexOf("宝塔") !== -1; }), "命令行关键字识别出宝塔面板 (python3 + BT-Panel)");
assert(!!nixRes.findings.db && nixRes.findings.db.some(function (f) { return f.name.indexOf("MySQL") !== -1; }), "识别出 MySQL");
assert(!!nixRes.findings.web && nixRes.findings.web.some(function (f) { return f.name === "Nginx"; }), "识别出 Nginx");
assert(!!nixRes.findings.container, "识别出容器组件 (docker/kubelet)");
assert(!!nixRes.findings.av && nixRes.findings.av.some(function (f) { return f.name === "ClamAV"; }), "识别出 ClamAV");
assert(nixRes.unresolved.some(function (u) { return u.raw.indexOf("corp-mon-agent") !== -1; }), "未识别进程 corp-mon-agent 进入待确认列表");
assert(!!nixRes.findings.remote && nixRes.findings.remote.some(function (f) { return f.name.indexOf("OpenSSH") !== -1; }), "识别出 OpenSSH 服务端");
console.log("  画像线索:");
nixRes.profile.forEach(function (l) { console.log("    - " + l); });

/* 5. PowerShell 分析 */
console.log("\n== PowerShell 示例分析 ==");
var psRes = A.analyze(psParsed);
assert(psRes.findings.av.some(function (f) { return f.name.indexOf("Defender") !== -1; }), "识别出 MsMpEng");
assert(!!psRes.findings.browser, "识别出 chrome");

/* 6. NetExec / CrackMapExec 脏数据清洗 */
console.log("\n== NetExec (nxc/cme) 输出清洗 ==");
var nxcParsed = P.parse(SAMPLES.netexec, null);
assert(nxcParsed.platform === "w", "nxc 输出平台识别为 w");
assert(nxcParsed.mode === "win-table", "清洗后格式识别为 win-table (实际: " + nxcParsed.mode + ")");
assert(nxcParsed.notes.length >= 1, "返回脏数据清洗提示");
assert(nxcParsed.entries.length === 11, "清洗后解析出 11 条 (实际: " + nxcParsed.entries.length + ")");
assert(nxcParsed.entries.every(function (e) { return e.raw.indexOf("PC-01") === -1; }), "进程名中不含主机名前缀");
assert(nxcParsed.entries.some(function (e) { return e.raw === "System Idle Process"; }), "含空格的进程名正确解析");
var nxcRes = A.analyze(nxcParsed);
assert(nxcRes.notes.length >= 1, "分析结果携带清洗提示");
assert(nxcRes.findings.av.some(function (f) { return f.name === "ESET"; }), "识别出 ESET (ekrn.exe)");
assert(nxcRes.findings.vm.some(function (f) { return f.name === "VMware Tools"; }), "识别出 VMware Tools (vmtools.exe)");

/* 7. 边界用例 */
console.log("\n== 边界用例 ==");
var ev = A.editDistance("scvhost", "svchost");
assert(ev === 1, "Damerau-Levenshtein 识别换位 (scvhost ↔ svchost = 1)");
var t1 = A.analyze(P.parse("C:\\Users\\Public\\svchost.exe --x\nsvchost.exe", "w"));
assert(t1.suspicious.some(function (s) { return s.reasons.join().indexOf("公共目录") !== -1; }), "临时/公共目录路径提示");
var t2 = A.analyze(P.parse("chrome.exe.exe", "w"));
assert(t2.suspicious.some(function (s) { return s.reasons.join().indexOf("双扩展名") !== -1; }), "双扩展名检测");
try {
  P.parse("这是一段没有进程信息的普通文字");
  assert(false, "无效输入应抛出错误");
} catch (e) {
  assert(true, "无效输入抛出友好错误");
}

console.log("\n== 双语支持 (i18n) ==");
assert(I18N.getLang() === "zh", "测试基线为中文 (实际: " + I18N.getLang() + ")");

// 英文翻译覆盖率
var missingSig = [];
S.SIGNATURES.forEach(function (sig) {
  if (!EN.SIG_EN[sig.cat + "|" + sig.name]) missingSig.push(sig.cat + "|" + sig.name);
});
console.log("  英文签名条目: " + Object.keys(EN.SIG_EN).length + " / 签名总数: " + S.SIGNATURES.length);
assert(missingSig.length === 0, "所有签名均有英文条目" + (missingSig.length ? " (缺失: " + missingSig.slice(0, 10).join(", ") + (missingSig.length > 10 ? " 等" : "") + ")" : ""));

var missingCmd = [];
S.CMD_KEYWORDS.forEach(function (kw) { if (!EN.CMD_EN[kw.n]) missingCmd.push(kw.n); });
assert(missingCmd.length === 0, "所有命令行关键字均有英文条目" + (missingCmd.length ? " (缺失: " + missingCmd.join(", ") + ")" : ""));

// 英文模式下的分析与启发式
I18N.setLang("en", { silent: true });
assert(typeof globalThis.sigName === "function", "signatures.en.js 导出助手函数");
var enRes = A.analyze(P.parse(SAMPLES.windows, null));
assert(enRes.profile.some(function (l) { return l.indexOf("Endpoint protection") !== -1; }), "英文画像生成正常");
assert(enRes.findings.av.some(function (f) { return f.name === "Kaspersky"; }), "英文模式识别名正常");
assert(globalThis.sigName({ cat: "av", name: "火绒安全" }) === "Huorong Security", "中文名条目的英文名覆盖正常");
assert(globalThis.sigDesc({ cat: "remote", name: "ToDesk", desc: "ToDesk 远程控制软件" }).indexOf("remote control") !== -1, "英文描述覆盖正常");
assert(globalThis.vendorName("火绒") === "Huorong", "厂商名英文化正常");
var enSus = A.analyze(P.parse("chrome.exe.exe\nC:\\Users\\Public\\svchost.exe", "w"));
assert(enSus.suspicious.some(function (s) { return s.reasons.join(" ").indexOf("Double file extension") !== -1; }), "英文可疑提示生成正常");
var enNxc = P.parse(SAMPLES.netexec, null);
assert(enNxc.notes.length && enNxc.notes[0].indexOf("Stripped NetExec") !== -1, "英文清洗提示正常");

I18N.setLang("zh", { silent: true });
assert(I18N.getLang() === "zh", "语言可切回中文");

console.log("\n" + (failed ? "❌ 共 " + failed + " 项失败" : "✅ 全部通过"));
process.exitCode = failed ? 1 : 0;
