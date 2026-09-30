/*!
 * TaskList Inspector - 分析引擎
 * ---------------------------------------------------------------
 * 职责:
 *   1. 将解析出的进程条目按进程名聚合;
 *   2. 与签名库匹配(名称精确 / 名称前缀 / 命令行关键字);
 *   3. 启发式可疑检测(仿冒系统进程名、临时目录运行等);
 *   4. 汇总关键发现并生成"主机画像"线索。
 */
(function (root) {
  "use strict";

  function norm(name) { return root.ProcParser.normName(name); }

  /* ---------- i18n 辅助 ---------- */
  function T(key, params) {
    return root.I18N ? root.I18N.t(key, params) : key;
  }
  function locSigName(sig) { return typeof root.sigName === "function" ? root.sigName(sig) : sig.name; }
  function locSigDesc(sig) { return typeof root.sigDesc === "function" ? root.sigDesc(sig) : sig.desc; }
  function locCmdName(kw) { return typeof root.cmdName === "function" ? root.cmdName(kw) : kw.n; }
  function locCmdDesc(kw) { return typeof root.cmdDesc === "function" ? root.cmdDesc(kw) : kw.d; }

  /* i18n 辅助(独立运行时回退中文) */

  /* ---------- 编辑距离(含相邻换位, 用于"仿冒进程名"检测) ---------- */
  function editDistance(a, b) {
    var al = a.length, bl = b.length;
    if (Math.abs(al - bl) > 2) return 99;
    var d = [];
    for (var i = 0; i <= al; i++) { d[i] = [i]; }
    for (var j = 0; j <= bl; j++) { d[0][j] = j; }
    for (i = 1; i <= al; i++) {
      for (j = 1; j <= bl; j++) {
        var cost = a.charAt(i - 1) === b.charAt(j - 1) ? 0 : 1;
        d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
        if (i > 1 && j > 1 && a.charAt(i - 1) === b.charAt(j - 2) && a.charAt(i - 2) === b.charAt(j - 1)) {
          d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
        }
      }
    }
    return d[al][bl];
  }

  /* 系统关键进程名(用于仿冒检测) */
  var CRITICAL = {
    w: ["svchost", "lsass", "csrss", "services", "winlogon", "wininit", "smss", "explorer", "dwm", "spoolsv",
      "taskhostw", "runtimebroker", "searchindexer", "conhost", "fontdrvhost", "ctfmon", "securityhealthservice",
      "msmpeng", "wmiprvse", "dllhost", "sihost", "userinit", "taskmgr", "winlogon"],
    l: ["systemd", "init", "sshd", "cron", "crond", "kthreadd", "bash", "sh", "nginx", "apache2", "httpd",
      "mysqld", "postgres", "redis-server", "containerd", "dockerd", "kubelet", "polkitd", "rsyslogd", "sudo", "su"]
  };

  /* 可疑运行路径特征: [正则, 提示文本 i18n key] */
  var SUSPECT_PATHS = [
    [/\\appdata\\local\\temp/i, "p.userTemp"],
    [/\\windows\\temp/i, "p.sysTemp"],
    [/\\temp\\/i, "p.temp"],
    [/\\tmp\\/i, "p.tmp"],
    [/\\downloads\\/i, "p.downloads"],
    [/\\users\\public\\/i, "p.public"],
    [/\/tmp\//i, "p.tmpl"],
    [/\/dev\/shm/i, "p.devshm"],
    [/\/var\/tmp/i, "p.vartmp"],
    [/\/run\/shm/i, "p.runshm"]
  ];

  /* ---------- 匹配 ---------- */
  function osOk(sigOs, platform) {
    if (!sigOs || sigOs === "b" || !platform) return true;
    return sigOs === platform;
  }

  function findMatch(nrm, platform) {
    var sigs = root.SIGNATURES || [];
    var i, j, s, m;
    // 1) 名称精确匹配
    for (i = 0; i < sigs.length; i++) {
      s = sigs[i];
      if (!osOk(s.os, platform)) continue;
      for (j = 0; j < s.match.length; j++) {
        if (nrm === s.match[j]) return { sig: s, type: "name" };
      }
    }
    // 2) 名称前缀匹配(取最长前缀)
    var best = null;
    for (i = 0; i < sigs.length; i++) {
      s = sigs[i];
      if (!s.prefix || !osOk(s.os, platform)) continue;
      for (j = 0; j < s.match.length; j++) {
        m = s.match[j];
        if (nrm.indexOf(m) === 0) {
          if (!best || m.length > best.len) best = { sig: s, type: "prefix", len: m.length };
        }
      }
    }
    if (best) return { sig: best.sig, type: "prefix" };
    return null;
  }

  /* ---------- 内存字段解析(KB) ---------- */
  function parseMemKB(mem) {
    if (!mem) return 0;
    var m = String(mem).replace(/,/g, "").match(/([\d.]+)\s*([KMGT]?)/i);
    if (!m) return 0;
    var v = parseFloat(m[1]);
    var unit = (m[2] || "K").toUpperCase();
    var f = { K: 1, M: 1024, G: 1048576, T: 1073741824 }[unit] || 1;
    if (isNaN(v)) return 0;
    return v * f;
  }

  /* ---------- 主分析流程 ---------- */
  /**
   * @param {{platform:string|null, mode:string, entries:Array}} parsed
   * @returns {Object} 分析结果
   */
  function analyze(parsed) {
    var platform = parsed.platform;
    var entries = parsed.entries || [];

    /* 1. 按进程名聚合 */
    var map = Object.create(null);
    var groups = [];
    for (var i = 0; i < entries.length; i++) {
      var e = entries[i];
      var g = map[e.norm];
      if (!g) {
        g = map[e.norm] = {
          norm: e.norm, raw: e.raw, count: 0,
          pids: [], users: [], cmds: [], memKB: 0,
          sig: null, matchType: null, conf: null,
          flags: [], tags: []
        };
        groups.push(g);
      }
      g.count++;
      if (e.pid && g.pids.indexOf(e.pid) === -1 && g.pids.length < 8) g.pids.push(e.pid);
      if (e.user && g.users.indexOf(e.user) === -1) g.users.push(e.user);
      if (e.cmd) {
        var cmdsJoined = g.cmds.join(" \u0001 ");
        if (cmdsJoined.indexOf(e.cmd) === -1 && g.cmds.length < 3) g.cmds.push(e.cmd);
      }
      g.memKB += parseMemKB(e.mem);
    }

    /* 2. 签名匹配 + 命令行关键字扫描 */
    var findings = {};          // cat -> [{name, vendor, proc, count}]
    var cmdFindings = [];       // 命令行关键字命中
    var foundKeys = Object.create(null);

    function pushFinding(cat, name, vendor, proc, count) {
      var key = cat + "|" + name + "|" + vendor;
      if (foundKeys[key]) return;
      foundKeys[key] = true;
      if (!findings[cat]) findings[cat] = [];
      findings[cat].push({ name: name, vendor: vendor, proc: proc, count: count || 1 });
    }

    var keywords = root.CMD_KEYWORDS || [];
    for (i = 0; i < groups.length; i++) {
      g = groups[i];
      var match = findMatch(g.norm, platform);
      if (match) {
        g.sig = match.sig;
        g.matchType = match.type;
        g.conf = match.type === "name" ? "高" : "中";
        pushFinding(match.sig.cat, locSigName(match.sig), match.sig.vendor, g.raw, g.count);
      }
      // 命令行关键字
      var cmdText = g.cmds.join(" ").toLowerCase();
      if (cmdText) {
        for (var k = 0; k < keywords.length; k++) {
          var kw = keywords[k];
          for (var kk = 0; kk < kw.k.length; kk++) {
            if (cmdText.indexOf(kw.k[kk].toLowerCase()) !== -1) {
              var dup = cmdFindings.some(function (f) { return f.tool === locCmdName(kw) && f.proc === g.raw; });
              if (!dup) {
                cmdFindings.push({ proc: g.raw, tool: locCmdName(kw), desc: locCmdDesc(kw), cat: kw.c });
              }
              if (g.tags.indexOf(kw.n) === -1) g.tags.push(kw.n);
              pushFinding(kw.c, locCmdName(kw), T("vendor.cmd"), g.raw + T("cmd.procSuffix"), 1);
              break;
            }
          }
        }
      }
    }

    /* 3. 可疑启发式检测 */
    var sus = [];
    for (i = 0; i < groups.length; i++) {
      g = groups[i];
      var reasons = [], level = "warn";

      // 3.1 名称含非 ASCII 字符(同形字伪装)
      if (/[^\x00-\x7F]/.test(g.raw)) {
        reasons.push(T("sus.nonascii"));
        level = "high";
      }
      // 3.2 双扩展名
      if (/\.(exe|scr|com)\s*\.(exe|scr|com)$/i.test(g.raw)) {
        reasons.push(T("sus.doubleext"));
        level = "high";
      }
      // 3.3 仿冒系统关键进程(编辑距离 <= 1 且未被识别为正常签名)
      if (!g.sig && g.norm.length >= 4 && g.norm.indexOf("/") === -1) {
        var critList = CRITICAL[platform || "w"] || [];
        for (var c = 0; c < critList.length; c++) {
          if (g.norm === critList[c]) break;
          if (editDistance(g.norm, critList[c]) <= 1) {
            reasons.push(T("sus.typosquat", { name: critList[c] }));
            level = "high";
            break;
          }
        }
      }
      // 3.4 从临时/公开目录运行(仅在输入包含完整命令行时有效)
      if (g.cmds.length) {
        var full = g.cmds.join(" ");
        for (var p = 0; p < SUSPECT_PATHS.length; p++) {
          if (SUSPECT_PATHS[p][0].test(full)) {
            reasons.push(T("sus.tempdir", { dir: T(SUSPECT_PATHS[p][1]) }));
            break;
          }
        }
      }
      // 3.5 UNC 路径运行
      if (g.cmds.length && /\\\\[^\\\\\s]+[\\\/]/.test(g.cmds.join(" "))) {
        reasons.push(T("sus.unc"));
      }

      if (reasons.length) {
        sus.push({ raw: g.raw, level: level, reasons: reasons });
        g.flags.push({ level: level, text: reasons[0] });
      }
    }

    /* 4. 统计与画像 */
    var identified = 0;
    for (i = 0; i < groups.length; i++) {
      if (groups[i].sig || groups[i].tags.length) identified++;
    }

    var unresolved = groups.filter(function (g) { return !g.sig && !g.tags.length; })
      .sort(function (a, b) { return b.count - a.count; })
      .map(function (g) { return { raw: g.raw, count: g.count, pids: g.pids }; });

    var profile = buildProfile(groups, findings);
    for (i = 0; i < sus.length; i++) {
      profile.unshift(T("pf.sus", { raw: sus[i].raw, reasons: sus[i].reasons.join(T("sep.reason")) }));
    }

    return {
      platform: platform,
      mode: parsed.mode,
      notes: parsed.notes || [],
      totalInstances: entries.length,
      uniqueCount: groups.length,
      identifiedCount: identified,
      groups: groups,
      findings: findings,
      cmdFindings: cmdFindings,
      suspicious: sus,
      unresolved: unresolved,
      profile: profile
    };
  }

  /* ---------- 主机画像 ---------- */
  function buildProfile(groups, findings) {
    var lines = [];
    var SEP = T("sep.list");
    var normSet = Object.create(null);
    for (var i = 0; i < groups.length; i++) normSet[groups[i].norm] = true;
    function hasAny(list) {
      for (var i = 0; i < list.length; i++) if (normSet[list[i]]) return true;
      return false;
    }
    function names(cat, max) {
      var arr = findings[cat] || [];
      var out = [];
      for (var i = 0; i < arr.length && i < max; i++) out.push(arr[i].name + "(" + arr[i].proc + ")");
      if (arr.length > max) out.push(T("pf.more", { n: arr.length }));
      return out.join(SEP);
    }
    function has(cat) { return findings[cat] && findings[cat].length; }

    if (has("av")) lines.push(T("pf.av", { list: names("av", 5) }));
    if (has("tool")) lines.push(T("pf.tool", { list: names("tool", 5) }));
    if (has("remote")) lines.push(T("pf.remote", { list: names("remote", 5) }));
    if (has("tunnel")) lines.push(T("pf.tunnel", { list: names("tunnel", 4) }));
    if (has("vpn")) lines.push(T("pf.vpn", { list: names("vpn", 4) }));
    if (has("cloud")) lines.push(T("pf.cloud", { list: names("cloud", 4) }));
    if (has("container")) lines.push(T("pf.container", { list: names("container", 4) }));
    if (has("db") || has("web")) {
      var svc = [];
      if (has("web")) svc.push(T("pf.svc.web", { list: names("web", 3) }));
      if (has("db")) svc.push(T("pf.svc.db", { list: names("db", 3) }));
      lines.push(T("pf.server", { svc: svc.join(SEP) }));
    }
    if (has("mail")) lines.push(T("pf.mail", { list: names("mail", 3) }));
    if (has("file")) lines.push(T("pf.file", { list: names("file", 3) }));
    var wsParts = [];
    if (has("browser")) wsParts.push(T("pf.ws.browser", { list: names("browser", 2) }));
    if (has("office")) wsParts.push(T("pf.ws.office", { list: names("office", 2) }));
    if (has("im")) wsParts.push(T("pf.ws.im", { list: names("im", 2) }));
    if (has("dev")) wsParts.push(T("pf.ws.dev", { list: names("dev", 2) }));
    if (wsParts.length) lines.push(T("pf.workspace", { parts: wsParts.join(SEP) }));

    if (hasAny(["ccmexec"]) || hasAny(["sssd", "winbindd", "krb5kdc", "kadmind"])) {
      lines.push(T("pf.domain"));
    }
    if (hasAny(["rdpclip", "rdpinit", "xrdp"])) lines.push(T("pf.rdp"));
    if (hasAny(["wsmprovhost"])) lines.push(T("pf.winrm"));

    var guest = hasAny(["vmtoolsd", "vmtools", "qemu-ga", "vboxservice", "vboxsvc"]);
    var host = hasAny(["vmware-vmx", "vmwp", "libvirtd", "qemu-system"]);
    if (guest) lines.push(T("pf.guest"));
    if (host) lines.push(T("pf.host"));

    if (!lines.length) lines.push(T("pf.none"));
    return lines;
  }

  var ProcAnalyzer = { analyze: analyze, editDistance: editDistance };

  root.ProcAnalyzer = ProcAnalyzer;
  if (typeof module !== "undefined" && module.exports) module.exports = ProcAnalyzer;
})(typeof window !== "undefined" ? window : globalThis);
