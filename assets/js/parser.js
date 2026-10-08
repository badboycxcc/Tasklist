/*!
 * TaskList Inspector - 进程列表解析器
 * ---------------------------------------------------------------
 * 支持格式:
 *   - Windows: tasklist 默认表格 / CSV(/fo csv) / 列表(/fo list) / PowerShell Get-Process
 *   - Linux:   ps aux / ps -ef / top 输出
 *   - 兜底:    一行一个进程名 或 简单的 "名称 PID" 列表
 */
(function (root) {
  "use strict";

  var INT_RE = /^\d+$/;

  /* i18n 辅助(未加载 i18n.js 时回退中文) */
  var FALLBACK_TEXT = {
    "parse.nxc": "已自动去除 NetExec / CrackMapExec 输出前缀(共处理 {n} 行), 并基于命令输出内容解析。",
    "err.noEntries": "未能从输入中解析出有效的进程条目。支持 tasklist(表格/CSV/列表)、PowerShell Get-Process、ps aux、ps -ef、top 等格式。"
  };
  function T(key, params) {
    if (root.I18N) return root.I18N.t(key, params);
    var s = FALLBACK_TEXT[key] || key;
    if (params) s = s.replace(/\{(\w+)\}/g, function (m, k) { return params[k] != null ? String(params[k]) : m; });
    return s;
  }

  /* ---------- 名称清洗与归一化 ---------- */

  /** 清洗进程名: 去引号/路径(保留 basename)/末尾冒号/括号序号等 */
  function cleanName(raw) {
    var s = String(raw == null ? "" : raw).trim();
    s = s.replace(/^["'`]+/, "").replace(/["'`]+$/, "").trim();
    if (/^n\s*\/\s*a$/i.test(s)) return "";              // 占位符 N/A 不是进程名
    // 内核线程形式 [kworker/0:1]
    var km = s.match(/^\[([^\]]+)\]$/);
    if (km) {
      s = km[1];
    } else {
      var parts = s.split(/[\\\/]/);
      s = parts[parts.length - 1].trim();
    }
    s = s.replace(/^\(+/, "").replace(/\)+$/, "");      // (sd-pam) -> sd-pam
    s = s.replace(/\s*\(\d+\)\s*$/, "").trim();          // "chrome (2)" -> "chrome"
    s = s.replace(/[:：]+$/, "").trim();                 // "sshd:" -> "sshd"
    s = s.replace(/^[-!]+/, "").trim();                  // "-bash" -> "bash"
    return s;
  }

  /** 归一化(用于匹配): 小写、去 .exe/.scr/.com、压缩空白 */
  function normName(raw) {
    return cleanName(raw)
      .toLowerCase()
      .replace(/(?:\.(?:exe|scr|com))+$/, "")
      .replace(/\s+/g, " ")
      .trim();
  }

  /** 从完整命令行提取进程名(取第一个 token 的 basename) */
  function nameFromCmd(cmd) {
    if (!cmd) return "";
    var first = String(cmd).trim().split(/\s+/)[0] || "";
    return cleanName(first);
  }

  /* ---------- 平台识别 ---------- */
  function detectPlatform(text) {
    var t = text || "";
    var winScore = 0, nixScore = 0;

    if (/映像名称|Image Name|内存使用|Mem Usage|会话名|Session Name/i.test(t)) winScore += 3;
    var exeCount = (t.match(/\.exe\b/gi) || []).length;
    if (exeCount >= 5) winScore += 2;
    else if (exeCount >= 1) winScore += 1;
    if (/Services\s+\d+|Console\s+\d+/i.test(t)) winScore += 1;

    if (/USER\s+PID\s+%CPU|%CPU\s+%MEM|UID\s+PID\s+PPID|PPID\s+CMD\b|\[kworker|\/usr\/sbin\/|\/sbin\/|\/usr\/bin\/|systemd|sshd\b|COMMAND/i.test(t)) nixScore += 3;
    var nixCount = (t.match(/\/usr\/|\/sbin\/|\/bin\/|\[kworker|\/etc\//g) || []).length;
    if (nixCount >= 3) nixScore += 2;
    else if (nixCount >= 1) nixScore += 1;

    if (winScore > nixScore) return "w";
    if (nixScore > winScore) return "l";
    return null;
  }

  /* ---------- 格式识别 ---------- */
  function detectMode(lines) {
    var text = lines.join("\n");
    if (/映像名称\s*[:：]\s*\S|Image Name\s*:\s*\S/i.test(text)) return "win-list";
    if (/^\s*"[^"]+","\d+"/m.test(text)) return "win-csv";
    if (/ProcessName/.test(text) && /Handles/.test(text)) return "win-ps";
    if (/映像名称|Image Name/i.test(text) && /(内存使用|Mem Usage|\bPID\b)/i.test(text)) return "win-table";
    if (/COMMAND/.test(text) && /\bRES\b/.test(text) && /%CPU/.test(text)) return "nix-top";
    if (/USER\s+PID\s+%CPU|%CPU\s+%MEM\s+VSZ/.test(text)) return "nix-aux";
    if (/UID\s+PID\s+PPID|PID\s+PPID\s+C\s+STIME/.test(text)) return "nix-ef";
    return null;
  }

  /* ---------- 去除 NetExec / CrackMapExec 等工具的输出前缀 ----------
   * 这类工具输出形如:
   *   SMB  192.168.1.10  445  PC-01  System Idle Process  0 Services  0  24 K
   * 每行包含 [协议 IP 端口 主机名] 前缀, 且主机名与内容之间用多空格分隔,
   * 而 tasklist 数据行内部只有单空格, 据此可安全剥离子进程实际内容。
   */
  var LOG_PROTO_RE = /^(SMB|SMB2|SSH|WINRM|WMI|LDAP|LDAPS|MSSQL|MYSQL|POSTGRES|REDIS|MONGO|RDP|VNC|FTP|FTPS|NFS|HTTP|HTTPS|DC|ADCS|DNS|SNMP|TELNET|DCOM)$/i;

  function stripLogPrefix(lines) {
    var out = [], hits = 0;
    var preRe = /^\s*([A-Za-z][A-Za-z0-9+_-]{1,11})\s+((?:\d{1,3}\.){3}\d{1,3}|\S+)\s+(\d{1,5})\s+(.*)$/;
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      var m = line.match(preRe);
      if (m && LOG_PROTO_RE.test(m[1])) {
        var msg = pickMessage(m[4]);
        if (msg === null) continue; // 状态类日志行([+] Executed command ...)直接丢弃
        hits++;
        out.push(msg);
      } else {
        out.push(line);
      }
    }
    return { lines: out, hits: hits };
  }

  /** 从 nxc 行“主机名列之后”的内容中选出真正的命令输出 */
  function pickMessage(rest) {
    var lead = String(rest || "").replace(/^\s+/, "").replace(/\s+$/, "");
    if (!lead) return null;
    if (/^\[[-+*!]\]/.test(lead)) return null; // npm/nxc 状态行
    var best = lead, bestScore = scoreDataLine(lead);
    var m = lead.match(/^(\S+)\s{2,}(.+)$/); // 主机名列(单 token) + 内容
    if (m) {
      var cand = m[2].replace(/^\s+/, "");
      var sc = scoreDataLine(cand);
      if (sc > 0 && sc >= bestScore) { best = cand; bestScore = sc; }
    }
    return best;
  }

  /** 行内容与 tasklist 数据/表头的相似度打分 */
  function scoreDataLine(s) {
    if (/^\s*=+(\s+=+)+\s*$/.test(s)) return 3;
    if (/(映像名称|Image Name)/i.test(s) && /\bPID\b/.test(s)) return 3;
    if (WIN_ROW_RE.test(s)) return 3;
    if (WIN_ROW_NA_RE.test(s)) return 3;
    if (/(内存使用|Mem Usage)/i.test(s)) return 1;
    return 0;
  }

  /* ---------- 各格式解析器 ---------- */

  var WIN_ROW_RE = /^\s*(.+?)\s+([\d,]+)\s+(\S+)\s+(-?\d+)\s+([\d,\.]+|N\/A)\s*([KMGTP]?B?)\s*$/i;
  /* NetExec 等工具透传 tasklist 时列被截断: "<名称> <PID> [<会话>] N/A" */
  var WIN_ROW_NA_RE = /^\s*(.+?)\s+([\d,]+)\s+(.*?)\s*N\s*\/\s*A\s*$/i;

  function parseWinTable(lines) {
    var out = [];
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      if (!line.trim()) continue;
      if (/=====|映像名称|Image Name|\bPID\b/.test(line)) continue;
      var m = line.match(WIN_ROW_RE);
      if (m) {
        out.push({
          raw: m[1].trim(),
          pid: m[2].replace(/,/g, ""),
          session: m[3],
          mem: (m[5] === "N/A" ? "" : (m[5] + " " + m[6]).trim()),
          cmd: null
        });
        continue;
      }
      var mn = line.match(WIN_ROW_NA_RE);
      if (mn) {
        out.push({
          raw: mn[1].trim(),
          pid: mn[2].replace(/,/g, ""),
          session: (mn[3] || "").trim() || null,
          mem: null,
          cmd: null
        });
      }
    }
    return out;
  }

  function parseWinCsv(lines) {
    var out = [];
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      if (!/^\s*"/.test(line)) continue;
      var fields = [], m, re = /"([^"]*)"/g;
      while ((m = re.exec(line)) !== null) fields.push(m[1]);
      if (fields.length >= 2 && INT_RE.test(fields[1].replace(/,/g, ""))) {
        out.push({
          raw: fields[0],
          pid: fields[1].replace(/,/g, ""),
          session: fields[2] || null,
          mem: fields[4] || null,
          cmd: null
        });
      }
    }
    return out;
  }

  function parseWinList(lines) {
    var out = [], cur = null;
    var nameRe = /^\s*(?:映像名称|Image Name|进程名)\s*[:：]\s*(.+?)\s*$/i;
    var pidRe = /^\s*PID\s*[:：]\s*(\d+)/i;
    var memRe = /^\s*(?:内存使用|Mem Usage)\s*[:：]\s*(.+?)\s*$/i;
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      var m1 = line.match(nameRe);
      var m2 = line.match(pidRe);
      var m3 = line.match(memRe);
      if (m1) {
        if (cur) out.push(cur);
        cur = { raw: m1[1], pid: null, session: null, mem: null, cmd: null };
      } else if (cur && m2) {
        cur.pid = m2[1];
      } else if (cur && m3) {
        cur.mem = m3[1];
      }
    }
    if (cur) out.push(cur);
    return out;
  }

  function parseWinPs(lines) {
    var out = [], started = false;
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      if (/ProcessName/.test(line) || /Handles\s+NPM/i.test(line)) { started = true; continue; }
      if (!started || !line.trim()) continue;
      if (/^-+/.test(line.trim())) continue;
      var t = line.trim().split(/\s+/);
      if (t.length < 5) continue;
      var name = t[t.length - 1];
      var si = t[t.length - 2].replace(/,/g, "");
      var id = t[t.length - 3].replace(/,/g, "");
      if (INT_RE.test(si) && INT_RE.test(id)) {
        out.push({ raw: name, pid: id, session: null, mem: null, cmd: null });
      } else if (INT_RE.test(si)) {
        // SI 列为空时的兜底
        out.push({ raw: name, pid: si, session: null, mem: null, cmd: null });
      }
    }
    return out;
  }

  /** ps aux / ps -ef (mode 可为 null 时逐行猜测) */
  function parseNixPs(lines, mode) {
    var out = [];
    var hdrAuxRe = /^\s*(USER|用户)\s+(PID)/i;
    var hdrEfRe = /^\s*(UID|用户)\s+(PID)\s+PPID/i;
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      if (!line.trim()) continue;
      if (hdrAuxRe.test(line) || hdrEfRe.test(line) || /%CPU|%MEM/.test(line) && /USER|UID/.test(line) && !/\d+\s+\d+\.\d/.test(line)) continue;
      var t = line.trim().split(/\s+/);
      if (t.length < 4 || !INT_RE.test(t[1])) continue;

      var lineMode = mode;
      if (!lineMode) {
        // 逐行猜测: aux 的特征是第 4 列(%MEM)为小数; ef 的特征是第 7 列(TIME)含冒号
        if (t.length >= 11 && /^\d+(\.\d+)?$/.test(t[3]) && /\./.test(t[3])) lineMode = "nix-aux";
        else if (/\d{1,2}:\d{2}(:\d{2})?/.test(t[6] || "")) lineMode = "nix-ef";
        else if (t.length >= 11) lineMode = "nix-aux";
        else if (t.length >= 8) lineMode = "nix-ef";
        else continue;
      }

      var cmd = null;
      if (lineMode === "nix-aux") {
        if (t.length < 11) continue;
        cmd = t.slice(10).join(" ");
      } else {
        if (t.length < 8) continue;
        cmd = t.slice(7).join(" ");
      }
      var name = nameFromCmd(cmd);
      if (!name) continue;
      out.push({ raw: name, pid: t[1], user: t[0], mem: null, cmd: cmd });
    }
    return out;
  }

  /** top 输出 */
  function parseNixTop(lines) {
    var out = [], hdrIdx = -1, cols = 0;
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      if (/^\s*PID\s+USER\s+/.test(line) && /COMMAND/.test(line)) {
        hdrIdx = i;
        cols = line.trim().split(/\s+/).length;
        continue;
      }
      if (hdrIdx < 0 || i <= hdrIdx) continue;
      if (!line.trim()) continue;
      var t = line.trim().split(/\s+/);
      if (!INT_RE.test(t[0] || "")) continue;
      var cmd = t.length > cols - 1 ? t.slice(cols - 1).join(" ") : "";
      if (!cmd) continue;
      var name = nameFromCmd(cmd);
      if (!name) continue;
      out.push({ raw: name, pid: t[0], user: t[1], mem: null, cmd: cmd });
    }
    return out;
  }

  /** 兜底: 逐行寻找最像进程名的 token */
  var STOP_WORDS = /^(USER|UID|PID|PPID|TTY|STAT|TIME|TIME\+|CMD|COMMAND|START|ELAPSED|SESSION|NAME|CPU|MEM|VSZ|RSS|%CPU|%MEM|PR|NI|VIRT|RES|SHR|S|IMAGE|IMAGE NAME|HANDLES|NPM|PM|WS|ID|SI|MEMUSAGE|用户|会话名|内存使用|映像名称|服务|控制台)$/i;

  function tScore(tok) {
    var s = 0;
    if (/\.exe$/i.test(tok)) s += 4;
    if (/[\\\/]/.test(tok) && !/^\d/.test(tok)) s += 2;
    if (/^[A-Za-z][\w.\-]*$/.test(tok) && tok.length >= 3) s += 1;
    return s;
  }

  function parseGeneric(lines, platform) {
    var out = [];
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      if (!line.trim() || /=====/.test(line)) continue;
      var t = line.trim().split(/\s+/);
      var best = null, bestScore = 0, bestIdx = -1;
      for (var j = 0; j < t.length; j++) {
        var tok = t[j].replace(/^["',]+|["',]+$/g, "");
        if (!tok || INT_RE.test(tok)) continue;
        if (/^\d[\d.,:]*$/.test(tok)) continue;        // 纯数字/时间戳
        if (STOP_WORDS.test(tok)) continue;
        var sc = tScore(tok);
        if (sc > bestScore) { best = tok; bestScore = sc; bestIdx = j; }
      }
      if (!best || bestScore < 1) continue;
      var pid = null;
      for (var k = 0; k < t.length; k++) {
        if (k === bestIdx) continue;
        if (/^\d{1,7}$/.test(t[k])) { pid = t[k]; break; }
      }
      out.push({ raw: best, pid: pid, session: null, mem: null, cmd: line.trim() });
    }
    return out;
  }

  /* ---------- 主入口 ---------- */

  /**
   * 解析进程列表文本
   * @param {string} text 用户粘贴的文本
   * @param {string|null} forcedPlatform "w" | "l" | null(自动)
   * @returns {{platform:string|null, mode:string, entries:Array}}
   */
  function parse(text, forcedPlatform) {
    var normalized = String(text || "").replace(/\t/g, " ").replace(/\u00a0/g, " ");
    var lines = normalized.split(/\r\n|\r|\n/);

    // 自动清洗 NetExec / CrackMapExec 等工具的日志前缀(脏数据)
    var notes = [];
    var stripped = stripLogPrefix(lines);
    if (stripped.hits >= 3) {
      lines = stripped.lines;
      notes.push(T("parse.nxc", { n: stripped.hits }));
    }
    var cleanedText = lines.join("\n");

    var platform = forcedPlatform || detectPlatform(cleanedText);
    var mode = detectMode(lines);
    var entries = [];

    try {
      if (mode === "win-list") entries = parseWinList(lines);
      else if (mode === "win-csv") entries = parseWinCsv(lines);
      else if (mode === "win-ps") entries = parseWinPs(lines);
      else if (mode === "win-table") entries = parseWinTable(lines);
      else if (mode === "nix-top") entries = parseNixTop(lines);
      else if (mode === "nix-aux") entries = parseNixPs(lines, "nix-aux");
      else if (mode === "nix-ef") entries = parseNixPs(lines, "nix-ef");
    } catch (e) { entries = []; }

    if (!entries.length && mode !== null) {
      // 指定格式没解析出东西, 再兜底试试 ps 逐行猜测
      try { entries = parseNixPs(lines, null); } catch (e) { entries = []; }
    }
    if (!entries.length) {
      entries = parseGeneric(lines, platform);
      if (entries.length) mode = mode || "generic";
    }
    if (!entries.length) {
      throw new Error(T("err.noEntries"));
    }

    // 清理非法条目
    var cleaned = [];
    for (var i = 0; i < entries.length; i++) {
      var e = entries[i];
      if (!e || !e.raw) continue;
      var nm = cleanName(e.raw);
      if (!nm || INT_RE.test(nm)) continue;
      e.raw = nm;
      e.norm = normName(nm);
      if (!e.norm) continue;
      cleaned.push(e);
    }

    if (!platform) platform = guessPlatformFromEntries(cleaned);
    return { platform: platform, mode: mode || "generic", entries: cleaned, notes: notes };
  }

  function guessPlatformFromEntries(entries) {
    var win = 0, nix = 0;
    for (var i = 0; i < entries.length; i++) {
      var raw = String(entries[i].raw || "");
      if (/\.exe$/i.test(raw)) win++;
      if (entries[i].cmd && /[\\\/]/.test(entries[i].cmd)) nix++;
      if (/^[a-z][a-z0-9\-_]+$/.test(raw) && !/\.exe$/i.test(raw)) nix++;
    }
    if (win > 0 && nix === 0) return "w";
    if (nix > 3 && win === 0) return "l";
    return null;
  }

  var ProcParser = {
    parse: parse,
    cleanName: cleanName,
    normName: normName,
    nameFromCmd: nameFromCmd,
    detectPlatform: detectPlatform,
    detectMode: detectMode
  };

  root.ProcParser = ProcParser;
  if (typeof module !== "undefined" && module.exports) module.exports = ProcParser;
})(typeof window !== "undefined" ? window : globalThis);
