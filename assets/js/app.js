/*!
 * TaskList Inspector - 页面交互与渲染
 */
(function () {
  "use strict";

  var $ = function (sel) { return document.querySelector(sel); };

  var els = {
    input: $("#input"),
    platformSel: $("#platformSel"),
    btnAnalyze: $("#btnAnalyze"),
    btnSampleWin: $("#btnSampleWin"),
    btnSampleNix: $("#btnSampleNix"),
    btnSampleNxc: $("#btnSampleNxc"),
    btnClear: $("#btnClear"),
    langBtn: $("#langBtn"),
    inputMeta: $("#inputMeta"),
    results: $("#results"),
    parseNote: $("#parseNote"),
    statsGrid: $("#statsGrid"),
    profileCard: $("#profileCard"),
    profileList: $("#profileList"),
    findingsCard: $("#findingsCard"),
    findingsGrid: $("#findingsGrid"),
    cmdCard: $("#cmdCard"),
    cmdList: $("#cmdList"),
    susCard: $("#susCard"),
    susList: $("#susList"),
    tablesWrap: $("#tablesWrap"),
    unresolvedCard: $("#unresolvedCard"),
    unresolvedChips: $("#unresolvedChips"),
    unresolvedCount: $("#unresolvedCount"),
    filterInput: $("#filterInput"),
    btnCopy: $("#btnCopy"),
    btnDownloadMd: $("#btnDownloadMd"),
    btnDownloadJson: $("#btnDownloadJson"),
    btnDownloadTxt: $("#btnDownloadTxt"),
    toast: $("#toast")
  };

  var state = { res: null, filter: "" };

  /* ---------- 工具函数 ---------- */
  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (m) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[m];
    });
  }

  function T(key, params) { return window.I18N ? window.I18N.t(key, params) : key; }
  function sigNameOf(sig) { return typeof window.sigName === "function" ? window.sigName(sig) : sig.name; }
  function descOf(sig) { return typeof window.sigDesc === "function" ? window.sigDesc(sig) : sig.desc; }
  function vendorOf(v) { return typeof window.vendorName === "function" ? window.vendorName(v) : v; }
  function tagNames(tags) { return tags.map(function (t) { return typeof window.cmdTagName === "function" ? window.cmdTagName(t) : t; }); }

  var toastTimer = null;
  function toast(msg, isErr) {
    els.toast.textContent = msg;
    els.toast.className = "show" + (isErr ? " err" : "");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { els.toast.className = ""; }, 2600);
  }

  var PLATFORM_LABEL = { w: "Windows", l: "Linux / Unix" };
  var MODE_KEYS = ["win-table", "win-csv", "win-list", "win-ps", "nix-aux", "nix-ef", "nix-top", "generic"];

  function platformLabel(p) { return p ? PLATFORM_LABEL[p] : T("st.undetermined"); }
  function modeLabel(m) { return MODE_KEYS.indexOf(m) !== -1 ? T("mode." + m) : m; }
  var CATS = (window.CATEGORIES || {});
  var KEY_CATS = (window.KEY_CATEGORIES || []);
  var CLOSED_CATS = ["system", "shell", "update", "midware", "desktop", "media", "sysutil", "other"];

  function catInfo(key) {
    var c = CATS[key];
    if (!c) return { label: key, icon: "❓", order: 90 };
    var label = (window.I18N && window.I18N.isEn() && c.labelEn) ? c.labelEn : c.label;
    return { label: label, icon: c.icon, order: c.order };
  }
  function catOrder(key) {
    return catInfo(key).order;
  }

  /* ---------- 分析 ---------- */
  function analyzeNow(noScroll) {
    var text = els.input.value;
    if (!text.trim()) { toast(T("toast.empty"), true); return; }
    var platform = els.platformSel.value || null;
    try {
      var parsed = window.ProcParser.parse(text, platform);
      var res = window.ProcAnalyzer.analyze(parsed);
      state.res = res;
      state.filter = "";
      els.filterInput.value = "";
      renderAll();
      els.results.classList.remove("hidden");
      if (!noScroll) els.results.scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (e) {
      toast(e && e.message ? e.message : T("err.parse"), true);
    }
  }

  /* ---------- 渲染 ---------- */
  function renderAll() {
    renderNotes();
    renderStats();
    renderProfile();
    renderFindings();
    renderCmdFindings();
    renderSuspicious();
    renderTables();
    renderUnresolved();
  }

  function renderNotes() {
    var notes = (state.res && state.res.notes) || [];
    if (!notes.length) { els.parseNote.classList.add("hidden"); return; }
    var html = "";
    for (var i = 0; i < notes.length; i++) {
      html += '<div>🧹 ' + esc(notes[i]) + "</div>";
    }
    els.parseNote.innerHTML = html;
    els.parseNote.classList.remove("hidden");
  }

  function renderStats() {
    var r = state.res;
    var avCount = (r.findings.av || []).length;
    var html = "";
    html += '<div class="stat v-cyan"><div class="k">' + T("st.platform") + '</div><div class="v" style="font-size:17px">' + esc(platformLabel(r.platform)) + ' <small>' + esc(modeLabel(r.mode)) + "</small></div></div>";
    html += '<div class="stat"><div class="k">' + T("st.instances") + '</div><div class="v">' + r.totalInstances + " <small>" + T("st.rows") + "</small></div></div>";
    html += '<div class="stat"><div class="k">' + T("st.unique") + '</div><div class="v">' + r.uniqueCount + "</div></div>";
    html += '<div class="stat v-green"><div class="k">' + T("st.identified") + '</div><div class="v">' + r.identifiedCount +
      " <small>/ " + r.uniqueCount + "</small></div></div>";
    html += '<div class="stat ' + (avCount ? "v-red" : "") + '"><div class="k">' + T("st.av") + '</div><div class="v">' + avCount + "</div></div>";
    html += '<div class="stat ' + (r.suspicious.length ? "v-yellow" : "") + '"><div class="k">' + T("st.sus") + '</div><div class="v">' + r.suspicious.length + "</div></div>";
    els.statsGrid.innerHTML = html;
  }

  function renderProfile() {
    if (!state.res.profile.length) { els.profileCard.classList.add("hidden"); return; }
    var html = "";
    for (var i = 0; i < state.res.profile.length; i++) {
      html += "<li>" + esc(state.res.profile[i]) + "</li>";
    }
    els.profileList.innerHTML = html;
    els.profileCard.classList.remove("hidden");
  }

  function renderFindings() {
    var findings = state.res.findings;
    var html = "";
    for (var i = 0; i < KEY_CATS.length; i++) {
      var key = KEY_CATS[i];
      var arr = findings[key];
      if (!arr || !arr.length) continue;
      var info = catInfo(key);
      html += '<div class="finding-card cat-' + esc(key) + '">';
      html += '<div class="fc-head">' + info.icon + " " + esc(info.label) + '<span class="fc-count">' + T("fc.items", { n: arr.length }) + "</span></div>";
      html += '<div class="fc-body">';
      for (var j = 0; j < arr.length; j++) {
        html += '<span class="chip">' + esc(arr[j].name) + ' <span class="dim">· ' + esc(arr[j].proc) + "</span></span>";
      }
      html += "</div></div>";
    }
    if (html) {
      els.findingsGrid.innerHTML = html;
      els.findingsCard.classList.remove("hidden");
    } else {
      els.findingsCard.classList.add("hidden");
    }
  }

  function renderCmdFindings() {
    var list = state.res.cmdFindings;
    if (!list.length) { els.cmdCard.classList.add("hidden"); return; }
    var html = "";
    for (var i = 0; i < list.length; i++) {
      html += '<div class="sus-item"><span class="sus-proc">' + esc(list[i].proc) + "</span>" +
        '<span class="sus-reason">' + T("cmd.hit") + "<b>" + esc(list[i].tool) + "</b> — " + esc(list[i].desc) + "</span></div>";
    }
    els.cmdList.innerHTML = html;
    els.cmdCard.classList.remove("hidden");
  }

  function renderSuspicious() {
    var sus = state.res.suspicious;
    if (!sus.length) { els.susCard.classList.add("hidden"); return; }
    var html = "";
    for (var i = 0; i < sus.length; i++) {
      html += '<div class="sus-item ' + esc(sus[i].level) + '"><span class="sus-proc">' + esc(sus[i].raw) + "</span>" +
        '<span class="sus-reason">' + esc(sus[i].reasons.join(T("sep.reason"))) + "</span></div>";
    }
    els.susList.innerHTML = html;
    els.susCard.classList.remove("hidden");
  }

  /** 计算每个分组的展示类别 */
  function groupCategory(g) {
    if (g.sig) return g.sig.cat;
    // 仅有命令行命中的分组
    var list = state.res.cmdFindings;
    for (var i = 0; i < list.length; i++) {
      if (list[i].proc === g.raw) return list[i].cat;
    }
    return "other";
  }

  function matchBadge(g) {
    if (g.matchType === "name") return '<span class="badge badge-hi">' + T("badge.name") + "</span>";
    if (g.matchType === "prefix") return '<span class="badge badge-mid">' + T("badge.prefix") + "</span>";
    if (g.tags.length) return '<span class="badge badge-cmd">' + T("badge.cmd") + "</span>";
    return '<span class="badge badge-lo">' + T("badge.none") + "</span>";
  }

  function renderTables() {
    var res = state.res, filter = state.filter;
    var byCat = {};
    var ordering = [];
    for (var i = 0; i < res.groups.length; i++) {
      var g = res.groups[i];
      if (!g.sig && !g.tags.length) continue; // 未识别项单独在下方展示, 不在明细表重复
      var cat = groupCategory(g);
      var hay = (g.raw + " " + (g.sig ? g.sig.name + " " + g.sig.vendor : "") + " " + g.tags.join(" ")).toLowerCase();
      if (filter && hay.indexOf(filter) === -1) continue;
      if (!byCat[cat]) { byCat[cat] = []; ordering.push(cat); }
      byCat[cat].push(g);
    }
    ordering.sort(function (a, b) { return catOrder(a) - catOrder(b); });

    var html = "";
    for (i = 0; i < ordering.length; i++) {
      var key = ordering[i];
      var info = catInfo(key);
      var rows = byCat[key].sort(function (a, b) { return b.count - a.count; });
      var open = CLOSED_CATS.indexOf(key) === -1 ? " open" : "";
      html += '<details class="cat-section"' + open + ">";
      html += "<summary>" + info.icon + " " + esc(info.label) + '<span class="cat-count">' + T("tbl.procs", { n: rows.length }) + "</span></summary>";
      html += '<div class="table-wrap"><table class="proc-table">';
      html += "<thead><tr><th>" + T("th.proc") + "</th><th>" + T("th.pid") + "</th><th>" + T("th.result") + "</th><th>" + T("th.match") + "</th><th>" + T("th.desc") + "</th></tr></thead><tbody>";
      for (var j = 0; j < rows.length; j++) {
        var g = rows[j];
        var idName = g.sig ? esc(sigNameOf(g.sig)) : esc(g.tags.length ? tagNames(g.tags).join(" / ") : g.raw);
        var vendor = g.sig ? esc(vendorOf(g.sig.vendor)) : "—";
        var desc = g.sig ? esc(descOf(g.sig)) : T("row.cmdKeyword");
        var flagsHtml = "";
        for (var f = 0; f < g.flags.length; f++) {
          flagsHtml += '<span class="flag ' + esc(g.flags[f].level) + '">⚠ ' + esc(g.flags[f].text) + "</span> ";
        }
        var tagsHtml = "";
        var tNames = tagNames(g.tags);
        for (var t = 0; t < tNames.length; t++) {
          tagsHtml += '<span class="tag-tool">⚔ ' + esc(tNames[t]) + "</span>";
        }
        var cmdHtml = "";
        if (g.cmds.length) {
          var cmd = g.cmds[0];
          cmdHtml = '<div class="cmd" title="' + esc(cmd) + '">$ ' + esc(cmd) + "</div>";
        }
        html += "<tr>";
        html += '<td class="c-proc"><code>' + esc(g.raw) + "</code>" + (g.count > 1 ? '<span class="tag-count">×' + g.count + "</span>" : "") + "</td>";
        html += '<td class="c-pid">' + esc(g.pids.slice(0, 5).join(", ") || (g.users[0] || "—")) + "</td>";
        html += '<td class="c-id"><b>' + idName + '</b><div class="vendor">' + vendor + "</div></td>";
        html += '<td class="c-match">' + matchBadge(g) + "</td>";
        html += '<td class="c-desc">' + desc + flagsHtml + tagsHtml + cmdHtml + "</td>";
        html += "</tr>";
      }
      html += "</tbody></table></div></details>";
    }
    if (!html) {
      html = '<p style="color:var(--txt3);font-size:13px">' + T("tbl.empty") + "</p>";
    }
    els.tablesWrap.innerHTML = html;
  }

  function renderUnresolved() {
    var list = state.res.unresolved, filter = state.filter;
    if (filter) {
      list = list.filter(function (u) { return u.raw.toLowerCase().indexOf(filter) !== -1; });
    }
    if (!list.length) { els.unresolvedCard.classList.add("hidden"); return; }
    var html = "";
    for (var i = 0; i < list.length && i < 200; i++) {
      var title = list[i].pids && list[i].pids.length ? "PID: " + list[i].pids.join(", ") : "";
      html += '<span class="chip-dim" title="' + esc(title) + '">' + esc(list[i].raw) + (list[i].count > 1 ? " ×" + list[i].count : "") + "</span>";
    }
    if (list.length > 200) html += '<span class="chip-dim">' + T("unresolved.more", { n: list.length }) + "</span>";
    els.unresolvedChips.innerHTML = html;
    els.unresolvedCount.textContent = T("unresolved.count", { n: list.length });
    els.unresolvedCard.classList.remove("hidden");
  }

  /* ---------- 报告导出 ---------- */
  function nowStr() {
    var d = new Date();
    function p(n) { return (n < 10 ? "0" : "") + n; }
    return d.getFullYear() + "-" + p(d.getMonth() + 1) + "-" + p(d.getDate()) + " " + p(d.getHours()) + ":" + p(d.getMinutes());
  }

  function buildMarkdown() {
    var r = state.res;
    var L = [];
    L.push(T("rep.title"));
    L.push("");
    L.push(T("rep.time", { t: nowStr() }));
    L.push(T("rep.platform", { p: platformLabel(r.platform), m: modeLabel(r.mode) }));
    L.push(T("rep.counts", { a: r.totalInstances, b: r.uniqueCount, c: r.identifiedCount }));
    L.push(T("rep.tool"));
    L.push("");

    if (r.profile.length) {
      L.push(T("rep.profile"));
      L.push("");
      for (var i = 0; i < r.profile.length; i++) L.push("- " + r.profile[i]);
      L.push("");
    }

    if (r.cmdFindings.length) {
      L.push(T("rep.cmd"));
      L.push("");
      for (i = 0; i < r.cmdFindings.length; i++) {
        L.push("- `" + r.cmdFindings[i].proc + "` → **" + r.cmdFindings[i].tool + "** (" + r.cmdFindings[i].desc + ")");
      }
      L.push("");
    }

    if (r.suspicious.length) {
      L.push(T("rep.sus"));
      L.push("");
      for (i = 0; i < r.suspicious.length; i++) {
        L.push("- `" + r.suspicious[i].raw + "`: " + r.suspicious[i].reasons.join(T("sep.reason")));
      }
      L.push("");
    }

    // 分类表
    var byCat = {}, cats = [];
    for (i = 0; i < r.groups.length; i++) {
      var g = r.groups[i];
      var cat = groupCategory(g);
      if (!byCat[cat]) { byCat[cat] = []; cats.push(cat); }
      byCat[cat].push(g);
    }
    cats.sort(function (a, b) { return catOrder(a) - catOrder(b); });

    L.push(T("rep.results"));
    L.push("");
    for (i = 0; i < cats.length; i++) {
      var key = cats[i], info = catInfo(key);
      L.push("### " + info.icon + " " + info.label);
      L.push("");
      L.push(T("rep.th"));
      L.push(T("rep.sep"));
      var rows = byCat[key].sort(function (a, b) { return b.count - a.count; });
      for (var j = 0; j < rows.length; j++) {
        var gg = rows[j];
        var idName = gg.sig ? sigNameOf(gg.sig) : (tagNames(gg.tags).join(" / ") || gg.raw);
        var vendor = gg.sig ? vendorOf(gg.sig.vendor) : (gg.tags.length ? T("vendor.cmd") : "—");
        var desc = gg.sig ? descOf(gg.sig) : "";
        if (gg.flags.length) desc += " ⚠ " + gg.flags.map(function (f) { return f.text; }).join(T("sep.reason"));
        L.push("| `" + gg.raw + (gg.count > 1 ? " ×" + gg.count : "") + "` | " + (gg.pids.slice(0, 3).join(",") || "-") +
          " | " + idName + " | " + vendor + " | " + (gg.matchType === "name" ? T("rep.match.name") : gg.matchType === "prefix" ? T("rep.match.prefix") : gg.tags.length ? T("rep.match.cmd") : "-") +
          " | " + desc.replace(/\|/g, "\\|") + " |");
      }
      L.push("");
    }

    if (r.unresolved.length) {
      L.push(T("rep.unresolved", { n: r.unresolved.length }));
      L.push("");
      L.push(r.unresolved.map(function (u) { return "`" + u.raw + (u.count > 1 ? "×" + u.count : "") + "`"; }).join(" "));
      L.push("");
    }

    L.push("---");
    L.push("");
    L.push(T("rep.footer"));
    return L.join("\n");
  }

  function buildTxt() {
    return buildMarkdown().replace(/[#*`>|]/g, function (m) {
      return m === "|" ? " " : "";
    }).replace(/\n{3,}/g, "\n\n");
  }

  function buildJson() {
    var r = state.res;
    function g2o(g) {
      return {
        proc: g.raw, count: g.count, pids: g.pids,
        identified: g.sig ? { name: sigNameOf(g.sig), vendor: vendorOf(g.sig.vendor), category: g.sig.cat, desc: descOf(g.sig) } : null,
        commandLineHits: g.tags,
        matchType: g.matchType,
        flags: g.flags,
        cmd: g.cmds[0] || null
      };
    }
    return JSON.stringify({
      meta: { time: nowStr(), tool: "TaskList Inspector", site: "tasklist.cxaqhq.cn", lang: window.I18N ? window.I18N.getLang() : "zh" },
      platform: r.platform, mode: r.mode,
      stats: { totalInstances: r.totalInstances, uniqueCount: r.uniqueCount, identifiedCount: r.identifiedCount },
      profile: r.profile,
      cmdFindings: r.cmdFindings,
      suspicious: r.suspicious,
      groups: r.groups.map(g2o),
      unresolved: r.unresolved
    }, null, 2);
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

  function fileBase() {
    var d = new Date();
    function p(n) { return (n < 10 ? "0" : "") + n; }
    return "process-report-" + d.getFullYear() + p(d.getMonth() + 1) + p(d.getDate()) + "-" + p(d.getHours()) + p(d.getMinutes());
  }

  function copyReport() {
    var text = buildMarkdown();
    function fallback() {
      var ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand("copy"); toast(T("toast.copied")); }
      catch (e) { toast(T("toast.copyFail"), true); }
      document.body.removeChild(ta);
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () { toast(T("toast.copied")); }, fallback);
    } else {
      fallback();
    }
  }

  /* ---------- 事件绑定 ---------- */
  function updateInputMeta() {
    var v = els.input.value;
    var lines = v ? v.split(/\r\n|\r|\n/).length : 0;
    var kb = (v.length / 1024).toFixed(1);
    els.inputMeta.textContent = v ? T("meta.input", { lines: lines, kb: kb }) : "";
  }

  function init() {
    els.btnAnalyze.addEventListener("click", analyzeNow);
    els.btnSampleWin.addEventListener("click", function () {
      els.input.value = window.SAMPLES.windows;
      els.platformSel.value = "w";
      updateInputMeta();
      toast(T("toast.sampleWin"));
    });
    els.btnSampleNix.addEventListener("click", function () {
      els.input.value = window.SAMPLES.linux;
      els.platformSel.value = "l";
      updateInputMeta();
      toast(T("toast.sampleNix"));
    });
    els.btnSampleNxc.addEventListener("click", function () {
      els.input.value = window.SAMPLES.netexec;
      els.platformSel.value = "";
      updateInputMeta();
      toast(T("toast.sampleNxc"));
    });
    els.btnClear.addEventListener("click", function () {
      els.input.value = "";
      state.res = null;
      els.results.classList.add("hidden");
      updateInputMeta();
    });
    // 语言切换
    els.langBtn.addEventListener("click", function () {
      window.I18N.setLang(window.I18N.isEn() ? "zh" : "en");
    });
    document.addEventListener("tli:lang", function () {
      updateInputMeta();
      if (state.res) { analyzeNow(true); } // 重新分析以刷新动态文本
    });

    els.input.addEventListener("input", updateInputMeta);
    els.input.addEventListener("keydown", function (e) {
      if ((e.ctrlKey || e.metaKey) && e.key === "Enter") { e.preventDefault(); analyzeNow(); }
    });
    els.filterInput.addEventListener("input", function () {
      state.filter = els.filterInput.value.trim().toLowerCase();
      if (state.res) { renderTables(); renderUnresolved(); }
    });
    els.btnCopy.addEventListener("click", copyReport);
    els.btnDownloadMd.addEventListener("click", function () {
      download(fileBase() + ".md", buildMarkdown(), "text/markdown;charset=utf-8");
    });
    els.btnDownloadJson.addEventListener("click", function () {
      download(fileBase() + ".json", buildJson(), "application/json;charset=utf-8");
    });
    els.btnDownloadTxt.addEventListener("click", function () {
      download(fileBase() + ".txt", buildTxt(), "text/plain;charset=utf-8");
    });
    updateInputMeta();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
