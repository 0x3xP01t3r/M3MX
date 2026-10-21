/* ════════════════════════════════════════════════════════════════════════
   FULL ANALYSIS — SSE triage + attack story (/api/full-analysis)
════════════════════════════════════════════════════════════════════════ */
function _faLog(text, kind = "info") {
  const term = $("fa-terminal"); if (!term) return;
  const span = document.createElement("span");
  span.className = `fa-log-line fa-log-${kind}`;
  span.textContent = `${fmtTime()}  ${text}\n`;
  term.appendChild(span); term.scrollTop = term.scrollHeight;
}
function _faClearLog() { const t = $("fa-terminal"); if (t) t.innerHTML = '<span class="fa-log-dim">$ awaiting start…</span>'; }
function _faSetStatus(label, kind) {
  const p = $("fa-status-pill"); if (!p) return;
  p.innerText = label;
  p.className = `status-chip status-chip-${kind || "idle"}`;
}
function _faUpdateStats() {
  const f = AppState.fa.findings;
  if ($("fa-stat-plugins"))  $("fa-stat-plugins").innerText  = AppState.fa.pluginsDone;
  if ($("fa-stat-findings")) $("fa-stat-findings").innerText = f.length;
  // keep the section subtitle in sync
  const sub = $("fa-findings-sub");
  if (sub) sub.innerText = f.length
    ? `${f.length} finding${f.length === 1 ? "" : "s"} · sorted critical → info`
    : "Run an analysis to populate this table.";
  if ($("fa-stat-critical")) $("fa-stat-critical").innerText = f.filter(x => x.severity === "critical").length;
  if ($("fa-stat-high"))     $("fa-stat-high").innerText     = f.filter(x => x.severity === "high").length;
}
function _faTickElapsed() {
  const s = Math.round((Date.now() - AppState.fa.t0) / 1000);
  if ($("fa-stat-elapsed")) $("fa-stat-elapsed").innerText = `${s}s`;
}
function _faRowHTML(f) {
  const sev = _renderSeverityCell(f.severity);
  const mit = _renderMitreCell((f.tags || []).join(" "));
  const con = _renderConfCell(f.confidence);
  // V2 findings carry richer fields; we show a summary in the row and
  // expose the full detail in an expandable sibling row.
  const hasDetail = !!(
    (f.entities && Object.keys(f.entities || {}).length) ||
    (f.evidence && Object.keys(f.evidence || {}).length) ||
    (f.mitre && f.mitre.length) ||
    f.false_positive_notes ||
    f.recommended_validation ||
    f.score != null
  );
  const expandIcon = hasDetail
    ? '<button class="fa-row-expand" type="button" data-click="expand-finding" title="Show details">▸</button>'
    : '<span class="fa-row-expand fa-row-expand-empty">·</span>';
  // Short entity summary inline so the table itself is informative.
  const summary = _faEntitySummary(f);
  return `<tr data-fid="${esc(f.id)}" class="fa-row-main">
    <td class="fa-cell-expand">${expandIcon}</td>
    <td><span class="fid-tag">${esc(f.id)}</span></td>
    <td>${sev}</td>
    <td>
      <div style="font-weight:600">${esc(f.title || "")}</div>
      <div style="font-size:11px;opacity:.7">${esc(f.description || "")}</div>
      ${summary ? `<div class="fa-row-summary">${summary}</div>` : ""}
    </td>
    <td><code class="plugin-tag">${esc(f.plugin || "")}</code></td>
    <td>${mit}</td>
    <td>${con}</td>
  </tr>`;
}

// Compact one-line summary of the most useful entities, shown beneath
// the title in the main row so the table is informative at a glance.
function _faEntitySummary(f) {
  const e = f.entities || {};
  const bits = [];
  if (e.pid != null)            bits.push(`PID <code>${esc(e.pid)}</code>`);
  if (e.process_name || e.name) bits.push(`<code>${esc(e.process_name || e.name)}</code>`);
  if (e.remote_ip)              bits.push(`→ <code>${esc(e.remote_ip)}${e.remote_port ? ":"+e.remote_port : ""}</code>`);
  if (e.path)                   bits.push(`path <code>${esc(e.path)}</code>`);
  if (e.cmdline) {
    const c = String(e.cmdline);
    bits.push(`cmd <code>${esc(c.length > 80 ? c.slice(0,80)+"…" : c)}</code>`);
  }
  if (e.service_name)           bits.push(`service <code>${esc(e.service_name)}</code>`);
  if (f.score != null)          bits.push(`score <code>${esc(f.score)}</code>`);
  return bits.join(" · ");
}

// Click handler on the chevron — toggles an expanded detail row.
function _faToggleRowDetail(btn) {
  const row = btn.closest("tr");
  if (!row) return;
  const fid = row.getAttribute("data-fid");
  const f = (AppState.fa.findings || []).find(x => x.id === fid);
  if (!f) return;
  const open = row.classList.toggle("fa-row-open");
  btn.textContent = open ? "▾" : "▸";
  const nxt = row.nextElementSibling;
  if (open) {
    // Insert (or reveal) the detail row.
    const detail = document.createElement("tr");
    detail.className = "fa-row-detail";
    detail.setAttribute("data-detail-for", fid);
    detail.innerHTML = `<td></td><td colspan="6">${_faDetailHTML(f)}</td>`;
    row.parentNode.insertBefore(detail, nxt);
  } else if (nxt && nxt.classList.contains("fa-row-detail")
                 && nxt.getAttribute("data-detail-for") === fid) {
    nxt.remove();
  }
}
window._faToggleRowDetail = _faToggleRowDetail;

// Full detail block: entities table, MITRE rationale, FP notes,
// validation steps, evidence (raw plugin row).
function _faDetailHTML(f) {
  const sections = [];
  const ents = f.entities || {};
  const entKeys = Object.keys(ents);
  if (entKeys.length) {
    const rows = entKeys.map(k =>
      `<tr><th>${esc(k)}</th><td><code>${esc(ents[k])}</code></td></tr>`,
    ).join("");
    sections.push(`<div class="fa-detail-block"><div class="fa-detail-h">Entities</div><table class="fa-detail-kv">${rows}</table></div>`);
  }
  if (f.score != null) {
    sections.push(`<div class="fa-detail-block"><div class="fa-detail-h">Score</div><div>final score <code>${esc(f.score)}</code> → severity <strong>${esc((f.severity||"").toUpperCase())}</strong>, confidence <code>${esc(f.confidence ?? "?")}</code></div></div>`);
  }
  const mitre = f.mitre || [];
  if (mitre.length) {
    const rows = mitre.map(m => `
      <tr>
        <td><code>${esc(m.technique || "")}</code></td>
        <td>${esc(m.name || "")}</td>
        <td>${esc(m.tactic || "")}</td>
        <td style="opacity:.85">${esc(m.reason || "")}</td>
        <td><code>${esc(m.confidence ?? "")}</code></td>
      </tr>`).join("");
    sections.push(`<div class="fa-detail-block"><div class="fa-detail-h">MITRE ATT&CK</div><table class="fa-detail-mitre"><thead><tr><th>Technique</th><th>Name</th><th>Tactic</th><th>Reason</th><th>Conf.</th></tr></thead><tbody>${rows}</tbody></table></div>`);
  } else if ((f.tags || []).length) {
    // Legacy tags-only: no rationale to show.
    sections.push(`<div class="fa-detail-block"><div class="fa-detail-h">MITRE tags (legacy)</div><div>${(f.tags||[]).map(t=>`<code>${esc(t)}</code>`).join(" ")}</div></div>`);
  }
  if (f.false_positive_notes) {
    sections.push(`<div class="fa-detail-block"><div class="fa-detail-h">False-positive considerations</div><div class="fa-detail-prose">${esc(f.false_positive_notes)}</div></div>`);
  }
  if (f.recommended_validation) {
    sections.push(`<div class="fa-detail-block"><div class="fa-detail-h">Recommended analyst validation</div><div class="fa-detail-prose">${esc(f.recommended_validation)}</div></div>`);
  }
  const ev = f.evidence || {};
  const evKeys = Object.keys(ev);
  if (evKeys.length) {
    const rows = evKeys.map(k =>
      `<tr><th>${esc(k)}</th><td><code>${esc(ev[k])}</code></td></tr>`,
    ).join("");
    sections.push(`<div class="fa-detail-block"><div class="fa-detail-h">Evidence (raw plugin row)</div><table class="fa-detail-kv">${rows}</table></div>`);
  }
  return sections.join("") || `<div class="fa-detail-block"><em style="opacity:.55">No additional details for this finding.</em></div>`;
}
function _faAppendFinding(f) {
  const tb = $("fa-findings-tbody"); if (!tb) return;
  if (tb.querySelector(".fa-empty")) tb.innerHTML = "";
  AppState.fa.findings.push(f);
  tb.insertAdjacentHTML("beforeend", _faRowHTML(f));
  _faUpdateStats();
}
function _faSortByCriticalFirst() {
  const tb = $("fa-findings-tbody"); if (!tb || !AppState.fa.findings.length) return;
  const order = { critical:0, high:1, medium:2, low:3, info:4 };
  AppState.fa.findings.sort((a,b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9));
  tb.innerHTML = AppState.fa.findings.map(_faRowHTML).join("");
}
function _faRoute(evt) {
  switch (evt.type) {
    case "start":
      _faLog(`▶ triage started · plugins: ${(evt.plugins || []).join(", ")}`, "cmd"); break;
    case "plugin_start":
      _faLog(`[${evt.index}/${evt.total}] running ${evt.plugin}…`, "info"); break;
    case "plugin_done":
      AppState.fa.pluginsDone++; _faUpdateStats();
      if (evt.success) _faLog(`✓ ${evt.plugin} → ${evt.rows||0} rows · ${evt.elapsed||0}s`, "ok");
      else            _faLog(`✗ ${evt.plugin} failed: ${evt.error || "see logs"}`, "err");
      break;
    case "finding":
      _faAppendFinding(evt.finding);
      _faLog(`! ${evt.finding.id} ${evt.finding.severity.toUpperCase()} · ${evt.finding.title}`, evt.finding.severity === "critical" ? "err" : "warn"); break;
    case "rules_done":
      _faLog(`rule engine produced ${evt.total_findings} finding(s)`, "cmd"); _faSortByCriticalFirst(); break;
    case "saved":
      _faLog(`findings persisted → ${evt.path}`, "dim"); break;
    case "done":
      _faLog(`triage complete in ${evt.elapsed}s · ${evt.case_dir}`, "ok"); break;
    case "story_start":
      const sp = $("fa-story-panel"); if (sp) sp.style.display = ""; const sb = $("fa-story-body"); if (sb) sb.innerHTML = '<em style="opacity:.55">Generating attack story…</em>';
      const sm = $("fa-story-meta"); if (sm) sm.innerText = `${evt.findings_count} finding(s) sent to LLM`;
      _faLog("composing AI attack story…", "cmd"); break;
    case "story_token":
      AppState.fa.storyText += evt.content;
      const sb2 = $("fa-story-body"); if (sb2) sb2.innerHTML = md2html(AppState.fa.storyText); break;
    case "story_done":
      const sm2 = $("fa-story-meta"); if (sm2) sm2.innerText = `model: ${evt.model || "—"} · ${evt.usage?.output || 0} output tokens`;
      _faLog(`AI attack story done · model=${evt.model || "?"}`, "ok"); break;
    case "story_saved":
      _faLog(`attack story saved → ${evt.path}`, "dim"); break;
    case "all_done":
      _faFinalize(evt.phase === "story" ? "Analysis complete" : "Triage complete", "ok"); break;
    case "error":
      _faLog(`ERROR: ${evt.message}`, "err"); _faFinalize("Error", "err"); break;

    /* ── Phase 11: Full Analysis V2 optional events (additive) ──
       Unknown events are still safely ignored by the surrounding switch.
       Each handler updates a card / panel without touching V1 elements. */
    case "os_detected":         try { _fa2HandleOsDetected(evt); } catch (e) { console.warn("os_detected:", e); } break;
    case "plugin_plan":         try { _fa2HandlePluginPlan(evt); } catch (e) { console.warn("plugin_plan:", e); } break;
    case "artifact_normalized": try { _fa2HandleArtifactNormalized(evt); } catch (e) { console.warn("artifact_normalized:", e); } break;
    case "mitre_done":          try { _fa2HandleMitreDone(evt); } catch (e) { console.warn("mitre_done:", e); } break;
    case "correlation":         try { _fa2HandleCorrelation(evt); } catch (e) { console.warn("correlation:", e); } break;
    case "correlations_done":   try { _fa2HandleCorrelationsDone(evt); } catch (e) { console.warn("correlations_done:", e); } break;
    case "timeline_done":       try { _fa2HandleTimelineDone(evt); } catch (e) { console.warn("timeline_done:", e); } break;
    case "report_ready":        try { _fa2HandleReportReady(evt); } catch (e) { console.warn("report_ready:", e); } break;
    case "ai_report_start":     try { _fa2HandleAIReportStart(evt); } catch (e) { console.warn("ai_report_start:", e); } break;
    case "ai_report_token":     try { _fa2HandleAIReportToken(evt); } catch (e) { console.warn("ai_report_token:", e); } break;
    case "ai_report_done":      try { _fa2HandleAIReportDone(evt); } catch (e) { console.warn("ai_report_done:", e); } break;
    case "ai_report_error":     try { _fa2HandleAIReportError(evt); } catch (e) { console.warn("ai_report_error:", e); } break;
  }
}

/* ════════════════════════════════════════════════════════════════════════
   Phase 11 — Full Analysis V2 additive UI
   These helpers only read/write the new fa2-* DOM elements. They never
   touch the V1 findings table, story panel, or export button.
════════════════════════════════════════════════════════════════════════ */

AppState.fa2 = {
  os: null, symbolStatus: null,
  plannedPlugins: [], pluginsSucceeded: 0, pluginsFailed: 0,
  artifactCount: 0, mitreCount: 0, chains: [], chainsCount: 0,
  timelineTimed: 0, timelineUntimed: 0,
  reportMdPath: null, reportHtmlPath: null, reportPdfPath: null,
  reportMdRel: null, reportHtmlRel: null, reportPdfRel: null,
  pdfExportRunning: false,
  aiReportMdPath: null, aiReportText: "", aiReportRunning: false,
  // Phase A migration: V2 defaults to true on the server; we still wait
  // for /api/status to confirm so the UI doesn't pre-trust a default.
  featureFlags: {
    full_analysis_v2:                 false,
    full_analysis_legacy_v1:          false,
    full_analysis_optional_ai_report: false,
  },
};

function _fa2ShowOverview() {
  const el = document.getElementById("fa2-overview");
  if (el) el.style.display = "";
}

function _fa2SetText(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = String(text == null ? "" : text);
}

function _fa2ShowPanel(id) {
  const el = document.getElementById(id);
  if (el) el.style.display = "";
}

function _fa2HandleOsDetected(evt) {
  _fa2ShowOverview();
  AppState.fa2.os = evt.os || "unknown";
  AppState.fa2.symbolStatus = evt.symbol_status || "unknown";
  _fa2SetText("fa2-os-value", (evt.os || "unknown").toUpperCase());
  const conf = typeof evt.confidence === "number" ? evt.confidence : null;
  const sub = [evt.detected_by, conf != null ? `conf ${conf.toFixed(2)}` : null,
               evt.kernel, evt.arch].filter(Boolean).join(" · ");
  _fa2SetText("fa2-os-sub", sub);
  _fa2SetText("fa2-symbols-value", (evt.symbol_status || "unknown").toUpperCase());
  if ((evt.warnings || []).length) {
    _fa2SetText("fa2-symbols-sub", `${evt.warnings.length} warning(s)`);
  }
}

function _fa2HandlePluginPlan(evt) {
  _fa2ShowOverview();
  AppState.fa2.plannedPlugins = Array.isArray(evt.plugins) ? evt.plugins : [];
  // plugins-ok / plugins-fail are updated incrementally from plugin_done; here
  // we only track the planned total.
  _fa2SetText("fa2-plugins-ok", AppState.fa2.pluginsSucceeded);
  _fa2SetText("fa2-plugins-fail", AppState.fa2.pluginsFailed);
}

// Wrap _faRoute's plugin_done to also tally V2 success/failure for the cards.
// We do this by listening to the same event from the existing case branch;
// the V2 card is updated alongside. Safe because plugin_done already exists.
const _faRouteV2OriginalPluginDone = (function () {
  // No-op factory — the wrapping is done inline below via a sub-handler that
  // _faRoute invokes via the new "plugin_done" branch handler. We instead
  // hook AppState.fa.pluginsDone++ at the call site below.
  return null;
})();

// Inline tally hook: every successful/failed plugin_done event bumps cards.
(function _patchPluginDoneForV2() {
  const _origFa2HandleAIReportStart = _fa2HandleAIReportStart; // forward decl alias
})();

function _fa2HandleArtifactNormalized(evt) {
  _fa2ShowOverview();
  AppState.fa2.artifactCount = typeof evt.total === "number" ? evt.total : 0;
  // Surface skipped plugins in the existing log only when present.
  const skipped = (evt.skipped || []).length;
  if (skipped) _faLog(`normalized ${evt.total} artifact(s), skipped ${skipped}`, "dim");
}

function _fa2HandleMitreDone(evt) {
  _fa2ShowOverview();
  AppState.fa2.mitreCount = evt.technique_count || 0;
  _fa2SetText("fa2-mitre-count", AppState.fa2.mitreCount);
  _fa2ShowPanel("fa2-mitre-panel");
  const meta = document.getElementById("fa2-mitre-meta");
  if (meta) meta.textContent = `${evt.technique_count || 0} technique(s) · ${(evt.tactics || []).length} tactic(s)`;
  const body = document.getElementById("fa2-mitre-body");
  if (body) {
    const tactics = evt.tactics || [];
    body.innerHTML = tactics.length
      ? `<div class="fa2-mitre-tactics">${tactics.map(t => `<span class="fa2-tactic">${esc(t)}</span>`).join("")}</div>`
      : '<em style="opacity:.55">No MITRE techniques produced.</em>';
  }
}

function _fa2HandleCorrelation(evt) {
  _fa2ShowOverview();
  AppState.fa2.chains.push(evt);
  _fa2ShowPanel("fa2-chains-panel");
  const body = document.getElementById("fa2-chains-body");
  if (body) {
    // First real chain arriving — clear the empty-state placeholder.
    if (body.classList.contains("fa2-empty")) {
      body.classList.remove("fa2-empty");
      body.innerHTML = "";
    }
    const row = document.createElement("div");
    row.className = "fa2-chain-row";
    const sev = (evt.severity || "info").toLowerCase();
    row.innerHTML = `
      <div class="fa2-chain-id">${esc(evt.chain_id || "")}</div>
      <div class="fa2-chain-title">
        ${esc(evt.title || "")}
        <span class="sev-pill sev-${sev}">${sev.toUpperCase()}</span>
      </div>
      <div class="fa2-chain-meta">
        confidence ${typeof evt.confidence === "number" ? evt.confidence.toFixed(2) : "?"} ·
        findings ${(evt.findings || []).map(f => `<code>${esc(f)}</code>`).join(", ") || "—"}
      </div>`;
    body.appendChild(row);
  }
}

function _fa2HandleCorrelationsDone(evt) {
  _fa2ShowOverview();
  AppState.fa2.chainsCount = evt.chain_count || 0;
  _fa2SetText("fa2-chains-count", AppState.fa2.chainsCount);
  const meta = document.getElementById("fa2-chains-meta");
  if (meta) meta.textContent = `${evt.chain_count || 0} chain(s) · ${evt.findings_in_chains || 0} finding(s)`;
}

function _fa2HandleTimelineDone(evt) {
  _fa2ShowOverview();
  AppState.fa2.timelineTimed = evt.timed || 0;
  AppState.fa2.timelineUntimed = evt.untimed || 0;
  _fa2ShowPanel("fa2-timeline-panel");
  const meta = document.getElementById("fa2-timeline-meta");
  if (meta) meta.textContent = `${evt.timed || 0} timed · ${evt.untimed || 0} untimed`;
  const body = document.getElementById("fa2-timeline-body");
  if (body) {
    const e = (evt.earliest || "—"), l = (evt.latest || "—");
    body.innerHTML = (evt.timed || 0) === 0
      ? '<em style="opacity:.55">No timed events available.</em>'
      : `<div class="fa2-timeline-summary">
           <div><b>${evt.timed || 0}</b> timed events</div>
           <div>${evt.untimed || 0} untimed</div>
           <div>earliest: <code>${esc(e)}</code></div>
           <div>latest: <code>${esc(l)}</code></div>
         </div>`;
  }
}

function _fa2HandleReportReady(evt) {
  _fa2ShowOverview();
  AppState.fa2.reportMdPath = evt.md_path || null;
  AppState.fa2.reportHtmlPath = evt.html_path || null;
  AppState.fa2.reportMdRel = evt.md_rel || null;
  AppState.fa2.reportHtmlRel = evt.html_rel || null;
  // A fresh Full Analysis invalidates the previously exported PDF.
  AppState.fa2.reportPdfPath = null;
  AppState.fa2.reportPdfRel = null;
  _fa2SetText("fa2-report-status", "ready");
  _fa2ShowPanel("fa2-report-panel");
  const meta = document.getElementById("fa2-report-meta");
  if (meta) {
    meta.textContent = `${evt.findings_count || 0} finding(s) · ${evt.chains_count || 0} chain(s) · ${evt.techniques_count || 0} technique(s)`;
  }
  _fa2RenderReportLinks();
  // Enable the PDF export button now that the deterministic report is on disk.
  _fa2MaybeShowPdfExportButton();
  // Refresh the AI Report button gate (now that we have report_ready).
  _fa2MaybeShowAIReportButton();
}

// Render the report.md / report.html / report.pdf link row.
// Shows only the file basename (e.g. "report.md") — not the full server
// path — but the href/download still routes through the safe
// /api/outputs/download endpoint so the file is actually downloadable.
function _fa2RenderReportLinks() {
  const links = document.getElementById("fa2-report-links");
  if (!links) return;
  links.classList.remove("fa2-empty-inline");
  links.innerHTML = "";
  const entries = [
    ["report.md",   AppState.fa2.reportMdPath,   AppState.fa2.reportMdRel,   "fa-file-lines"],
    ["report.html", AppState.fa2.reportHtmlPath, AppState.fa2.reportHtmlRel, "fa-file-code"],
    ["report.pdf",  AppState.fa2.reportPdfPath,  AppState.fa2.reportPdfRel,  "fa-file-pdf"],
  ];
  for (const [label, p, rel, icon] of entries) {
    if (!p) continue;
    if (rel) {
      const a = document.createElement("a");
      a.className = "fa2-link fa2-link-clickable";
      a.href = `/api/outputs/download?name=${encodeURIComponent(rel)}`;
      a.setAttribute("download", label);
      a.target = "_blank";
      a.innerHTML = `<i class="fa-solid ${icon}"></i> <code>${esc(label)}</code>`;
      a.title = `${label} — click to download`;
      links.appendChild(a);
    } else {
      const sp = document.createElement("span");
      sp.className = "fa2-link";
      sp.innerHTML = `<i class="fa-solid ${icon}"></i> <code>${esc(label)}</code>`;
      sp.title = `${label} — saved on server`;
      links.appendChild(sp);
    }
  }
}

function _fa2MaybeShowAIReportButton() {
  // The AI Report is an *optional* secondary action gated by a Settings
  // toggle. We never leak the raw env-var name into the UI — when the
  // feature is off the whole section is hidden and a friendly hint
  // points the user at Settings instead.
  const ff = AppState.fa2.featureFlags || {};
  const section = document.getElementById("fa2-ai-report-section");
  const hint    = document.getElementById("fa2-ai-report-hint");
  const btn     = document.getElementById("fa2-ai-report-btn");
  const status  = document.getElementById("fa2-ai-report-status");

  const flagOn  = !!ff.full_analysis_optional_ai_report;
  const ready   = !!AppState.fa2.reportMdPath;
  const running = !!AppState.fa2.aiReportRunning;

  if (section) section.style.display = flagOn ? "" : "none";
  if (hint)    hint.style.display    = flagOn ? "none" : "";

  if (!btn) return;
  let reason = "";
  if (running)      reason = "generating…";
  else if (!ready)  reason = "awaiting Full Analysis completion";
  else              reason = "ready";

  btn.disabled = !(flagOn && ready) || running;
  btn.title = btn.disabled
    ? `Disabled: ${reason}`
    : "Generate a detailed AI report from the completed Full Analysis results.";
  if (status) status.textContent = reason;
}

// Gate for the deterministic "Download PDF Report" button. Enabled once
// report.md exists on disk (i.e. report_ready has fired). The export
// itself is a pure file-on-disk transform — no Volatility, no AI.
function _fa2MaybeShowPdfExportButton() {
  const btn = document.getElementById("fa2-pdf-export-btn");
  const status = document.getElementById("fa2-pdf-export-status");
  if (!btn) return;

  const ready   = !!AppState.fa2.reportMdPath;
  const running = !!AppState.fa2.pdfExportRunning;

  let reason;
  if (running)     reason = "generating PDF…";
  else if (!ready) reason = "awaiting Full Analysis completion";
  else             reason = "ready";

  btn.disabled = !ready || running;
  btn.title = btn.disabled
    ? `Disabled: ${reason}`
    : "Export the deterministic Markdown/HTML report as a PDF.";
  if (status) status.textContent = reason;
}

function _fa2HandleAIReportStart(evt) {
  _fa2ShowPanel("fa2-report-panel");
  AppState.fa2.aiReportText = "";
  AppState.fa2.aiReportRunning = true;
  const body = document.getElementById("fa2-ai-report-body");
  const status = document.getElementById("fa2-ai-report-status");
  const btn = document.getElementById("fa2-ai-report-btn");
  if (body) { body.style.display = ""; body.innerHTML = '<em style="opacity:.55">Generating AI Report…</em>'; }
  if (status) status.textContent = `${evt.findings_count || 0} findings · model ${evt.model || "?"}`;
  if (btn) btn.disabled = true;
}

function _fa2HandleAIReportToken(evt) {
  AppState.fa2.aiReportText += (evt.content || "");
  const body = document.getElementById("fa2-ai-report-body");
  if (body) body.innerHTML = md2html(AppState.fa2.aiReportText);
}

function _fa2HandleAIReportDone(evt) {
  AppState.fa2.aiReportRunning = false;
  AppState.fa2.aiReportMdPath  = evt.md_path || evt.path || null;
  AppState.fa2.aiReportHtmlPath = evt.html_path || null;
  AppState.fa2.aiReportPdfPath  = evt.pdf_path  || null;

  const body = document.getElementById("fa2-ai-report-body");
  const status = document.getElementById("fa2-ai-report-status");
  const btn = document.getElementById("fa2-ai-report-btn");
  if (body && evt.text) body.innerHTML = md2html(evt.text);

  let statusText = `done · ${evt.model || ""} · ${(evt.usage?.output || 0)} tokens`;
  if (evt.pdf_error && !evt.pdf_path) {
    statusText += " · pdf: skipped";
  }
  if (status) status.textContent = statusText;
  if (btn) btn.disabled = false;

  const links = document.getElementById("fa2-ai-report-links");
  if (links) {
    const chips = [];
    // Each link chip is now a real <a> tag pointing at /api/outputs/download
    // so the user can open or save the file directly from the browser.
    const add = (label, rel, path, icon) => {
      if (!path) return;
      const href = rel
        ? `/api/outputs/download?name=${encodeURIComponent(rel)}`
        : null;
      if (href) {
        chips.push(`<a class="fa2-link fa2-link-clickable" href="${href}" target="_blank" download title="${esc(label)} — click to download"><i class="fa-solid ${icon}"></i> <code>${esc(path)}</code></a>`);
      } else {
        chips.push(`<span class="fa2-link" title="${esc(label)} — saved at this absolute path on the server"><i class="fa-solid ${icon}"></i> <code>${esc(path)}</code></span>`);
      }
    };
    add("Markdown source (canonical)",  evt.md_rel,   AppState.fa2.aiReportMdPath,   "fa-file-lines");
    add("HTML rendered from Markdown",  evt.html_rel, AppState.fa2.aiReportHtmlPath, "fa-file-code");
    add("PDF rendered from Markdown",   evt.pdf_rel,  AppState.fa2.aiReportPdfPath,  "fa-file-pdf");
    if (evt.pdf_error && !evt.pdf_path) {
      chips.push(`<span class="fa2-link" title="${esc(evt.pdf_error)}" style="color:var(--t2);font-style:italic"><i class="fa-solid fa-circle-info"></i> PDF not produced (hover for reason)</span>`);
    }
    links.innerHTML = chips.join("") || "—";
    // Add a persistent "Download PDF" button (kept around so the user
    // can grab the file again later without re-running the AI Report).
    if (evt.pdf_rel && AppState.fa2.aiReportPdfPath) {
      const dlBtn = document.createElement("a");
      dlBtn.className = "cta-main sm";
      dlBtn.href = `/api/outputs/download?name=${encodeURIComponent(evt.pdf_rel)}`;
      dlBtn.setAttribute("download", "ai_report.pdf");
      dlBtn.target = "_blank";
      dlBtn.innerHTML = '<i class="fa-solid fa-file-pdf"></i> Download PDF';
      dlBtn.style.marginLeft = "8px";
      if (btn && btn.parentNode) {
        const prev = document.getElementById("fa2-ai-report-dl-pdf");
        if (prev) prev.remove();
        dlBtn.id = "fa2-ai-report-dl-pdf";
        btn.parentNode.insertBefore(dlBtn, btn.nextSibling);
      }
      // Auto-trigger the download immediately on completion. Uses a
      // throwaway anchor with the `download` attribute so the browser
      // saves to the user's Downloads folder instead of navigating.
      _fa2TriggerAutoDownload(evt.pdf_rel, "ai_report.pdf");
    }
  }
}

// Trigger an immediate file download via a synthetic <a download> click.
// Used right after the AI Report PDF is produced so the user doesn't need
// to hunt for the download button — the browser saves it automatically.
function _fa2TriggerAutoDownload(relPath, suggestedName) {
  if (!relPath) return;
  try {
    const a = document.createElement("a");
    a.href = `/api/outputs/download?name=${encodeURIComponent(relPath)}`;
    a.download = suggestedName || "";
    // Keep it off-screen + out of layout flow.
    a.style.display = "none";
    document.body.appendChild(a);
    a.click();
    setTimeout(() => a.remove(), 250);
    // Briefly reflect the action in the status text so the user notices.
    const status = document.getElementById("fa2-ai-report-status");
    if (status) {
      const orig = status.textContent;
      status.textContent = `${orig} · ⤓ downloading ${suggestedName}`;
      setTimeout(() => { if (status.textContent.endsWith(`⤓ downloading ${suggestedName}`)) status.textContent = orig; }, 4000);
    }
  } catch (e) {
    console.warn("auto-download failed:", e);
  }
}

function _fa2HandleAIReportError(evt) {
  AppState.fa2.aiReportRunning = false;
  const body = document.getElementById("fa2-ai-report-body");
  const status = document.getElementById("fa2-ai-report-status");
  const btn = document.getElementById("fa2-ai-report-btn");
  if (body) { body.style.display = ""; body.innerHTML = `<span style="color:var(--red)">${esc(evt.message || "AI Report failed")}</span>`; }
  if (status) status.textContent = "error";
  if (btn) btn.disabled = false;
}

// User-triggered: explicit click on the Generate AI Report button.
async function runAIReport() {
  if (AppState.fa2.aiReportRunning) return;
  const ff = AppState.fa2.featureFlags || {};
  if (!ff.full_analysis_optional_ai_report) {
    toast("AI Report is disabled (server flag is OFF).", "warn");
    return;
  }
  if (!AppState.currentFile) {
    toast("Load a memory image and run Full Analysis first.", "warn");
    return;
  }
  AppState.fa2.aiReportRunning = true;
  const btn = document.getElementById("fa2-ai-report-btn");
  if (btn) btn.disabled = true;

  try {
    const r = await m3mxFetch("/api/full-analysis/ai-report", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    if (!r.ok) {
      let msg = `${r.status} ${r.statusText}`;
      try { const j = await r.json(); msg = j.error || msg; } catch {}
      _fa2HandleAIReportError({ message: msg });
      return;
    }
    if (!r.body) { _fa2HandleAIReportError({ message: "no response stream" }); return; }
    const reader = r.body.getReader(); const dec = new TextDecoder(); let buf = "";
    while (true) {
      const { value, done } = await reader.read(); if (done) break;
      buf += dec.decode(value, { stream: true });
      let idx;
      while ((idx = buf.indexOf("\n\n")) !== -1) {
        const block = buf.slice(0, idx); buf = buf.slice(idx + 2);
        const lines = block.split("\n").filter(l => l.startsWith("data:"));
        if (!lines.length) continue;
        try { _faRoute(JSON.parse(lines.map(l => l.slice(5).trimStart()).join("\n"))); }
        catch (e) { console.warn("bad AI Report chunk:", e); }
      }
    }
  } catch (e) {
    _fa2HandleAIReportError({ message: e.message || String(e) });
  } finally {
    AppState.fa2.aiReportRunning = false;
  }
}
window.runAIReport = runAIReport;

// User-triggered: explicit click on the Download PDF Report button.
//
// Renders the deterministic report as a PDF by hitting the
// `/api/full-analysis/export-pdf` endpoint, which performs the
// pure file-on-disk transform:
//
//     report.md  →  report.html  →  report.pdf
//
// No AI is invoked. Volatility is NOT re-run. The downloaded file is
// fetched through the existing safe /api/outputs/download endpoint.
async function exportReportPdf() {
  if (AppState.fa2.pdfExportRunning) return;
  if (!AppState.fa2.reportMdPath) {
    toast("Run Full Analysis first before exporting a PDF.", "warn");
    return;
  }
  AppState.fa2.pdfExportRunning = true;
  _fa2MaybeShowPdfExportButton();
  try {
    const r = await m3mxFetch("/api/full-analysis/export-pdf", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    let j = {};
    try { j = await r.json(); } catch {}
    if (!r.ok) {
      const msg = j.error || `${r.status} ${r.statusText}`;
      toast(`PDF export failed: ${msg}`, "error");
      return;
    }
    AppState.fa2.reportPdfPath = j.pdf_path || null;
    AppState.fa2.reportPdfRel  = j.pdf_rel  || null;
    if (j.md_rel)   AppState.fa2.reportMdRel   = j.md_rel;
    if (j.html_rel) AppState.fa2.reportHtmlRel = j.html_rel;
    _fa2RenderReportLinks();
    if (j.pdf_rel) {
      _fa2TriggerAutoDownload(j.pdf_rel, "report.pdf");
      toast("Report exported as PDF", "ok");
    } else if (j.pdf_error) {
      toast(`PDF export failed: ${j.pdf_error}`, "error");
    }
  } catch (e) {
    toast(`PDF export failed: ${e.message || e}`, "error");
  } finally {
    AppState.fa2.pdfExportRunning = false;
    _fa2MaybeShowPdfExportButton();
  }
}
window.exportReportPdf = exportReportPdf;

// Tally plugin success/failure for the V2 overview card. The V1 _faRoute
// branch fires for every plugin_done event; this hook reads the same event
// after _faRoute returns by patching _faRoute once at module init.
(function _fa2InstallPluginDoneTally() {
  if (typeof _faRoute !== "function") return;
  const orig = _faRoute;
  // eslint-disable-next-line no-func-assign
  _faRoute = function (evt) {
    const r = orig(evt);
    if (evt && evt.type === "plugin_done") {
      if (evt.success) AppState.fa2.pluginsSucceeded++;
      else             AppState.fa2.pluginsFailed++;
      _fa2SetText("fa2-plugins-ok",   AppState.fa2.pluginsSucceeded);
      _fa2SetText("fa2-plugins-fail", AppState.fa2.pluginsFailed);
    } else if (evt && evt.type === "rules_done") {
      // Update Critical/High card off the current findings list.
      const crit = AppState.fa.findings.filter(f => (f.severity||"").toLowerCase() === "critical").length;
      const high = AppState.fa.findings.filter(f => (f.severity||"").toLowerCase() === "high").length;
      _fa2SetText("fa2-crit", crit);
      _fa2SetText("fa2-high", high);
    }
    return r;
  };
})();

// On boot, fetch /api/status so the AI Report button reflects the
// resolved server-side feature-flag state. The button stays visible
// either way; the gate function decides whether it's enabled.
(function _fa2LoadFeatureFlags() {
  if (typeof fetch !== "function") {
    _fa2MaybeShowAIReportButton();
    return;
  }
  m3mxFetch("/api/status").then(r => r.ok ? r.json() : null).then(d => {
    if (d && d.features) {
      AppState.fa2.featureFlags = {
        full_analysis_v2:                  !!d.features.full_analysis_v2,
        full_analysis_legacy_v1:           !!d.features.full_analysis_legacy_v1,
        full_analysis_optional_ai_report:  !!d.features.full_analysis_optional_ai_report,
      };
    }
  }).catch(() => { /* silent — defaults stay off */ })
    .finally(() => _fa2MaybeShowAIReportButton());
})();
function _faFinalize(label, kind) {
  AppState.fa.running = false;
  if (AppState.fa.elapsedTimer) clearInterval(AppState.fa.elapsedTimer);
  _faSetStatus(label, kind || "ok");
  const btn = $("fa-start-btn"); if (btn) { btn.disabled = false; btn.innerHTML = '<i class="fa-solid fa-rocket"></i> Start Full Analysis'; }
  if ($("fa-export-btn")) $("fa-export-btn").disabled = !AppState.fa.findings.length && !AppState.fa.storyText;
}

async function runFullSuite() {
  if (AppState.fa.running) return;
  if (!AppState.currentFile) { toast("Upload a memory image first.", "warn"); return; }
  Object.assign(AppState.fa, { running: true, findings: [], storyText: "", t0: Date.now(), pluginsDone: 0 });
  const tb = $("fa-findings-tbody"); if (tb) tb.innerHTML = "";
  const sp = $("fa-story-panel"); if (sp) sp.style.display = "none";
  _faClearLog(); _faUpdateStats();
  AppState.fa.elapsedTimer = setInterval(_faTickElapsed, 1000);
  _faSetStatus("Running", "loading");
  const btn = $("fa-start-btn"); if (btn) { btn.disabled = true; btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Running…'; }
  if ($("fa-export-btn")) $("fa-export-btn").disabled = true;
  try {
    const r = await m3mxFetch("/api/full-analysis", { method: "POST", headers: {"Content-Type":"application/json"}, body: JSON.stringify({}) });
    if (!r.ok || !r.body) throw new Error(`HTTP ${r.status}`);
    const reader = r.body.getReader(); const dec = new TextDecoder(); let buf = "";
    while (true) {
      const { value, done } = await reader.read(); if (done) break;
      buf += dec.decode(value, { stream: true });
      let idx;
      while ((idx = buf.indexOf("\n\n")) !== -1) {
        const block = buf.slice(0, idx); buf = buf.slice(idx + 2);
        const lines = block.split("\n").filter(l => l.startsWith("data:"));
        if (!lines.length) continue;
        const json = lines.map(l => l.slice(5).trimStart()).join("\n");
        try { _faRoute(JSON.parse(json)); } catch (e) { console.warn("bad SSE chunk:", json); }
      }
    }
  } catch (e) { _faLog(`stream failed: ${e.message}`, "err"); _faFinalize("Error", "err"); }
}
window.runFullSuite = runFullSuite;
