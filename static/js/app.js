/* ════════════════════════════════════════════════════════════════════════
   m3mx CORTEX — frontend integration
   Wires the new design to the existing Flask backend (untouched):
     /api/upload, /api/loaded-image, /api/settings, /api/fs/*,
     /api/plugins, /api/run-plugin, /api/run-plugin/stream,
     /api/agent/chat, /api/agent/test,
     /api/full-analysis, /api/full-analysis/case,
     /api/files/scan, /api/files/preview, /api/files/extract,
     /api/status
   100% feature parity with the previous implementation.
════════════════════════════════════════════════════════════════════════ */

/* ── helpers ──────────────────────────────────────────────────────────── */
const $  = (id) => document.getElementById(id);
const $$ = (sel, root = document) => root.querySelectorAll(sel);
const esc = (s) => String(s ?? "")
  .replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;")
  .replace(/"/g,"&quot;").replace(/'/g,"&#039;");
const debounce = (fn, ms) => { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; };
const fmtBytes = (n) => {
  if (n == null) return "—";
  const u = ["B","KB","MB","GB","TB"]; let i = 0; let v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(1)} ${u[i]}`;
};
const fmtTime = (d = new Date()) => d.toTimeString().slice(0,8);

const API = {
  async get (url)        { const r = await fetch(url);                                                                              if (!r.ok) throw new Error(`${r.status} ${r.statusText}`); return r.json(); },
  async post(url, body)  { const r = await fetch(url,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body||{})}); if (!r.ok) throw new Error(`${r.status} ${r.statusText}`); return r.json(); },
};

/* ── app state ────────────────────────────────────────────────────────── */
const AppState = {
  currentFile: null,            // { filename, path, size, size_human }
  serverConfig: null,
  pluginRegistry: null,         // /api/plugins response
  pluginByShortName: {},        // { short → plugin meta }
  activePlugin: null,           // currently-selected manual-analysis plugin
  lastPluginResult: null,       // for export buttons
  chatHistory: [],
  fa: {                         // Full Analysis state
    running: false, findings: [], storyText: "", t0: 0, pluginsDone: 0, elapsedTimer: null,
  },
  ext: {                        // Extractor state
    files: [], selected: null, selectedRow: null, previewCache: {},
  },
};
window.AppState = AppState;

/* ── toasts ───────────────────────────────────────────────────────────── */
function toast(msg, kind = "info", timeout = 3500) {
  const host = $("toasts") || (() => { const e = document.createElement("div"); e.id = "toasts"; document.body.appendChild(e); return e; })();
  const el = document.createElement("div");
  el.className = `m3mx-toast m3mx-toast-${kind}`;
  const icon = kind === "ok" ? "fa-circle-check"
            : kind === "error" ? "fa-circle-xmark"
            : kind === "warn"  ? "fa-triangle-exclamation"
            : "fa-circle-info";
  el.innerHTML = `<i class="fa-solid ${icon}"></i><span>${esc(msg)}</span>`;
  host.appendChild(el);
  requestAnimationFrame(() => el.classList.add("show"));
  setTimeout(() => { el.classList.remove("show"); setTimeout(() => el.remove(), 250); }, timeout);
}
window.toast = toast;

/* ════════════════════════════════════════════════════════════════════════
   BOOT, NAV, THEME, BACKGROUND
════════════════════════════════════════════════════════════════════════ */
window.addEventListener("DOMContentLoaded", () => {
  let pct = 0, logIdx = 0;
  const bootPct = $("bootPct"), bootRing = $("bootRing"), bootLog = $("bootLog"),
        boot = $("boot"), appShell = $("app");
  const logs = ["Calibrating neural interface…","Loading Volatility framework…","Establishing secure connection…","Initializing Cortex engine…","System Ready."];
  const t = setInterval(() => {
    pct += Math.floor(Math.random() * 15) + 5; if (pct > 100) pct = 100;
    if (bootPct) bootPct.innerText = pct;
    if (bootRing) bootRing.style.strokeDashoffset = 553 - (pct / 100 * 553);
    if (pct % 25 === 0 && logIdx < logs.length && bootLog) bootLog.innerText = logs[logIdx++];
    if (pct === 100) {
      clearInterval(t);
      setTimeout(() => {
        if (boot) boot.style.opacity = "0";
        setTimeout(() => {
          if (boot) boot.style.display = "none";
          if (appShell) appShell.classList.remove("hidden");
          initNeuralCanvas(); initApp();
        }, 500);
      }, 500);
    }
  }, 150);
});

let lastClickX = innerWidth/2, lastClickY = innerHeight/2;
document.addEventListener("click", (e) => { lastClickX = e.clientX; lastClickY = e.clientY; }, true);

let currentView = "home";
function navigateTo(view, ev) {
  if (view === currentView) return;
  let ox = lastClickX, oy = lastClickY;
  if (ev) { ox = ev.clientX; oy = ev.clientY; }
  $$(".pn-btn").forEach(b => b.classList.toggle("active", (b.getAttribute("onclick") || "").includes(`'${view}'`)));
  const reveal = $("screenReveal");
  if (!reveal) { swapScene(view); return; }
  reveal.style.left = ox + "px"; reveal.style.top = oy + "px";
  reveal.classList.add("animating"); void reveal.offsetWidth;
  reveal.style.transform = "translate(-50%, -50%) scale(1)";
  setTimeout(() => {
    swapScene(view);
    reveal.style.opacity = "0";
    setTimeout(() => { reveal.classList.remove("animating"); reveal.style.transform = "translate(-50%, -50%) scale(0)"; reveal.style.opacity = ""; }, 400);
  }, 550);
}
function swapScene(view) { $$(".scene").forEach(el => el.classList.remove("active")); const t = $("scene-" + view); if (t) t.classList.add("active"); currentView = view; }
window.navigateTo = navigateTo; window.swapScene = swapScene;

function setTheme(v) { document.documentElement.setAttribute("data-theme", v || "dark"); }
function toggleTheme() {
  const cur = document.documentElement.getAttribute("data-theme") || "dark";
  setTheme(cur === "dark" ? "light" : "dark");
  if ($("theme-select")) $("theme-select").value = cur === "dark" ? "light" : "dark";
}
window.setTheme = setTheme; window.toggleTheme = toggleTheme;

function toggleAlerts() { $("alertDrawer")?.classList.toggle("hidden"); }
function clearAlerts()  { const l = $("alertList"); if (l) l.innerHTML = '<div style="padding:14px;color:var(--t2);font-family:var(--fm);font-size:.7rem">No alerts</div>'; const d = $("alertDot"); if (d) d.style.display = "none"; }
window.toggleAlerts = toggleAlerts; window.clearAlerts = clearAlerts;

function initNeuralCanvas() {
  const c = $("neural"); if (!c) return; const ctx = c.getContext("2d");
  c.width = innerWidth; c.height = innerHeight;
  addEventListener("resize", () => { c.width = innerWidth; c.height = innerHeight; });
  const ps = Array.from({length: 20}, () => ({ x: Math.random()*c.width, y: Math.random()*c.height, vx:(Math.random()-0.5)*0.3, vy:(Math.random()-0.5)*0.3 }));
  (function draw() {
    ctx.clearRect(0,0,c.width,c.height);
    ctx.fillStyle="rgba(255,255,255,0.5)"; ctx.strokeStyle="rgba(255,255,255,0.1)";
    ps.forEach(p => { p.x+=p.vx; p.y+=p.vy; if(p.x<0||p.x>c.width)p.vx*=-1; if(p.y<0||p.y>c.height)p.vy*=-1; ctx.beginPath(); ctx.arc(p.x,p.y,1.5,0,Math.PI*2); ctx.fill(); });
    for (let i=0;i<ps.length;i++) for (let j=i+1;j<ps.length;j++) {
      const dx=ps[i].x-ps[j].x, dy=ps[i].y-ps[j].y;
      if (Math.hypot(dx,dy)<150) { ctx.beginPath(); ctx.moveTo(ps[i].x,ps[i].y); ctx.lineTo(ps[j].x,ps[j].y); ctx.stroke(); }
    }
    requestAnimationFrame(draw);
  })();
}
function toggleParticles(el) { el.classList.toggle("on"); const c = $("neural"); if (c) c.style.display = el.classList.contains("on") ? "block" : "none"; }
function toggleGrain(el)     { el.classList.toggle("on"); const g = document.querySelector(".grain"); if (g) g.style.display = el.classList.contains("on") ? "block" : "none"; }
window.toggleParticles = toggleParticles; window.toggleGrain = toggleGrain;

/* ════════════════════════════════════════════════════════════════════════
   IMAGE UPLOAD + SESSION STATE
════════════════════════════════════════════════════════════════════════ */
async function handleFile(e) {
  const f = e?.target?.files?.[0]; if (!f) return;
  const sbText = $("sbText"), sbDot = $("sbDot");
  if (sbText) sbText.innerText = `Uploading ${f.name}…`;
  if (sbDot)  sbDot.classList.remove("on");
  const ev = $("panel-evidence-name"); if (ev) ev.innerText = f.name;
  const sc = $("panel-status-chip");   if (sc) { sc.innerText = "Uploading"; sc.className = "status-chip status-chip-loading"; }

  const fd = new FormData(); fd.append("image", f);
  try {
    const r = await fetch("/api/upload", { method: "POST", body: fd });
    if (!r.ok) {
      const j = await r.json().catch(() => ({}));
      // Friendlier messages for the common failure classes.
      if (r.status === 507) {
        const freeMB     = j.free_bytes     != null ? Math.round(j.free_bytes/1048576)     : null;
        const requiredMB = j.required_bytes != null ? Math.round(j.required_bytes/1048576) : null;
        const detail = freeMB != null
          ? ` Server has ${freeMB} MB free; needs ~${requiredMB} MB. Free space and retry.`
          : "";
        throw new Error("Insufficient disk space on the server." + detail);
      }
      if (r.status === 413) throw new Error("File is larger than the server allows. Bump MAX_CONTENT_LENGTH or the reverse-proxy limit.");
      if (r.status === 400 && (j.error || "").toLowerCase().includes("unsupported"))
        throw new Error(`${j.error}. Supported: .raw .mem .dmp .vmem .bin .lime .img`);
      throw new Error(j.error || `${r.status} ${r.statusText}`);
    }
    const data = await r.json();
    AppState.currentFile = data;
    if (sbText) sbText.innerText = `${data.filename} · ${data.size_human || fmtBytes(data.size)}`;
    if (sbDot)  sbDot.classList.add("on");
    if (ev) ev.innerText = data.filename;
    if (sc) { sc.innerText = "Loaded"; sc.className = "status-chip status-chip-ok"; }
    const aiImg = $("aiImg"); if (aiImg) aiImg.innerText = data.filename;
    const fa = $("fa-image-label"); if (fa) fa.innerText = data.path || data.filename;
    toast(`Loaded ${data.filename} (${data.size_human || fmtBytes(data.size)})`, "ok");
  } catch (err) {
    if (sbText) sbText.innerText = "Upload failed";
    if (sc) { sc.innerText = "Error"; sc.className = "status-chip status-chip-err"; }
    toast(`Upload failed: ${err.message}`, "error", 8000);
  }
}
function loadDemo() { toast("Drop a real .raw/.mem/.dmp via the upload panel.", "warn"); }
window.handleFile = handleFile; window.loadDemo = loadDemo;

/* ════════════════════════════════════════════════════════════════════════
   OUTPUT DIRECTORY (Home panel) — picker + persist
════════════════════════════════════════════════════════════════════════ */
async function _saveOutputDir() {
  const v = ($("output-dir")?.value || "").trim();
  if (!v) { toast("Type a path first or click the folder icon.", "warn"); return; }
  const btn = $("save-dir-btn"); const orig = btn ? btn.innerHTML : "";
  if (btn) { btn.disabled = true; btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i>'; }
  try {
    const merged = await API.post("/api/settings", { output: { directory: v } });
    AppState.serverConfig = merged;
    if ($("output-directory")) $("output-directory").value = merged?.output?.directory || v;
    toast(`Output directory saved: ${merged?.output?.directory || v}`, "ok");
  } catch (e) { toast(`Save failed: ${e.message}`, "error"); }
  finally { if (btn) { btn.disabled = false; btn.innerHTML = orig; } }
}
async function _browseOutputDir() {
  const btn = $("browse-dir-btn"); const orig = btn ? btn.innerHTML : "";
  if (btn) { btn.disabled = true; btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i>'; }
  try {
    const r = await fetch("/api/fs/pick-dir-native", { method: "POST", headers: {"Content-Type":"application/json"}, body: JSON.stringify({ start: $("output-dir")?.value?.trim() || undefined }) });
    const body = await r.json();
    if (!r.ok) throw new Error(body.error || `HTTP ${r.status}`);
    if (body.cancelled) { toast("Folder selection cancelled", "info"); return; }
    if (body.path) { $("output-dir").value = body.path; toast(`Selected: ${body.path} — click 💾 to persist`, "ok"); }
  } catch (e) { toast(`Picker failed: ${e.message}`, "error"); }
  finally { if (btn) { btn.disabled = false; btn.innerHTML = orig; } }
}

/* ════════════════════════════════════════════════════════════════════════
   SETTINGS  ⇄ /api/settings
════════════════════════════════════════════════════════════════════════ */
async function loadSettings() {
  let cfg; try { cfg = await API.get("/api/settings"); } catch (e) { toast(`Settings load failed: ${e.message}`, "error"); return; }
  AppState.serverConfig = cfg;
  const ai = cfg.ai || {}, vol = cfg.volatility || {}, out = cfg.output || {}, look = cfg.appearance || {};

  if ($("vol3-path"))      $("vol3-path").value      = vol.vol3_path || "";
  if ($("vol2-path"))      $("vol2-path").value      = vol.vol2_path || "";
  if ($("vol-preference")) $("vol-preference").value = vol.preference || "auto";
  if ($("vol-timeout"))    $("vol-timeout").value    = vol.timeout_seconds ?? 600;

  if ($("output-directory")) $("output-directory").value = out.directory || "";
  if ($("output-dir") && !$("output-dir").value) $("output-dir").value = out.directory || "";

  if ($("ai-provider"))    $("ai-provider").value    = ai.provider || "google";
  if ($("ai-model"))       $("ai-model").value       = ai.model || "";
  if ($("ai-max-tokens"))  $("ai-max-tokens").value  = ai.max_tokens ?? 1500;
  if ($("ai-temperature")) $("ai-temperature").value = ai.temperature ?? 0.2;
  if ($("ai-base-url"))    $("ai-base-url").value =
        ai.provider === "glm"         ? (ai.glm_base_url || "")
      : ai.provider === "agentrouter" ? (ai.agentrouter_base_url || "")
      : ai.provider === "ollama"      ? (ai.ollama_url || "")
      : "";
  if ($("ai-api-key")) {
    const stored = (ai.api_keys || {})[ai.provider] || "";
    $("ai-api-key").value = "";
    $("ai-api-key").placeholder = stored ? `stored: ${stored}` : "sk-…";
  }
  if ($("key-abuseipdb")) {
    const v = (ai.api_keys || {}).abuseipdb || "";
    $("key-abuseipdb").value = ""; $("key-abuseipdb").placeholder = v ? `stored: ${v}` : "—";
  }
  if ($("key-virustotal")) {
    const v = (ai.api_keys || {}).virustotal || "";
    $("key-virustotal").value = ""; $("key-virustotal").placeholder = v ? `stored: ${v}` : "—";
  }

  // Full Analysis feature-flag toggles (Phase A — server-side defaults:
  // V2 ON, legacy V1 OFF, optional AI Report OFF). Reads the resolved
  // state from /api/status so env-var overrides are reflected.
  try {
    const status = await API.get("/api/status");
    const ff = (status && status.features) || {};
    const setTog = (id, on) => {
      const el = $(id); if (!el) return;
      el.classList.toggle("on", !!on);
    };
    setTog("fa-v2-enabled",          ff.full_analysis_v2 !== false);          // default ON
    setTog("fa-legacy-v1",           !!ff.full_analysis_legacy_v1);
    setTog("fa-optional-ai-report",  !!ff.full_analysis_optional_ai_report);
    // Mirror into AppState so the AI Report button updates immediately
    // after Settings → Save without a page reload.
    AppState.fa2 = AppState.fa2 || {};
    AppState.fa2.featureFlags = {
      full_analysis_v2:                 !!ff.full_analysis_v2,
      full_analysis_legacy_v1:          !!ff.full_analysis_legacy_v1,
      full_analysis_optional_ai_report: !!ff.full_analysis_optional_ai_report,
    };
    if (typeof _fa2MaybeShowAIReportButton === "function") {
      _fa2MaybeShowAIReportButton();
    }
  } catch (_) { /* silent — toggles will simply reflect their HTML defaults */ }
  if ($("ai-allow-shell")) $("ai-allow-shell").classList.toggle("on", ai.allow_shell_commands !== false);

  if (look.theme) { setTheme(look.theme); if ($("theme-select")) $("theme-select").value = look.theme; }

  const ap = $("ai-provider-pill"); if (ap) ap.innerText = `${ai.provider || "?"} · ${ai.model || "auto"}`;
  if ($("aiProviderName")) $("aiProviderName").innerText = ai.provider || "—";
  if ($("aiModelName"))    $("aiModelName").innerText    = ai.model || "—";
}

async function saveSettings() {
  const isMasked = (s) => typeof s === "string" && (s.includes("…") || s.includes("***"));
  const provider = $("ai-provider")?.value || "google";
  const apiKeys = {};
  const put = (slot, v) => { v = (v || "").trim(); if (v && !isMasked(v)) apiKeys[slot] = v; };
  put(provider,    $("ai-api-key")?.value);
  put("abuseipdb", $("key-abuseipdb")?.value);
  put("virustotal",$("key-virustotal")?.value);
  const baseUrl = ($("ai-base-url")?.value || "").trim();
  const payload = {
    ai: {
      provider,
      model:        ($("ai-model")?.value || "").trim(),
      max_tokens:   parseInt($("ai-max-tokens")?.value, 10) || 1500,
      temperature:  parseFloat($("ai-temperature")?.value) || 0.2,
      allow_shell_commands: $("ai-allow-shell")?.classList.contains("on") !== false,
      api_keys: apiKeys,
    },
    volatility: {
      vol3_path:       ($("vol3-path")?.value || "").trim(),
      vol2_path:       ($("vol2-path")?.value || "").trim(),
      preference:      $("vol-preference")?.value || "auto",
      timeout_seconds: parseInt($("vol-timeout")?.value, 10) || 600,
    },
    output: {
      directory: ($("output-directory")?.value || "").trim(),
      auto_save: $("output-autosave")?.classList.contains("on") !== false,
    },
    appearance: { theme: $("theme-select")?.value || "dark" },
    // Phase A: Full Analysis feature flags persisted in config.json
    // under `features.<NAME>`. Env vars still override these at
    // runtime (resolved by app/config.py::feature_flag_enabled).
    features: {
      FULL_ANALYSIS_V2:                 $("fa-v2-enabled")?.classList.contains("on") !== false,
      FULL_ANALYSIS_LEGACY_V1:          !!$("fa-legacy-v1")?.classList.contains("on"),
      FULL_ANALYSIS_OPTIONAL_AI_REPORT: !!$("fa-optional-ai-report")?.classList.contains("on"),
    },
  };
  if (provider === "glm" && baseUrl)         payload.ai.glm_base_url         = baseUrl;
  if (provider === "agentrouter" && baseUrl) payload.ai.agentrouter_base_url = baseUrl;
  if (provider === "ollama" && baseUrl)      payload.ai.ollama_url           = baseUrl;

  const btn = $("save-settings-btn"); const orig = btn ? btn.innerHTML : "";
  if (btn) { btn.disabled = true; btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Saving…'; }
  try { await API.post("/api/settings", payload); toast("Settings saved", "ok"); await loadSettings(); }
  catch (e) { toast(`Save failed: ${e.message}`, "error"); }
  finally { if (btn) { btn.disabled = false; btn.innerHTML = orig; } }
}
window.saveSettings = saveSettings;

/* ════════════════════════════════════════════════════════════════════════
   SHARED CELL RENDERERS — severity / MITRE / tags / confidence
   Used by Manual Analysis (results table) and Full Analysis (findings).
════════════════════════════════════════════════════════════════════════ */
const _SEV_NORMALISE = {
  critical:"critical",crit:"critical",sev1:"critical",
  high:"high",sev2:"high",
  medium:"medium",med:"medium",moderate:"medium",sev3:"medium",
  low:"low",sev4:"low",
  info:"info",informational:"info",notice:"info",
  warning:"high",warn:"high",
};
function _renderSeverityCell(v) {
  const raw = String(v ?? "").trim();
  if (!raw) return '<span style="opacity:.4">—</span>';
  const sev = _SEV_NORMALISE[raw.toLowerCase()];
  if (!sev) return esc(raw);
  return `<span class="sev-pill sev-${sev}">${esc(raw)}</span>`;
}
function _mitreUrl(tag) {
  const t = String(tag || "").trim().toUpperCase(); let m;
  if ((m = t.match(/^T(\d{4})\.(\d{3})$/))) return `https://attack.mitre.org/techniques/T${m[1]}/${m[2]}/`;
  if (/^T\d{4}$/.test(t))  return `https://attack.mitre.org/techniques/${t}/`;
  if (/^TA\d{4}$/.test(t)) return `https://attack.mitre.org/tactics/${t}/`;
  if (/^S\d{4}$/.test(t))  return `https://attack.mitre.org/software/${t}/`;
  if (/^G\d{4}$/.test(t))  return `https://attack.mitre.org/groups/${t}/`;
  if (/^M\d{4}$/.test(t))  return `https://attack.mitre.org/mitigations/${t}/`;
  return null;
}
function _renderMitreCell(v) {
  const raw = String(v ?? "").trim();
  if (!raw) return '<span style="opacity:.4">—</span>';
  const tokens = raw.split(/[,;|/\s]+/).map(t => t.trim()).filter(Boolean);
  return tokens.map(t => {
    const safe = esc(t), url = _mitreUrl(t);
    return url
      ? `<a class="mitre-pill mitre-pill-link" href="${url}" target="_blank" rel="noopener noreferrer" title="Open ${safe} on attack.mitre.org">${safe}<i class="fa-solid fa-arrow-up-right-from-square mitre-pill-ext" aria-hidden="true"></i></a>`
      : `<span class="mitre-pill">${safe}</span>`;
  }).join(" ");
}
function _renderTagsCell(v) {
  const raw = String(v ?? "").trim();
  if (!raw) return '<span style="opacity:.4">—</span>';
  return raw.split(/[,;|]+/).map(t => t.trim()).filter(Boolean).map(t => `<span class="tag-pill">${esc(t)}</span>`).join(" ");
}
function _renderConfCell(v) {
  const num = parseFloat(String(v ?? "").trim());
  if (!isFinite(num)) return esc(String(v ?? ""));
  const pct = num <= 1 ? Math.round(num * 100) : Math.round(num);
  return `<span class="conf-bar" title="${pct}%"><span class="conf-bar-fill" style="width:${Math.min(100,pct)}%"></span></span>`;
}
function pickCellRenderer(name) {
  const c = String(name || "").toLowerCase().trim(); if (!c) return null;
  if (/^(severity|sev|risk|level|priority)$/.test(c))   return _renderSeverityCell;
  if (/(mitre|att&?ck|technique[s]?)/.test(c))          return _renderMitreCell;
  if (/^(tags?|labels?|categor(y|ies))$/.test(c))       return _renderTagsCell;
  if (/^(confidence|conf|score)$/.test(c))              return _renderConfCell;
  return null;
}
window.pickCellRenderer = pickCellRenderer;

async function _appendHTMLInBatches(container, chunks, batch = 500) {
  for (let i = 0; i < chunks.length; i += batch) {
    container.insertAdjacentHTML("beforeend", chunks.slice(i, i + batch).join(""));
    if (i + batch < chunks.length) await new Promise(r => setTimeout(r, 0));
  }
}

/* ════════════════════════════════════════════════════════════════════════
   MANUAL ANALYSIS — plugin registry, run, render, exports, search nav
════════════════════════════════════════════════════════════════════════ */
async function _loadPluginRegistry() {
  const deck = $("pluginDeck"); if (!deck) return;
  deck.innerHTML = '<div style="padding:14px;color:var(--t2);font-family:var(--fm);font-size:.7rem"><i class="fa-solid fa-spinner fa-spin"></i> loading plugins…</div>';
  try {
    const reg = await API.get("/api/plugins");
    AppState.pluginRegistry = reg;
    const map = {};
    (reg.categories || []).forEach(cat => (cat.plugins || []).forEach(p => { map[p.name] = { ...p, category: cat.name }; }));
    AppState.pluginByShortName = map;
    _renderPluginDeck("");
    if ($("pluginCount")) $("pluginCount").innerText = Object.keys(map).length;
  } catch (e) {
    deck.innerHTML = `<div style="padding:14px;color:var(--red);font-family:var(--fm);font-size:.7rem">load failed: ${esc(e.message)}</div>`;
  }
}

function _renderPluginDeck(filter) {
  const deck = $("pluginDeck"); if (!deck || !AppState.pluginRegistry) return;
  const q = (filter || "").toLowerCase().trim();
  deck.innerHTML = "";
  let count = 0;
  (AppState.pluginRegistry.categories || []).forEach(cat => {
    const matched = (cat.plugins || []).filter(p =>
      !q || (p.name||"").toLowerCase().includes(q) ||
            (p.desc||"").toLowerCase().includes(q) ||
            (p.vol3||"").toLowerCase().includes(q));
    if (!matched.length) return;
    const head = document.createElement("div");
    head.style.cssText = "padding:14px 16px 6px;font-family:var(--fc);font-size:.6rem;color:var(--t2);font-weight:700;letter-spacing:.1em;text-transform:uppercase";
    head.innerHTML = `${esc(cat.name)} <span style="opacity:.5;font-weight:normal;margin-left:4px">${matched.length}</span>`;
    deck.appendChild(head);
    matched.forEach(p => {
      const isActive = AppState.activePlugin === p.name;
      const item = document.createElement("div");
      item.style.cssText = `padding:10px 16px;cursor:pointer;display:flex;align-items:center;border-left:3px solid ${isActive ? "#6366f1" : "transparent"};background:${isActive ? "rgba(99,102,241,0.08)" : "transparent"};transition:all .2s`;
      const dotStyle = isActive ? "background:#6366f1;box-shadow:0 0 6px #6366f1" : "background:var(--t3)";
      const txtCol  = isActive ? "#6366f1" : "var(--t1)";
      const v2pill  = p.vol2 ? '<span style="font-family:var(--fc);font-size:.6rem;font-weight:700;color:var(--amber)">V2</span>' : "";
      const v3pill  = p.vol3 ? '<span style="font-family:var(--fc);font-size:.6rem;font-weight:700;color:var(--green)">V3</span>' : "";
      const naPill  = !p.available ? '<span style="font-family:var(--fc);font-size:.6rem;font-weight:700;color:var(--red)">N/A</span>' : "";
      item.innerHTML = `
        <div style="width:6px;height:6px;border-radius:50%;${dotStyle};margin-right:10px;flex-shrink:0"></div>
        <div style="flex:1;font-family:var(--fm);font-size:.75rem;color:${txtCol};white-space:nowrap;overflow:hidden;text-overflow:ellipsis" title="${esc(p.desc || "")}">${esc(p.vol3 || p.name)}</div>
        <div style="display:flex;gap:6px;align-items:center">${v2pill}${v3pill}${naPill}</div>`;
      item.addEventListener("mouseenter", () => { if (!isActive) item.style.background = "var(--bg1)"; });
      item.addEventListener("mouseleave", () => { if (!isActive) item.style.background = "transparent"; });
      item.addEventListener("click", () => _selectPlugin(p));
      deck.appendChild(item); count++;
    });
  });
  if (!count) deck.innerHTML = `<div style="padding:14px;color:var(--t2);font-family:var(--fm);font-size:.7rem">No plugins match "${esc(q)}"</div>`;
}

function _selectPlugin(p) {
  AppState.activePlugin = p.name;
  if ($("rfName")) $("rfName").innerText = p.vol3 || p.name;
  if ($("rfDesc")) $("rfDesc").innerText = `${p.desc || ""}${p.vol3 ? "  · vol3: " + p.vol3 : ""}${p.vol2 ? "  · vol2: " + p.vol2 : ""}`;
  if ($("run-plugin-btn")) $("run-plugin-btn").disabled = !p.available;
  _renderPluginDeck($("pSearch")?.value || "");
}

function filterPlugins(v) { _renderPluginDeck(v); }
window.filterPlugins = filterPlugins;

async function execPlugin() {
  const p = AppState.activePlugin && AppState.pluginByShortName[AppState.activePlugin];
  if (!p) { toast("Pick a plugin from the list first.", "warn"); return; }
  if (!AppState.currentFile) { toast("Upload a memory image first.", "warn"); return; }

  const btn      = $("run-plugin-btn");
  const tableEl  = $("results-table");
  const thead    = $("results-thead");
  const tbody    = $("results-tbody");
  const placeh   = $("results-placeholder");
  const countEl  = $("results-count");
  const rawOut   = $("raw-output");

  if (placeh) placeh.style.display = "none";
  if (tableEl) tableEl.style.display = "table";
  if (thead) thead.innerHTML = "";
  if (tbody) tbody.innerHTML = `<tr><td colspan="9" style="padding:20px;text-align:center;color:var(--t2)"><i class="fa-solid fa-spinner fa-spin" style="margin-right:8px"></i>Running ${esc(p.vol3 || p.name)}…</td></tr>`;
  if (countEl) countEl.innerText = `Running ${p.name}…`;
  if (rawOut) rawOut.textContent = "";
  _setExportButtons(false);

  const orig = btn ? btn.innerHTML : "";
  if (btn) { btn.disabled = true; btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Running…'; }

  try {
    const extra = ($("rfArgs")?.value || "").trim();
    const res = await API.post("/api/run-plugin", {
      plugin: p.name, version: "auto",
      params: {}, extra_params: extra,
    });

    AppState.lastPluginResult = { ...res, plugin: p.name, displayName: p.vol3 || p.name,
      imageName: AppState.currentFile?.filename, params: extra, timestamp: new Date().toISOString() };

    if (!res.success) {
      if (tbody) tbody.innerHTML = `<tr><td colspan="9" style="padding:20px;color:var(--red)"><i class="fa-solid fa-triangle-exclamation"></i> ${esc(res.error || "plugin failed")}</td></tr>`;
      if (countEl) countEl.innerText = `Failed · ${p.name} · ${res.elapsed || 0}s`;
      if (rawOut) rawOut.textContent = `> ${res.command || (p.name + " (see logs)")}\n\n${res.output || res.error || ""}`;
      _setExportButtons(true);
      toast(`${p.name} failed: ${(res.error || "").slice(0, 120)}`, "error");
      return;
    }

    const cols = res.columns || [], rows = res.rows || [];
    if (cols.length && rows.length) {
      const renderers = cols.map(pickCellRenderer);
      thead.innerHTML = `<tr>${cols.map(h => `<th style="background:var(--bg0);border-bottom:1px solid var(--border);font-weight:600">${esc(h)}</th>`).join("")}</tr>`;
      tbody.innerHTML = "";
      const chunks = rows.map(row => `<tr>${cols.map((_, i) => `<td>${renderers[i] ? renderers[i](row[i]) : esc(String(row[i] ?? ""))}</td>`).join("")}</tr>`);
      if (countEl) countEl.innerHTML = `<span style="color:var(--t0)">${rows.length.toLocaleString()}</span> rows · <span style="color:var(--t0)">${esc(p.name)}</span> · ${esc(res.version || "auto")} · ${res.elapsed || 0}s`;
      await _appendHTMLInBatches(tbody, chunks, 500);
    } else {
      thead.innerHTML = `<tr><th>Output</th></tr>`;
      const lines = (res.output || "").split("\n");
      while (lines.length && lines[lines.length - 1] === "") lines.pop();
      if (lines.length) {
        tbody.innerHTML = "";
        const chunks = lines.map(l => `<tr><td style="font-family:var(--fm);font-size:.7rem;white-space:pre">${esc(l)}</td></tr>`);
        if (countEl) countEl.innerHTML = `<span style="color:var(--t0)">${lines.length.toLocaleString()}</span> line(s) · ${esc(p.name)} · ${esc(res.version || "auto")} · ${res.elapsed || 0}s`;
        await _appendHTMLInBatches(tbody, chunks, 800);
      } else {
        tbody.innerHTML = `<tr><td style="opacity:.6;padding:20px">Plugin succeeded but produced no output.</td></tr>`;
        if (countEl) countEl.innerText = `0 rows · ${p.name} · ${res.version || "auto"} · ${res.elapsed || 0}s`;
      }
    }

    if (rawOut) rawOut.textContent = `> ${res.command || ""}\n\n${res.output || "(parsed into table above)"}`;
    _setExportButtons(true);
    window.__m3mxRefreshResultsSearch?.();
    toast(`${p.name} completed · ${(rows.length || 0).toLocaleString()} rows in ${res.elapsed || 0}s`, "ok");
  } catch (e) {
    if (tbody) tbody.innerHTML = `<tr><td colspan="9" style="padding:20px;color:var(--red)"><i class="fa-solid fa-triangle-exclamation"></i> ${esc(e.message)}</td></tr>`;
    toast(`Request failed: ${e.message}`, "error");
  } finally {
    if (btn) { btn.disabled = false; btn.innerHTML = orig; }
  }
}
window.execPlugin = execPlugin;

function _setExportButtons(on) {
  ["export-csv-btn","export-json-btn","export-txt-btn"].forEach(id => { const b = $(id); if (b) b.disabled = !on; });
}

/* exports + copy */
function _sanFilePart(s) { return String(s||"").replace(/[^a-zA-Z0-9._-]+/g,"_").replace(/^_+|_+$/g,"") || "unknown"; }
function _exportFilename(ext) {
  const r = AppState.lastPluginResult || {};
  const ts = (r.timestamp || new Date().toISOString()).replace(/[-:]/g,"").replace(/\..+$/,"").replace("T","-");
  return [_sanFilePart(r.imageName||"image"), _sanFilePart(r.plugin||"plugin"), _sanFilePart(r.version||"auto"), ts].join("_") + "." + ext;
}
function _csvEsc(v) { const s = v == null ? "" : String(v); return /[",\r\n]/.test(s) ? `"${s.replace(/"/g,'""')}"` : s; }
function _download(content, mime, name) {
  const b = new Blob([content], { type: mime }); const u = URL.createObjectURL(b);
  const a = document.createElement("a"); a.href = u; a.download = name; document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(u), 0);
}
function _exportCsv() {
  const r = AppState.lastPluginResult; if (!r) { toast("Run a plugin first.", "warn"); return; }
  const cols = r.columns || [], rows = r.rows || [];
  let csv;
  if (cols.length && rows.length) {
    csv = cols.map(_csvEsc).join(",") + "\r\n" + rows.map(row => cols.map((_,i) => _csvEsc(row[i])).join(",")).join("\r\n") + "\r\n";
  } else {
    const lines = (r.output||"").split("\n");
    while (lines.length && lines[lines.length-1] === "") lines.pop();
    csv = "output\r\n" + lines.map(_csvEsc).join("\r\n") + "\r\n";
  }
  _download("﻿" + csv, "text/csv;charset=utf-8", _exportFilename("csv"));
  toast("Exported CSV", "ok");
}
function _exportJson() {
  const r = AppState.lastPluginResult; if (!r) { toast("Run a plugin first.", "warn"); return; }
  _download(JSON.stringify(r, null, 2), "application/json;charset=utf-8", _exportFilename("json"));
  toast("Exported JSON", "ok");
}
function _exportTxt() {
  const r = AppState.lastPluginResult; if (!r) { toast("Run a plugin first.", "warn"); return; }
  const head = `# m3mx — ${r.displayName || r.plugin}\n# version: ${r.version}\n# image: ${r.imageName}\n# command: ${r.command || ""}\n# elapsed: ${r.elapsed}s\n${"-".repeat(60)}\n\n`;
  _download(head + (r.output || ""), "text/plain;charset=utf-8", _exportFilename("txt"));
  toast("Exported TXT", "ok");
}
function _copyResults() {
  const tbl = $("results-table"); if (!tbl) return;
  const text = Array.from(tbl.querySelectorAll("tr")).map(row => Array.from(row.cells).map(c => c.textContent.trim()).join("\t")).join("\n");
  navigator.clipboard.writeText(text).then(() => toast("Results copied", "ok"));
}

/* ── highlight search across results-table / fa-findings / extractor ── */
function _clearMarks(c) { c?.querySelectorAll("mark.m3mx-hl").forEach(m => { const p = m.parentNode; if (p) { p.replaceChild(document.createTextNode(m.textContent), m); p.normalize(); } }); }
function _wrapMarks(c, q) {
  if (!c || !q) return [];
  const ql = q.toLowerCase();
  const w = document.createTreeWalker(c, NodeFilter.SHOW_TEXT, { acceptNode: n => {
    if (!n.nodeValue || !n.nodeValue.toLowerCase().includes(ql)) return NodeFilter.FILTER_REJECT;
    const p = n.parentElement; if (!p || p.closest("input,textarea,script,style") || (p.tagName === "MARK" && p.classList.contains("m3mx-hl"))) return NodeFilter.FILTER_REJECT;
    return NodeFilter.FILTER_ACCEPT;
  }});
  const tnodes = []; let n; while ((n = w.nextNode())) tnodes.push(n);
  const marks = [];
  tnodes.forEach(tn => {
    const text = tn.nodeValue, lower = text.toLowerCase(), frag = document.createDocumentFragment();
    let i = 0, idx;
    while ((idx = lower.indexOf(ql, i)) !== -1) {
      if (idx > i) frag.appendChild(document.createTextNode(text.slice(i, idx)));
      const m = document.createElement("mark"); m.className = "m3mx-hl"; m.textContent = text.slice(idx, idx + ql.length);
      frag.appendChild(m); marks.push(m); i = idx + ql.length;
    }
    if (i < text.length) frag.appendChild(document.createTextNode(text.slice(i)));
    tn.parentNode.replaceChild(frag, tn);
  });
  return marks;
}
function attachHighlightSearch(opts) {
  const inp = $(opts.inputId), prev = $(opts.prevBtnId), next = $(opts.nextBtnId), counter = $(opts.counterId);
  const get = () => typeof opts.container === "function" ? opts.container() : $(opts.container);
  if (!inp) return { refresh: () => {} };
  let marks = [], active = -1;
  const setActive = (i) => {
    if (!marks.length) { active = -1; if (counter) counter.textContent = "0 / 0"; return; }
    marks.forEach(m => m.classList.remove("m3mx-hl-active"));
    active = ((i % marks.length) + marks.length) % marks.length;
    const cur = marks[active]; cur.classList.add("m3mx-hl-active");
    cur.scrollIntoView({ block: "center", behavior: "smooth" });
    if (counter) counter.textContent = `${active + 1} / ${marks.length}`;
  };
  const run = () => {
    const c = get(); if (!c) return;
    _clearMarks(c);
    const q = inp.value.trim();
    if (!q) { marks = []; active = -1; if (counter) counter.textContent = "0 / 0"; return; }
    marks = _wrapMarks(c, q);
    if (!marks.length) { active = -1; if (counter) counter.textContent = "0 / 0"; return; }
    setActive(0);
  };
  inp.addEventListener("input", debounce(run, 120));
  inp.addEventListener("keydown", e => {
    if (e.key === "Enter") { e.preventDefault(); if (!marks.length) run(); else setActive(active + (e.shiftKey ? -1 : 1)); }
    else if (e.key === "Escape") { inp.value = ""; run(); }
  });
  prev?.addEventListener("click", () => marks.length && setActive(active - 1));
  next?.addEventListener("click", () => marks.length && setActive(active + 1));
  return { refresh: run };
}

/* ════════════════════════════════════════════════════════════════════════
   AI AGENT — SSE chat with /api/agent/chat
════════════════════════════════════════════════════════════════════════ */
function md2html(src) {
  const e = (s) => s.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
  let s = e(src || "");
  s = s.replace(/```([\s\S]*?)```/g, (_, c) => `<pre class="md-code">${c.trim()}</pre>`);
  s = s.replace(/`([^`\n]+)`/g, '<code class="md-inline">$1</code>');
  s = s.replace(/^####\s+(.*)$/gm,'<h4>$1</h4>')
       .replace(/^###\s+(.*)$/gm, '<h3>$1</h3>')
       .replace(/^##\s+(.*)$/gm,  '<h2>$1</h2>')
       .replace(/^#\s+(.*)$/gm,   '<h1>$1</h1>');
  s = s.replace(/\*\*([^*]+)\*\*/g,'<strong>$1</strong>')
       .replace(/(?<!\*)\*([^*\n]+)\*(?!\*)/g,'<em>$1</em>');
  s = s.replace(/^[ \t]*-\s+(.*)$/gm, '<li>$1</li>')
       .replace(/(?:<li>[\s\S]*?<\/li>\s*)+/g, m => `<ul>${m}</ul>`);
  s = s.replace(/(F-\d{2,4})/g, '<span class="md-finding-ref">$1</span>');
  s = s.replace(/\n{2,}/g, "</p><p>");
  return `<p>${s}</p>`;
}

function _appendChatRow(role, html) {
  const feed = $("chatFeed"); if (!feed) return null;
  AppState.chatHistory.push({ role, html });
  const row = document.createElement("div");
  row.className = "cf-row" + (role === "bot" ? " bot" : "");
  const ico = role === "bot"
    ? '<svg viewBox="0 0 18 18" fill="none" stroke="currentColor" stroke-width="1.5" width="13"><circle cx="9" cy="9" r="7"/><circle cx="9" cy="9" r="3" fill="currentColor" opacity="0.35"/></svg>'
    : '<svg viewBox="0 0 18 18" fill="none" stroke="currentColor" stroke-width="1.5" width="13"><circle cx="9" cy="6" r="3"/><path d="M3 16c1-3 4-5 6-5s5 2 6 5"/></svg>';
  row.innerHTML = `<div class="cf-av ${role === "bot" ? "bot-av" : ""}">${ico}</div><div class="cf-bbl">${html}<span class="cf-ts">${fmtTime()}</span></div>`;
  feed.appendChild(row); feed.scrollTop = feed.scrollHeight;
  return row;
}

function _appendToolCard(parent, kind, name, payload) {
  const w = document.createElement("div");
  w.className = `tool-card tool-card-${kind}`;
  const icon  = kind === "call" ? "fa-wrench" : "fa-square-check";
  const label = kind === "call" ? "Tool call" : "Tool result";
  const body  = typeof payload === "string" ? payload : JSON.stringify(payload, null, 2);
  w.innerHTML = `<div class="tool-card-hd"><i class="fa-solid ${icon}"></i><b>${label}</b><code>${esc(name || "")}</code></div><pre class="tool-card-body">${esc(body)}</pre>`;
  parent.appendChild(w);
  const feed = $("chatFeed"); if (feed) feed.scrollTop = feed.scrollHeight;
}

function _renderChatMD(text) { return md2html(String(text || "").replace(/```tool\s*\n[\s\S]*?\n```/gi, "").trim()); }

async function streamAgentResponse(userMsg) {
  _appendChatRow("user", esc(userMsg).replace(/\n/g,"<br/>"));
  const botRow = _appendChatRow("bot", '<em style="opacity:.55">thinking…</em>');
  const bbl    = botRow?.querySelector(".cf-bbl");
  const tsSpan = bbl?.querySelector(".cf-ts");
  const toolHost = document.createElement("div"); toolHost.className = "tool-cards";
  if (bbl) bbl.appendChild(toolHost);
  let raw = "";

  const setText = () => { if (!bbl) return; const html = _renderChatMD(raw); bbl.innerHTML = html + (toolHost.outerHTML); /* re-attach */ const newHost = bbl.querySelector(".tool-cards"); if (newHost && toolHost.parentNode !== bbl) toolHost.parentNode?.replaceChild(toolHost, newHost); if (tsSpan) bbl.appendChild(tsSpan); };

  try {
    const r = await fetch("/api/agent/chat", { method: "POST", headers: {"Content-Type":"application/json"}, body: JSON.stringify({ message: userMsg }) });
    if (!r.ok || !r.body) throw new Error(`HTTP ${r.status}`);
    const reader = r.body.getReader(); const dec = new TextDecoder(); let buf = "";
    if (bbl) bbl.innerHTML = ""; if (bbl) bbl.appendChild(toolHost);

    while (true) {
      const { value, done } = await reader.read(); if (done) break;
      buf += dec.decode(value, { stream: true });
      let idx;
      while ((idx = buf.indexOf("\n\n")) !== -1) {
        const block = buf.slice(0, idx); buf = buf.slice(idx + 2);
        const dataLines = block.split("\n").filter(l => l.startsWith("data:"));
        if (!dataLines.length) continue;
        const json = dataLines.map(l => l.slice(5).trimStart()).join("\n");
        let evt; try { evt = JSON.parse(json); } catch { continue; }
        if (evt.type === "token") {
          raw += evt.content || "";
          if (bbl) {
            const cleaned = String(raw).replace(/```tool\s*\n[\s\S]*?\n```/gi, "").trim();
            const textNode = document.createElement("div"); textNode.innerHTML = md2html(cleaned);
            // Replace text content but keep toolHost + ts
            while (bbl.firstChild && bbl.firstChild !== toolHost) bbl.removeChild(bbl.firstChild);
            bbl.insertBefore(textNode, toolHost);
            const feed = $("chatFeed"); if (feed) feed.scrollTop = feed.scrollHeight;
          }
        } else if (evt.type === "tool_call") {
          _appendToolCard(toolHost, "call", evt.name, evt.args || {});
        } else if (evt.type === "tool_result") {
          _appendToolCard(toolHost, "result", evt.name, evt.result || {});
        } else if (evt.type === "error") {
          if (bbl) bbl.innerHTML = `<span style="color:var(--red)">Agent error: ${esc(evt.message || "unknown")}</span>`;
        }
      }
    }
    // Append timestamp
    if (bbl && tsSpan && !bbl.contains(tsSpan)) bbl.appendChild(tsSpan);
    AppState.chatHistory[AppState.chatHistory.length - 1].html = bbl?.innerHTML || "";
  } catch (e) {
    if (bbl) bbl.innerHTML = `<span style="color:var(--red)">Request failed: ${esc(e.message)}</span>`;
    toast(`Agent stream failed: ${e.message}`, "error");
  }
}

function sendMsg(forced) {
  const inp = $("cbInput"); if (!inp) return;
  const text = (forced || inp.value).trim(); if (!text) return;
  inp.value = ""; streamAgentResponse(text);
}
function cbKey(e) { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendMsg(); } }
function chipSend(btn) { sendMsg(btn.innerText); }
window.sendMsg = sendMsg; window.cbKey = cbKey; window.chipSend = chipSend;

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
    ? '<button class="fa-row-expand" type="button" onclick="_faToggleRowDetail(this)" title="Show details">▸</button>'
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
    const r = await fetch("/api/full-analysis/ai-report", {
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
    const r = await fetch("/api/full-analysis/export-pdf", {
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
  fetch("/api/status").then(r => r.ok ? r.json() : null).then(d => {
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
    const r = await fetch("/api/full-analysis", { method: "POST", headers: {"Content-Type":"application/json"}, body: JSON.stringify({}) });
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

/* ════════════════════════════════════════════════════════════════════════
   FILE EXTRACTOR — /api/files/{scan,preview,extract}
════════════════════════════════════════════════════════════════════════ */
function _extBuildTree(entries) {
  const root = { name: "", type: "dir", children: [], _map: {} };
  entries.forEach(e => {
    const parts = String(e.path || e.name || "").split(/[\\/]/).filter(Boolean);
    let c = root;
    parts.forEach((part, i) => {
      const leaf = i === parts.length - 1;
      if (leaf) c.children.push({ type: "file", name: part, entry: e });
      else {
        if (!c._map[part]) { const d = { name: part, type: "dir", children: [], _map: {} }; c._map[part] = d; c.children.push(d); }
        c = c._map[part];
      }
    });
  });
  const strip = (n) => { delete n._map; (n.children || []).forEach(strip); };
  strip(root);
  const sortRec = (n) => { if (!n.children) return; n.children.sort((a,b) => (a.type !== b.type) ? (a.type === "dir" ? -1 : 1) : a.name.localeCompare(b.name)); n.children.forEach(sortRec); };
  sortRec(root); return root.children;
}

function _extRenderTree(nodes, depth = 0) {
  let html = "";
  nodes.forEach(n => {
    const indent = depth * 14 + 6;
    if (n.type === "dir") {
      const id = `d-${Math.random().toString(36).slice(2)}`;
      html += `<div class="tree-node">
        <div class="tree-row" data-dir="${id}" style="padding:5px 0;cursor:pointer">
          <div style="width:${indent}px"></div>
          <i class="fa-solid fa-chevron-right" style="color:var(--t2);font-size:.65rem;margin-right:6px;transition:transform .15s"></i>
          <i class="fa-solid fa-folder" style="color:#facc15;margin-right:8px"></i>
          <div class="tree-name" style="flex:1">${esc(n.name)}</div>
          <div class="tree-count">${(n.children || []).length}</div>
        </div>
        <div class="tree-children" data-children="${id}" style="display:none">${_extRenderTree(n.children || [], depth + 1)}</div>
      </div>`;
    } else {
      const e = n.entry;
      const danger = e.high_value ? "color:var(--red);font-weight:600" : "";
      const ic = e.high_value ? "fa-skull" : "fa-file";
      const icColor = e.high_value ? "color:var(--red)" : "color:var(--t2)";
      const flagsAttr = Array.isArray(e.flags) ? e.flags.join(",") : "";
      html += `<div class="tree-node">
        <div class="tree-row" data-offset="${esc(e.offset || "")}"
             data-name="${esc(e.name || "")}"
             data-path="${esc(e.path || "")}"
             data-ext="${esc(e.ext || "")}"
             data-size="${e.size != null ? e.size : ""}"
             data-flags="${esc(flagsAttr)}"
             data-priority="${e.priority || 0}"
             data-high="${e.high_value ? 1 : 0}"
             style="padding:5px 0;cursor:pointer">
          <div style="width:${indent}px"></div>
          <i class="fa-solid ${ic}" style="${icColor};margin-right:8px"></i>
          <div class="tree-name" style="${danger};flex:1">${esc(e.name)}</div>
          <div class="tree-count">${e.size != null ? fmtBytes(e.size) : ""}</div>
        </div>
      </div>`;
    }
  });
  return html;
}

function _extWireTreeEvents() {
  $$("#extTreeBody [data-dir]").forEach(row => {
    row.addEventListener("click", () => {
      const id = row.dataset.dir;
      const ch = document.querySelector(`#extTreeBody [data-children="${id}"]`);
      if (!ch) return;
      const open = ch.style.display !== "none";
      ch.style.display = open ? "none" : "block";
      const chev = row.querySelector("i.fa-chevron-right");
      if (chev) chev.style.transform = open ? "" : "rotate(90deg)";
    });
  });
  $$("#extTreeBody [data-offset]").forEach(row => {
    row.addEventListener("click", () => _extSelectFile(row));
  });
}

async function _extScan() {
  if (!AppState.currentFile) { toast("Upload a memory image first.", "warn"); return; }
  const tb = $("extTreeBody"); if (tb) tb.innerHTML = '<div style="padding:14px;color:var(--t2);font-family:var(--fm);font-size:.7rem"><i class="fa-solid fa-spinner fa-spin"></i> running windows.filescan…</div>';
  const idx = $("treeIndexed"); if (idx) idx.innerText = "Scanning…";
  try {
    const data = await API.post("/api/files/scan", {});
    AppState.ext.files = data.files || [];
    const tree = _extBuildTree(AppState.ext.files);
    if (tb) tb.innerHTML = _extRenderTree(tree);
    if (idx) idx.innerText = `${data.count || AppState.ext.files.length} files indexed · ${data.elapsed || 0}s · ${data.version || ""}`;
    _extWireTreeEvents();
    toast(`Indexed ${data.count} files`, "ok");
  } catch (e) {
    if (tb) tb.innerHTML = `<div style="padding:14px;color:var(--red)">scan failed: ${esc(e.message)}</div>`;
    toast(`filescan failed: ${e.message}`, "error");
  }
}

function _extSelectFile(row) {
  const offset = row.dataset.offset;
  const entry  = AppState.ext.files.find(f => f.offset === offset);
  if (!entry) return;
  $$("#extTreeBody .tree-row").forEach(r => { r.style.background = ""; r.style.borderLeft = ""; });
  row.style.background = "rgba(99,102,241,.1)";
  row.style.borderLeft = "3px solid #6366f1";
  AppState.ext.selected = entry;
  AppState.ext.selectedRow = row;
  if ($("extract-selected-btn")) $("extract-selected-btn").disabled = false;
  if ($("extEmpty")) $("extEmpty").style.display = "none";
  // metadata
  const mg = $("metaGrid"); const tab = $("tab-metadata");
  if (tab) tab.style.display = "block";
  if ($("tab-hex")) $("tab-hex").style.display = "none";
  if ($("tab-strings")) $("tab-strings").style.display = "none";
  $$(".ext-tab").forEach(t => t.classList.remove("active")); $$(".ext-tab")[0]?.classList.add("active");
  if (mg) {
    const flagsLabel = (entry.flags && entry.flags.length) ? entry.flags.join(", ") : "none";
    const fields = [
      ["File Name", entry.name, false, false],
      ["Full Path", entry.path, true,  false],
      ["Offset",    entry.offset, true, false],
      ["Extension", entry.ext || "—", false, false],
      ["Size",      entry.size != null ? `${fmtBytes(entry.size)} (${entry.size} B)` : "unknown", false, false],
      ["Priority",  String(entry.priority ?? 0), false, false],
      ["Flags",     flagsLabel, false, !!entry.high_value],
      ["High Value",entry.high_value ? "YES — high priority target" : "no", false, !!entry.high_value],
    ];
    mg.innerHTML = `<div style="display:grid;grid-template-columns:1fr 1fr;gap:14px">` + fields.map(([k,v,mono,danger]) => `
      <div style="background:var(--bg1);border:1px solid var(--border);border-radius:8px;padding:14px">
        <div style="font-family:var(--fc);font-size:.65rem;color:var(--t2);margin-bottom:6px;letter-spacing:.05em">${esc(k.toUpperCase())}</div>
        <div style="font-family:var(--fm);font-size:.85rem;${mono ? "" : ""}${danger ? "color:var(--red);font-weight:600" : "color:var(--t0);font-weight:600"};word-break:break-all">${esc(v || "")}</div>
      </div>`).join("") + `</div>`;
  }
  // Pre-fetch preview for hex/strings
  _extPreview(entry);
}

async function _extPreview(entry) {
  if (AppState.ext.previewCache[entry.offset]) { _extRenderAllTabs(AppState.ext.previewCache[entry.offset]); return; }
  const hb = $("hexBody"), sb = $("strBody"), eb = $("exifBody");
  const spin = '<div style="padding:14px;opacity:.6"><i class="fa-solid fa-spinner fa-spin"></i> previewing…</div>';
  if (hb) hb.innerHTML = spin;
  if (sb) sb.innerHTML = spin;
  if (eb) eb.innerHTML = spin;
  try {
    const data = await API.post("/api/files/preview", { offset: entry.offset });
    AppState.ext.previewCache[entry.offset] = data;
    _extRenderAllTabs(data);
  } catch (e) {
    const err = `<div style="padding:14px;color:var(--red)">preview failed: ${esc(e.message)}</div>`;
    if (hb) hb.innerHTML = err; if (sb) sb.innerHTML = err; if (eb) eb.innerHTML = err;
  }
}

function _extRenderAllTabs(data) {
  const hb = $("hexBody"), sb = $("strBody"), sc = $("strCount");
  // hex
  if (hb) {
    const rows = data.hex_rows || [];
    hb.innerHTML = rows.length
      ? rows.map(r => `<div class="hex-line"><span class="hex-off">${esc(r.offset)}</span><span class="hex-bytes">${esc(r.hex || r.bytes || "")}</span><span class="hex-ascii">${esc(r.ascii)}</span></div>`).join("")
      : '<div style="padding:14px;opacity:.6">No hex preview.</div>';
  }
  // strings
  if (sb) {
    const arr = data.strings || [];
    sb.innerHTML = arr.length
      ? arr.map(s => `<div class="str-row"><div class="str-addr">${esc(s.offset || "")}</div><div class="str-len">${esc((s.value || s.text || "").length)}</div><div class="str-val">${esc(s.value || s.text || s)}</div><div class="str-flag">${esc(s.kind || "STR")}</div></div>`).join("")
      : '<div style="padding:14px;opacity:.6">No strings extracted.</div>';
    if (sc) sc.innerText = `${arr.length} strings found`;
  }
  // exif
  _extRenderExif(data);
  // image
  _extRenderImage(data);
}

function _extRenderExif(data) {
  const eb = $("exifBody"), ec = $("exifCount");
  if (!eb) return;
  const rows = data.exif || [];
  if (!rows.length) {
    eb.innerHTML = `<div class="exif-none"><i class="fa-solid fa-circle-info"></i>
      No exiftool metadata for this file.${data.exif === undefined ? "" : " "}
      ${(typeof data.exif === "object" && data.exif !== null && !rows.length) ? "" : ""}
    </div>`;
    if (ec) ec.innerText = "0 fields";
    return;
  }
  eb.innerHTML = rows.map(r =>
    `<div class="exif-row"><div class="exif-tag">${esc(r.tag)}</div><div class="exif-val">${esc(r.value)}</div></div>`
  ).join("");
  if (ec) ec.innerText = `${rows.length} field${rows.length === 1 ? "" : "s"}`;
}

function _extRenderImage(data) {
  const tabBtn = $("ext-tab-image"), img = $("imgView"),
        empty  = $("imgEmpty"), meta = $("imgMeta");
  const isImg = !!data.is_image && !!data.extracted_path;
  if (tabBtn) tabBtn.disabled = !isImg;
  if (!img) return;
  if (!isImg) {
    img.style.display = "none"; img.removeAttribute("src");
    if (empty) { empty.style.display = "block"; empty.innerText = "No image preview available for this file."; }
    if (meta)  meta.innerHTML = "";
    return;
  }
  img.src = `/api/files/raw?path=${encodeURIComponent(data.extracted_path)}`;
  img.style.display = "block";
  if (empty) empty.style.display = "none";
  if (meta) {
    meta.innerHTML = `
      <div><b>${esc(data.name || "")}</b></div>
      <div>MIME: <code>${esc(data.mime || "?")}</code> · ${esc(fmtBytes(data.size || 0))}</div>`;
  }
}

function filterStrings(q) {
  const ql = (q || "").toLowerCase();
  $$("#strBody .str-row").forEach(r => { r.style.display = !ql || r.textContent.toLowerCase().includes(ql) ? "" : "none"; });
}
function filterExif(q) {
  const ql = (q || "").toLowerCase();
  $$("#exifBody .exif-row").forEach(r => { r.style.display = !ql || r.textContent.toLowerCase().includes(ql) ? "" : "none"; });
}
window.filterStrings = filterStrings;
window.filterExif    = filterExif;

async function extractSelected() {
  if (!AppState.ext.selected) { toast("Select a file in the tree first.", "warn"); return; }
  const off = AppState.ext.selected.offset;
  const btn = $("extract-selected-btn"); const orig = btn ? btn.innerHTML : "";
  if (btn) { btn.disabled = true; btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Extracting…'; }
  try {
    const data = await API.post("/api/files/extract", { offsets: [off] });
    const r0 = (data.results || [])[0] || {};
    if (r0.ok) toast(`Extracted ${r0.dumped?.length || 0} file(s) to ${data.output_dir || "outputs/"}`, "ok");
    else       toast(`Extract failed: ${r0.error || "see logs"}`, "error");
  } catch (e) { toast(`Extract failed: ${e.message}`, "error"); }
  finally { if (btn) { btn.disabled = false; btn.innerHTML = orig; } }
}
function switchTab(btn, name) {
  if (btn?.disabled) return;
  $$(".ext-tab").forEach(t => t.classList.remove("active"));
  btn.classList.add("active");
  ["metadata","hex","strings","exif","image"].forEach(n => {
    const el = $("tab-" + n); if (el) el.style.display = (n === name) ? "block" : "none";
  });
  if ($("extEmpty")) $("extEmpty").style.display = "none";
}
window.extractSelected = extractSelected; window.switchTab = switchTab;

/* ════════════════════════════════════════════════════════════════════════
   APP INIT — wires everything once boot finishes
════════════════════════════════════════════════════════════════════════ */
async function initApp() {
  await loadSettings();
  await _loadPluginRegistry();

  // Output-dir buttons
  $("save-dir-btn")  ?.addEventListener("click", _saveOutputDir);
  $("browse-dir-btn")?.addEventListener("click", _browseOutputDir);
  $("output-dir")    ?.addEventListener("keydown", e => { if (e.key === "Enter") { e.preventDefault(); _saveOutputDir(); } });

  // Provider change → swap base-url + key placeholder
  $("ai-provider")?.addEventListener("change", function () {
    const ai = AppState.serverConfig?.ai || {}, v = this.value;
    if ($("ai-base-url")) $("ai-base-url").value =
        v === "glm"         ? (ai.glm_base_url         || "https://open.bigmodel.cn/api/paas/v4/")
      : v === "agentrouter" ? (ai.agentrouter_base_url || "https://agentrouter.org/v1")
      : v === "ollama"      ? (ai.ollama_url           || "http://127.0.0.1:11434")
      : "";
    const stored = (ai.api_keys || {})[v] || "";
    if ($("ai-api-key")) {
      $("ai-api-key").value = "";
      $("ai-api-key").placeholder = stored ? `stored: ${stored}` : v === "ollama" ? "(no key needed)" : "sk-…";
    }
  });

  // Manual export buttons + copy + raw toggle
  $("export-csv-btn")?.addEventListener("click", _exportCsv);
  $("export-json-btn")?.addEventListener("click", _exportJson);
  $("export-txt-btn")?.addEventListener("click", _exportTxt);
  $("copy-results-btn")?.addEventListener("click", _copyResults);
  $("toggle-raw-btn")?.addEventListener("click", e => {
    e.preventDefault();
    const ro = $("raw-output"); if (!ro) return;
    const open = ro.style.display !== "none";
    ro.style.display = open ? "none" : "block";
    e.currentTarget.innerHTML = `<i class="fa-solid fa-code" style="margin-right:6px"></i>${open ? "Show" : "Hide"} raw output`;
  });

  // Highlight searches
  const resultsCtl = attachHighlightSearch({ inputId: "results-filter", prevBtnId: "results-filter-prev", nextBtnId: "results-filter-next", counterId: "results-filter-count", container: () => $("results-table-wrap") });
  window.__m3mxRefreshResultsSearch = () => resultsCtl.refresh();
  attachHighlightSearch({ inputId: "fa-findings-filter", prevBtnId: null, nextBtnId: null, counterId: null, container: () => $("fa-findings-table") });

  // Severity filter dropdown — hide rows whose severity doesn't match.
  $("fa-findings-sev-filter")?.addEventListener("change", function () {
    const want = (this.value || "").toLowerCase();
    document.querySelectorAll("#fa-findings-tbody tr[data-fid]").forEach(row => {
      const sev = (row.querySelector(".sev-pill")?.innerText || "").trim().toLowerCase();
      row.style.display = (!want || sev === want) ? "" : "none";
    });
  });
  // Extractor tree search — smart token filter + match highlighting.
  // Syntax:
  //   plain words  → AND-substring across name+path+ext
  //   "exact"      → exact phrase
  //   ext:exe      → extension match (also: name:, path:, flag:)
  //   is:high|exe|doc|image|archive  → preset class
  //   size:>1M / size:<10K / size:=512  → size comparator (k/m/g suffixes)
  //   -<token>     → negate
  function _extParseQuery(q) {
    const tokens = [];
    let i = 0;
    while (i < q.length) {
      while (i < q.length && /\s/.test(q[i])) i++;
      if (i >= q.length) break;
      let neg = false;
      if (q[i] === "-") { neg = true; i++; }
      if (q[i] === '"') {
        let j = q.indexOf('"', i + 1); if (j < 0) j = q.length;
        const v = q.slice(i + 1, j); i = j + 1;
        if (v) tokens.push({ kind: "text", field: "any", value: v.toLowerCase(), neg, raw: v });
        continue;
      }
      let j = i;
      while (j < q.length && !/\s/.test(q[j])) j++;
      const tok = q.slice(i, j); i = j;
      const m = tok.match(/^([a-zA-Z]+):(.*)$/);
      if (m) {
        const field = m[1].toLowerCase();
        const val = m[2];
        if (field === "size") {
          const sm = val.match(/^([<>]=?|=)?\s*([\d.]+)\s*([kmgKMG])?[bB]?$/);
          if (sm) {
            let n = parseFloat(sm[2]);
            const u = (sm[3] || "").toLowerCase();
            if (u === "k") n *= 1024;
            else if (u === "m") n *= 1024 * 1024;
            else if (u === "g") n *= 1024 * 1024 * 1024;
            tokens.push({ kind: "size", op: sm[1] || ">=", value: n, neg });
            continue;
          }
        }
        if (field === "is") {
          tokens.push({ kind: "is", value: val.toLowerCase(), neg });
          continue;
        }
        if (val) {
          tokens.push({ kind: "text", field, value: val.toLowerCase(), neg, raw: val });
          continue;
        }
      }
      tokens.push({ kind: "text", field: "any", value: tok.toLowerCase(), neg, raw: tok });
    }
    return tokens;
  }
  const _EXT_GROUPS = {
    exe: ["exe","dll","sys","scr","ps1","vbs","bat","cmd","js","py","sh"],
    doc: ["pdf","doc","docx","xls","xlsx","csv","rtf","txt","log","ini"],
    image: ["jpg","jpeg","png","gif","bmp","webp","tiff"],
    archive: ["zip","rar","7z","tar","gz"],
  };
  function _extRowMatches(row, tokens) {
    const name  = (row.dataset.name  || "").toLowerCase();
    const path  = (row.dataset.path  || "").toLowerCase();
    const ext   = (row.dataset.ext   || "").toLowerCase();
    const flags = (row.dataset.flags || "").toLowerCase();
    const sizeS = row.dataset.size;
    const size  = sizeS === "" || sizeS == null ? null : parseInt(sizeS, 10);
    const high  = row.dataset.high === "1";
    for (const t of tokens) {
      let ok;
      if (t.kind === "size") {
        if (size == null) { ok = false; }
        else if (t.op === ">")  ok = size >  t.value;
        else if (t.op === ">=") ok = size >= t.value;
        else if (t.op === "<")  ok = size <  t.value;
        else if (t.op === "<=") ok = size <= t.value;
        else if (t.op === "=")  ok = size === t.value;
        else                    ok = size >= t.value;
      } else if (t.kind === "is") {
        const g = _EXT_GROUPS[t.value === "img" ? "image" : (t.value === "zip" ? "archive" : t.value)];
        if (t.value === "high" || t.value === "danger") ok = high;
        else if (g) ok = g.includes(ext);
        else ok = false;
      } else {
        const v = t.value;
        switch (t.field) {
          case "name": ok = name.includes(v); break;
          case "path": ok = path.includes(v); break;
          case "ext":  ok = ext === v || (v.length > 1 && ext.includes(v)); break;
          case "flag":
          case "flags":ok = flags.split(",").some(f => f.includes(v)); break;
          default:     ok = name.includes(v) || path.includes(v) || (v.length >= 2 && ext.includes(v));
        }
      }
      if (t.neg) ok = !ok;
      if (!ok) return false;
    }
    return true;
  }
  function _extClearMarks(scope) {
    scope.querySelectorAll("mark.m3mx-hl").forEach(m => {
      const p = m.parentNode;
      if (p) { p.replaceChild(document.createTextNode(m.textContent), m); p.normalize(); }
    });
  }
  function _extHighlightInName(nameEl, terms) {
    if (!nameEl || !terms.length) return;
    const text = nameEl.textContent;
    const lower = text.toLowerCase();
    const hits = [];
    terms.forEach(t => {
      if (!t) return;
      let idx = 0;
      while ((idx = lower.indexOf(t, idx)) !== -1) {
        hits.push([idx, idx + t.length]);
        idx += t.length;
      }
    });
    if (!hits.length) return;
    hits.sort((a,b) => a[0] - b[0]);
    const merged = [];
    hits.forEach(h => {
      const last = merged[merged.length - 1];
      if (last && h[0] <= last[1]) last[1] = Math.max(last[1], h[1]);
      else merged.push([h[0], h[1]]);
    });
    const frag = document.createDocumentFragment();
    let cur = 0;
    merged.forEach(([a, b]) => {
      if (a > cur) frag.appendChild(document.createTextNode(text.slice(cur, a)));
      const mk = document.createElement("mark");
      mk.className = "m3mx-hl";
      mk.textContent = text.slice(a, b);
      frag.appendChild(mk);
      cur = b;
    });
    if (cur < text.length) frag.appendChild(document.createTextNode(text.slice(cur)));
    nameEl.innerHTML = "";
    nameEl.appendChild(frag);
  }

  // Closure state shared between input + Enter/Shift+Enter navigation.
  const extSearchState = { matches: [], active: -1, totalFiles: 0 };

  function _extSetActiveMatch(i) {
    const cnt = $("extSearchCount");
    const bar = $("extSearchBar");
    const root = $("extTreeBody");
    // Clear previous active styling everywhere (idempotent + survives DOM rewrites).
    root?.querySelectorAll(".tree-row.active-match").forEach(r => r.classList.remove("active-match"));
    root?.querySelectorAll("mark.m3mx-hl-active").forEach(m => m.classList.remove("m3mx-hl-active"));

    if (!extSearchState.matches.length) {
      extSearchState.active = -1;
      if (cnt) { cnt.innerText = "0 / 0"; cnt.classList.remove("hit"); cnt.classList.add("miss"); }
      bar?.classList.add("no-match");
      return;
    }

    const n = extSearchState.matches.length;
    extSearchState.active = ((i % n) + n) % n;
    const row = extSearchState.matches[extSearchState.active];
    if (!row) return;

    row.classList.add("active-match");
    const firstMark = row.querySelector("mark.m3mx-hl");
    (firstMark || row).classList.add?.("m3mx-hl-active");
    // Some browsers won't honor classList on null — guard above; fallback target:
    if (!firstMark) row.classList.add("active-match");

    (firstMark || row).scrollIntoView({ behavior: "smooth", block: "center" });

    if (cnt) {
      cnt.innerText = `${extSearchState.active + 1} / ${n}`;
      cnt.classList.add("hit");
      cnt.classList.remove("miss");
    }
    bar?.classList.remove("no-match");
  }

  function _extRunSearch(raw) {
    const bar = $("extSearchBar");
    const clearBtn = $("extSearchClear");
    const root = $("extTreeBody"); if (!root) return;
    const fileRows = root.querySelectorAll(".tree-row[data-offset]");
    const dirContainers = root.querySelectorAll(".tree-children");
    extSearchState.totalFiles = fileRows.length;
    if (clearBtn) clearBtn.hidden = !raw;
    bar?.classList.toggle("active", !!raw);
    bar?.classList.remove("no-match");

    // Always scrub prior marks + active styling before re-rendering.
    _extClearMarks(root);
    root.querySelectorAll(".tree-row.active-match").forEach(r => r.classList.remove("active-match"));

    if (!raw) {
      fileRows.forEach(r => { r.style.display = ""; r.closest(".tree-node").style.display = ""; });
      dirContainers.forEach(c => c.style.display = "none");
      root.querySelectorAll(".tree-row[data-dir] i.fa-chevron-right").forEach(i => i.style.transform = "");
      const c = $("extSearchCount");
      if (c) { c.innerText = `${fileRows.length} files`; c.classList.remove("hit", "miss"); }
      extSearchState.matches = [];
      extSearchState.active = -1;
      return;
    }

    const tokens = _extParseQuery(raw);
    const highlightTerms = tokens
      .filter(t => t.kind === "text" && !t.neg && t.value && (t.field === "any" || t.field === "name"))
      .map(t => t.value);

    fileRows.forEach(r => { r.closest(".tree-node").style.display = "none"; });
    dirContainers.forEach(c => c.style.display = "none");

    const matches = [];
    fileRows.forEach(r => {
      if (!_extRowMatches(r, tokens)) return;
      matches.push(r);
      r.closest(".tree-node").style.display = "";
      _extHighlightInName(r.querySelector(".tree-name"), highlightTerms);
      let node = r.parentElement;
      while (node && node !== root) {
        if (node.classList?.contains("tree-children")) {
          node.style.display = "block";
          const dirRow = node.previousElementSibling;
          if (dirRow) {
            dirRow.closest(".tree-node").style.display = "";
            const ico = dirRow.querySelector("i.fa-chevron-right");
            if (ico) ico.style.transform = "rotate(90deg)";
          }
        }
        node = node.parentElement;
      }
    });

    extSearchState.matches = matches;
    extSearchState.active = -1;

    if (!matches.length) {
      const c = $("extSearchCount");
      if (c) { c.innerText = "0 / 0"; c.classList.remove("hit"); c.classList.add("miss"); }
      bar?.classList.add("no-match");
      return;
    }

    // Auto-focus the first match: smooth scroll + active styling.
    _extSetActiveMatch(0);
  }

  $("extSearch")?.addEventListener("input", debounce(function () {
    _extRunSearch((this.value || "").trim());
  }, 120));

  $("extSearchClear")?.addEventListener("click", () => {
    const inp = $("extSearch"); if (!inp) return;
    inp.value = "";
    _extRunSearch("");
    inp.focus();
  });

  $("extSearch")?.addEventListener("keydown", e => {
    if (e.key === "Enter") {
      e.preventDefault();
      if (!extSearchState.matches.length) {
        // Run synchronously in case debounce hasn't fired yet.
        _extRunSearch((e.target.value || "").trim());
        return;
      }
      _extSetActiveMatch(extSearchState.active + (e.shiftKey ? -1 : 1));
    } else if (e.key === "Escape") {
      e.preventDefault();
      e.target.value = "";
      _extRunSearch("");
    }
  });

  // Full-analysis log clear + export
  $("fa-log-clear-btn")?.addEventListener("click", _faClearLog);
  $("fa-export-btn")?.addEventListener("click", () => {
    const blob = new Blob([JSON.stringify({ image: AppState.currentFile?.path, findings: AppState.fa.findings, story: AppState.fa.storyText, ts: new Date().toISOString() }, null, 2)], { type: "application/json" });
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob);
    a.download = `full_analysis_${(AppState.currentFile?.filename || "case").split(/[\\/]/).pop()}.json`;
    a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 0);
    toast("Exported analysis bundle", "ok");
  });

  // Extractor refresh
  $("ext-refresh-btn")?.addEventListener("click", _extScan);

  // Expand-all / collapse-all directories in the tree.
  $("ext-expand-all")?.addEventListener("click", () => {
    document.querySelectorAll("#extTreeBody [data-children]").forEach(c => c.style.display = "block");
    document.querySelectorAll("#extTreeBody [data-dir] i.fa-chevron-right").forEach(i => i.style.transform = "rotate(90deg)");
  });
  $("ext-collapse-all")?.addEventListener("click", () => {
    document.querySelectorAll("#extTreeBody [data-children]").forEach(c => c.style.display = "none");
    document.querySelectorAll("#extTreeBody [data-dir] i.fa-chevron-right").forEach(i => i.style.transform = "");
  });
  // Auto-scan on first visit to extractor scene
  let extractorAutoScanDone = false;
  document.querySelector('[onclick="navigateTo(\'extractor\')"]')?.addEventListener("click", () => {
    if (!extractorAutoScanDone && AppState.currentFile && !AppState.ext.files.length) {
      extractorAutoScanDone = true;
      setTimeout(_extScan, 300);
    }
  });

  // Restore loaded image on refresh
  try {
    const li = await API.get("/api/loaded-image");
    if (li && li.path) {
      const fname = li.path.split("/").pop();
      AppState.currentFile = { filename: fname, path: li.path };
      if ($("sbText")) $("sbText").innerText = fname;
      if ($("sbDot"))  $("sbDot").classList.add("on");
      if ($("panel-evidence-name")) $("panel-evidence-name").innerText = fname;
      if ($("panel-status-chip")) { const c = $("panel-status-chip"); c.innerText = "Loaded"; c.className = "status-chip status-chip-ok"; }
      if ($("aiImg")) $("aiImg").innerText = fname;
      if ($("fa-image-label")) $("fa-image-label").innerText = li.path;
      if (li.profile) {
        if ($("panel-profile-label")) $("panel-profile-label").innerText = li.profile;
        if ($("aiProfile")) $("aiProfile").innerText = li.profile;
      }
    }
  } catch (e) { /* no image — fine */ }

  // Vitals poll
  setInterval(async () => {
    try {
      const s = await API.get("/api/status");
      if (s?.cpu_pct != null && $("cpuV")) { $("cpuV").innerText = `${Math.round(s.cpu_pct)}%`; $("cpuBar").style.width = `${Math.min(100, s.cpu_pct)}%`; }
      if (s?.mem_pct != null && $("memV")) { $("memV").innerText = `${Math.round(s.mem_pct)}%`; $("memBar").style.width = `${Math.min(100, s.mem_pct)}%`; }
    } catch {}
  }, 5000);
}

/* ════════════════════════════════════════════════════════════════════════
   AUTOMATION WORKFLOWS
   Quick playbooks + visual pipeline + AI synthesis (no tool calls).
   The AI step ingests preceding plugin outputs as context and produces
   a high-level executive summary — it MUST NOT invoke run_volatility,
   run_shell, or any other tool. We enforce this in the user message.
════════════════════════════════════════════════════════════════════════ */
const PLAYBOOKS = {
  triage: {
    label: "Malware Triage",
    icon: "fa-bug",
    color: "red",
    chain: ["pslist", "malfind", "netscan", "cmdline", "__ai__"],
    aiMode: "summary",
  },
  creds: {
    label: "Credential Hunt",
    icon: "fa-key",
    color: "amber",
    chain: ["hashdump", "lsadump", "cachedump", "hivelist", "__ai__"],
    aiMode: "report",
  },
  network: {
    label: "Network Recon",
    icon: "fa-network-wired",
    color: "indigo",
    chain: ["netscan", "netstat", "pslist", "dlllist", "__ai__"],
    aiMode: "mitre",
  },
  sweep: {
    label: "Full Sweep",
    icon: "fa-broom",
    color: "green",
    chain: ["pslist", "psscan", "cmdline", "malfind", "netscan",
            "ldrmodules", "svcscan", "handles", "dlllist", "filescan",
            "hivelist", "__ai__"],
    aiMode: "executive",
  },
};

const _PLUGIN_ICONS = {
  pslist: "fa-list", psscan: "fa-radar", pstree: "fa-sitemap",
  malfind: "fa-bug", netscan: "fa-globe", netstat: "fa-globe",
  cmdline: "fa-terminal", dlllist: "fa-puzzle-piece", handles: "fa-link",
  hashdump: "fa-key", lsadump: "fa-key", cachedump: "fa-key",
  hivelist: "fa-database", svcscan: "fa-cogs", ldrmodules: "fa-cube",
  filescan: "fa-folder",
};

AppState.automation = AppState.automation || { running: false, history: [], current: null };

/* ── render the visual pipeline from a chain of step names ──────────── */
function _autoRenderPipeline(chain) {
  const track = $("pl-track"); if (!track) return;
  track.innerHTML = "";

  // Always lead with a "Start" node
  const start = document.createElement("div");
  start.className = "pl-node is-start";
  start.dataset.idx = "start";
  start.innerHTML = `
    <div class="pl-node-icon"><i class="fa-solid fa-play"></i></div>
    <div class="pl-node-body">
      <div class="pl-node-title">Start</div>
      <div class="pl-node-sub">Load memory image</div>
    </div>
    <div class="pl-node-status"><i class="fa-solid fa-circle-check"></i></div>`;
  track.appendChild(start);

  chain.forEach((step, i) => {
    const conn = document.createElement("div"); conn.className = "pl-connector"; track.appendChild(conn);
    const node = document.createElement("div");
    const isAI = step === "__ai__";
    node.className = "pl-node" + (isAI ? " is-ai" : "");
    node.dataset.step = step; node.dataset.idx = String(i);
    const icon  = isAI ? "fa-robot"  : (_PLUGIN_ICONS[step] || "fa-terminal");
    const title = isAI ? "AI Analyst" : `windows.${step}`;
    const sub   = isAI ? "Synthesize findings (no tool calls)" : `Volatility 3 plugin`;
    node.innerHTML = `
      <div class="pl-node-icon"><i class="fa-solid ${icon}"></i></div>
      <div class="pl-node-body">
        <div class="pl-node-title">${esc(title)}</div>
        <div class="pl-node-sub">${esc(sub)}</div>
      </div>
      <div class="pl-node-status"><i class="fa-regular fa-clock"></i></div>`;
    track.appendChild(node);
  });
}

function _autoSetNodeStatus(idx, status, msg) {
  const node = document.querySelector(`#pl-track .pl-node[data-idx="${idx}"]`);
  if (!node) return;
  node.classList.remove("is-running", "is-ok", "is-err");
  node.classList.add(`is-${status}`);
  const ico = node.querySelector(".pl-node-status i");
  if (ico) {
    ico.className =
      status === "running" ? "fa-solid fa-spinner fa-spin"
    : status === "ok"      ? "fa-solid fa-circle-check"
    : status === "err"     ? "fa-solid fa-circle-xmark"
    :                        "fa-regular fa-clock";
  }
  if (msg) {
    const sub = node.querySelector(".pl-node-sub");
    if (sub) sub.innerText = msg;
  }
}

function _autoSetCardStatus(key, status) {
  const el = document.querySelector(`.pb-status[data-status="${key}"]`);
  if (!el) return;
  el.classList.remove("is-running", "is-ok", "is-err");
  el.classList.add(`is-${status}`);
  el.innerText = status === "running" ? "RUNNING" : status === "ok" ? "DONE" : "FAILED";
  setTimeout(() => { if (status !== "running") el.classList.remove("is-ok","is-err"); }, 6000);
}

/* ── compact a plugin result for the AI prompt (cap at 40 rows) ─────────
   Mirrors what Manual Analysis surfaces: CSV plugins yield columns+rows,
   text plugins (malfind, vadtree, mimikatz, …) yield raw `output`. Keep
   both so downstream code never loses findings. */
function _autoCompactResult(name, res) {
  const cols = res.columns || [];
  const rows = (res.rows || []).slice(0, 40);
  const truncated = (res.rows || []).length > 40;
  // Preserve text output for plugins whose findings live in `output`
  // (anything declared `format: "text"` in plugins.json).
  let textOutput = null;
  if (res.output && (!cols.length || !rows.length)) {
    textOutput = res.output.length > 14000
      ? res.output.slice(0, 14000) + "\n…[truncated for prompt budget]"
      : res.output;
  }
  return {
    plugin: name,
    success: !!res.success,
    elapsed: res.elapsed,
    rowCount: (res.rows || []).length,
    columns: cols,
    rows,
    truncatedRows: truncated,
    output: textOutput,                    // text-format plugins land here
    format: res.format || "text",
    command: res.command || null,
    error: res.error || null,
  };
}

/* ── AI synthesis step: NO tool calls, pure analyst mode ────────────── */
async function _autoRunAIStep(stepResults, mode) {
  const modeBlurb = {
    summary:   "an executive Malware Triage summary",
    report:    "a Credential Hunt report (which secrets were exposed, on which hives, what to rotate)",
    mitre:     "a network behavior analysis with MITRE ATT&CK technique mapping",
    executive: "an executive incident-response brief covering all observations",
  }[mode] || "an executive summary";

  const ctx = JSON.stringify(stepResults, null, 2);
  // Hard cap so we don't blow the agent's 4 KB feedback compaction.
  const ctxTrimmed = ctx.length > 14000 ? ctx.slice(0, 14000) + "\n…[truncated for prompt budget]" : ctx;

  const prompt = `PIPELINE_SYNTHESIS_MODE — ANALYST ONLY, NO TOOL CALLS.

You are the final node of an automated forensic pipeline. The Volatility plugins
listed below have ALREADY been executed. Your ONLY job is to act as a senior
DFIR analyst and produce ${modeBlurb} based exclusively on the JSON outputs
below. Do not invent data, do not call any tools, do not emit any \`\`\`tool
fenced block under any circumstance — if you do, the pipeline fails.

Required output:
- Use markdown headers (##, ###). Cite concrete artifacts (PIDs, paths, IPs, hashes).
- Map suspicious findings to MITRE ATT&CK techniques where supported by evidence.
- End with a "Recommended Next Actions" bullet list of 3-5 items.
- If the data shows nothing notable, say so plainly — do NOT fabricate findings.

Plugin outputs (JSON):
\`\`\`json
${ctxTrimmed}
\`\`\``;

  // Stream the response and reject any tool_call events (safety net if the
  // model ignores instructions). Returns the synthesized markdown.
  const r = await fetch("/api/agent/chat", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message: prompt }),
  });
  if (!r.ok || !r.body) throw new Error(`AI synth HTTP ${r.status}`);
  const reader = r.body.getReader(); const dec = new TextDecoder(); let buf = "";
  let text = ""; let toolCallsSeen = 0;
  while (true) {
    const { value, done } = await reader.read(); if (done) break;
    buf += dec.decode(value, { stream: true });
    let idx;
    while ((idx = buf.indexOf("\n\n")) !== -1) {
      const block = buf.slice(0, idx); buf = buf.slice(idx + 2);
      const lines = block.split("\n").filter(l => l.startsWith("data:"));
      if (!lines.length) continue;
      const json = lines.map(l => l.slice(5).trimStart()).join("\n");
      let evt; try { evt = JSON.parse(json); } catch { continue; }
      if (evt.type === "token")        text += evt.content || "";
      else if (evt.type === "tool_call") toolCallsSeen++;
      else if (evt.type === "error")   throw new Error(evt.message || "AI error");
    }
  }
  if (toolCallsSeen > 0) {
    text += `\n\n_[m3mx note: model attempted ${toolCallsSeen} tool call(s); they were ignored per pipeline policy.]_`;
  }
  return text.trim() || "_(LLM returned no synthesis text)_";
}

/* ── show the AI summary modal ──────────────────────────────────────── */
function _autoShowSummary(title, markdown) {
  const bg = document.createElement("div");
  bg.className = "auto-modal-bg";
  bg.innerHTML = `
    <div class="auto-modal">
      <div class="auto-modal-hd">
        <i class="fa-solid fa-robot" style="color:#a5b4fc"></i>
        <h3>${esc(title)}</h3>
        <button class="auto-modal-copy" title="Copy markdown"><i class="fa-regular fa-copy"></i></button>
        <button class="auto-modal-close" title="Close"><i class="fa-solid fa-xmark"></i></button>
      </div>
      <div class="auto-modal-body"></div>
    </div>`;
  document.body.appendChild(bg);
  bg.querySelector(".auto-modal-body").innerHTML = md2html(markdown);
  const close = () => bg.remove();
  bg.addEventListener("click", e => { if (e.target === bg) close(); });
  bg.querySelector(".auto-modal-close").addEventListener("click", close);
  bg.querySelector(".auto-modal-copy").addEventListener("click", () => {
    navigator.clipboard.writeText(markdown).then(() => toast("Markdown copied", "ok"));
  });
}

/* ── append a row to execution history ──────────────────────────────── */
function _autoLogHistory({ key, label, status, elapsed, summary }) {
  const host = $("exec-history"); if (!host) return;
  AppState.automation.history.unshift({ key, label, status, elapsed, summary, ts: new Date() });
  // Switch from empty state to list
  host.classList.remove("exec-history-empty"); host.classList.add("exec-history-list");
  host.innerHTML = "";
  AppState.automation.history.slice(0, 12).forEach((h, i) => {
    const row = document.createElement("div");
    row.className = "exec-row";
    const ico = PLAYBOOKS[h.key]?.icon || "fa-bolt";
    row.innerHTML = `
      <div class="ex-ico"><i class="fa-solid ${esc(ico)}"></i></div>
      <div><div class="ex-name">${esc(h.label)}</div><div class="ex-meta">${esc(h.summary || "")}</div></div>
      <div class="ex-time">${esc(h.ts.toLocaleString())}</div>
      <div class="ex-time">${esc(h.elapsed || "")}</div>
      <div class="ex-status ${h.status === "ok" ? "ok" : "err"}">${h.status === "ok" ? "OK" : "FAIL"}</div>
      <button class="ex-view" data-idx="${i}"><i class="fa-solid fa-eye"></i> View</button>`;
    host.appendChild(row);
  });
  host.querySelectorAll(".ex-view").forEach(b => b.addEventListener("click", () => {
    const h = AppState.automation.history[Number(b.dataset.idx)];
    if (h?.summary) _autoShowSummary(h.label, h.summary);
    else            toast("No summary captured for this run.", "warn");
  }));
}

/* ── execute the currently-displayed pipeline ───────────────────────── */
async function _autoExecute(playbookKey) {
  if (AppState.automation.running) { toast("Pipeline already running.", "warn"); return; }
  if (!AppState.currentFile)       { toast("Upload a memory image first.", "warn"); return; }

  const pb = PLAYBOOKS[playbookKey];
  if (!pb) { toast("Unknown playbook.", "error"); return; }

  AppState.automation.running = true;
  AppState.automation.current = playbookKey;
  _autoRenderPipeline(pb.chain);
  _autoSetCardStatus(playbookKey, "running");
  document.querySelectorAll(".pb-run").forEach(b => b.disabled = true);
  if ($("pl-execute")) $("pl-execute").disabled = true;

  const t0 = Date.now();
  const stepResults = [];   // { plugin, success, columns, rows, ... }
  let aiSummary = null;
  let finalStatus = "ok";

  for (let i = 0; i < pb.chain.length; i++) {
    const step = pb.chain[i];
    _autoSetNodeStatus(i, "running");
    try {
      if (step === "__ai__") {
        _autoSetNodeStatus(i, "running", "Synthesizing findings…");
        aiSummary = await _autoRunAIStep(stepResults, pb.aiMode);
        _autoSetNodeStatus(i, "ok", "Synthesis complete");
      } else {
        const res = await API.post("/api/run-plugin", {
          plugin: step, version: "auto", params: {}, extra_params: "",
        });
        stepResults.push(_autoCompactResult(step, res));
        if (res.success) {
          // Mirror Manual Analysis: prefer row count, fall back to line count
          // for text plugins (malfind, vadtree, …) so the node never reads "0".
          const rowCount = (res.rows || []).length;
          const lineCount = (res.output || "").split("\n").filter(Boolean).length;
          const measure = rowCount > 0
            ? `${rowCount} row${rowCount === 1 ? "" : "s"}`
            : `${lineCount} line${lineCount === 1 ? "" : "s"}`;
          _autoSetNodeStatus(i, "ok", `${measure} · ${res.elapsed||0}s`);
        } else {
          _autoSetNodeStatus(i, "err", (res.error || "failed").slice(0, 60));
          finalStatus = "err";
          // Continue to AI step regardless — partial data is still useful.
        }
      }
    } catch (e) {
      _autoSetNodeStatus(i, "err", (e.message || "error").slice(0, 60));
      finalStatus = "err";
      if (step !== "__ai__") {
        stepResults.push({ plugin: step, success: false, error: e.message });
      } else {
        aiSummary = `> AI synthesis failed: ${e.message}`;
        break;
      }
    }
  }

  const elapsed = `${((Date.now() - t0) / 1000).toFixed(1)}s`;
  _autoSetCardStatus(playbookKey, finalStatus === "ok" ? "ok" : "err");
  _autoLogHistory({
    key: playbookKey, label: pb.label, status: finalStatus,
    elapsed, summary: aiSummary,
  });

  AppState.automation.running = false;
  document.querySelectorAll(".pb-run").forEach(b => b.disabled = false);
  if ($("pl-execute")) $("pl-execute").disabled = false;

  if (aiSummary) _autoShowSummary(`${pb.label} · AI Summary`, aiSummary);
  else           toast(`${pb.label} pipeline finished (${finalStatus}) in ${elapsed}.`, finalStatus === "ok" ? "ok" : "warn");
}

/* ── public hook & wiring ───────────────────────────────────────────── */
function runPlaybook(key) { _autoExecute(key); }
window.runPlaybook = runPlaybook;

function _autoInit() {
  // Default pipeline: render the Malware Triage chain into the builder.
  _autoRenderPipeline(PLAYBOOKS.triage.chain);

  // Run buttons on each card
  document.querySelectorAll(".pb-run").forEach(btn => {
    btn.addEventListener("click", () => runPlaybook(btn.dataset.run));
  });

  // Pipeline execute
  $("pl-execute")?.addEventListener("click", () => runPlaybook(AppState.automation.current || "triage"));
  $("pl-add-step")?.addEventListener("click", () => toast("Custom workflow editor coming soon — pick a playbook to run.", "info"));

  // Header buttons (placeholders for now)
  $("auto-import-btn")?.addEventListener("click", () => toast("Workflow import coming soon.", "info"));
  $("auto-new-btn")?.addEventListener("click",     () => toast("Custom workflow builder coming soon.", "info"));
}
// Run init after the boot sequence completes (the rest of initApp runs then).
const _origInitApp = initApp;
initApp = async function () { await _origInitApp.apply(this, arguments); _autoInit(); };
