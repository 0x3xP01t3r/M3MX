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
  async get (url)        { const r = await m3mxFetch(url);                                                                              if (!r.ok) throw new Error(`${r.status} ${r.statusText}`); return r.json(); },
  async post(url, body)  { const r = await m3mxFetch(url,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body||{})}); if (!r.ok) throw new Error(`${r.status} ${r.statusText}`); return r.json(); },
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
  $$(".pn-btn").forEach(b => b.classList.toggle("active", b.dataset.view === view));
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
    const r = await m3mxFetch("/api/upload", { method: "POST", body: fd });
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
    const r = await m3mxFetch("/api/fs/pick-dir-native", { method: "POST", headers: {"Content-Type":"application/json"}, body: JSON.stringify({ start: $("output-dir")?.value?.trim() || undefined }) });
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
  if ($("ai-allow-shell")) $("ai-allow-shell").classList.toggle("on", ai.allow_shell_commands === true);
  if ($("ai-allow-network")) $("ai-allow-network").classList.toggle("on", ai.allow_network_tools === true);

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
      allow_shell_commands: !!$("ai-allow-shell")?.classList.contains("on"),
      allow_network_tools: !!$("ai-allow-network")?.classList.contains("on"),
      api_keys: apiKeys,
    },
    volatility: {
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
  if (!payload.output.directory) delete payload.output.directory;
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
