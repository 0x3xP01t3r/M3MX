/* m3mx tool — Phase 2 UI controller.
   Handles boot screen, tab navigation, toasts, settings load/save,
   file upload, model dropdown seeding. Later phases extend via
   window.m3mx.* hooks.
*/

const $  = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));

const MODELS_BY_PROVIDER = {
  // Latest as of 2026-Q2. Ordered newest → legacy.
  openai: [
    "gpt-5",
    "gpt-5-mini",
    "gpt-4.1",
    "gpt-4.1-mini",
    "gpt-4o",
    "gpt-4o-mini",
    "o3",
    "o3-mini",
    "o1",
    "o1-mini",
    "gpt-4-turbo",
    "gpt-3.5-turbo",
  ],
  anthropic: [
    "claude-opus-4-6",
    "claude-sonnet-4-6",
    "claude-haiku-4-5",
    "claude-opus-4-5",
    "claude-sonnet-4-5",
    "claude-3-7-sonnet-latest",
    "claude-3-5-sonnet-latest",
    "claude-3-5-haiku-latest",
  ],
  google: [
    "gemini-2.5-pro",
    "gemini-2.5-flash",
    "gemini-2.0-pro",
    "gemini-2.0-flash",
    "gemini-1.5-pro",
    "gemini-1.5-flash",
  ],
  ollama: [],                                      // filled dynamically
};

const state = {
  loadedImage: null,
  outputDir:   "outputs/",
  settings:    null,
  bootHints: [
    "initializing…",
    "checking backend…",
    "scanning volatility…",
    "loading plugin registry…",
    "preparing forensics workspace…",
  ],
};

window.m3mx = {};

// ---------------------------------------------------------------------------
// Boot screen
// ---------------------------------------------------------------------------

async function boot() {
  const hint = $("#boot-hint");
  let i = 0;
  const iv = setInterval(() => {
    hint.textContent = state.bootHints[i++ % state.bootHints.length];
  }, 450);

  try {
    const [health, settings] = await Promise.all([
      m3mxFetch("/api/health").then(r => r.json()),
      m3mxFetch("/api/settings").then(r => r.json()).catch(() => null),
    ]);
    window.m3mx.health   = health;
    window.m3mx.settings = settings;
    state.settings = settings;

    $("#brand-version").textContent = `v${health.version}`;

    if (settings?.output?.directory) {
      state.outputDir = settings.output.directory;
      $("#output-dir-path").textContent = state.outputDir;
    }

    // Warn if no Volatility
    const v = health.volatility || {};
    if (!v.vol2 && !v.vol3) {
      toast("Volatility not detected — plugins cannot run until installed.", "warn");
    }
  } catch (e) {
    hint.textContent = "backend unreachable";
    toast(`Backend unreachable: ${e.message}`, "err");
    return;
  } finally {
    clearInterval(iv);
  }

  // Fade out boot screen (removed artificial delay — paint when ready)
  $("#boot-screen").classList.add("hidden");
  $("#app").hidden = false;

  applySettings(state.settings);
  bindUI();
}

// ---------------------------------------------------------------------------
// UI bindings
// ---------------------------------------------------------------------------

function bindUI() {
  // Sidebar tab navigation
  $$(".sidebar .nav-item[data-tab]").forEach(btn => {
    btn.addEventListener("click", () => switchTab(btn.dataset.tab));
  });

  // File upload
  $("#btn-pick-file").addEventListener("click", () => $("#file-input").click());
  $("#file-input").addEventListener("change", onFilePicked);

  // Output dir (browser-sandboxed — uses a prompt)
  $("#btn-pick-output").addEventListener("click", () => {
    const val = prompt("Output directory (absolute path):", state.outputDir);
    if (val && val.trim()) setOutputDir(val.trim());
  });

  // Provider / model
  $("#set-provider").addEventListener("change", onProviderChange);

  // API key show/hide
  $("#btn-toggle-key").addEventListener("click", () => {
    const el = $("#set-apikey");
    el.type = el.type === "password" ? "text" : "password";
  });

  // Sliders
  $("#set-maxtokens").addEventListener("input", e => $("#maxtokens-val").textContent = e.target.value);
  $("#set-temp").addEventListener("input", e => {
    const v = (parseInt(e.target.value, 10) / 10).toFixed(1);
    $("#temp-val").textContent = v;
  });
  $("#set-font").addEventListener("input", e => {
    $("#font-val").textContent = e.target.value;
    document.body.style.fontSize = e.target.value + "px";
  });

  // Language
  $("#set-lang").addEventListener("change", e => window.m3mxI18n.apply(e.target.value));

  // Save settings
  $("#btn-save-settings").addEventListener("click", saveSettings);

  // Test connection
  $("#btn-test-connection").addEventListener("click", testConnection);

  // Chat input auto-grow + suggestion chips
  const chatInput = $("#chat-input");
  chatInput.addEventListener("input", () => {
    chatInput.style.height = "auto";
    chatInput.style.height = Math.min(chatInput.scrollHeight, 140) + "px";
  });
  $$(".chat-suggestions .chip").forEach(chip => {
    chip.addEventListener("click", () => {
      chatInput.value = chip.dataset.prompt;
      chatInput.focus();
    });
  });
  $("#chat-form").addEventListener("submit", (e) => {
    e.preventDefault();
    toast("AI chat ships in Phase 4.", "info");
  });

  // Results categories
  $$(".results-cats .nav-item").forEach(btn => {
    btn.addEventListener("click", () => {
      $$(".results-cats .nav-item").forEach(x => x.classList.remove("active"));
      btn.classList.add("active");
      $("#results-cat-title").textContent = btn.textContent.trim();
    });
  });

  // Scan files
  $("#btn-scan-files").addEventListener("click", () => {
    if (!state.loadedImage) return toast("Load a memory image first.", "warn");
    toast("File extractor ships in Phase 5.", "info");
  });

  // Quick Triage
  $("#btn-quick-triage").addEventListener("click", quickTriage);

  // Keyboard shortcuts
  document.addEventListener("keydown", onKeydown);

  // Context menu on plugin output terminal
  wireContextMenu();

  // Start on i18n pass
  window.m3mxI18n.apply(state.settings?.appearance?.language || "en");
}

function switchTab(name) {
  $$(".sidebar .nav-item[data-tab]").forEach(b => b.classList.toggle("active", b.dataset.tab === name));
  $$(".panel").forEach(p => p.classList.toggle("active", p.dataset.panel === name));
}

function setStatus(state_, label) {
  const el = $("#status-indicator");
  el.dataset.state = state_;
  const lbl = el.querySelector(".status-label");
  lbl.removeAttribute("data-i18n");
  lbl.textContent = label;
}

// ---------------------------------------------------------------------------
// File upload
// ---------------------------------------------------------------------------

async function onFilePicked(e) {
  const file = e.target.files?.[0];
  if (!file) return;

  const sizeStr = humanSize(file.size);
  toast(`Uploading ${file.name} (${sizeStr})…`, "info");
  setStatus("running", `uploading ${sizeStr}`);

  const fd = new FormData();
  fd.append("image", file);

  try {
    const r = await m3mxFetch("/api/upload", { method: "POST", body: fd });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const data = await r.json();
    state.loadedImage = data.path || file.name;
    $("#loaded-file-name").textContent = file.name;
    const sub = $("#loaded-file-sub");
    if (sub) sub.textContent = humanSize(file.size) + " · loaded";
    $("#loaded-file-pill").hidden = false;
    setStatus("ok", "loaded");
    toast(`Loaded ${file.name}.`, "success");
    document.dispatchEvent(new CustomEvent("m3mx:image-loaded", { detail: data }));
  } catch (err) {
    setStatus("err", "error");
    toast(`Upload failed: ${err.message}`, "err");
  }
}

function setOutputDir(path) {
  state.outputDir = path;
  $("#output-dir-path").textContent = path;
  m3mxFetch("/api/settings", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ output: { directory: path } }),
  }).catch(() => {});
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

function applySettings(s) {
  if (!s) return;
  $("#set-provider").value = s.ai?.provider || "ollama";
  onProviderChange(); // fills models dropdown
  if (s.ai?.model) $("#set-model").value = s.ai.model;
  $("#set-maxtokens").value = s.ai?.max_tokens || 1000;
  $("#maxtokens-val").textContent = $("#set-maxtokens").value;
  $("#set-temp").value = Math.round((s.ai?.temperature ?? 0.2) * 10);
  $("#temp-val").textContent = (parseInt($("#set-temp").value, 10) / 10).toFixed(1);

  $("#set-vol3").value  = s.volatility?.vol3_path || "";
  $("#set-vol2").value  = s.volatility?.vol2_path || "";
  $("#set-volpref").value = s.volatility?.preference || "auto";
  $("#set-timeout").value = s.volatility?.timeout_seconds || 600;

  $("#set-outdir").value = s.output?.directory || "outputs/";
  $("#set-autosave").checked = !!s.output?.auto_save;
  const formats = s.output?.formats || [];
  $$(".checkbox-row input[type=checkbox]").forEach(cb => cb.checked = formats.includes(cb.value));

  $("#set-lang").value = s.appearance?.language || "en";
  $("#set-font").value = s.appearance?.font_size || 14;
  $("#font-val").textContent = $("#set-font").value;
  document.body.style.fontSize = $("#set-font").value + "px";
}

function onProviderChange() {
  const provider = $("#set-provider").value;
  const models   = MODELS_BY_PROVIDER[provider] || [];
  const modelSel = $("#set-model");

  modelSel.innerHTML = "";
  models.forEach(m => {
    const o = document.createElement("option");
    o.value = m; o.textContent = m;
    modelSel.appendChild(o);
  });

  // Mirror to topbar model picker
  const top = $("#model-select");
  top.innerHTML = "";
  const hdr = document.createElement("option");
  hdr.value = ""; hdr.textContent = provider;
  hdr.disabled = true; top.appendChild(hdr);
  models.forEach(m => {
    const o = document.createElement("option");
    o.value = m; o.textContent = m;
    top.appendChild(o);
  });

  if (provider === "ollama" && models.length === 0) {
    loadOllamaModels().then(names => {
      names.forEach(n => {
        [modelSel, top].forEach(sel => {
          const o = document.createElement("option");
          o.value = n; o.textContent = n;
          sel.appendChild(o);
        });
      });
    });
  }
}

async function loadOllamaModels() {
  try {
    const r = await m3mxFetch("/api/ollama/models");
    if (!r.ok) return [];
    const d = await r.json();
    return d.models || [];
  } catch { return []; }
}

async function quickTriage() {
  if (!state.loadedImage) { toast("Load a memory image first.", "warn"); return; }
  const btn = $("#btn-quick-triage");
  btn.disabled = true;
  setStatus("running", "quick triage");
  toast("Running 10 essential plugins in parallel…", "info");

  try {
    const r = await m3mxFetch("/api/triage", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
    });
    const d = await r.json();
    if (d.error) throw new Error(d.error);

    const ok = d.successful || 0;
    const total = d.total || 0;
    toast(`Triage: ${ok}/${total} plugins succeeded in ${d.elapsed}s.`,
          ok === total ? "success" : "warn");
    setStatus(ok === total ? "ok" : "warn", `triage ${ok}/${total}`);

    // Switch to Results tab so the user sees the auto-saved outputs
    switchTab("results");
    // Refresh results list if loaded
    document.dispatchEvent(new CustomEvent("m3mx:outputs-changed"));

    // Offer to generate an AI report immediately
    if (ok >= 3 && confirm(`${ok} plugins ran. Generate AI report now?`)) {
      $("#btn-gen-report")?.click();
    }
  } catch (e) {
    toast(`Triage failed: ${e.message}`, "err");
    setStatus("err", "triage failed");
  } finally {
    btn.disabled = false;
  }
}

function wireContextMenu() {
  const term = $("#output-terminal");
  const menu = $("#context-menu");

  term.addEventListener("contextmenu", (e) => {
    e.preventDefault();
    menu.style.left = e.pageX + "px";
    menu.style.top  = e.pageY + "px";
    menu.hidden = false;
  });
  document.addEventListener("click", () => menu.hidden = true);

  menu.addEventListener("click", (e) => {
    const a = e.target.dataset?.a;
    if (!a) return;
    const sel = window.getSelection().toString();
    const all = term.innerText;

    if (a === "copy")      navigator.clipboard.writeText(sel || all).then(() => toast("Copied.", "success"));
    if (a === "copy-all")  navigator.clipboard.writeText(all).then(() => toast("Copied all.", "success"));
    if (a === "save-txt")  saveBlob(all, "output.txt", "text/plain");
    if (a === "save-json") saveBlob(JSON.stringify({ output: all }, null, 2), "output.json", "application/json");
    if (a === "analyze") {
      switchTab("agent");
      const ta = $("#chat-input");
      ta.value = `Analyze this plugin output and tell me what's interesting:\n\n${(sel || all).slice(0, 4000)}`;
      ta.focus();
    }
  });
}

function humanSize(n) {
  const units = ["B","KB","MB","GB","TB"];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(1)} ${units[i]}`;
}

function saveBlob(text, filename, mime) {
  const blob = new Blob([text], { type: mime });
  const url  = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click(); a.remove();
  URL.revokeObjectURL(url);
}

async function testConnection() {
  const btn = $("#btn-test-connection");
  const status = $("#test-connection-status");
  const provider = $("#set-provider").value;
  const model    = $("#set-model").value || "";
  const apiKey   = $("#set-apikey").value.trim();

  btn.disabled = true;
  status.innerHTML = `<span class="spinner small" style="display:inline-block;vertical-align:middle"></span> testing…`;

  try {
    const body = { provider, model };
    if (apiKey && !apiKey.includes("…")) body.api_key = apiKey;
    const r = await m3mxFetch("/api/agent/test", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const d = await r.json();

    if (d.ok) {
      status.innerHTML = `<span style="color:var(--success)">✓ ${d.message}</span> <span class="muted">(${d.elapsed_ms}ms)</span>`;
      toast(`${provider}: ${d.message}`, "success");
    } else {
      status.innerHTML = `<span style="color:var(--danger)">✗ ${d.message}</span>`;
      toast(`${provider} test failed: ${d.detail || d.message}`, "err");
    }
  } catch (e) {
    status.innerHTML = `<span style="color:var(--danger)">✗ ${e.message}</span>`;
  } finally {
    btn.disabled = false;
    setTimeout(() => status.textContent = "", 6000);
  }
}

async function saveSettings() {
  const formats = $$(".checkbox-row input[type=checkbox]")
    .filter(cb => cb.checked).map(cb => cb.value);

  const body = {
    ai: {
      provider: $("#set-provider").value,
      model:    $("#set-model").value || "",
      max_tokens: parseInt($("#set-maxtokens").value, 10),
      temperature: parseInt($("#set-temp").value, 10) / 10,
      api_keys: {},
    },
    volatility: {
      vol3_path: $("#set-vol3").value.trim(),
      vol2_path: $("#set-vol2").value.trim(),
      preference: $("#set-volpref").value,
      timeout_seconds: parseInt($("#set-timeout").value, 10),
    },
    output: {
      directory: $("#set-outdir").value.trim(),
      auto_save: $("#set-autosave").checked,
      formats,
    },
    appearance: {
      language: $("#set-lang").value,
      font_size: parseInt($("#set-font").value, 10),
    },
  };

  const key = $("#set-apikey").value.trim();
  if (key && !key.includes("…")) {
    body.ai.api_keys[$("#set-provider").value] = key;
  }

  const status = $("#settings-save-status");
  status.textContent = "Saving…";

  try {
    const r = await m3mxFetch("/api/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    status.textContent = "Saved.";
    toast("Settings saved.", "success");
    $("#set-apikey").value = "";
    setTimeout(() => status.textContent = "", 2000);
  } catch (err) {
    status.textContent = "";
    toast(`Save failed: ${err.message}`, "err");
  }
}

// ---------------------------------------------------------------------------
// Toasts
// ---------------------------------------------------------------------------

function toast(msg, kind = "info", ms = 3500) {
  const host = $("#toasts");
  const el = document.createElement("div");
  el.className = `toast ${kind}`;
  el.textContent = msg;
  host.appendChild(el);
  setTimeout(() => {
    el.classList.add("fade-out");
    setTimeout(() => el.remove(), 240);
  }, ms);
}

// ---------------------------------------------------------------------------
// Keyboard shortcuts (extended in Phase 10)
// ---------------------------------------------------------------------------

function onKeydown(e) {
  const mod = e.ctrlKey || e.metaKey;
  if (mod && e.key.toLowerCase() === "o") { e.preventDefault(); $("#btn-pick-file").click(); }
  if (mod && e.key.toLowerCase() === "l") {
    e.preventDefault();
    if ($(".panel.active")?.dataset.panel === "agent") {
      $("#chat-messages").innerHTML = "";
      toast("Chat cleared.", "info");
    }
  }
  if (mod && e.key.toLowerCase() === "r") {
    const lastName = $("#output-plugin-name")?.textContent;
    if (lastName && window.m3mx.runPlugin && lastName !== "—") {
      e.preventDefault();
      window.m3mx.runPlugin(lastName);
      toast(`Re-running ${lastName}…`, "info");
    }
  }
  if (mod && e.key.toLowerCase() === "s") {
    const btn = $$(".plugin-output .card-actions .btn").find(b =>
      b.textContent.trim() === "TXT");
    if (btn && !btn.disabled) { e.preventDefault(); btn.click(); }
  }
  if (mod && e.shiftKey && e.key.toLowerCase() === "t") {
    e.preventDefault(); $("#btn-quick-triage")?.click();
  }
}

// Expose for later phases
window.m3mx.toast = toast;
window.m3mx.setStatus = setStatus;
window.m3mx.state = state;
window.m3mx.switchTab = switchTab;

document.addEventListener("DOMContentLoaded", boot);
