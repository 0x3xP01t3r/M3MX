/* m3mx tool — Phase 5: File Extractor.
   Scans the memory image for cached files, renders them in a paginated,
   filterable, selectable table, and dumps selected offsets. Optional
   AI-Assisted flagging asks the backend agent to flag high-priority
   files using metadata ONLY (never file contents). */

(function () {
  const $  = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));

  const PAGE_SIZE = 50;

  const state = {
    all: [],
    filtered: [],
    selected: new Set(),
    page: 0,
    filter: "high",
    query: "",
    scanning: false,
  };

  // ------------------------------------------------------------------
  function init() {
    $("#btn-scan-files").addEventListener("click", scan);
    $("#btn-extract-selected").addEventListener("click", extractSelected);
    $("#fx-filter").addEventListener("change", e => { state.filter = e.target.value; state.page = 0; render(); });
    $("#fx-search").addEventListener("input",   e => { state.query  = e.target.value.toLowerCase(); state.page = 0; render(); });
    $("#fx-prev").addEventListener("click", () => { if (state.page > 0) { state.page--; render(); } });
    $("#fx-next").addEventListener("click", () => {
      if ((state.page + 1) * PAGE_SIZE < state.filtered.length) { state.page++; render(); }
    });

    // Event delegation for checkbox changes (no per-row listeners)
    $("#fx-body").addEventListener("change", onTableChange);
  }

  // ------------------------------------------------------------------
  async function scan() {
    if (!window.m3mx.state.loadedImage) {
      window.m3mx.toast("Load a memory image first.", "warn");
      return;
    }
    if (state.scanning) return;
    state.scanning = true;

    const body = $("#fx-body");
    body.innerHTML = `
      <div class="running-banner">
        <span class="spinner"></span>
        <span>Scanning memory for file objects…</span>
      </div>`;
    window.m3mx.setStatus("running", "filescan");

    try {
      const r = await m3mxFetch("/api/files/scan", { method: "POST" });
      const d = await r.json();
      if (d.error) throw new Error(d.error);

      state.all = d.files || [];
      state.selected.clear();
      state.page = 0;
      render();

      const count = d.count || state.all.length;
      $("#fx-count").hidden = false;
      $("#fx-count").textContent = count;
      $("#fx-meta").textContent =
        `${count} files · filescan ${d.version || ""} · ${d.elapsed || "?"}s`;

      window.m3mx.toast(`${count} files found.`, "success");
      window.m3mx.setStatus("ok", "scan done");

      if ($("#ai-assist-toggle").checked) runAIAssist();
    } catch (e) {
      body.innerHTML = `<div class="error-block">${escapeHtml(e.message)}</div>`;
      window.m3mx.toast(`Scan failed: ${e.message}`, "err");
      window.m3mx.setStatus("err", "scan failed");
    } finally {
      state.scanning = false;
    }
  }

  // ------------------------------------------------------------------
  function applyFilter() {
    const q = state.query;
    const f = state.filter;
    state.filtered = state.all.filter(row => {
      if (q && !(row.name.toLowerCase().includes(q) || row.path.toLowerCase().includes(q)))
        return false;
      if (f === "high") return row.high_value || row.priority > 0;
      if (f === "exe")  return ["exe","dll","sys","scr","ps1","vbs","bat","cmd"].includes(row.ext);
      if (f === "doc")  return ["pdf","doc","docx","xls","xlsx","csv","rtf","txt"].includes(row.ext);
      return true;
    });
  }

  function render() {
    applyFilter();

    const body = $("#fx-body");
    if (!state.filtered.length) {
      body.innerHTML = `<div class="empty"><p>No files match your filters.</p></div>`;
      $("#fx-foot").hidden = true;
      return;
    }

    const start = state.page * PAGE_SIZE;
    const pageRows = state.filtered.slice(start, start + PAGE_SIZE);

    const head = `
      <tr>
        <th style="width:30px"><input type="checkbox" id="fx-select-all"/></th>
        <th style="width:30px"></th>
        <th>Name</th>
        <th>Path</th>
        <th style="width:130px">Offset</th>
        <th style="width:80px">Size</th>
        <th>Flags</th>
      </tr>`;

    const rows = pageRows.map(f => {
      const selected = state.selected.has(f.offset) ? "checked" : "";
      const flagBadges = (f.flags || []).map(
        fl => `<span class="flag flag-${fl.replace(/[^a-z]/gi,'')}">${escapeHtml(fl)}</span>`
      ).join("");
      const priRow = f.priority >= 5 ? "row-danger" : (f.priority >= 2 ? "row-warn" : "");
      const sizeStr = f.size != null ? humanBytes(f.size) : "—";
      const aiNote = f.ai_reason ? `<span class="ai-reason" title="${escapeHtml(f.ai_reason)}">🧠</span>` : "";
      return `
        <tr class="${priRow}" data-offset="${escapeHtml(f.offset)}">
          <td><input type="checkbox" class="fx-sel" ${selected}/></td>
          <td>${f.icon || "📁"}</td>
          <td class="mono">${escapeHtml(f.name)} ${aiNote}</td>
          <td class="mono muted" title="${escapeHtml(f.path)}">${escapeHtml(ellipsize(f.path, 80))}</td>
          <td class="mono">${escapeHtml(f.offset)}</td>
          <td class="mono muted">${sizeStr}</td>
          <td>${flagBadges}</td>
        </tr>`;
    }).join("");

    body.innerHTML = `
      <div class="result-table-wrap">
        <table class="result-table fx-table"><thead>${head}</thead><tbody>${rows}</tbody></table>
      </div>`;

    $("#fx-foot").hidden = false;
    $("#fx-pager").textContent =
      `page ${state.page + 1}/${Math.max(1, Math.ceil(state.filtered.length / PAGE_SIZE))}`;
    $("#fx-prev").disabled = state.page === 0;
    $("#fx-next").disabled = (state.page + 1) * PAGE_SIZE >= state.filtered.length;

    // Stash page rows for the delegated click handler
    state._pageRows = pageRows;

    // "Select all" on this page (toggles only in-place, no full re-render)
    $("#fx-select-all").addEventListener("change", (e) => {
      const on = e.target.checked;
      pageRows.forEach(f => on ? state.selected.add(f.offset) : state.selected.delete(f.offset));
      $$(".fx-sel", body).forEach(cb => { cb.checked = on; });
      updateSelectionUI();
    });

    updateSelectionUI();
  }

  // Single delegated change handler for individual checkboxes
  function onTableChange(e) {
    const cb = e.target;
    if (!cb.classList.contains("fx-sel")) return;
    const tr = cb.closest("tr");
    const off = tr?.dataset?.offset;
    if (!off) return;
    if (cb.checked) state.selected.add(off); else state.selected.delete(off);
    updateSelectionUI();
  }

  function updateSelectionUI() {
    $("#fx-selected").textContent = state.selected.size;
    $("#btn-extract-selected").disabled = state.selected.size === 0;
  }

  // ------------------------------------------------------------------
  async function extractSelected() {
    if (!state.selected.size) return;
    const offsets = Array.from(state.selected).slice(0, 100);
    window.m3mx.setStatus("running", `extracting ${offsets.length}`);
    window.m3mx.toast(`Extracting ${offsets.length} files…`, "info");

    try {
      const r = await m3mxFetch("/api/files/extract", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ offsets }),
      });
      const d = await r.json();
      if (d.error) throw new Error(d.error);

      window.m3mx.toast(
        `Extracted ${d.count}/${d.total} → ${(d.dumped || []).length} file(s).`,
        d.count > 0 ? "success" : "warn"
      );
      window.m3mx.setStatus("ok", "extract done");
      state.selected.clear();

      // Show what was actually written so the user can grab it
      showExtractResult(d);

      // Tell the Results viewer to refresh in the background
      document.dispatchEvent(new CustomEvent("m3mx:outputs-changed"));
    } catch (e) {
      window.m3mx.toast(`Extract failed: ${e.message}`, "err");
      window.m3mx.setStatus("err", "extract failed");
    }
  }

  function showExtractResult(d) {
    const dumped = d.dumped || [];
    const failures = (d.results || []).filter(r => !r.ok);
    const dlList = dumped.map(f => `
      <li>
        <a class="ext-dl"
           href="/api/outputs/download?name=${encodeURIComponent(f.path)}"
           download>${escapeHtml(f.name)}</a>
        <span class="muted small">${humanBytes(f.size)}</span>
      </li>`).join("");
    const failList = failures.slice(0, 10).map(r =>
      `<li class="err">
         <code>${escapeHtml(r.offset)}</code>
         <div class="muted small">${escapeHtml((r.error || "no message").slice(0, 280))}</div>
       </li>`
    ).join("");

    const html = `
      <div class="extract-result-modal">
        <div class="extract-result-card">
          <div class="extract-result-head">
            <h3>Extraction complete</h3>
            <button class="icon-btn" id="ext-modal-close">✕</button>
          </div>
          <div class="extract-result-body">
            <p class="muted small">Saved to <code>${escapeHtml(d.output_dir || "")}</code></p>
            <h4>Dumped (${dumped.length})</h4>
            ${dumped.length ? `<ul class="extract-result-list">${dlList}</ul>`
                            : `<p class="muted small">No files were dumped — check failures below.</p>`}
            ${failures.length ? `<h4>Failures (${failures.length})</h4><ul class="extract-result-fail">${failList}</ul>` : ""}
          </div>
          <div class="extract-result-foot">
            <button class="btn btn-ghost btn-sm" id="ext-modal-results">Open Results Viewer →</button>
            <button class="btn btn-primary btn-sm" id="ext-modal-ok">Done</button>
          </div>
        </div>
      </div>`;

    const wrap = document.createElement("div");
    wrap.innerHTML = html;
    const modal = wrap.firstElementChild;
    document.body.appendChild(modal);

    const close = () => modal.remove();
    modal.querySelector("#ext-modal-close").onclick = close;
    modal.querySelector("#ext-modal-ok").onclick = close;
    modal.querySelector("#ext-modal-results").onclick = () => {
      close();
      window.m3mx.switchTab("results");
      // Click the "Extracted Files" category once Results is mounted
      setTimeout(() => {
        document.querySelector('.results-cats [data-cat="files"]')?.click();
      }, 100);
    };
    modal.addEventListener("click", e => { if (e.target === modal) close(); });
  }

  // ------------------------------------------------------------------
  // AI-assisted flagging: send metadata only
  // ------------------------------------------------------------------
  async function runAIAssist() {
    const sample = state.all.slice(0, 200).map(f => ({
      name: f.name, path: f.path, ext: f.ext, flags: f.flags,
    }));

    const prompt =
      "Below is a list of files discovered in a memory dump (metadata only — " +
      "NO file contents). Flag files that look suspicious or forensically " +
      "high-value. Return a single fenced JSON array of objects like " +
      '{"name":"foo.exe","reason":"..."}. Keep it concise, max 15 entries.\n' +
      "\n" + JSON.stringify(sample);

    try {
      const r = await m3mxFetch("/api/agent/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: prompt }),
      });
      const text = await r.text();
      let collected = "";
      text.split("\n\n").forEach(line => {
        if (!line.startsWith("data:")) return;
        try {
          const evt = JSON.parse(line.slice(5).trim());
          if (evt.type === "token") collected += evt.content;
        } catch {}
      });
      // Parse a fenced JSON block from the model's response
      const m = collected.match(/```(?:json)?\s*(\[[\s\S]*?\])\s*```/);
      if (!m) { window.m3mx.toast("AI-assist: no structured flags returned.", "warn"); return; }
      const flags = JSON.parse(m[1]);
      let applied = 0;
      flags.forEach(flag => {
        const hit = state.all.find(f => f.name === flag.name);
        if (hit) { hit.ai_reason = flag.reason; hit.priority = Math.max(hit.priority, 4); hit.high_value = true; applied++; }
      });
      render();
      window.m3mx.toast(`AI flagged ${applied} files.`, "success");
    } catch (e) {
      window.m3mx.toast(`AI-assist failed: ${e.message}`, "warn");
    }
  }

  // ------------------------------------------------------------------
  // Helpers
  // ------------------------------------------------------------------
  function humanBytes(n) {
    if (n < 1024) return n + "B";
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + "K";
    if (n < 1024 * 1024 * 1024) return (n / 1024 / 1024).toFixed(1) + "M";
    return (n / 1024 / 1024 / 1024).toFixed(1) + "G";
  }
  function ellipsize(s, n) {
    return s.length > n ? "…" + s.slice(-(n - 1)) : s;
  }
  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, c => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
    }[c]));
  }

  document.addEventListener("DOMContentLoaded", () => {
    const iv = setInterval(() => {
      if (!document.getElementById("app").hidden) { clearInterval(iv); init(); }
    }, 150);
  });
})();
