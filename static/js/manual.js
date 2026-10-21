/* m3mx tool — Phase 3: Manual Analysis tab.
   Fetches /api/plugins, renders grouped cards with search + run,
   calls /api/run-plugin, renders CSV as a table (or raw terminal),
   and wires export buttons (Copy / TXT / CSV / JSON).
*/

(function () {
  const $  = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));

  const state = {
    registry: null,
    lastResult: null,
    queue: [],
    running: false,
  };

  // Suspicious pattern highlighter
  const SUSPICIOUS_NAMES = /(mimikatz|pwdump|meterpreter|beacon\.exe|cobalt|psexec|lazagne|procdump)/i;

  // ------------------------------------------------------------------
  // Public bootstrap
  // ------------------------------------------------------------------
  async function init() {
    try {
      const res = await m3mxFetch("/api/plugins");
      state.registry = await res.json();
      renderRegistry();
    } catch (e) {
      $("#plugin-categories").innerHTML =
        `<div class="empty"><p>Failed to load plugin registry: ${e.message}</p></div>`;
    }

    $("#plugin-search").addEventListener("input", renderRegistry);
    wireExportButtons();
    window.m3mx.runPlugin = runPlugin;
  }

  // ------------------------------------------------------------------
  // Rendering the plugin list
  // ------------------------------------------------------------------
  function renderRegistry() {
    const root = $("#plugin-categories");
    const q = ($("#plugin-search").value || "").trim().toLowerCase();
    if (!state.registry?.categories?.length) {
      root.innerHTML = `<div class="empty"><p>No plugins in registry.</p></div>`;
      return;
    }
    const frag = document.createDocumentFragment();

    state.registry.categories.forEach(cat => {
      const matching = cat.plugins.filter(p =>
        !q || p.name.toLowerCase().includes(q) || (p.desc || "").toLowerCase().includes(q)
      );
      if (!matching.length) return;

      const head = document.createElement("div");
      head.className = "pcat-head";
      head.innerHTML = `<span>${cat.name}</span><span class="muted small">${matching.length}</span>`;
      frag.appendChild(head);

      const group = document.createElement("div");
      group.className = "pcat-group";

      matching.forEach(p => {
        const card = document.createElement("button");
        card.className = "plugin-card";
        card.dataset.name = p.name;
        card.disabled = !p.available;

        const badges = (p.versions || [])
          .map(v => `<span class="ver-badge ver-${v}">${v}</span>`).join("");

        card.innerHTML = `
          <div class="plugin-title">
            <span>${p.name}</span>
            <span class="badges">${badges}</span>
          </div>
          <div class="plugin-desc">${p.desc || ""}</div>
          ${p.available ? "" : '<div class="plugin-muted">not available with installed Volatility</div>'}
        `;
        card.addEventListener("click", () => runPlugin(p.name));
        group.appendChild(card);
      });

      frag.appendChild(group);
    });

    root.innerHTML = "";
    root.appendChild(frag);
  }

  // ------------------------------------------------------------------
  // Running a plugin
  // ------------------------------------------------------------------
  async function runPlugin(name, version = "auto") {
    if (state.running) {
      window.m3mx.toast(`Already running. '${name}' queued.`, "info");
      state.queue.push({ name, version });
      return;
    }
    if (!window.m3mx.state.loadedImage) {
      window.m3mx.toast("Load a memory image first.", "warn");
      return;
    }

    state.running = true;
    window.m3mx.setStatus("running", `running ${name}`);
    $("#output-plugin-name").textContent = name;
    $("#output-plugin-name").hidden = false;

    const term = $("#output-terminal");
    term.innerHTML = `
      <div class="output-doc">
        <h1 class="doc-title">${escapeHtml(name)}</h1>
        <div class="doc-sub"><span class="muted small">running plugin…</span></div>
        <div class="running-banner" style="padding:16px 0;">
          <span class="spinner"></span>
          <span>Running <b>${escapeHtml(name)}</b>…</span>
        </div>
      </div>`;

    try {
      const r = await m3mxFetch("/api/run-plugin", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ plugin: name, version }),
      });
      const data = await r.json();
      state.lastResult = data;
      renderResult(data);

      if (data.success) {
        window.m3mx.toast(`${name} finished in ${data.elapsed}s`, "success");
        window.m3mx.setStatus("ok", `${name} done`);
      } else {
        window.m3mx.toast(`${name} failed: ${data.error || "unknown error"}`, "err");
        window.m3mx.setStatus("err", `${name} failed`);
      }
    } catch (e) {
      term.innerHTML = `<div class="error-block">Network error: ${e.message}</div>`;
      window.m3mx.toast(`Error: ${e.message}`, "err");
      window.m3mx.setStatus("err", "error");
    } finally {
      state.running = false;
      if (state.queue.length) {
        const next = state.queue.shift();
        setTimeout(() => runPlugin(next.name, next.version), 200);
      }
    }
  }

  // ------------------------------------------------------------------
  // Output rendering
  // ------------------------------------------------------------------
  function renderResult(data) {
    const term = $("#output-terminal");

    const header = `
      <div class="output-doc">
        <h1 class="doc-title">${escapeHtml(data.plugin || "result")}</h1>
        <div class="doc-sub">
          <span>version&nbsp;<b>${escapeHtml(data.version || "")}</b></span>
          <span>elapsed&nbsp;<b>${data.elapsed ?? "?"}s</b></span>
          ${data.rows ? `<span>rows&nbsp;<b>${data.rows.length.toLocaleString()}</b></span>` : ""}
          ${data.success ? '<span class="chip" style="color:var(--ok);border-color:var(--ok);background:transparent;">success</span>'
                         : '<span class="chip" style="color:var(--err);border-color:var(--err);background:transparent;">failed</span>'}
        </div>
        <details class="command-toggle">
          <summary>command</summary>
          <code>${escapeHtml(data.command || "")}</code>
        </details>
        <div id="output-doc-body"></div>
      </div>`;

    term.innerHTML = header;
    const mount = $("#output-doc-body");

    if (!data.success) {
      mount.innerHTML = `
        <div class="error-block">
          <b>Failed.</b><br/>${escapeHtml(data.error || "unknown")}
          ${data.output ? `<pre>${escapeHtml(data.output)}</pre>` : ""}
        </div>`;
      enableExports(false);
      return;
    }

    if (data.format === "csv" && data.columns && data.rows) {
      renderTableFull(mount, data.columns, data.rows);
    } else {
      const pre = document.createElement("pre");
      pre.className = "raw-output";
      pre.innerHTML = highlightRaw(data.output || "");
      mount.appendChild(pre);
    }
    enableExports(true);
  }

  /**
   * Render the FULL table with client-side filter + virtualization.
   * Handles 100k rows without freezing the browser.
   */
  function renderTableFull(mount, cols, rows) {
    const wrap = document.createElement("div");
    wrap.className = "result-table-wrap";

    // Toolbar: live filter + row counter
    const toolbar = document.createElement("div");
    toolbar.className = "result-table-toolbar";
    toolbar.innerHTML = `
      <input type="search" placeholder="Filter rows…" />
      <span class="spacer"></span>
      <span class="counter"><b>${rows.length.toLocaleString()}</b> rows</span>`;
    wrap.appendChild(toolbar);

    const scroll = document.createElement("div");
    scroll.className = "result-table-scroll";
    scroll.innerHTML = `
      <table class="result-table">
        <thead><tr>${cols.map(c => `<th>${escapeHtml(c)}</th>`).join("")}</tr></thead>
        <tbody></tbody>
      </table>`;
    wrap.appendChild(scroll);
    mount.appendChild(wrap);

    const tbody = scroll.querySelector("tbody");
    const input = toolbar.querySelector("input");
    const counter = toolbar.querySelector(".counter");

    // Precompute row search strings once
    const joined = rows.map(r => r.join("\u0001").toLowerCase());

    let filteredIdx = rows.map((_, i) => i);
    const PAGE = 200;
    let rendered = 0;
    let rafId = null;

    const buildCell = (v, i) => {
      const col = (cols[i] || "").toLowerCase();
      const val = v == null ? "" : String(v);
      let cls = "";
      if (SUSPICIOUS_NAMES.test(val)) cls = "cell-danger";
      else if (col.includes("ppid") && val === "0") cls = "cell-muted";
      else if (col === "hidden" && /true|yes/i.test(val)) cls = "cell-danger";
      return `<td class="${cls}" title="${escapeHtml(val)}">${escapeHtml(val)}</td>`;
    };

    const appendBatch = () => {
      const end = Math.min(rendered + PAGE, filteredIdx.length);
      const frag = document.createDocumentFragment();
      for (let i = rendered; i < end; i++) {
        const r = rows[filteredIdx[i]];
        const tr = document.createElement("tr");
        tr.innerHTML = r.map(buildCell).join("");
        frag.appendChild(tr);
      }
      tbody.appendChild(frag);
      rendered = end;
    };

    const onScroll = () => {
      if (rendered >= filteredIdx.length) return;
      const remaining = scroll.scrollHeight - scroll.scrollTop - scroll.clientHeight;
      if (remaining < 400) appendBatch();
    };

    const refilter = () => {
      const q = input.value.trim().toLowerCase();
      filteredIdx = q ? joined.reduce((acc, s, i) => { if (s.includes(q)) acc.push(i); return acc; }, [])
                     : rows.map((_, i) => i);
      counter.innerHTML = `<b>${filteredIdx.length.toLocaleString()}</b> of ${rows.length.toLocaleString()} rows`;
      tbody.innerHTML = "";
      rendered = 0;
      appendBatch();
    };

    let debounce;
    input.addEventListener("input", () => {
      clearTimeout(debounce);
      debounce = setTimeout(refilter, 120);
    });

    scroll.addEventListener("scroll", () => {
      cancelAnimationFrame(rafId);
      rafId = requestAnimationFrame(onScroll);
    });

    // First paint
    appendBatch();
  }

  function highlightRaw(text) {
    const esc = escapeHtml(text);
    // Highlight PIDs, IPs, hex addresses
    return esc
      .replace(/\b([0-9]{1,3}\.){3}[0-9]{1,3}(?::\d+)?\b/g, m => `<span class="hl-ip">${m}</span>`)
      .replace(/\b0x[0-9a-fA-F]{6,16}\b/g, m => `<span class="hl-hex">${m}</span>`)
      .replace(/(mimikatz|pwdump|meterpreter|cobalt)/gi, m => `<span class="hl-danger">${m}</span>`);
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, c => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
    }[c]));
  }

  // ------------------------------------------------------------------
  // Export buttons
  // ------------------------------------------------------------------
  function enableExports(on) {
    $$(".plugin-output .card-actions .btn").forEach(b => b.disabled = !on);
  }

  function wireExportButtons() {
    const btns = $$(".plugin-output .card-actions .btn");
    if (btns.length !== 4) return;
    const [copy, txt, csv, json] = btns;

    copy.addEventListener("click", () => {
      const r = state.lastResult;
      if (!r) return;
      navigator.clipboard.writeText(r.output || "")
        .then(() => window.m3mx.toast("Copied to clipboard.", "success"))
        .catch(() => window.m3mx.toast("Clipboard blocked.", "warn"));
    });

    txt.addEventListener("click", () => saveBlob(
      state.lastResult?.output || "",
      `${state.lastResult?.plugin || "output"}.txt`, "text/plain"));

    csv.addEventListener("click", () => {
      const r = state.lastResult;
      if (!r) return;
      if (r.format === "csv") {
        saveBlob(r.output, `${r.plugin}.csv`, "text/csv");
      } else if (r.columns && r.rows) {
        const text = [r.columns.join(","), ...r.rows.map(row => row.join(","))].join("\n");
        saveBlob(text, `${r.plugin}.csv`, "text/csv");
      } else {
        window.m3mx.toast("Current output isn't tabular.", "warn");
      }
    });

    json.addEventListener("click", () => saveBlob(
      JSON.stringify(state.lastResult || {}, null, 2),
      `${state.lastResult?.plugin || "output"}.json`, "application/json"));

    enableExports(false);
  }

  function saveBlob(text, filename, mime) {
    const blob = new Blob([text], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = filename;
    document.body.appendChild(a); a.click(); a.remove();
    URL.revokeObjectURL(url);
    window.m3mx.toast(`Saved ${filename}.`, "success");
  }

  // ------------------------------------------------------------------
  // Auto-detect profile on image load
  // ------------------------------------------------------------------
  document.addEventListener("m3mx:image-loaded", () => {
    window.m3mx.toast("Detecting OS profile…", "info");
    runPlugin("imageinfo");
  });

  document.addEventListener("DOMContentLoaded", () => {
    // Wait for boot to hand off
    const iv = setInterval(() => {
      if (!document.getElementById("app").hidden) {
        clearInterval(iv);
        init();
      }
    }, 150);
  });
})();
