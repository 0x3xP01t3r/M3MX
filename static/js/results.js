/* m3mx tool — Phase 6: Results Viewer + AI report generator. */

(function () {
  const $  = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));

  const state = {
    categories: { plugins: [], files: [], chats: [], reports: [] },
    active: "plugins",
    selected: null,
    outputDir: "",
  };

  function init() {
    $("#btn-refresh-results").addEventListener("click", refresh);
    $("#btn-gen-report").addEventListener("click", generateReport);

    $$(".results-cats .nav-item").forEach(b => {
      b.addEventListener("click", () => {
        state.active = b.dataset.cat;
        $$(".results-cats .nav-item").forEach(x => x.classList.remove("active"));
        b.classList.add("active");
        $("#results-cat-title").textContent = b.querySelector("span").textContent;
        renderList();
      });
    });

    // Refresh once at startup, then again every time the modal opens
    refresh();
    document.addEventListener("m3mx:open-results", refresh);
    document.addEventListener("m3mx:outputs-changed", refresh);
  }

  // ------------------------------------------------------------------
  async function refresh() {
    try {
      const d = await m3mxFetch("/api/outputs").then(r => r.json());
      state.categories = d.categories || { plugins: [], files: [], chats: [], reports: [] };
      state.outputDir  = d.output_dir || "";

      Object.entries(state.categories).forEach(([k, v]) => {
        const chip = $(`[data-cat-chip='${k}']`);
        if (chip) chip.textContent = v.length;
      });
      renderList();
    } catch (e) {
      $("#results-files").innerHTML = `<div class="error-block small">${e.message}</div>`;
    }
  }

  function renderList() {
    const list = state.categories[state.active] || [];
    const root = $("#results-files");

    if (!list.length) {
      root.innerHTML = `<div class="empty muted small">No ${state.active}.</div>`;
      return;
    }

    root.innerHTML = list.map(f => {
      const ext = (f.ext || "").toUpperCase();
      const size = humanBytes(f.size);
      const path = f.relpath || f.name;
      return `
        <div class="result-row" data-name="${escapeHtml(path)}">
          <div class="result-row-main">
            <span class="result-ext">${ext || "·"}</span>
            <span class="mono">${escapeHtml(f.name)}</span>
          </div>
          <div class="result-row-meta muted small">
            <span>${size}</span>
            <span>${escapeHtml(f.modified)}</span>
            <div class="result-row-actions">
              <button class="icon-btn" data-a="view" title="View">👁</button>
              <a class="icon-btn" href="/api/outputs/download?name=${encodeURIComponent(path)}" title="Download">⬇</a>
              <button class="icon-btn" data-a="del" title="Delete">✕</button>
            </div>
          </div>
        </div>`;
    }).join("");

    $$(".result-row", root).forEach(row => {
      row.addEventListener("click", (e) => {
        if (e.target.closest("button, a")) return;
        view(row.dataset.name);
      });
      row.querySelector('[data-a="view"]')?.addEventListener("click", () => view(row.dataset.name));
      row.querySelector('[data-a="del"]')?.addEventListener("click", (e) => {
        e.stopPropagation();
        remove(row.dataset.name);
      });
    });
  }

  // ------------------------------------------------------------------
  async function view(name) {
    const pane = $("#results-viewer");
    state.selected = name;
    pane.innerHTML = `<div class="running-banner"><span class="spinner"></span> loading ${escapeHtml(name)}…</div>`;

    try {
      const d = await m3mxFetch(`/api/outputs/view?name=${encodeURIComponent(name)}`).then(r => r.json());
      if (d.error) throw new Error(d.error);

      const ext = (name.split(".").pop() || "").toLowerCase();
      const trunc = d.truncated ? `<div class="muted small" style="margin:.4rem 0;">…truncated to 500 KB</div>` : "";

      if (d.binary) {
        pane.innerHTML = `
          <div class="viewer-head"><b>${escapeHtml(name)}</b> <span class="muted small">(binary — hex preview)</span></div>
          <pre class="md-code small">${escapeHtml(d.hex || "")}</pre>${trunc}`;
        return;
      }
      if (ext === "csv") {
        pane.innerHTML = `<div class="viewer-head"><b>${escapeHtml(name)}</b></div>${renderCsvTable(d.text)}${trunc}`;
        return;
      }
      if (ext === "json") {
        let pretty = d.text;
        try { pretty = JSON.stringify(JSON.parse(d.text), null, 2); } catch {}
        pane.innerHTML = `<div class="viewer-head"><b>${escapeHtml(name)}</b></div><pre class="md-code small">${escapeHtml(pretty)}</pre>${trunc}`;
        return;
      }
      if (ext === "md") {
        pane.innerHTML = `<div class="viewer-head"><b>${escapeHtml(name)}</b></div>
          <div class="md-render">${mdBasic(d.text)}</div>${trunc}`;
        return;
      }
      // default: text
      pane.innerHTML = `<div class="viewer-head"><b>${escapeHtml(name)}</b></div>
        <pre class="md-code small">${escapeHtml(d.text || "")}</pre>${trunc}`;
    } catch (e) {
      pane.innerHTML = `<div class="error-block small">${escapeHtml(e.message)}</div>`;
    }
  }

  async function remove(name) {
    if (!confirm(`Delete ${name}?`)) return;
    try {
      const r = await m3mxFetch("/api/outputs/delete", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name }),
      });
      const d = await r.json();
      if (d.error) throw new Error(d.error);
      window.m3mx.toast(`Deleted ${name}.`, "success");
      if (state.selected === name) $("#results-viewer").innerHTML =
        `<div class="empty muted small">Select a file to view it.</div>`;
      refresh();
    } catch (e) {
      window.m3mx.toast(`Delete failed: ${e.message}`, "err");
    }
  }

  // ------------------------------------------------------------------
  async function generateReport() {
    window.m3mx.setStatus("running", "generating report");
    window.m3mx.toast("Generating forensics report…", "info");
    const btn = $("#btn-gen-report"); btn.disabled = true;

    try {
      const r = await m3mxFetch("/api/reports/generate", { method: "POST" });
      const d = await r.json();
      if (d.error) throw new Error(d.error);

      const fmts = Object.keys(d.files || {}).join(" + ") || "md";
      window.m3mx.toast(`Report saved (${fmts}).`, "success");
      window.m3mx.setStatus("ok", "report done");

      // Switch to Reports category and open latest
      state.active = "reports";
      $$(".results-cats .nav-item").forEach(x => x.classList.toggle("active", x.dataset.cat === "reports"));
      $("#results-cat-title").textContent = "Reports";
      await refresh();
      const mdName = d.files?.md ? d.files.md.split("/").pop() : null;
      if (mdName) view(mdName);
    } catch (e) {
      window.m3mx.toast(`Report failed: ${e.message}`, "err");
      window.m3mx.setStatus("err", "report failed");
    } finally {
      btn.disabled = false;
    }
  }

  // ------------------------------------------------------------------
  // Helpers
  // ------------------------------------------------------------------
  function renderCsvTable(text) {
    const rows = text.split(/\r?\n/).filter(l => l.length).slice(0, 500);
    if (!rows.length) return `<div class="muted small">empty</div>`;
    // naive CSV split — good enough for viewer
    const split = r => {
      const out = []; let cur = ""; let q = false;
      for (const ch of r) {
        if (ch === '"') q = !q;
        else if (ch === "," && !q) { out.push(cur); cur = ""; }
        else cur += ch;
      }
      out.push(cur); return out;
    };
    const [head, ...body] = rows.map(split);
    const th = head.map(h => `<th>${escapeHtml(h)}</th>`).join("");
    const tr = body.map(r => `<tr>${r.map(c => `<td title="${escapeHtml(c)}">${escapeHtml(c)}</td>`).join("")}</tr>`).join("");
    return `<div class="mini-table scroll"><table class="result-table"><thead><tr>${th}</tr></thead><tbody>${tr}</tbody></table></div>`;
  }

  function mdBasic(src) {
    let s = escapeHtml(src);
    s = s.replace(/^##\s+(.*)$/gm, "<h3>$1</h3>");
    s = s.replace(/^#\s+(.*)$/gm,  "<h2>$1</h2>");
    s = s.replace(/\*\*([^*]+)\*\*/g, "<b>$1</b>");
    s = s.replace(/`([^`]+)`/g, "<code class='md-inline'>$1</code>");
    s = s.replace(/(^|\n)([-*]\s+.+(?:\n[-*]\s+.+)*)/g, (_, p, blk) => {
      const items = blk.split(/\n/).map(l => `<li>${l.replace(/^[-*]\s+/, "")}</li>`).join("");
      return `${p}<ul>${items}</ul>`;
    });
    s = s.replace(/\n{2,}/g, "</p><p>");
    return `<p>${s}</p>`;
  }

  function humanBytes(n) {
    if (n == null) return "—";
    if (n < 1024) return n + "B";
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + "K";
    if (n < 1024 * 1024 * 1024) return (n / 1024 / 1024).toFixed(1) + "M";
    return (n / 1024 / 1024 / 1024).toFixed(1) + "G";
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
