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
  document.querySelector('[data-view="extractor"]')?.addEventListener("click", () => {
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
  const r = await m3mxFetch("/api/agent/chat", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message: prompt, mode: "synthesis" }),
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
