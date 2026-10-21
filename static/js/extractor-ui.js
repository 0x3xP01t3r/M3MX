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
