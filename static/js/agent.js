/* m3mx tool — Phase 4: AI Agent chat.
   Streams tokens via SSE, renders markdown inline, displays tool
   calls + results (with inline tables), tracks token usage. */

(function () {
  const $  = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));

  const state = {
    history: [],
    streaming: false,
  };

  // -------------------------------------------------------------------------
  // Markdown → HTML (lightweight, handles the common cases we need)
  // -------------------------------------------------------------------------
  function md(src) {
    let s = escapeHtml(src);

    // Code blocks (```lang\n...)
    s = s.replace(/```(\w*)\n([\s\S]*?)```/g, (_, lang, body) => {
      const safe = body.replace(/\n$/, "");
      return `<pre class="md-code" data-lang="${lang || ""}"><button class="md-copy" title="Copy">⧉</button><code>${safe}</code></pre>`;
    });

    // Inline code
    s = s.replace(/`([^`\n]+)`/g, '<code class="md-inline">$1</code>');

    // Bold / italic
    s = s.replace(/\*\*([^*\n]+)\*\*/g, "<b>$1</b>");
    s = s.replace(/(^|[^*])\*([^*\n]+)\*/g, "$1<i>$2</i>");

    // Headings
    s = s.replace(/^###\s+(.*)$/gm, "<h4>$1</h4>");
    s = s.replace(/^##\s+(.*)$/gm,  "<h3>$1</h3>");
    s = s.replace(/^#\s+(.*)$/gm,   "<h2>$1</h2>");

    // Bullet lists
    s = s.replace(/(^|\n)([-*]\s+.+(?:\n[-*]\s+.+)*)/g, (_, pre, blk) => {
      const items = blk.split(/\n/).map(l => l.replace(/^[-*]\s+/, ""))
                       .map(i => `<li>${i}</li>`).join("");
      return `${pre}<ul>${items}</ul>`;
    });

    // Paragraph breaks
    s = s.replace(/\n{2,}/g, "</p><p>");
    return `<p>${s}</p>`;
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, c => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
    }[c]));
  }

  function installCopyButtons(root) {
    $$(".md-copy", root).forEach(btn => {
      if (btn._bound) return;
      btn._bound = true;
      btn.addEventListener("click", (e) => {
        e.stopPropagation();
        const code = btn.parentElement.querySelector("code")?.textContent || "";
        navigator.clipboard.writeText(code)
          .then(() => window.m3mx.toast("Copied.", "success"))
          .catch(() => {});
      });
    });
  }

  // -------------------------------------------------------------------------
  // Chat bubble rendering
  // -------------------------------------------------------------------------
  function addMessage(role, { text = "", model = "", usage = null } = {}) {
    const inner = $("#chat-inner") || (() => {
      const hostScroll = $("#chat-messages");
      const i = document.createElement("div");
      i.id = "chat-inner"; i.className = "chat-inner";
      hostScroll.appendChild(i); return i;
    })();
    const scroll = $("#chat-messages");

    const wrap = document.createElement("div");
    wrap.className = `chat-msg ${role}`;
    wrap.innerHTML = `
      <div class="chat-avatar">${role === "user" ? "U" : "m3"}</div>
      <div class="chat-bubble">
        <div class="chat-meta">
          <span class="role">${role === "user" ? "you" : "m3mx"}</span>
          <span class="muted">${model || ""}</span>
        </div>
        <div class="chat-body"></div>
        <div class="chat-usage muted small" hidden></div>
        ${role === "ai" ? `
          <div class="msg-actions">
            <button class="icon-btn" data-a="copy" title="Copy">⧉</button>
            <button class="icon-btn" data-a="regen" title="Regenerate">↻</button>
          </div>` : ""}
      </div>`;
    inner.appendChild(wrap);
    scroll.scrollTop = scroll.scrollHeight;

    const body  = wrap.querySelector(".chat-body");
    const usageEl = wrap.querySelector(".chat-usage");
    if (text) { body.innerHTML = md(text); installCopyButtons(body); }
    if (usage) {
      usageEl.hidden = false;
      usageEl.textContent = `in ${usage.input} · out ${usage.output} tokens`;
    }

    // Message actions
    wrap.querySelector('[data-a="copy"]')?.addEventListener("click", () => {
      const t = body.innerText || "";
      navigator.clipboard.writeText(t).then(() =>
        window.m3mx.toast("Copied.", "success"));
    });
    wrap.querySelector('[data-a="regen"]')?.addEventListener("click", () => {
      // Find the preceding user message's text and resend
      const prevUser = wrap.previousElementSibling;
      const ut = prevUser?.querySelector(".chat-body")?.innerText?.trim();
      if (ut) {
        wrap.remove();
        send(ut);
      }
    });
    return { wrap, body, usageEl };
  }

  function addToolCallBlock(name, args, aiWrap) {
    const el = document.createElement("div");
    el.className = "tool-call";
    el.innerHTML = `
      <div class="tool-head">
        <span class="tool-icon">⚙</span>
        <span>calling <b>${escapeHtml(name)}</b></span>
        <span class="muted small">${escapeHtml(JSON.stringify(args))}</span>
        <span class="spinner small"></span>
      </div>
      <div class="tool-body" hidden></div>`;
    const target = aiWrap?.querySelector(".chat-bubble") || $("#chat-inner");
    target.appendChild(el);
    $("#chat-messages").scrollTop = $("#chat-messages").scrollHeight;
    return el;
  }

  function fillToolResult(el, name, result) {
    el.querySelector(".spinner")?.remove();
    const head = el.querySelector(".tool-head");
    head.classList.add(result.error || result.success === false ? "err" : "ok");
    const body = el.querySelector(".tool-body");
    body.hidden = false;

    if (result.error) {
      body.innerHTML = `<div class="error-block small">${escapeHtml(result.error)}</div>`;
      return;
    }

    if (name === "run_volatility") {
      if (result.columns && result.rows) {
        body.innerHTML = renderMiniTable(result.columns, result.rows,
          { plugin: result.plugin, elapsed: result.elapsed, version: result.version });
      } else {
        const out = (result.output || "").slice(0, 4000);
        body.innerHTML = `
          <div class="tool-meta muted small">
            ${escapeHtml(result.plugin)} · ${escapeHtml(result.version)} · ${result.elapsed}s
          </div>
          <pre class="md-code small"><code>${escapeHtml(out)}</code></pre>`;
      }
    } else if (name === "list_outputs") {
      const files = result.files || [];
      if (!files.length) { body.innerHTML = `<div class="muted small">no files</div>`; return; }
      body.innerHTML = `<ul class="file-list">${files.slice(0, 40)
        .map(f => `<li><code>${escapeHtml(f.name)}</code> <span class="muted small">${f.size}B</span></li>`)
        .join("")}</ul>`;
    } else if (name === "read_output") {
      body.innerHTML = `
        <div class="tool-meta muted small">${escapeHtml(result.filename || "")}
         · ${result.bytes || 0}B${result.truncated ? " (truncated)" : ""}</div>
        <pre class="md-code small"><code>${escapeHtml((result.content || "").slice(0, 4000))}</code></pre>`;
    } else {
      body.innerHTML = `<pre class="md-code small"><code>${escapeHtml(JSON.stringify(result, null, 2))}</code></pre>`;
    }
  }

  function renderMiniTable(cols, rows, meta = {}) {
    const head = cols.map(c => `<th>${escapeHtml(c)}</th>`).join("");
    const body = rows.slice(0, 20).map(r =>
      `<tr>${r.map(v => `<td title="${escapeHtml(v)}">${escapeHtml(v)}</td>`).join("")}</tr>`
    ).join("");
    const more = rows.length > 20
      ? `<div class="muted small" style="padding:.3rem .5rem;">showing 20 of ${rows.length} rows</div>`
      : "";
    return `
      <div class="tool-meta muted small">
        <b>${escapeHtml(meta.plugin || "")}</b> · ${escapeHtml(meta.version || "")} · ${meta.elapsed}s
      </div>
      <div class="mini-table scroll">
        <table class="result-table">
          <thead><tr>${head}</tr></thead>
          <tbody>${body}</tbody>
        </table>
        ${more}
      </div>`;
  }

  // -------------------------------------------------------------------------
  // Streaming
  // -------------------------------------------------------------------------
  async function send(message) {
    if (state.streaming) {
      window.m3mx.toast("Already streaming — wait for the agent to finish.", "warn");
      return;
    }
    state.streaming = true;

    addMessage("user", { text: message });
    const ai = addMessage("ai", {});
    const typing = document.createElement("span");
    typing.className = "typing";
    typing.innerHTML = "<span></span><span></span><span></span>";
    ai.body.appendChild(typing);

    let fullText = "";
    let lastModel = "";
    let currentToolEl = null;
    let toolByName = {};

    window.m3mx.setStatus("analyzing", "agent");

    try {
      const res = await m3mxFetch("/api/agent/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message }),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({ error: res.statusText }));
        throw new Error(err.error || `HTTP ${res.status}`);
      }

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });

        let sep;
        while ((sep = buffer.indexOf("\n\n")) !== -1) {
          const chunk = buffer.slice(0, sep);
          buffer = buffer.slice(sep + 2);
          const line = chunk.trim();
          if (!line.startsWith("data:")) continue;
          const payload = line.slice(5).trim();
          if (!payload) continue;
          let evt;
          try { evt = JSON.parse(payload); } catch { continue; }
          handleEvent(evt, ai, {
            set fullText(v) { fullText = v; },
            get fullText() { return fullText; },
            set lastModel(v) { lastModel = v; },
            get lastModel() { return lastModel; },
            get typing() { return typing; },
            currentToolEl, toolByName,
          }, (k, v) => {
            if (k === "currentToolEl") currentToolEl = v;
            else if (k === "lastModel") lastModel = v;
            else if (k === "fullText") fullText = v;
          });
        }
      }
    } catch (e) {
      ai.body.innerHTML = `<div class="error-block small">${escapeHtml(e.message)}</div>`;
      window.m3mx.toast(`Agent error: ${e.message}`, "err");
      window.m3mx.setStatus("err", "error");
    } finally {
      state.streaming = false;
      window.m3mx.setStatus("idle", "idle");
    }
  }

  function handleEvent(evt, ai, bag, setter) {
    if (evt.type === "token") {
      // Remove typing indicator on first token
      bag.typing?.remove?.();
      setter("fullText", bag.fullText + evt.content);
      ai.body.innerHTML = md(bag.fullText);
      installCopyButtons(ai.body);
      $("#chat-messages").scrollTop = $("#chat-messages").scrollHeight;
    } else if (evt.type === "tool_call") {
      // Strip any ```tool blocks from the rendered markdown
      const scrubbed = bag.fullText.replace(/```tool[\s\S]*?```/g, "").trim();
      setter("fullText", scrubbed);
      ai.body.innerHTML = md(scrubbed);
      const el = addToolCallBlock(evt.name, evt.args || {}, ai.wrap);
      setter("currentToolEl", el);
      bag.toolByName[evt.name + "|" + JSON.stringify(evt.args)] = el;
    } else if (evt.type === "tool_result") {
      const el = bag.currentToolEl;
      if (el) fillToolResult(el, evt.name, evt.result || {});
    } else if (evt.type === "done") {
      setter("lastModel", evt.model || "");
      ai.wrap.querySelector(".chat-meta .muted").textContent = bag.lastModel;
      if (evt.usage) {
        ai.usageEl.hidden = false;
        ai.usageEl.textContent = `in ${evt.usage.input} · out ${evt.usage.output} tokens · ${bag.lastModel}`;
      }
    } else if (evt.type === "error") {
      ai.body.innerHTML += `<div class="error-block small">${escapeHtml(evt.message)}</div>`;
      window.m3mx.toast(evt.message, "err");
    }
  }

  // -------------------------------------------------------------------------
  // Wire up
  // -------------------------------------------------------------------------
  function init() {
    const form = $("#chat-form");
    const input = $("#chat-input");

    // Replace Phase 2 stub submit handler
    form.replaceWith(form.cloneNode(true));
    const newForm = $("#chat-form");
    const newInput = $("#chat-input");

    newForm.addEventListener("submit", (e) => {
      e.preventDefault();
      const msg = newInput.value.trim();
      if (!msg) return;
      newInput.value = "";
      newInput.style.height = "auto";
      send(msg);
    });

    newInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        newForm.requestSubmit();
      }
    });

    newInput.addEventListener("input", () => {
      newInput.style.height = "auto";
      newInput.style.height = Math.min(newInput.scrollHeight, 140) + "px";
    });

    // Re-wire suggestion chips (original chips still exist, old handler was cloned out)
    $$(".chat-suggestions .chip").forEach(chip => {
      chip.addEventListener("click", () => {
        newInput.value = chip.dataset.prompt;
        newInput.focus();
      });
    });

    // Load history
    m3mxFetch("/api/agent/history").then(r => r.json()).then(d => {
      const h = d.history || [];
      if (h.length) {
        // Replace welcome message with real history
        const inner = $("#chat-inner");
        if (inner) inner.innerHTML = "";
        h.forEach(m => {
          if (m.role === "user") addMessage("user", { text: m.content });
          else if (m.role === "assistant")
            addMessage("ai", { text: m.content, model: m.model, usage: m.usage });
        });
      }
    }).catch(() => {});

    // Ctrl+L reset
    document.addEventListener("keydown", (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "l"
          && $(".panel.active")?.dataset.panel === "agent") {
        e.preventDefault();
        m3mxFetch("/api/agent/reset", { method: "POST" })
          .then(() => {
            const inner = $("#chat-inner");
            if (inner) inner.innerHTML = "";
            window.m3mx.toast("Chat cleared.", "info");
          });
      }
    });
  }

  document.addEventListener("DOMContentLoaded", () => {
    const iv = setInterval(() => {
      if (!document.getElementById("app").hidden) {
        clearInterval(iv);
        init();
      }
    }, 150);
  });
})();
