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
  if (kind === "result" && payload?.approval_required) {
    const approve = document.createElement("button");
    approve.type = "button";
    approve.className = "cta-sec";
    approve.textContent = "Approve this command (expires in 2 minutes)";
    approve.addEventListener("click", async () => {
      approve.disabled = true;
      try {
        const result = await API.post("/api/agent/approve", {
          approval_id: payload.approval_id, approve: true
        });
        w.querySelector("pre").textContent = JSON.stringify(result, null, 2);
        approve.textContent = "Command completed";
      } catch (error) {
        approve.textContent = error.message;
      }
    });
    w.appendChild(approve);
  }
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
    const r = await m3mxFetch("/api/agent/chat", { method: "POST", headers: {"Content-Type":"application/json"}, body: JSON.stringify({ message: userMsg }) });
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
