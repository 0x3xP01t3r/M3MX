# m3mx AI Agent — Operational Workflow

How the agent integrated in this tool actually processes a request like
*"Find any suspicious network activity or hidden processes in this
memory dump."* Code references point at the real implementation in
`app/agent.py`, `app/full_analysis.py`, and `app/main.py`.

> Naming note. The user-facing question used the term **MCP** (Model
> Context Protocol). m3mx does not use Anthropic's MCP wire format; it
> ships a smaller fenced-JSON tool-call protocol baked into
> `agent.stream_chat()`. The mechanics below are the same in spirit.

---

## 1. Task Reception & Context

When the analyst clicks **Send** in the chat panel, the browser POSTs
`{"message": "..."}` to `/api/agent/chat`. The Flask handler builds two
things before any token leaves for the LLM:

**(a) Live runtime context** — `agent.current_context(app.config)`:

| key            | source                                                      |
|----------------|-------------------------------------------------------------|
| `image_path`   | `app.config["LOADED_IMAGE"]` set by `/api/upload`           |
| `os_profile`   | `forensics.cached_profile(image)` — populated by Vol2 imageinfo or Vol3 `windows.info` |
| `output_dir`   | `config.json → output.directory` (default `outputs/`)       |
| `vol_paths`    | `{vol2, vol3}` from `start.detect_volatility()` / config    |
| `timeout`      | `config.json → volatility.timeout_seconds`                  |

**(b) System prompt** — `agent.build_system_prompt(ctx)` interpolates
the live context into a DFIR-analyst persona. It also enumerates every
plugin the registry exposes (truncated to 60 names) so the LLM picks
real names, not hallucinated ones.

The first user message therefore sees: the analyst's question, the
loaded image path, the detected OS profile, all available plugin
names, and a chat history capped at the last 20 turns
(`stream_chat(... history)` slices `[-20:]`).

---

## 2. Reasoning & Planning

For *"suspicious network activity or hidden processes"* the agent
plans along two axes — **network** and **processes** — and
cross-checks both for hiding tradecraft.

**Plugin blueprint (logical order, not all required):**

1. **Ground truth.** `run_volatility(plugin="info")` →
   `windows.info.Info` — confirms layer/symbols built, prints kernel
   build, shows analyst the image is sane.
2. **Process baseline.** `windows.pslist.PsList` (linked-list) and
   `windows.psscan.PsScan` (pool-scan). Diff = candidates for hidden
   processes. On partial dumps, only `psscan` is reliable
   (see §4).
3. **Hidden-process specifics.** `windows.psxview.PsXView` and
   `windows.malware.hollowprocesses.HollowProcesses` —
   process-listing inconsistencies + RWX/no-image masquerade.
4. **Process injection signal.** `windows.malfind.Malfind` —
   PAGE_EXECUTE_READWRITE regions with no backing image. Strong
   pairing with the hidden-process diff.
5. **Network state.** `windows.netscan.NetScan` (pool-scan) is the
   primary; `windows.netstat.NetStat` (active-list walk) only when the
   dump is full.
6. **Per-PID drilldown** for anything suspicious from steps 2–5:
   `windows.cmdline.CmdLine`, `windows.dlllist.DllList`,
   `windows.handles.Handles`, `windows.ldrmodules.LdrModules`.
7. **Persistence.** `windows.svcscan.SvcScan` and the registry
   plugins (`hivelist.HiveList`, `printkey.PrintKey` against
   Run/RunOnce/AutoRun keys, `userassist.UserAssist`).

The agent does not always run all of these — it runs what the question
needs, in dependency order, and pivots based on what each result
yields.

---

## 3. Data Handling & Token Management

Volatility output is the dominant token risk. Three layers protect
the context window:

**(a) Backend truncation, before the LLM ever sees the result.**
`agent._tool_run_volatility()` enforces:

```
if d.output and len(d.output) > 20_000: truncate
if d.rows   and len(d.rows)   > 40:     keep first 40, mark truncated_rows
```

Shell output (`_tool_run_shell`) caps stdout at 16 KB, stderr at 4 KB.
File reads (`_tool_read_file`) are hard-capped at 512 KB per call.

**(b) Save-then-grep pattern, recommended in the system prompt.**
For anything large, the agent is told to write to `outputs/` via a
shell pipe and then issue a targeted follow-up:

```tool
{"name":"run_shell","args":{
  "command":"strings -n 8 /uploads/img.mem > outputs/strings.txt"
}}
```

```tool
{"name":"run_shell","args":{
  "command":"grep -i 'cobalt\\|powershell.*-enc' outputs/strings.txt | head -50"
}}
```

This keeps each tool result small enough to summarise without losing
the raw evidence on disk.

**(c) Per-turn feedback compaction.** When a tool result is fed back
into the next LLM turn (`stream_chat` line ~754), if its JSON
serialisation exceeds 4000 chars it is sliced to 4000 + a `…[truncated]`
sentinel. The full result is still streamed to the UI as a separate
`tool_result` event so the analyst sees everything.

The agent is instructed to **summarise long outputs, show the top 20
rows max, and offer to expand on demand** (system prompt line 50ish).
That is a behavioural convention, not a hard limit.

---

## 4. Autonomous Action (The Agentic Loop)

`agent.stream_chat()` runs an up-to-**8-round** loop
(`for turn in range(8)` at line 730ish). Each round:

1. Stream tokens from the provider.
2. After the stream closes, parse fenced ` ```tool ` blocks for
   JSON tool calls (`_parse_tool_calls`).
3. If none → break, persist history, emit `done`.
4. If any → dispatch each (`dispatch_tool` → `TOOLS[name](args, ctx)`),
   yield `tool_call` and `tool_result` SSE events to the UI, then
   feed a compacted result back into the messages list as a
   synthetic user turn.

**Pivot logic for the netscan-empty case** is purely behavioural —
the loop does not enforce it; the system prompt does. The model sees:

- Result: `success=true, rows=[]` for `windows.netstat.NetStat`.
- Two reasonable interpretations: (a) host is genuinely idle,
  (b) the linked-list walk hit unmapped pages on a partial dump.

The system prompt says *"Cite concrete evidence ... never guess"* and
*"prefer pool-scan plugins on partial dumps"*. So the agent emits a
follow-up tool call to `windows.netscan.NetScan` in the same response
turn, without asking. If that also returns empty, it falls through to
`run_shell` strings/yara passes against the raw image. Pivot stops
when:

- The 8-round budget is exhausted, **or**
- The model emits a turn with no tool blocks (it is ready to
  summarise), **or**
- A tool result contains an `error` payload that suggests user action
  (e.g. "no memory image loaded").

The loop is bounded; the *order* is not. The model owns the order
based on what each result reveals.

---

## 5. Reporting

When the agent has enough evidence, it stops calling tools and writes
the summary directly into the chat. For the example question, the
expected structure is:

```markdown
## Findings — Suspicious Network & Hidden Processes

### Network
- **PID 4256 → 185.220.101.47:443** (ESTABLISHED, owner powershell.exe)
  Tor exit node. Source: `windows.netscan.NetScan`, row 14.
- *No additional external connections were observed in netscan.*

### Hidden / Anomalous Processes
- **PID 1340 svchost.exe** running from `C:\Windows\Temp\` (T1036.005).
  Source: `windows.pslist`, row 7. PPID is `services.exe` (672) —
  inconsistent with the parent path.
- `windows.psscan` ∖ `windows.pslist` diff = ∅ — no process is
  list-only-hidden.

### Cross-correlation
- malfind reported a PAGE_EXECUTE_READWRITE region at
  `0x00000180_00000` in PID 1340 (T1055.001).

### Recommended next actions
1. `windows.cmdline --pid 1340` to capture the spawn arguments.
2. `windows.dumpfiles --virtaddr 0x...` for offline AV scan.
3. Block 185.220.101.47 at the firewall pending IR.

### Provenance
| Plugin                  | rows | elapsed |
|-------------------------|------|---------|
| windows.info            | 1    | 4.1 s   |
| windows.psscan          | 137  | 6.0 s   |
| windows.pslist          | 0    | 4.4 s   |
| windows.malfind         | 3    | 5.2 s   |
| windows.netscan         | 41   | 7.8 s   |
```

This format is enforced by convention (system prompt) rather than
schema. It is also what `app.attack_story.SYSTEM_PROMPT` instructs the
LLM to produce when it runs from `Full Analysis` — explicit ATT&CK
mapping per finding (T-codes), citation back to the
`app.full_analysis.Finding.id` (e.g. `F-007`), and a final IOC bullet
list of concrete artifacts (PIDs, paths, hashes, IPs).

The narrative the agent delivers in the chat is the analyst-facing
view; the machine-readable view is what was already streamed back
through the SSE channel as `tool_result` events plus, for triage runs,
the `findings.jsonl` written to `outputs/full_analysis/<case>/`.

---

## Code reference index

| Concern                | File                                  |
|------------------------|---------------------------------------|
| Loop, providers        | `app/agent.py:stream_chat`            |
| Tool definitions       | `app/agent.py:TOOLS, dispatch_tool`   |
| Truncation budgets     | `app/agent.py:_tool_run_*`            |
| Live context           | `app/agent.py:current_context`        |
| System prompt          | `app/agent.py:SYSTEM_PROMPT_TEMPLATE` |
| Triage rule engine     | `app/full_analysis.py`                |
| Attack-story prompt    | `app/attack_story.py:SYSTEM_PROMPT`   |
| SSE plumbing           | `app/main.py:/api/agent/chat`         |
