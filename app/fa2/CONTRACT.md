# Full Analysis V2 — Compatibility Contract

**Status:** Phase 0 — documentation only, no runtime changes.

This document is the authoritative specification of the *existing* Full
Analysis surface that V2 work must not break. Any code merged under
`app/fa2/` must keep every guarantee listed here.

The contract reflects the codebase as inspected at the time of this
document and is verified by tests under `tests/test_phase1_*` and
`tests/test_compatibility_*`.

---

## 1. Backend routes (canonical, must remain functional)

| Method | Path                                | Module                         | Purpose                                            |
| ------ | ----------------------------------- | ------------------------------ | -------------------------------------------------- |
| GET    | `/`                                 | `app/main.py`                  | Render `templates/index.html`                      |
| GET    | `/api/health`                       | `app/main.py`                  | Liveness                                           |
| GET    | `/api/loaded-image`                 | `app/main.py`                  | Returns current `LOADED_IMAGE` for page refresh    |
| GET    | `/api/settings`                     | `app/main.py`                  | Config read (masked secrets)                       |
| POST   | `/api/settings`                     | `app/main.py`                  | Config write                                       |
| POST   | **`/api/upload`**                   | `app/main.py`                  | **Stores image, sets `LOADED_IMAGE`, returns JSON. NO side effects.** |
| GET    | `/api/plugins`                      | `app/main.py`                  | Volatility plugin registry                         |
| POST   | `/api/run-plugin`                   | `app/main.py`                  | **Manual Analysis**                                |
| POST   | `/api/run-plugin/stream`            | `app/main.py`                  | Manual Analysis (SSE)                              |
| POST   | `/api/agent/chat`                   | `app/main.py`                  | **AI Agent**                                       |
| GET    | `/api/agent/history`                | `app/main.py`                  | AI Agent — chat history                            |
| POST   | `/api/agent/test`                   | `app/main.py`                  | AI Agent — provider test                           |
| POST   | `/api/agent/reset`                  | `app/main.py`                  | AI Agent — reset                                   |
| POST   | `/api/files/scan`                   | `app/main.py`                  | **File Extractor** — filescan                      |
| POST   | `/api/files/preview`                | `app/main.py`                  | File Extractor — hex/strings/exif/image preview    |
| POST   | `/api/files/extract`                | `app/main.py`                  | File Extractor — bulk dumpfiles                    |
| GET    | `/api/files/raw`                    | `app/main.py`                  | File Extractor — stream a dumped file              |
| GET    | `/api/outputs`                      | `app/main.py`                  | Outputs index                                      |
| GET    | `/api/outputs/view`                 | `app/main.py`                  | Read a saved output                                |
| GET    | `/api/outputs/download`             | `app/main.py`                  | Download a saved output                            |
| POST   | `/api/outputs/delete`               | `app/main.py`                  | Delete a saved output                              |
| POST   | `/api/reports/generate`             | `app/main.py`                  | Reports                                            |
| GET    | `/api/status`                       | `app/main.py`                  | Status indicator                                   |
| POST   | `/api/triage`                       | `app/main.py`                  | Quick triage (Workflow) — distinct from Full Analysis |
| POST   | **`/api/full-analysis`**            | `app/main.py` → `full_analysis.run_triage` | **Full Analysis (SSE, triage + AI story)** |
| GET    | `/api/full-analysis/case`           | `app/main.py`                  | Re-load findings + `attack_story.md` for a prior run |
| GET    | `/api/fs/browse`                    | `app/main.py`                  | Filesystem picker (browse)                         |
| POST   | `/api/fs/mkdir`                     | `app/main.py`                  | Filesystem picker (mkdir)                          |
| POST   | `/api/fs/pick-dir-native`           | `app/main.py`                  | Filesystem picker (native)                         |

V2 **must not** rename, remove, or change the meaning of any of these
routes. V2 may add **new** routes under `/api/full-analysis/*` or other
prefixes provided existing routes keep working.

---

## 2. Upload behavior (invariant)

`POST /api/upload` (`app/main.py:135`):

1. Pre-flight disk-space check.
2. Validate extension against `ALLOWED_EXT = {.mem .raw .dmp .vmem .bin .lime .img}`.
3. Stream-write the body to `uploads/<filename>` in 16 MB chunks.
4. Set `app.config["LOADED_IMAGE"] = str(dest)`.
5. Return `{"filename","path","size","size_human"}` as JSON.

Critically: **no Volatility, no triage, no LLM, no `run_triage`, no
`yield_attack_story` is invoked from the upload route or from
`handleFile()` in the frontend.** Confirmed by static inspection of
`app/main.py` lines 135–191 and `static/js/app.js` lines 152–193.

V2 **must not** introduce any side-effect chain from upload to triage,
to AI Story, or to AI Report.

---

## 3. Full Analysis trigger (invariant)

The only paths that start Full Analysis today:

- **Frontend:** `static/js/app.js:849` — `runFullSuite()` function, which
  is wired to the button `#fa-start-btn` in `templates/index.html:316`
  via `onclick="runFullSuite()"`.
- **Backend:** `POST /api/full-analysis` in `app/main.py:557`, which
  iterates over `full_analysis.run_triage(...)` and then
  `attack_story.yield_attack_story(...)` (unless `skip_story` is set in
  the request body).

V2 **must not** add automatic invocations of `runFullSuite` or
`/api/full-analysis` from upload, navigation, or any other section.

---

## 4. SSE event contract (Full Analysis route)

The route is `POST /api/full-analysis` and streams `text/event-stream`.
Each `data:` line is one JSON object. **The frontend (`app.js:803
_faRoute`) must continue to accept all of these unchanged.**

### Triage phase — emitted by `full_analysis.run_triage`

| `type`          | Required payload fields                                                                                  |
| --------------- | -------------------------------------------------------------------------------------------------------- |
| `start`         | `image: str`, `plugins: list[str]`                                                                       |
| `plugin_start`  | `plugin: str`, `index: int`, `total: int`                                                                |
| `plugin_done`   | `plugin: str`, `success: bool`, `rows: int|null`, `elapsed: float`, `error: str|null`                    |
| `finding`       | `finding: Finding`                                                                                       |
| `rules_done`    | `total_findings: int`                                                                                    |
| `saved`         | `path: str`                                                                                              |
| `done`          | `findings: list[Finding]`, `case_dir: str`, `findings_path: str`, `elapsed: float`                       |
| `error`         | `message: str`                                                                                           |

### Story phase — emitted by the route + `attack_story.yield_attack_story`

| `type`          | Required payload fields                                                                                  |
| --------------- | -------------------------------------------------------------------------------------------------------- |
| `story_start`   | `findings_count: int` (emitted by the route, not by `attack_story`)                                      |
| `story_token`   | `content: str` (incremental token from the LLM stream)                                                   |
| `story_done`    | `model: str`, `usage: dict`, `text: str`                                                                 |
| `story_saved`   | `path: str` (emitted by the route after persisting `attack_story.md`)                                    |
| `error`         | `message: str` (LLM stream error)                                                                        |
| `all_done`      | `phase: "triage"|"story"` (emitted by the route at the very end)                                         |

V2 **may add** new SSE event types **only as additions**. The 11 types
listed above must keep firing with at least the listed required fields
present. V2 may freely add optional new fields to the payload of any
existing event so long as the listed required keys remain.

V2 reserves these new optional event names (must not be confused with
existing ones): `os_detected`, `symbol_status`, `plugin_plan`,
`artifact_normalized`, `scoring_done`, `correlation`,
`correlations_done`, `timeline_done`, `mitre_done`, `report_ready`,
`warning`, `limitation`, `ai_report_start`, `ai_report_token`,
`ai_report_done`, `ai_report_error`. The frontend must be able to
safely ignore any unknown event.

---

## 5. Finding schema (old/canonical)

Defined by `Finding` in `app/full_analysis.py:73`:

```python
@dataclass
class Finding:
    id: str           # "F-NNN", auto-numbered
    plugin: str       # short name, e.g. "pslist"
    severity: str     # "critical" | "high" | "medium" | "low" | "info"
    title: str
    description: str
    evidence: dict    # raw row columns → values
    tags: list[str]   # MITRE technique IDs as plain strings
    confidence: float # 0.0–1.0
```

V2 may extend the JSON shape with new **optional** fields. The serialised
output must always contain the eight fields above and the frontend must
never need to do additional field lookups to display the basic finding.

When a V2 finding is serialised, missing/None optional fields must be
omitted from the JSON (or otherwise rendered tolerable to the old
frontend). The eight required fields above must always be present and
the values must satisfy the same domains (e.g. `severity` is always one
of the five strings, `confidence` is always a float).

---

## 6. Output files (existing)

```
outputs/full_analysis/<image_stem>/
  findings.jsonl     # one JSON-encoded Finding per line, written by save_findings()
  attack_story.md    # written by the SSE route after story_done
```

`<image_stem>` is `Path(image).stem` (no extension).

V2 invariants:

- `findings.jsonl` filename and format must remain valid for older
  readers. New fields are additive.
- `attack_story.md` filename **must not be renamed**. V2 may write
  additional files (e.g. `story.md`, `ai_report.md`, `correlations.json`,
  `timeline.json`, `mitre_summary.json`, `normalized_artifacts.jsonl`,
  `report.html`) into the same directory.
- `app/full_analysis.py:_case_dir()` is the authoritative path resolver
  and must keep returning the same directory for a given image.

---

## 7. Feature flags

V2 introduces two flags, both **default OFF**:

- `FULL_ANALYSIS_V2` — when ON, allows the V2 pipeline to run **only
  when Full Analysis is explicitly started**. When OFF, V1 behaviour is
  used exactly as today.
- `FULL_ANALYSIS_OPTIONAL_AI_REPORT` — when ON, exposes the optional
  AI Report endpoint and button. When OFF, the button must not appear
  and the optional endpoint must not run.

Resolution order: environment variable first, then `config.json` →
`features.<flag>`. Truthy values: `"1"`, `"true"`, `"yes"`, `"on"`
(case-insensitive). Anything else (including unset) is OFF.

While both flags are OFF the tool must behave **byte-for-byte** as it
does without `app/fa2/` present.

---

## 8. Section independence (invariants)

Every section under the pill nav must remain functional without Full
Analysis being involved:

| Section          | Owning module           | Independence invariant                                                                   |
| ---------------- | ----------------------- | --------------------------------------------------------------------------------------- |
| Manual Analysis  | `app/forensics.py` via `/api/run-plugin` | Plugin execution must not depend on `app/fa2/` or `full_analysis.run_triage`.        |
| AI Agent         | `app/agent.py` via `/api/agent/*`        | The agent must not invoke Full Analysis or AI Report automatically.                  |
| File Extractor   | `app/file_extractor.py` via `/api/files/*` | Filescan, preview, extract must work without `app/fa2/`.                            |
| Workflow         | `/api/triage` and any future workflows   | Existing workflows must not start the V2 pipeline silently.                          |
| Results viewer   | `app/reports.py` via `/api/outputs/*`    | Must continue listing and serving outputs regardless of V2 outputs being present.    |
| Full Analysis    | `app/full_analysis.py` + `app/attack_story.py` via `/api/full-analysis` | V1 path is preserved verbatim while `FULL_ANALYSIS_V2` is OFF.  |

V2 **may** read existing Full Analysis outputs (`findings.jsonl`, etc.)
when generating reports, but **may not** trigger Full Analysis or any
LLM call from any section other than the explicit Full Analysis button
or the explicit Generate AI Report button.

---

## 9. Frontend invariants

- `static/js/app.js:98` `navigateTo(view, ev)` continues to be the only
  navigation entry point.
- `static/js/app.js:152` `handleFile(e)` — upload handler — must not
  add any post-upload triggers for Full Analysis or AI report.
- `static/js/app.js:849` `runFullSuite()` — the only function that POSTs
  to `/api/full-analysis`.
- `static/js/app.js:803` `_faRoute(evt)` — the only SSE consumer for
  Full Analysis events. V2 may extend this with new case branches, but
  existing branches and DOM IDs (`#fa-start-btn`, `#fa-findings-table`,
  `#fa-findings-tbody`, `#fa-story-panel`, `#fa-story-body`,
  `#fa-story-meta`) must continue to function unchanged.

---

## 10. Hard invariants (enforced by tests)

1. Upload does not invoke `run_triage` / `yield_attack_story`.
2. `handleFile()` body does not call `runFullSuite()` or POST to
   `/api/full-analysis` or any AI Report endpoint.
3. `runFullSuite()` is invoked only from `#fa-start-btn`.
4. Both feature flags resolve to `False` with no env set and no
   `features` block in `config.json`.
5. `Finding` JSON output always contains the eight required keys.
6. Score-to-severity mapping is exactly the bands documented in §11.
7. Weak-signal-only inputs never reach `critical`.

---

## 11. Scoring bands (V2 only)

V2 introduces a scoring engine in `app/fa2/scoring.py`. The bands are:

```
score ≥ 15   → critical
score ≥ 10   → high
score ≥ 6    → medium
score ≥ 3    → low
score <  3   → info
```

Confidence is an independent float in `[0.0, 1.0]` carried alongside the
severity. **Severity describes how dangerous the behaviour is if true.
Confidence describes how sure we are that the evidence supports the
claim.** They must not be derived from each other.

---

## 12. Quality bar for future detection rules (Phase ≥ 4)

No rule is accepted unless it carries:

- stable `id`
- `title`, `description`
- `applies_to` (OS list)
- `artifact_type`
- match expression
- `base_score`, `confidence`, `category`
- MITRE mapping **with reason**
- `false_positive_notes`
- `recommended_validation`
- ≥ 1 positive test case
- ≥ 1 negative test case

High/critical severity requires either (a) strong standalone evidence
(code injection, credential access, kernel hook, deleted-running-binary,
destructive command, confirmed persistence) **or** (b) correlation
between at least two suspicious artifacts. Weak indicators (public IP
alone, temp execution alone, browser HTTPS, generic admin tool name,
suspicious filename only) must never reach critical by themselves.

---

*End of Phase 0 contract.*
