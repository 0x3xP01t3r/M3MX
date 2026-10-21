# Full Analysis compatibility contract

This describes the current implementation, including the security migration.
The former Phase 0 document described historical defaults and test files that
were not present in this checkout. Current regression coverage lives in
`tests/test_requests.py`, `tests/test_boundaries.py`, `tests/test_forensics.py`,
and `tests/test_agent_commands.py`.

## HTTP and upload behavior

Existing analysis, extraction, output, reporting, settings, agent, and
filesystem route names remain available. Unsafe requests require the
`X-M3MX-Token` supplied by the same-origin page. All requests are subject to
Host/Origin/path policies; filesystem routes are confined to approved roots.
See `docs/MIGRATION.md` for intentional security restrictions.

Upload streams the image to a unique evidence directory, calculates SHA-256,
writes a manifest, sets `LOADED_IMAGE`, and returns the existing
`filename/path/size/size_human` fields plus `sha256/evidence_id`.
It must not invoke Volatility, Full Analysis, an LLM, or report generation.
The frontend upload handler must not start any analysis automatically.

Full Analysis starts only from the explicit Start button or an explicit
`POST /api/full-analysis`. Navigation, upload, settings load, and report export
must not trigger it. `skip_story: true` suppresses the LLM story phase.

## Finding schema

Every finding contains the original eight fields:

```text
id: string
plugin: string
severity: info | low | medium | high | critical
title: string
description: string
evidence: object
tags: list of strings
confidence: float in [0, 1]
```

V2 fields such as score, entities, mappings, validation notes, source plugin,
raw-artifact references, limitations, and correlations are additive. Empty
optional fields may be omitted. Severity and confidence are independent.

## Streaming events

`POST /api/full-analysis` streams `text/event-stream`, one JSON object per
`data:` event. Preserve these existing types and fields:

| Type | Fields |
|---|---|
| start | image, plugins |
| plugin_start | plugin, index, total |
| plugin_done | plugin, success, rows, elapsed, error |
| finding | finding |
| rules_done | total_findings |
| saved | path |
| done | findings, case_dir, findings_path, elapsed |
| error | message |
| story_start | findings_count |
| story_token | content |
| story_done | model, usage, text |
| story_saved | path |
| all_done | phase |

V2 events (OS detection, planning, normalization, MITRE, correlation, timeline,
reports, warnings, and limitations) are additive. Unknown event types must be
safe to ignore. A closed stream must release workload ownership and terminate
any active streaming subprocess.

## Flags and independence

- `FULL_ANALYSIS_V2`: defaults **true**.
- `FULL_ANALYSIS_LEGACY_V1`: defaults **false**; requires V2 disabled.
- `FULL_ANALYSIS_OPTIONAL_AI_REPORT`: defaults **false**.

Environment values override persisted settings. If both analysis pipelines
are disabled, emit an explicit error instead of silently choosing another.
The optional AI Report runs only on explicit request, reads existing outputs,
and never reruns Volatility. PDF export also reads existing outputs only.
Manual Analysis, File Extractor, Agent, and Quick Triage do not automatically
invoke Full Analysis. Report-only chat and automation synthesis cannot execute
agent tools.

## Storage and frontend

New cases use `outputs/full_analysis/<evidence-key>/<run-id>/`. Preserve
`findings.jsonl` and `attack_story.md` basenames. Additional manifests,
normalized artifacts, raw CSVs, MITRE/correlation/timeline data, failed-plugin
and limitation records, and reports live beside them. Each explicit analysis
gets a new run directory. A private latest-run pointer supports reload/export.
Legacy case directories remain readable; new runs do not overwrite them.

Frontend ownership:

- `core.js`: navigation, upload, settings, manual analysis, shared rendering.
- `agent-ui.js`: agent chat and explicit command approval controls.
- `analysis-ui.js`: Full Analysis SSE consumer, findings, timeline, exports.
- `extractor-ui.js`: extractor tree, previews, extraction.
- `app.js`: initialization and automation workflows.
- `requests.js`: same-origin requests and mutation tokens.
- `events.js`: named DOM actions replacing inline event handlers.

## Detection validation

Severity bands are unchanged: 15+ critical, 10+ high, 6+ medium, 3+ low,
below 3 info. Rule changes require positive and negative fixtures and must
preserve raw evidence. Test weak signals and legitimate administration cases
before increasing scores. Strong conclusions require supporting evidence;
neither an LLM narrative nor a MITRE label establishes that evidence.
