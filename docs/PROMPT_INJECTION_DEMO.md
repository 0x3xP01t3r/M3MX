# Reproducible prompt-injection boundary demonstration

Use synthetic fixtures, not a real compromised image or analyst credentials:

```sh
pytest -q tests/test_agent_commands.py tests/test_boundaries.py
```

`tests/fixtures/prompt_injection.txt` represents text recovered from a hostile
memory image. The tests deliberately simulate a model attempting to obey that
text. They show that private-file reads are rejected, external OSINT is off,
command proposals do not execute, and a separate browser approval is required.
Approval replay, expiry, file changes, and context changes are rejected.

The report-mode test simulates a model emitting a fenced command request.
The application never dispatches it. Automation synthesis uses the same
backend restriction. This tests enforced capabilities, not an assumption that
a prompt can make a model immune to injection.

The prior implementation fed tool output back as a user message and directly
dispatched permitted shell text. Do not run that implementation's unrestricted
shell on an analyst workstation for a demonstration. If comparing versions,
mock the subprocess boundary in both and compare recorded attempted actions.
