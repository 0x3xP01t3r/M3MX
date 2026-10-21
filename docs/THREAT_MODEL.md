# Threat model

Assets: analyst credentials, original memory images, findings, extracted
artifacts, workstation files, and investigation integrity.

Untrusted inputs: browser/API requests, memory strings, command lines,
recovered filenames, Volatility output, LLM text, remote search/OSINT data,
and HTML/Markdown derived from those sources.

Trusted inputs: analyst interaction with the local page, launch environment,
approved binaries and rule packs. The model is not an authorization authority.

| Attack | Boundary and control | Verification |
|---|---|---|
| Malicious website calls local APIs / DNS rebinding | Host + Origin checks, no CORS, request token, loopback publication | `test_requests.py` |
| Prompt injection asks for a command or private file | Evidence labels, file roots, command allowlist, separate UI approval | `test_agent_commands.py`, `test_boundaries.py` |
| Model invents an approval or replays one | Random one-use ID, deadline, exact argv and file identity, current image check | `test_agent_commands.py` |
| Path traversal or symlink escape | Resolved approved roots, private-file restrictions, no-follow bounded reads | `test_boundaries.py` |
| AI endpoint probes metadata/internal services | Fixed destinations and operator allowlists; no redirects; loopback/public DNS checks | `test_boundaries.py` |
| Evidence contaminates HTML/PDF | Sanitization, strict script CSP, no resource fetching, bounded render subprocess | `test_forensics.py` |
| Reupload or rerun overwrites evidence | Unique upload/run IDs, hashes/manifests, file-aware cache identities | `test_requests.py`, `test_forensics.py` |
| Large output, hung child, disconnected stream | Bounded capture, deadlines, group cleanup, workload lock | `test_forensics.py`, `test_requests.py` |

These controls address OWASP LLM01 (prompt injection), LLM06 (excessive
agency), and ASVS topics including access control, validation, file handling,
browser security, secrets, and configuration. This is a control mapping,
not an ASVS certification or a claim of complete OWASP compliance.

Residual risks include model misinterpretation, parser vulnerabilities,
malicious local users with access to the application's account, and
provider-side retention of intentionally submitted evidence. The legacy Vol2
runtime remains EOL. CI scanning does not prove the absence of vulnerabilities.
