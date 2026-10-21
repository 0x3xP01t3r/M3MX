# Security policy

M3MX is a local, single-analyst memory-forensics workbench. Report security
issues privately to the repository maintainer through GitHub private
vulnerability reporting when enabled. Do not attach real memory images,
credentials, or personal data to public issues.

## Supported deployment

Use the current Python 3.11+ application and default Volatility 3 container.
The native launcher binds to loopback. Compose publishes only
`127.0.0.1:5000`. Do not expose the service to a network without an
authenticated TLS reverse proxy and an explicit deployment security review.
The per-process browser request token protects local browser mutations;
it is not multi-user authentication and does not protect against hostile
software already running under the analyst's OS account.

## Enforced controls

- Exact Host and same-origin checks; no permissive CORS.
- A random per-process token in `X-M3MX-Token` for every unsafe request.
  The same-origin page supplies it; a restarted server requires a page reload.
- Evidence, output, and rules paths are resolved and confined to launch-time
  approved roots. Symlink escapes and private filenames are rejected.
- Commands default off. The historical `run_shell` name now proposes only
  read-only, argument-validated commands without a shell. Each command needs
  an explicit, expiring, single-use browser approval bound to its file and
  loaded-image context. Interpreters, package installers, pipes, and redirects
  are unavailable. Regular Volatility plugins remain available independently.
- AI endpoint allowlists apply to Ollama discovery/test/chat and configurable
  GLM/AgentRouter bases. Ollama requests and SDK HTTP transports do not follow
  redirects. Custom destinations require trusted launch environment variables.
- Script CSP disallows inline handlers and eval. Fonts/icons are served
  locally. Extracted active content is downloaded as an attachment.
- Generated HTML is sanitized. PDF rendering runs in a separate process with
  a deadline, memory/CPU/file limits, and a resource fetcher that rejects file,
  network, and data URLs.
- Secrets live in mode-0600 state files or environment variables, outside
  evidence/output roots. Environment keys take priority. Secrets are not
  returned to the browser or passed to forensic subprocesses.
- Uploaded images receive unique IDs, streaming SHA-256 hashes, and read-only
  files. Runs receive separate directories and manifests. Caches include file
  identity, executable paths, and plugin arguments.
- One forensic workload at a time; subprocess output and time are bounded,
  and process groups are terminated on timeout or stream cancellation.

## Trust assumptions and limitations

The operator controls the launch environment, installed executables, approved
roots, DNS for explicitly approved custom services, and rule packs. Do not
register a home directory, filesystem root, secrets directory, or
attacker-controlled service as trusted. Keep approved directories inaccessible
to unrelated users. Path validation does not defend against a malicious local
administrator racing directory replacements.

Memory images, recovered files, plugin output, and search results remain
untrusted. A prompt cannot guarantee that a model will ignore hostile text;
the application enforces capabilities regardless of the model's response.
Cloud AI and OSINT tools send the supplied evidence/query/indicator to the
selected provider. OSINT tools default off and require a separate Settings
opt-in. Use local Ollama and leave external lookups disabled for investigations
that must stay offline. Volatility may still need network access to obtain
missing symbols; prepopulate its symbol cache for a fully disconnected workflow.

Volatility, YARA, exiftool, fonts, and document parsers are complex native or
third-party software. A patched, isolated analyst host is still required.
The application does not acquire live memory, provide courtroom chain-of-custody
certification, or guarantee malware detection accuracy.

Python 2 / Volatility 2 is unsupported legacy software. The optional
`Dockerfile.vol2` is an offline CLI compatibility aid, excluded from the modern
web image. Do not publish it as a service. It retains EOL dependencies and is
not covered by the modern runtime's clean dependency-audit result.

See [the threat model](docs/THREAT_MODEL.md), [migration guide](docs/MIGRATION.md),
and [regression tests](tests/) for the controls' practical scope.
