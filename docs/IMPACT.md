# IMPACT ADDENDUM — red-team scenarios for the two cle findings

All "REAL" items below were executed on the release stack (angr/cle 9.2.99, PyPI wheels,
macOS/arm64 host) with default options. Artifacts in this directory.

## S1 — Filesystem recon oracle via crafted cores [REAL]
`recon_oracle.py` — one crafted 4KB core per probe; distinct outcomes classify any host path:

| probe target | oracle result | meaning |
|---|---|---|
| /etc/passwd | `Could not find a compatible loader for ...` | EXISTS + READABLE (only reachable after successful open()) |
| /var/run/docker.sock, fabricated path | `Dependency ... does not exist` | NOT FOUND |
| /tmp/.cle_probe_noperm (chmod 000) | `Could not load ...` | PERMISSION DENIED (EACCES) |
| /tmp, ~/.ssh/id_rsa (a dir here) | **uncaught IsADirectoryError** | IS A DIRECTORY — and the Project build CRASHES |
| ~/.zsh_history | **uncaught CLEError (Hex backend)** | readable, non-ELF starting with `:` — build CRASHES |

Fidelity note: the oracle reported `/usr/lib/libSystem.B.dylib` as NOT FOUND — correct on
Apple Silicon (dyld shared cache; no file on disk). It reflects true filesystem state.

Bonus crash states (availability, outside the primary class): naming a directory or a
`:`-prefixed text file (zsh history, some CSVs) raises *uncaught* exceptions out of
`angr.Project()` — the Hex backend's `is_compatible` is `s.startswith(b":")`
(cle/backends/ihex.py:216), and `__reload_children`'s except clause doesn't cover the
resulting CLEError. A pipeline that loads one crafted core can be killed at will.

## S2 — Host-binary ingestion with content capture [REAL]
`exfil_ingest.py` — crafted core names `/tmp/victim_corp_tool.so` (stand-in for any host
ELF: a licensed tool, another malware sample, proprietary firmware):
- the victim is parsed and attached as a child object (visible in `all_objects`),
- its original bytes are recoverable from the child's memory backer via the public API
  (`child.memory.load`) — demonstrated by recovering an embedded fake access key verbatim
  at rva 0x2000. Core-supplied "patches" overwrite only the ranges the core names; the
  rest of the victim's original content survives intact.
- macOS caveat (honest): release cle's Mach-O backend rejected FAT system binaries
  (/bin/zsh), so on this testbed only ELF-format files ingested. On a Linux analysis
  host — the realistic deployment — /usr/lib/*.so and local samples are ELF and ingestible.

## S3 — Triage-service round trip [SIMULATED wrapper, REAL primitives]
`triage_service_sim.py` — a minimal "hosted triage microservice": takes an upload, runs
`angr.Project(upload)` with defaults, returns JSON (warnings, object list, auto-extracted
strings from every loaded object). Warning passthrough, object listing, and string
extraction are ordinary triage-frontend features — but they are OUR code, an assumption
about the pipeline, not angr's.

Result of the simulated round trip on the S2 core:
  ingested host object visible to submitter: {'type': 'ELF', 'range': '0x400000-0x402fff'}
  SECRETS EXFILTRATED TO SUBMITTER: ['PROJECT-APPLESEED-ACCESS-KEY=REDACTED-FOR-DEMO-0001']

## What this does NOT prove (keep in any writeup)
- Read-only: no file write, no process execution, no network, no deserialization.
- Non-loadable file contents (e.g. /etc/passwd text) are opened and magic-probed but not
  returned anywhere; for those, impact is the S1 oracle only.
- S3 exfiltration requires the service to return analysis-derived output to the submitter.
  A logs-only service still yields S1 (oracle) and the crash/DoS states.
