# Scenarios

`triage_roundtrip.py` — SIMULATED deployment wrapper over real primitives.

| component | status |
|---|---|
| upload → `angr.Project(upload)` with defaults → NT_FILE-named host file ingested, bytes recoverable | real, verified (see `findings/S1-ntfile-host-read/ingest.py`) |
| "service" returning warnings/objects/extracted strings to the submitter | **our code, an assumption about pipelines** — not angr behavior |

Needs `angr` (not just cle). Prints the marker string surfacing in the returned
report on vulnerable stacks.
