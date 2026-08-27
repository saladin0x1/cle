# S1 — NT_FILE host-path read

**Sink:** `cle/backends/elf/elfcore.py:434` — `ELFCore.__reload_children`, called
unconditionally from `__init__`. `filename` is the verbatim string from the loaded
core dump's NT_FILE note; nothing validates or gates it.

**Policy anchor:** SECURITY.md's operative clause — "opportunities for guest code to manipulate the host environment **without the analysis author explicitly allowing it**". S1 has no flag or opt-in, so the author cannot allow or disallow it. (Whether a read-only effect counts as "manipulate" is a question for the maintainers, noted rather than asserted.)

**Class:** unauthorized host file access / information disclosure / availability.

| file | demonstrates |
|---|---|
| `oracle.py` | exists+readable vs permission-denied vs missing produce three distinct warnings — a filesystem probe for anyone who can observe cle output |
| `ingest.py` | a named host ELF is parsed and attached as a child object; its original bytes (outside the page the core overwrites) are recoverable via `child.memory.load` |
| `crash.py` | naming a directory (`IsADirectoryError`) or any `:`-prefixed text file (Hex backend `is_compatible` is `startswith(b":")`, e.g. `~/.zsh_history`) raises out of `cle.Loader()` / `angr.Project()` and kills the load |

Run each directly; expected output on vulnerable cle is `RESULT: VULNERABLE`.
On the fix (`docs/FIX.diff`, PR #797): `RESULT: NOT REPRODUCIBLE`.
