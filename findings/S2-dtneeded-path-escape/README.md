# S2 — DT_NEEDED path escape

**Sink:** `cle/loader.py:1221` — `Loader._possible_paths` joins the raw DT_NEEDED
string (origin: `cle/backends/elf/elf.py:1059`) against each search dir. An
absolute spec discards the dir (`os.path.join` semantics); `..` components escape it.

**Class:** unauthorized host file read via dependency resolution.

**Status:** documented, intended behavior under `auto_load_libs` (per the PR #797 discussion). Included for completeness because the flag defaults to `True` in every released cle; HEAD flips the default to `False` (`ce6d0c4`, unreleased). No security claim is being advanced for this path.

| file | demonstrates |
|---|---|
| `arbitrary_paths.py` | one ET_DYN, two DT_NEEDED entries: an absolute path and a `./sub/../` traversal; both named host files are ingested as dependency objects under `auto_load_libs=True` |

On the fix (`docs/FIX.diff`): `RESULT: NOT REPRODUCIBLE`.
