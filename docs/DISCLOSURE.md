To: audrey@rhelmot.io, fishw@asu.edu
Subject: [SECURITY] cle sandbox escapes: crafted ELF/core causes unauthorized host file reads (2 findings, PoCs)
Format: coordinated disclosure — no public disclosure until you clear it. All PoCs are minimal hand-crafted files; no real malware involved.

---

SUMMARY
Two behaviors that conflict with angr's SECURITY.md promise, quoted in full because the operative clause matters here: angr "is meant to be able to function as fully secure environment for analyzing code of any kind in its default configuration", and the project takes seriously "sandbox escapes - opportunities for guest code to manipulate the host environment without the analysis author explicitly allowing it". Finding 1 has no flag or opt-in at all, so the analysis author cannot allow or disallow it; Finding 2 sits behind `auto_load_libs`, which constitutes such an allow (see maintainer ruling below). Whether a read-only effect counts as "manipulate" is a question we put to the maintainers rather than assert. Both findings are read-only (no write/exec/network/deserialization) and both are reproduced on the current release stack (angr/cle 9.2.99 from PyPI).

FINDING 1 — ELFCore: NT_FILE note drives unconditional open() of arbitrary host paths
  Location: cle/backends/elf/elfcore.py:434 (open(filename,"rb") in ELFCore.__reload_children, called unconditionally from __init__ at line 70).
  Reach: angr.Project("crafted.core") / cle.Loader("crafted.core") — default options, no flags, verified on release 9.2.99 AND current git HEAD.
  Impact:
    (a) arbitrary host file open+read attempt for any path named in the NT_FILE note;
    (b) existence/readability oracle: three distinct warnings distinguish "does not exist" / "exists but no compatible loader" / "permission denied" (FileNotFoundError vs CLECompatibilityError vs PermissionError branches);
    (c) content ingestion: if the named path is a loadable host ELF, it is parsed and attached as a child object with its bytes mapped into the analysis.
  Note: the ELFCore docstring acknowledges remote-path issues and offers opt-in remote_file_mapping/remote_file_mapper — but the unsafe behavior is the default and unauthenticated.
  Suggested fix: require explicit executable=/remote_file_mapper (or a new opt-in flag) before honoring NT_FILE filenames; otherwise ignore them. Sanitizing to basename is insufficient for the oracle (a) — the open itself must be gated.

FINDING 2 — DT_NEEDED: absolute paths and ../ traversal escape the library search dirs
  Location: cle/loader.py:1221 (os.path.join(libdir, spec) in Loader._possible_paths); open at loader.py:979 via _search_load_path -> _load_object_isolated. spec originates from the binary's DT_NEEDED string (cle/backends/elf/elf.py:1059).
  Reach:
    - release cle 9.2.99: default auto_load_libs=True -> plain angr.Project("crafted.elf"), no options. REPRODUCED.
    - git HEAD: auto_load_libs now defaults False (thanks — good hardening), but with auto_load_libs=True (a very common analyst configuration) both variants still reproduce. The flag's contract is "search the configured library dirs for dependencies"; an absolute DT_NEEDED (join() discards libdir) or ../../../ traversal (escapes the dir) violates that contract and reads attacker-chosen paths.
  Impact: arbitrary host file open+parse; if the path is a loadable ELF, its contents are mapped into the analysis (demonstrated by ingesting /tmp/cle_pwn_dep_{abs,rel}.so — one via absolute path, one via traversal).
  Suggested fix: in _possible_paths, reject specs that are absolute or contain path separators / .. components before joining (dependency *names* should be basenames by definition), or confine resolution to the configured dirs via realpath prefix check.

REPRODUCTION (macOS/arm64, Python 3.10; artifacts attached / at path below)
  Dir: cle-audit-poc/
    craft_core.py  -> oracle_a.core (NT_FILE="/etc/passwd"), oracle_b.core (nonexistent path), ingest.core (NT_FILE names a real ELF)
    craft_dyn.py   -> dynpoc.elf (DT_NEEDED="/tmp/cle_pwn_dep_abs.so" and "../../../tmp/cle_pwn_dep_rel.so") + the two marker .so files
    run_angr.py / run_dyn_angr.py / run_load.py / run_dyn.py  -> loaders, all default options
  Commands & expected evidence:
    python run_angr.py          # WARNING ... Could not find a compatible loader for /etc/passwd  (= open succeeded)
    python run_load.py oracle_b.core   # WARNING ... Dependency /nonexistent_dir_9x/missing.so does not exist  (distinct branch)
    python run_load.py ingest.core     # child_objects includes the named host ELF, its bytes readable via loader.memory
    python run_dyn_angr.py      # all_objects includes /private/tmp/cle_pwn_dep_abs.so and .../cle_pwn_dep_rel.so
  Verified versions: angr 9.2.99 / cle 9.2.99 (PyPI wheels) and cle @ git HEAD (clone 2025-08-27, commit range ~0e18fa25e in angr monorepo).
  Impact addendum (recon-oracle table incl. two uncaught-exception DoS states, host-binary ingestion w/ content capture, simulated triage-service exfil round-trip): IMPACT.md.

SEVERITY (our read, not a demand): moderate at most, calibrated against the two Ghidra analogues above (both medium, no CVE). Read-only; requires the analyst to load a hostile file; the oracle additionally requires an observable log/output channel; ingestion is limited to loadable binary formats (not arbitrary file read); the crash states are unqualified. Finding 1 has no mitigating flag at all.

PRECEDENT & TIMELINE (added after external research)
- Closest precedent: Ghidra advisory GHSA-57g6-7qw2-p5hx (medium, no CVE, published 2026-05-14) — "Path Traversal via .gnu_debuglink in DWARF External Debug File Resolution": `SameDirDebugInfoProvider` used the unvalidated filename from an ELF's `.gnu_debuglink` to probe the local filesystem and leak CRC32 hashes during *automatic* DWARF analysis, and the advisory notes the sibling `LocalDirDebugLinkProvider` already had an `ensureSafeFilename()` check that simply wasn't applied. The structural parallel to cle is exact: `remote_file_mapping`/`remote_file_mapper` exist for this indirection; the unmapped default trusts the note.
- Second precedent: Ghidra advisory GHSA-3f3p-5h4j-gq2r (medium, no CVE, published 2026-08-19) — XmlLoader resolved attacker-controlled FILE_NAME from an imported XML and read the host file into program memory. Same shape: a filename inside an import file reaches a host path unvalidated. Note the sobering calibration for both: a cooperative NSA-maintained project, automatic-analysis exposure, severity capped at medium, no CVEs assigned.
- Exposure timeline: Finding 1 (NT_FILE child loading) shipped 2020-04-16 (cle commit 09eff76) — exposed ~5.5 years, every release since, no flag. Finding 2: git history shows auto_load_libs=True in EVERY published cle release; the default flipped to False in commit ce6d0c4 (2026-01-12, "let's accept reality, and make the Auto Load Libs value False!", PR #566) — i.e. the maintainers already recognize the hazard, but the change is unreleased (9.3.4.dev0), so all PyPI users remain on default-True.
- We found no published CVE/GHSA for angr or cle; these appear to be novel reports.
- Additional maintainer-adjacency: cle PR #300 (merged 2021-09-23, "ELFCore: Catch CLECompatibilityError when loading children") shows the team already encountered failures from child loading — and fixed only the crash (for cross-OS compat), leaving the trust issue (open() of NT_FILE-named host paths) untouched. As of 2026-08-27, no open PR on angr/cle addresses path validation for NT_FILE or DT_NEEDED resolution.

Happy to retest any patch. Please advise on your timeline for public disclosure/CVE.
