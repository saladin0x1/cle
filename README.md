# cle PoC package — unauthorized host file reads driven by analyzed input files

Two findings. Both reproduce on the release stack (angr/cle 9.2.99 from PyPI,
default options) and against cle @ HEAD.

| ID  | Finding                                                        | Sink                                                   |
|-----|----------------------------------------------------------------|--------------------------------------------------------|
| S1  | NT_FILE note filenames are `open()`ed on the host, unconditionally | `cle/backends/elf/elfcore.py:434` (`__reload_children`) |
| S2  | Path-like DT_NEEDED entries escape the library search dirs     | `cle/loader.py:1221` (`_possible_paths`; origin `cle/backends/elf/elf.py:1059`) |

All PoCs are deterministic, hand-crafted minimal ELF64 files (`struct.pack` only —
no malware, no network). Each script self-reports `RESULT: VULNERABLE` or
`RESULT: NOT REPRODUCIBLE`, so the same scripts verify the fix in `docs/FIX.diff`
(PR #797).

---

## S1 — NT_FILE host read

Vulnerable code (unchanged from 2020-04-16 through 9.2.99 and HEAD):

```python
# cle/backends/elf/elfcore.py — __parse_files: filenames come verbatim from the note
self.filename_lookup = [
    (ent.vm_start, ent.vm_end, ent.page_offset * desc.page_size,
     self._remote_file_mapper(fn.decode()))
    for ent, fn in zip(desc.Elf_Nt_File_Entry, desc.filename)
]

# __reload_children — called unconditionally from ELFCore.__init__:
for filename, patches in child_patches.items():
    try:
        with open(filename, "rb") as fp:                     # attacker-named host path
            obj = self.loader._load_object_isolated(fp)
    except (FileNotFoundError, PermissionError, CLECompatibilityError) as ex:
        # three distinct warnings below -> filesystem existence/permission oracle
```

Fix (excerpt of `docs/FIX.diff`, PR #797) — opt-in gate + widened except clause:

```diff
+        if not self._honor_file_notes:        # only when executable=/remote_file_* given
+            log.warning("Ignoring NT_FILE mappings ...")
+            return
...
-            except (FileNotFoundError, PermissionError, CLECompatibilityError) as ex:
+            except (OSError, CLEError, CLECompatibilityError) as ex:
```

### PoCs — `findings/S1-ntfile-host-read/`

| script | demonstrates | expected (vulnerable) |
|---|---|---|
| `oracle.py` | 3-way oracle: exists+readable / denied / missing → three distinct warnings | `EXISTS_READABLE`, `DENIED`, `NOT_FOUND` |
| `ingest.py` | named host ELF parsed as child object; `MARKER` recovered via `child.memory.load` | marker bytes verbatim |
| `crash.py` | directory or `:`-prefixed file (Hex backend claims `startswith(b":")`) raises out of `Loader()` | `IsADirectoryError`, `CLEError` |

## S2 — DT_NEEDED path escape

Vulnerable code:

```python
# cle/backends/elf/elf.py:1059 — spec is the raw string from the analyzed ELF:
self.deps.append(maybedecode(tag.needed))

# cle/loader.py — _possible_paths:
for libdir in dirs:
    fullpath = os.path.realpath(os.path.join(libdir, spec))
    if os.path.exists(fullpath):
        yield fullpath
```

An absolute `spec` makes `os.path.join` discard `libdir` entirely; `./sub/../x.so`
escapes it. `auto_load_libs=True` is the default in every released cle (the flip
to False, `ce6d0c4`, is unreleased). Documented, intended behavior under the flag
(PR #797 discussion); included for completeness. The PoC passes the flag
explicitly so it also runs on HEAD where the default is `False`.

Fix (excerpt of `docs/FIX.diff`): reject path-like specs in the dependency loop.

```diff
+            if os.path.isabs(spec) or "/" in spec or "\\" in spec:
+                log.warning("Refusing to resolve path-like dependency name %r ...", spec)
+                cached_failures.add(spec)
+                continue
```

### PoC — `findings/S2-dtneeded-path-escape/arbitrary_paths.py`
Builds one ET_DYN with two DT_NEEDED entries (absolute + traversal); both named
host files are ingested as dependency objects.

## Running

```sh
python3 findings/S1-ntfile-host-read/oracle.py
python3 findings/S1-ntfile-host-read/ingest.py
python3 findings/S1-ntfile-host-read/crash.py
python3 findings/S2-dtneeded-path-escape/arbitrary_paths.py
python3 scenarios/triage_roundtrip.py     # needs angr; simulated service wrapper
```

Tested with python3.10/3.13, unix, run as non-root (as root, the `DENIED` oracle
case degrades to `EXISTS_READABLE`). On vulnerable cle each prints
`RESULT: VULNERABLE ...`; with `docs/FIX.diff` applied, `RESULT: NOT REPRODUCIBLE`.

## Layout

```
findings/S1-ntfile-host-read/     oracle.py, ingest.py, crash.py, README.md
findings/S2-dtneeded-path-escape/ arbitrary_paths.py, README.md
lib/builders.py                   deterministic ELF64 builders + warning capture/classify
scenarios/                        triage_roundtrip.py — SIMULATED service, real primitives
docs/                             DISCLOSURE.md, IMPACT.md, FIX.diff (PR #797)
```

## Scope / honest limits

Read-only: no file write, exec, network, or deserialization. Ingestion is limited
to loadable binary formats — it is not arbitrary file read, and we say so rather
than let someone else discover the limit. The oracle requires an observable
log/output channel. Non-loadable file contents are opened and format-probed but
not returned anywhere. The exfiltration in `scenarios/` additionally assumes a
deployment that returns analysis output to the submitter. The crash states carry
no such qualifiers.

Precedent (Ghidra, both medium, no CVE): GHSA-57g6-7qw2-p5hx (`.gnu_debuglink`
filename unvalidated during automatic DWARF analysis; the safe helper existed in
a sibling class — the exact shape of cle's `remote_file_mapping`) and
GHSA-3f3p-5h4j-gq2r (XmlLoader read a host file named by an imported XML). See
`docs/DISCLOSURE.md` for the full policy discussion.
