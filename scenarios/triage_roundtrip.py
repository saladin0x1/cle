#!/usr/bin/env python3
"""Scenario - triage-service round trip (SIMULATED wrapper over real primitives).

Everything angr-side is the verified behavior from poc1b: a submitted core names
a host binary, angr.Project() with defaults ingests it, and its bytes are
recoverable. The 'service' (upload -> analyze -> return warnings/objects/strings
to the submitter) is our code and represents an assumption about deployment
pipelines, not angr behavior. Requires angr (not just cle).
"""
import json
import logging
import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import angr  # noqa: E402

from lib.builders import MARKER, build_core, build_victim_elf  # noqa: E402


class _Cap(logging.Handler):
    def __init__(self):
        super().__init__()
        self.msgs = []

    def emit(self, record):
        self.msgs.append(record.getMessage())


def triage(upload_path):
    cap = _Cap()
    lg = logging.getLogger("cle")
    lg.addHandler(cap)
    try:
        p = angr.Project(upload_path)  # defaults, exactly as a service would
    finally:
        lg.removeHandler(cap)
    objects, strings = [], []
    for o in p.loader.all_objects:
        objects.append({"type": type(o).__name__, "path": str(o.binary)})
        if o is p.loader.main_object:
            continue
        try:
            blob = bytes(o.memory.load(0, min(0x4000, o.max_addr - o.min_addr)))
            strings += [s.decode() for s in re.findall(rb"[\x20-\x7e]{16,}", blob)]
        except Exception:  # noqa: BLE001
            pass
    return {"warnings": cap.msgs, "objects": objects, "strings": sorted(set(strings))}


def main():
    print(f"SIMULATION - angr {angr.__version__} / cle {__import__('cle').__version__}")
    with tempfile.TemporaryDirectory() as td:
        victim = build_victim_elf(os.path.join(td, "victim_corp_tool.so"))
        core = os.path.join(td, "upload.core")
        build_core([(0x400000, 0x401000, 0, victim)], core)

        report = triage(core)
        leaked = [s for s in report["strings"] if MARKER[:-1].decode() in s]
        print("  objects returned to submitter:", [o["path"] for o in report["objects"]])
        print("  marker in returned strings:", leaked)
        print("RESULT:", "VULNERABLE - victim binary contents exfiltrated to the submitter"
              if leaked else "NOT REPRODUCIBLE")
        print(json.dumps({"objects": len(report["objects"]), "strings": len(report["strings"])}, indent=2))


if __name__ == "__main__":
    main()
