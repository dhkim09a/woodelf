"""Shared fixtures for functional tests.

Builds a small but spec-compliant ELF64 LSB shared object from scratch with
struct.pack so the functional tests have deterministic, known field values to
assert against. No cross toolchain is required — only the system `readelf` /
`objcopy` that woodelf already shells out to.

The synthesized file deliberately uses canonical section names (.shstrtab,
.dynsym, .dynstr, .symtab, .strtab, .dynamic, .text) so woodelf's hard-coded
section-name lookups all hit.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

import pytest


# ELF constants we need locally so the fixture doesn't import from the package
# under test (keeps the fixture honest as ground truth).
ELFCLASS64 = 2
ELFDATA2LSB = 1
EV_CURRENT = 1
ET_DYN = 3
EM_X86_64 = 62

PT_LOAD = 1

SHT_NULL = 0
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_DYNAMIC = 6
SHT_DYNSYM = 11

SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4

STB_LOCAL = 0
STB_GLOBAL = 1
STT_NOTYPE = 0
STT_OBJECT = 1
STT_FUNC = 2
STV_DEFAULT = 0

DT_NULL = 0
DT_NEEDED = 1
DT_STRTAB = 5
DT_SYMTAB = 6
DT_STRSZ = 10
DT_SYMENT = 11
DT_SONAME = 14


def _st_info(bind: int, typ: int) -> int:
    return (bind << 4) | (typ & 0xF)


@dataclass(frozen=True)
class ElfBlueprint:
    """The exact values baked into the synthesized ELF. Tests assert against these."""

    path: str

    # Header
    machine: int = EM_X86_64
    elf_type: int = ET_DYN

    # .text content
    text_vaddr: int = 0x1000
    text_bytes: bytes = b"\x90" * 16  # 16 NOPs

    # Names baked into .dynstr (offsets resolved at build time)
    soname: str = "libtest.so.1"
    needed: tuple[str, ...] = ("libc.so.6", "libm.so.6")

    # Symbol names baked into .strtab/.dynsym
    dynsym_names: tuple[str, ...] = ("printf", "my_export")
    symtab_names: tuple[str, ...] = ("_start", "main", "data_obj")

    # Name to give the section-name string table. Defaults to canonical
    # ".shstrtab"; override (e.g. ".strtab") to exercise woodelf's
    # shstrndx-based name resolution rather than a hard-coded name.
    shstrtab_name: str = ".shstrtab"


def _build_strtab(strings: list[str]) -> tuple[bytes, dict[str, int]]:
    """Pack strings into a string table; return bytes and {string -> offset}."""
    buf = bytearray(b"\x00")  # empty string at offset 0
    offsets: dict[str, int] = {"": 0}
    for s in strings:
        if s in offsets:
            continue
        offsets[s] = len(buf)
        buf += s.encode("ascii") + b"\x00"
    return bytes(buf), offsets


def _build_elf(bp: ElfBlueprint) -> bytes:
    # --- string tables -------------------------------------------------------
    shstrtab_names = [
        "",
        ".text",
        ".dynsym",
        ".dynstr",
        ".symtab",
        ".strtab",
        bp.shstrtab_name,
        ".dynamic",
    ]
    shstrtab_bytes, sh_off = _build_strtab(shstrtab_names[1:])

    dynstr_bytes, dynstr_off = _build_strtab([bp.soname, *bp.needed, *bp.dynsym_names])
    strtab_bytes, strtab_off = _build_strtab(list(bp.symtab_names))

    # --- symbol tables -------------------------------------------------------
    # ELF64 Sym layout: st_name(4) st_info(1) st_other(1) st_shndx(2) st_value(8) st_size(8)
    def sym(name_off: int, info: int, other: int, shndx: int, value: int, size: int) -> bytes:
        return struct.pack("<IBBHQQ", name_off, info, other, shndx, value, size)

    SHN_UNDEF = 0
    TEXT_SHNDX = 1  # .text is section index 1 in our layout

    dynsym_entries = [
        sym(0, 0, 0, SHN_UNDEF, 0, 0),  # mandatory undef
        # external "printf" — undefined import
        sym(dynstr_off["printf"], _st_info(STB_GLOBAL, STT_FUNC),
            STV_DEFAULT, SHN_UNDEF, 0, 0),
        # exported "my_export" — defined in .text
        sym(dynstr_off["my_export"], _st_info(STB_GLOBAL, STT_FUNC),
            STV_DEFAULT, TEXT_SHNDX, bp.text_vaddr, 8),
    ]
    dynsym_bytes = b"".join(dynsym_entries)

    symtab_entries = [
        sym(0, 0, 0, SHN_UNDEF, 0, 0),
        # one local (sh_info points one past the last local)
        sym(strtab_off["_start"], _st_info(STB_LOCAL, STT_FUNC),
            STV_DEFAULT, TEXT_SHNDX, bp.text_vaddr, 8),
        sym(strtab_off["main"], _st_info(STB_GLOBAL, STT_FUNC),
            STV_DEFAULT, TEXT_SHNDX, bp.text_vaddr + 8, 8),
        sym(strtab_off["data_obj"], _st_info(STB_GLOBAL, STT_OBJECT),
            STV_DEFAULT, TEXT_SHNDX, bp.text_vaddr, 16),
    ]
    symtab_bytes = b"".join(symtab_entries)
    symtab_local_count = 2  # null + _start

    # --- dynamic entries -----------------------------------------------------
    # ELF64 Dyn layout: d_tag(8) d_un(8). DT_STRTAB/DT_SYMTAB are addresses
    # (vaddrs); we use file offsets since this isn't going to be loaded.
    # File offsets get filled in once we know the layout.
    # We'll patch the dynamic section after computing layout.

    # --- layout --------------------------------------------------------------
    EHDR_SIZE = 64
    PHDR_SIZE = 56
    SHDR_SIZE = 64
    SYM_SIZE = 24
    DYN_SIZE = 16

    def align(x: int, a: int) -> int:
        return (x + a - 1) & ~(a - 1)

    off_ehdr = 0
    off_phdr = EHDR_SIZE
    off_text = align(off_phdr + PHDR_SIZE, 16)
    off_dynsym = align(off_text + len(bp.text_bytes), 8)
    off_dynstr = off_dynsym + len(dynsym_bytes)
    off_symtab = align(off_dynstr + len(dynstr_bytes), 8)
    off_strtab = off_symtab + len(symtab_bytes)
    off_shstrtab = off_strtab + len(strtab_bytes)
    off_dynamic = align(off_shstrtab + len(shstrtab_bytes), 8)

    # placeholder dynamic entries — exact count needed for layout
    needed_entries = [(DT_NEEDED, dynstr_off[n]) for n in bp.needed]
    dyn_entries = [
        (DT_SONAME, dynstr_off[bp.soname]),
        *needed_entries,
        (DT_STRTAB, off_dynstr),  # use file offset; tests treat as opaque int
        (DT_SYMTAB, off_dynsym),
        (DT_STRSZ, len(dynstr_bytes)),
        (DT_SYMENT, SYM_SIZE),
        (DT_NULL, 0),
    ]
    dynamic_bytes = b"".join(struct.pack("<qQ", tag, val) for tag, val in dyn_entries)

    off_shdr = align(off_dynamic + len(dynamic_bytes), 8)
    total_size = off_shdr + SHDR_SIZE * len(shstrtab_names)

    # --- section headers -----------------------------------------------------
    def shdr(name_off: int, typ: int, flags: int, addr: int, offset: int,
             size: int, link: int, info: int, addralign: int, entsize: int) -> bytes:
        return struct.pack("<IIQQQQIIQQ", name_off, typ, flags, addr, offset,
                           size, link, info, addralign, entsize)

    # Section index assignments:
    SH_NULL = 0
    SH_TEXT = 1
    SH_DYNSYM = 2
    SH_DYNSTR = 3
    SH_SYMTAB = 4
    SH_STRTAB = 5
    SH_SHSTRTAB = 6
    SH_DYNAMIC = 7

    shdrs = [
        shdr(0, SHT_NULL, 0, 0, 0, 0, 0, 0, 0, 0),
        shdr(sh_off[".text"], SHT_PROGBITS,
             SHF_ALLOC | SHF_EXECINSTR,
             bp.text_vaddr, off_text, len(bp.text_bytes), 0, 0, 16, 0),
        shdr(sh_off[".dynsym"], SHT_DYNSYM,
             SHF_ALLOC,
             0, off_dynsym, len(dynsym_bytes), SH_DYNSTR, 1, 8, SYM_SIZE),
        shdr(sh_off[".dynstr"], SHT_STRTAB,
             SHF_ALLOC,
             0, off_dynstr, len(dynstr_bytes), 0, 0, 1, 0),
        shdr(sh_off[".symtab"], SHT_SYMTAB,
             0,
             0, off_symtab, len(symtab_bytes), SH_STRTAB, symtab_local_count, 8, SYM_SIZE),
        shdr(sh_off[".strtab"], SHT_STRTAB,
             0,
             0, off_strtab, len(strtab_bytes), 0, 0, 1, 0),
        shdr(sh_off[bp.shstrtab_name], SHT_STRTAB,
             0,
             0, off_shstrtab, len(shstrtab_bytes), 0, 0, 1, 0),
        shdr(sh_off[".dynamic"], SHT_DYNAMIC,
             SHF_WRITE | SHF_ALLOC,
             0, off_dynamic, len(dynamic_bytes), SH_DYNSTR, 0, 8, DYN_SIZE),
    ]

    # --- program header ------------------------------------------------------
    # A single PT_LOAD covering the whole file at vaddr 0.
    phdr = struct.pack(
        "<IIQQQQQQ",
        PT_LOAD,           # p_type
        5,                 # p_flags = PF_R | PF_X
        0,                 # p_offset
        0,                 # p_vaddr
        0,                 # p_paddr
        total_size,        # p_filesz
        total_size,        # p_memsz
        0x1000,            # p_align
    )

    # --- ELF header ----------------------------------------------------------
    e_ident = bytes([
        0x7F, ord("E"), ord("L"), ord("F"),
        ELFCLASS64, ELFDATA2LSB, EV_CURRENT, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
    ])
    ehdr = e_ident + struct.pack(
        "<HHIQQQIHHHHHH",
        bp.elf_type,                  # e_type
        bp.machine,                   # e_machine
        EV_CURRENT,                   # e_version
        bp.text_vaddr,                # e_entry
        off_phdr,                     # e_phoff
        off_shdr,                     # e_shoff
        0,                            # e_flags
        EHDR_SIZE,                    # e_ehsize
        PHDR_SIZE,                    # e_phentsize
        1,                            # e_phnum
        SHDR_SIZE,                    # e_shentsize
        len(shdrs),                   # e_shnum
        SH_SHSTRTAB,                  # e_shstrndx
    )

    # --- stitch it all together ----------------------------------------------
    buf = bytearray(total_size)

    def put(off: int, data: bytes) -> None:
        buf[off:off + len(data)] = data

    put(off_ehdr, ehdr)
    put(off_phdr, phdr)
    put(off_text, bp.text_bytes)
    put(off_dynsym, dynsym_bytes)
    put(off_dynstr, dynstr_bytes)
    put(off_symtab, symtab_bytes)
    put(off_strtab, strtab_bytes)
    put(off_shstrtab, shstrtab_bytes)
    put(off_dynamic, dynamic_bytes)
    put(off_shdr, b"".join(shdrs))

    return bytes(buf)


@pytest.fixture
def elf_blueprint(tmp_path) -> ElfBlueprint:
    """Synthesize a minimal ELF64 LSB shared object and return its blueprint."""
    bp = ElfBlueprint(path=str(tmp_path / "synth.so"))
    with open(bp.path, "wb") as f:
        f.write(_build_elf(bp))
    return bp


@pytest.fixture
def elf_blueprint_factory(tmp_path):
    """Build customized ELFs (e.g. with a non-canonical shstrtab name)."""
    counter = {"n": 0}

    def make(**overrides) -> ElfBlueprint:
        counter["n"] += 1
        path = str(tmp_path / f"synth_{counter['n']}.so")
        bp = ElfBlueprint(path=path, **overrides)
        with open(bp.path, "wb") as f:
            f.write(_build_elf(bp))
        return bp

    return make
