"""End-to-end tests that drive woodelf against a real ELF on disk.

The fixture in conftest.py synthesizes a minimal but spec-compliant ELF64 LSB
shared object whose every field value is known up front; these tests assert
woodelf reads those fields back correctly and round-trips header mutations.

Note: tests that mutate section *contents* (SymbolEditor.write_symbol_table,
DynamicEntryEditor.write_dynamic_entries) would land on
SectionEditor.write_content, which shells out to `objcopy --update-section`.
objcopy refuses to rewrite our minimal layout ("not enough room for program
headers"). Header/section-header writes use direct file I/O and are covered.
"""

from __future__ import annotations

import shutil
import struct

import pytest
import sh

import woodelf
from woodelf.constants import (
    DYNAMIC_ENTRY_TAG,
    ELF64,
    ELF_CLASS,
    ELF_MACHINE,
    ELF_TYPE,
    SECTION,
    SYMBOL_BIND,
    SYMBOL_TYPE,
    SYMBOL_VISIBILITY,
)
from woodelf.editors.dynamic_entry_editor import DynamicEntryEditor
from woodelf.editors.elf_header_editor import ElfHeaderEditor
from woodelf.editors.section_editor import SectionEditor
from woodelf.editors.section_header_editor import SectionHeaderEditor
from woodelf.editors.strtab_editor import StrTabEditor
from woodelf.editors.symbol_editor import SymbolEditor
from woodelf.util import MalformedElfError


class TestParseTopLevel:
    def test_parse_returns_elf_with_correct_class_and_endian(self, elf_blueprint):
        elf = woodelf.parse(elf_blueprint.path)
        assert elf is not None
        assert elf.unit is ELF64
        assert elf.endian == "little"

    def test_parse_returns_none_for_non_elf(self, tmp_path):
        bogus = tmp_path / "not_an_elf.bin"
        bogus.write_bytes(b"MZ\x00\x00" + b"\x00" * 60)  # DOS header bytes
        assert woodelf.parse(str(bogus)) is None

    def test_parse_returns_none_for_short_file(self, tmp_path):
        short = tmp_path / "short.bin"
        short.write_bytes(b"\x7fELF\x02\x01")  # truncated e_ident
        assert woodelf.parse(str(short)) is None


class TestElfHeaderEditor:
    def test_read_e_ident(self, elf_blueprint):
        elf = woodelf.parse(elf_blueprint.path)
        ident = ElfHeaderEditor(elf).read_e_ident()

        assert ident is not None
        assert ident.magic == b"\x7fELF"
        assert ident.cls == ELF_CLASS.CLASS64
        assert ident.data.endian() == "little"

    def test_read_elf_header_fields(self, elf_blueprint):
        elf = woodelf.parse(elf_blueprint.path)
        hdr = ElfHeaderEditor(elf).read_elf_header()

        assert hdr.typ == ELF_TYPE.DYN
        assert hdr.machine == ELF_MACHINE.EM_X86_64
        assert hdr.entry == elf_blueprint.text_vaddr
        assert hdr.phnum == 1
        assert hdr.shnum == 8
        assert hdr.phentsize == 56
        assert hdr.shentsize == 64
        assert hdr.ehsize == 64
        # shstrndx points at .shstrtab (index 6 in the synthesized layout)
        assert hdr.shstrndx == 6

    def test_write_header_round_trip(self, elf_blueprint):
        elf = woodelf.parse(elf_blueprint.path)
        editor = ElfHeaderEditor(elf)

        hdr = editor.read_elf_header()
        hdr.entry = 0xDEADBEEF
        hdr.flags = 0xCAFE
        assert editor.write_elf_header(hdr) is True

        # Cache is invalidated; re-parsing from disk picks up the new values.
        elf2 = woodelf.parse(elf_blueprint.path)
        hdr2 = ElfHeaderEditor(elf2).read_elf_header()
        assert hdr2.entry == 0xDEADBEEF
        assert hdr2.flags == 0xCAFE

    def test_e_ident_cached(self, elf_blueprint):
        elf = woodelf.parse(elf_blueprint.path)
        editor = ElfHeaderEditor(elf)
        assert editor.read_e_ident() is editor.read_e_ident()


class TestSectionHeaderEditor:
    def test_section_count_and_names(self, elf_blueprint):
        elf = woodelf.parse(elf_blueprint.path)
        sht = SectionHeaderEditor(elf).read_section_header_table()

        assert len(sht) == 8
        names = [sh.name for sh in sht]
        assert names == [
            "",
            ".text",
            ".dynsym",
            ".dynstr",
            ".symtab",
            ".strtab",
            ".shstrtab",
            ".dynamic",
        ]

    def test_lookup_by_section_enum(self, elf_blueprint):
        elf = woodelf.parse(elf_blueprint.path)
        editor = SectionHeaderEditor(elf)

        text = editor.read_section_header(SECTION.TEXT)
        assert text is not None
        assert text.addr == elf_blueprint.text_vaddr
        assert text.siz == len(elf_blueprint.text_bytes)
        assert text.addralign == 16

        dynsym = editor.read_section_header(SECTION.DYNSYM)
        assert dynsym is not None
        assert dynsym.entsize == 24
        # .dynsym's sh_link points to .dynstr (section index 3)
        assert dynsym.link == 3

    def test_lookup_missing_section_returns_none(self, elf_blueprint):
        elf = woodelf.parse(elf_blueprint.path)
        # .rodata isn't in the synthesized layout.
        assert SectionHeaderEditor(elf).read_section_header(SECTION.RODATA) is None

    def test_write_section_header_round_trip(self, elf_blueprint):
        elf = woodelf.parse(elf_blueprint.path)
        editor = SectionHeaderEditor(elf)

        text = editor.read_section_header(SECTION.TEXT)
        text.addr = 0x4000
        editor.write_section_header(SECTION.TEXT, text)

        elf2 = woodelf.parse(elf_blueprint.path)
        text2 = SectionHeaderEditor(elf2).read_section_header(SECTION.TEXT)
        assert text2.addr == 0x4000

    def test_truncated_section_header_table_raises(self, elf_blueprint, tmp_path):
        # Truncate the file partway through the section header table —
        # shoff is still valid but the table itself is short.
        with open(elf_blueprint.path, "rb") as f:
            full = f.read()
        shoff = struct.unpack_from("<Q", full, 0x28)[0]  # e_shoff in ELF64

        truncated = tmp_path / "trunc.so"
        truncated.write_bytes(full[:shoff + 16])

        elf = woodelf.parse(str(truncated))
        with pytest.raises(MalformedElfError):
            SectionHeaderEditor(elf).read_section_header_table()


class TestStrTabEditor:
    def test_read_strtab_content(self, elf_blueprint):
        elf = woodelf.parse(elf_blueprint.path)
        editor = StrTabEditor(elf, SECTION.STRTAB)

        content = editor.read_content()
        assert content is not None
        # the symtab names from the blueprint should all appear
        for name in elf_blueprint.symtab_names:
            assert name.encode("ascii") in bytes(content)

    def test_find_and_has(self, elf_blueprint):
        elf = woodelf.parse(elf_blueprint.path)
        dynstr = StrTabEditor(elf, SECTION.DYNSTR)

        assert dynstr.has(elf_blueprint.soname)
        assert dynstr.find(elf_blueprint.soname) > 0
        assert not dynstr.has("definitely_not_present_xyz")
        assert dynstr.find("definitely_not_present_xyz") < 0

    def test_get_str_at_offset(self, elf_blueprint):
        elf = woodelf.parse(elf_blueprint.path)
        dynstr = StrTabEditor(elf, SECTION.DYNSTR)

        off = dynstr.find(elf_blueprint.needed[0])
        assert dynstr.get_str(off) == elf_blueprint.needed[0]

    def test_shstrtab_via_readelf_fallback(self, elf_blueprint):
        # .shstrtab can't be dumped by objcopy, so this exercises the readelf
        # -x fallback path in SectionEditor.read_content.
        elf = woodelf.parse(elf_blueprint.path)
        shstrtab = StrTabEditor(elf, SECTION.SHSTRTAB)
        content = bytes(shstrtab.read_content())
        for name in (".text", ".dynsym", ".shstrtab", ".dynamic"):
            assert name.encode("ascii") in content


class TestSymbolEditor:
    def test_dynsym_contents(self, elf_blueprint):
        elf = woodelf.parse(elf_blueprint.path)
        dynsyms = SymbolEditor(elf, SECTION.DYNSYM).read_symbol_table()

        assert len(dynsyms) == 3
        # entry 0 is the mandatory undef
        assert dynsyms[0].name == ""
        assert dynsyms[0].shndx == 0

        printf = dynsyms[1]
        assert printf.name == "printf"
        assert printf.bind == SYMBOL_BIND.STB_GLOBAL
        assert printf.typ == SYMBOL_TYPE.STT_FUNC
        assert printf.other == SYMBOL_VISIBILITY.STV_DEFAULT
        assert printf.is_needed()  # value=0 size=0 shndx=0

        my_export = dynsyms[2]
        assert my_export.name == "my_export"
        assert my_export.value == elf_blueprint.text_vaddr
        assert my_export.siz == 8
        assert my_export.is_defined()

    def test_symtab_contents(self, elf_blueprint):
        elf = woodelf.parse(elf_blueprint.path)
        syms = SymbolEditor(elf, SECTION.SYMTAB).read_symbol_table()

        assert len(syms) == 4
        by_name = {s.name: s for s in syms}

        assert by_name["_start"].bind == SYMBOL_BIND.STB_LOCAL
        assert by_name["main"].bind == SYMBOL_BIND.STB_GLOBAL
        assert by_name["main"].typ == SYMBOL_TYPE.STT_FUNC
        assert by_name["main"].value == elf_blueprint.text_vaddr + 8
        assert by_name["data_obj"].typ == SYMBOL_TYPE.STT_OBJECT
        assert by_name["data_obj"].siz == 16

    def test_defined_and_needed_filters(self, elf_blueprint):
        elf = woodelf.parse(elf_blueprint.path)
        dynsyms = SymbolEditor(elf, SECTION.DYNSYM).read_symbol_table()

        defined = [s.name for s in dynsyms.defined_symbols()]
        needed = [s.name for s in dynsyms.needed_symbols()]

        assert "my_export" in defined
        assert "printf" in needed
        assert "printf" not in defined
        assert "my_export" not in needed


class TestDynamicEntryEditor:
    def test_read_dynamic_entries(self, elf_blueprint):
        elf = woodelf.parse(elf_blueprint.path)
        entries = DynamicEntryEditor(elf).read_dynamic_entries()

        # Last entry must be DT_NULL terminator.
        assert entries[-1].tag == DYNAMIC_ENTRY_TAG.DT_NULL

        tags = [e.tag for e in entries]
        assert DYNAMIC_ENTRY_TAG.DT_SONAME in tags
        assert DYNAMIC_ENTRY_TAG.DT_NEEDED in tags
        assert DYNAMIC_ENTRY_TAG.DT_STRTAB in tags
        assert DYNAMIC_ENTRY_TAG.DT_SYMENT in tags

    def test_needed_names_resolved_from_dynstr(self, elf_blueprint):
        elf = woodelf.parse(elf_blueprint.path)
        entries = DynamicEntryEditor(elf).read_dynamic_entries()

        needed = [e.un for e in entries if e.tag == DYNAMIC_ENTRY_TAG.DT_NEEDED]
        assert list(needed) == list(elf_blueprint.needed)

    def test_read_soname(self, elf_blueprint):
        elf = woodelf.parse(elf_blueprint.path)
        assert DynamicEntryEditor(elf).read_soname() == elf_blueprint.soname

    def test_syment_value_matches_symbol_size(self, elf_blueprint):
        elf = woodelf.parse(elf_blueprint.path)
        entries = DynamicEntryEditor(elf).read_dynamic_entries()
        syment = next(e for e in entries if e.tag == DYNAMIC_ENTRY_TAG.DT_SYMENT)
        assert syment.un == 24  # ELF64 Sym is always 24 bytes


class TestElfWriteSaveRoundTrip:
    def test_write_to_new_path_copies_unchanged_bytes(self, elf_blueprint, tmp_path):
        elf = woodelf.parse(elf_blueprint.path)
        out = tmp_path / "copy.so"
        elf.write(str(out))

        with open(elf_blueprint.path, "rb") as a, open(out, "rb") as b:
            assert a.read() == b.read()

    def test_write_creates_parent_directories(self, elf_blueprint, tmp_path):
        elf = woodelf.parse(elf_blueprint.path)
        out = tmp_path / "nested" / "subdir" / "copy.so"
        elf.write(str(out))
        assert out.exists()

    def test_header_mutation_persists_through_save(self, elf_blueprint, tmp_path):
        elf = woodelf.parse(elf_blueprint.path)
        hdr = ElfHeaderEditor(elf).read_elf_header()
        hdr.entry = 0x12345
        ElfHeaderEditor(elf).write_elf_header(hdr)

        out = tmp_path / "mutated.so"
        elf.write(str(out))

        reparsed = woodelf.parse(str(out))
        assert ElfHeaderEditor(reparsed).read_elf_header().entry == 0x12345


class TestSectionEditorReadelfFallback:
    def test_readelf_dump_section_returns_none_when_readelf_keeps_failing(
        self, elf_blueprint
    ):
        # Regression: the retry loop must terminate. /usr/bin/false exits 1 on
        # every call, so a buggy `while range(2):` would hang here forever.
        elf = woodelf.parse(elf_blueprint.path)
        elf.readelf = sh.Command("false")

        assert SectionEditor(elf, SECTION.TEXT).readelf_dump_section() is None
