from hexdump import hexdump
from os import path as _p

from ..util import MalformedElfError

from .elf_header_editor import ElfHeaderEditor
from ..constants import SECTION
from ..core import Editor
from ..elements.section_header import SectionHeader, SectionHeaderTable


class SectionHeaderEditor(Editor):
    def read_section_header_table(self, rev_idx: int = -1) -> SectionHeaderTable | None:
        # elfhdr_editor: ElfHeaderEditor = self.elf.get_editor(EDITOR.ELF_HEADER)
        elfhdr_editor = ElfHeaderEditor(self.elf)
        elfhdr = elfhdr_editor.read_elf_header(rev_idx=rev_idx)

        if not elfhdr:
            return

        rev = self.elf.revisions[rev_idx]
        cache = self.elf.get_cache(rev, 'sht')

        if sht := cache.lookup():
            return sht

        if (siz := _p.getsize(rev)) < elfhdr.shoff + elfhdr.shnum * elfhdr.shentsize:
            raise MalformedElfError(f'Section header table is truncated: file size ({siz}) < section header table offset ({elfhdr.shoff}) + section header table size ({elfhdr.shnum * elfhdr.shentsize})')

        with open(rev, 'rb') as f:
            f.seek(elfhdr.shoff)
            sht_bytes = f.read(elfhdr.shnum * elfhdr.shentsize)

        sht = SectionHeaderTable()

        if elfhdr.shnum == 0:
            cache.update(sht)
            return sht

        assert elfhdr.shentsize == SectionHeader.size(self.elf)

        shstrtab = self._read_shstrtab(elfhdr, sht_bytes, rev)

        for i in range(elfhdr.shnum):
            sh = SectionHeader.from_bytes(
                self.elf,
                sht_bytes[i*elfhdr.shentsize:(i+1)*elfhdr.shentsize],
                shstrtab,
            )
            sht.append(sh)

        cache.update(sht)

        return sht

    def _read_shstrtab(self, elfhdr, sht_bytes: bytes, rev: str) -> bytes:
        """Read the section-name string table located via e_shstrndx.

        Resolving names through e_shstrndx (not a hard-coded ".shstrtab") is
        required by the spec: some toolchains (e.g. clang object files) reuse
        ".strtab" as both the symbol and section-name string table.
        """
        idx = elfhdr.shstrndx
        if idx == 0 or idx >= elfhdr.shnum:
            return b''

        shstr_hdr = SectionHeader.from_bytes(
            self.elf,
            sht_bytes[idx*elfhdr.shentsize:(idx+1)*elfhdr.shentsize],
        )

        if shstr_hdr.siz == 0:
            return b''

        with open(rev, 'rb') as f:
            f.seek(shstr_hdr.offset)
            return f.read(shstr_hdr.siz)

    def read_section_header(self, section: SECTION, rev_idx: int = -1) -> SectionHeader | None:
        if not (sht := self.read_section_header_table(rev_idx=rev_idx)):
            return

        for sh in sht:
            if sh.name == str(section):
                return sh

    def __get_section_header_offset_by_name(self, section: SECTION) -> int:
        elfhdr_editor = ElfHeaderEditor(self.elf)
        elfhdr = elfhdr_editor.read_elf_header()

        if not elfhdr:
            return -1

        rev = self.elf.get_current_revision()
        with open(rev, 'rb') as f:
            f.seek(elfhdr.shoff)
            sht_bytes = f.read(elfhdr.shnum * elfhdr.shentsize)

        assert elfhdr.shentsize == SectionHeader.size(self.elf)

        shstrtab = self._read_shstrtab(elfhdr, sht_bytes, rev)

        offset = -1
        for i in range(elfhdr.shnum):
            sh = SectionHeader.from_bytes(
                self.elf,
                sht_bytes[i*elfhdr.shentsize:(i+1)*elfhdr.shentsize],
                shstrtab,
            )
            if sh.name == str(section):
                offset = elfhdr.shoff + i * elfhdr.shentsize
                break

        return offset

    def write_section_header_table(self, sht: SectionHeaderTable) -> bool:
        elfhdr_editor = ElfHeaderEditor(self.elf)
        elfhdr = elfhdr_editor.read_elf_header()

        if not elfhdr:
            return False

        rev = self.elf.get_current_revision()
        cache = self.elf.get_cache(rev, 'sht')

        with open(rev, 'rb') as f:
            f.seek(elfhdr.shoff)
            sht_bytes = f.read(elfhdr.shnum * elfhdr.shentsize)
        shstrtab = self._read_shstrtab(elfhdr, sht_bytes, rev)

        with open(rev, 'r+b') as f:
            f.seek(elfhdr.shoff)
            for sh in sht:
                f.write(sh.to_bytes(self.elf, shstrtab))

        elfhdr.shnum = len(sht)

        elfhdr_editor.write_elf_header(elfhdr)

        cache.invalidate()

        return True

    def write_section_header(self, section: SECTION, sh: SectionHeader):
        offset = self.__get_section_header_offset_by_name(section)
        rev = self.elf.get_current_revision()
        cache = self.elf.get_cache(rev, 'sht')

        if offset < 0:
            raise ValueError

        elfhdr = ElfHeaderEditor(self.elf).read_elf_header()
        with open(rev, 'rb') as f:
            f.seek(elfhdr.shoff)
            sht_bytes = f.read(elfhdr.shnum * elfhdr.shentsize)
        shstrtab = self._read_shstrtab(elfhdr, sht_bytes, rev)

        with open(rev, 'r+b') as f:
            f.seek(offset)
            f.write(sh.to_bytes(self.elf, shstrtab))

        cache.invalidate()
