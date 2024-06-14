from . import ElfHeaderEditor
from .. import api, EDITOR
from ..core import Editor
from ..elements.program_header import ProgramHeader, ProgramHeaderTable


class ProgramHeaderEditor(Editor, api.ProgramHeaderEditor):
    def read_program_header_table(self, rev_idx: int = -1) -> ProgramHeaderTable:
        elfhdr_editor: ElfHeaderEditor = self.elf.get_editor(EDITOR.ELF_HEADER)
        elfhdr = elfhdr_editor.read_elf_header(rev_idx=rev_idx)
        rev = self.elf.revisions[rev_idx]
        cache = self.elf.get_cache(rev, 'pht')

        with open(rev, 'rb') as f:
            f.seek(elfhdr.phoff)
            pht_bytes = f.read(elfhdr.phnum * elfhdr.phentsize)

        pht = ProgramHeaderTable()

        if elfhdr.phnum == 0:
            cache.update(pht)
            return pht

        assert elfhdr.phentsize == ProgramHeader.size(self.elf)

        for i in range(elfhdr.phnum):
            ph = ProgramHeader.from_bytes(self.elf, pht_bytes[i*elfhdr.phentsize:(i+1)*elfhdr.phentsize])
            pht.append(ph)

        cache.update(pht)

        return pht

    def write_program_header_table(self, pht: ProgramHeaderTable):
        elfhdr_editor: ElfHeaderEditor = self.elf.get_editor(EDITOR.ELF_HEADER)
        elfhdr = elfhdr_editor.read_elf_header()
        rev = self.elf.get_current_revision()
        cache = self.elf.get_cache(rev, 'pht')

        with open(rev, 'r+b') as f:
            f.seek(elfhdr.phoff)
            for ph in pht:
                f.write(ph.to_bytes(self.elf))

        elfhdr.phnum = len(pht)

        elfhdr_editor.write_elf_header(elfhdr)

        cache.invalidate()
