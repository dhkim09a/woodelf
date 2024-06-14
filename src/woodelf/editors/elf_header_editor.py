from .. import api
from ..core import Editor
from ..elements import E_Ident, ElfHeader


class ElfHeaderEditor(api.ElfHeaderEditor, Editor):

    def read_e_ident(self) -> E_Ident:
        rev = self.elf.get_current_revision()
        cache = self.elf.get_cache(rev, 'e_ident')

        if e_ident := cache.lookup():
            return e_ident

        with open(rev, 'rb') as f:
            b = f.read(E_Ident.size())

        e_ident = E_Ident.from_bytes(b)
        cache.update(e_ident)
        return e_ident

    def read_elf_header(self, rev_idx: int = -1) -> ElfHeader:
        rev = self.elf.revisions[rev_idx]
        cache = self.elf.get_cache(rev, 'elfh')

        if elfh := cache.lookup():
            return elfh

        with open(rev, 'rb') as f:
            b = f.read(ElfHeader.size(self.elf))

        elfh = ElfHeader.from_bytes(self.elf, b)
        cache.update(elfh)
        return elfh

    def write_elf_header(self, elf_header: ElfHeader):
        rev = self.elf.get_current_revision()

        with open(rev, 'r+b') as f:
            f.write(elf_header.to_bytes(self.elf))

        self.elf.get_cache(rev, 'e_ident').invalidate()
        self.elf.get_cache(rev, 'elfh').invalidate()

