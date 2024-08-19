from ..core.elf import Elf
# from ..editors.strtab_editor import StrTabEditor
from ..constants import ELF32, ELF64, SECTION
from ..core import Element


class SectionHeader(Element):
    name: str
    type: int
    flags: int
    addr: int
    offset: int
    siz: int
    link: int
    info: int
    addralign: int
    entsize: int

    @classmethod
    def units(cls, elf: Elf) -> list[ELF32 | ELF64]:
        return [elf.unit.Word, elf.unit.Word, elf.unit.Xword, elf.unit.Addr,
                elf.unit.Off, elf.unit.Xword, elf.unit.Word, elf.unit.Word,
                elf.unit.Xword, elf.unit.Xword]

    @classmethod
    def from_bytes(cls, elf: Elf, b: bytes):
        from ..editors.strtab_editor import StrTabEditor
        r = cls.deserialize(elf, b)
        assert isinstance(r, tuple) and len(r) == 10
        sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize \
            = r

        # shstrtab: StrTabEditor = elf.get_editor(EDITOR.STRTAB, SECTION.SHSTRTAB, _unsafe=True)
        shstrtab = StrTabEditor(elf, SECTION.SHSTRTAB, _unsafe=True)

        sh = SectionHeader()
        sh.name = shstrtab.get_str(sh_name)
        sh.type = sh_type
        sh.flags = sh_flags
        sh.addr = sh_addr
        sh.offset = sh_offset
        sh.siz = sh_size
        sh.link = sh_link
        sh.info = sh_info
        sh.addralign = sh_addralign
        sh.entsize = sh_entsize

        return sh

    def to_bytes(self, elf: Elf):
        from ..editors.strtab_editor import StrTabEditor
        # shstrtab: StrTabEditor = elf.get_editor(EDITOR.STRTAB, SECTION.SHSTRTAB)
        shstrtab = StrTabEditor(elf, SECTION.SHSTRTAB)
        return self.serialize(elf, shstrtab.find(self.name), self.type, self.flags, self.addr,
                              self.offset, self.siz, self.link, self.info,
                              self.addralign, self.entsize)

    def __str__(self):
        string = 'Section Header {'
        string += 'name: ' + str(self.name) + ', '
        string += 'type: ' + hex(self.type) + ', '
        string += 'flags: ' + hex(self.flags) + ', '
        string += 'addr: ' + hex(self.addr) + ', '
        string += 'offset: ' + hex(self.offset) + ', '
        string += 'size: ' + hex(self.siz) + ', '
        string += 'link: ' + hex(self.link) + ', '
        string += 'info: ' + hex(self.info) + ', '
        string += 'addralign: ' + hex(self.addralign) + ', '
        string += 'entsize: ' + hex(self.entsize) + '}'
        return string


class SectionHeaderTable(list[SectionHeader]):
    def __str__(self):
        string = '=== Section Header Table ===\n'
        for sh in self:
            string += str(sh) + '\n'
        return string
