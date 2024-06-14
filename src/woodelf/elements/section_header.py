from .. import api, Elf, List, Union, ELF32, ELF64, EDITOR, SECTION, StrTabEditor
from ..core import Element


class SectionHeader(Element, api.SectionHeader):
    @classmethod
    def units(cls, elf: Elf) -> List[Union[ELF32, ELF64]]:
        return [elf.unit.Word, elf.unit.Word, elf.unit.Xword, elf.unit.Addr,
                elf.unit.Off, elf.unit.Xword, elf.unit.Word, elf.unit.Word,
                elf.unit.Xword, elf.unit.Xword]

    @classmethod
    def from_bytes(cls, elf: Elf, b: bytes):
        sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize \
            = cls.deserialize(elf, b)

        shstrtab: StrTabEditor = elf.get_editor(EDITOR.STRTAB, SECTION.SHSTRTAB, _unsafe=True)

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
        shstrtab: StrTabEditor = elf.get_editor(EDITOR.STRTAB, SECTION.SHSTRTAB)
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


class SectionHeaderTable(api.SectionHeaderTable):
    def __str__(self):
        string = '=== Section Header Table ===\n'
        for sh in self:
            string += str(sh) + '\n'
        return string
