from ..core.elf import Elf
from ..constants import ELF32, ELF64
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
    def from_bytes(cls, elf: Elf, b: bytes, shstrtab: bytes = b''):
        r = cls.deserialize(elf, b)
        assert isinstance(r, tuple) and len(r) == 10
        sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize \
            = r

        sh = SectionHeader()
        sh.name = _str_at(shstrtab, sh_name)
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

    def to_bytes(self, elf: Elf, shstrtab: bytes = b''):
        name_off = _find_str(shstrtab, self.name)
        if name_off < 0:
            raise ValueError(f'section name {self.name!r} not in shstrtab')
        return self.serialize(elf, name_off, self.type, self.flags, self.addr,
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


def _str_at(buf: bytes, offset: int) -> str:
    if offset < 0 or offset >= len(buf):
        return ''
    end = buf.find(b'\x00', offset)
    if end < 0:
        end = len(buf)
    return buf[offset:end].decode('ascii', errors='replace')


def _find_str(buf: bytes, s: str) -> int:
    needle = s.encode('ascii')
    # Match either the empty string at offset 0 or a null-terminated occurrence.
    if not needle:
        return 0 if buf[:1] == b'\x00' else -1
    pos = buf.find(b'\x00' + needle + b'\x00')
    if pos < 0:
        return -1
    return pos + 1
