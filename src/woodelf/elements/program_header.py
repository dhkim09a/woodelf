from typing import List, Union

from .. import api, Elf, ELF32, ELF64, SEGMENT_TYPE
from ..core import Element


class ProgramHeader(api.ProgramHeader, Element):
    @classmethod
    def units(cls, elf: Elf) -> List[Union[ELF32, ELF64]]:
        if elf.unit == ELF32:
            return [elf.unit.Word, elf.unit.Off, elf.unit.Addr, elf.unit.Addr,
                    elf.unit.Word, elf.unit.Word, elf.unit.Word, elf.unit.Word]
        elif elf.unit == ELF64:
            return [elf.unit.Word, elf.unit.Word, elf.unit.Off, elf.unit.Addr,
                    elf.unit.Addr, elf.unit.Xword, elf.unit.Xword, elf.unit.Xword]
        else:
            raise AssertionError

    @classmethod
    def from_bytes(cls, elf: Elf, b: bytes):
        if elf.unit == ELF32:
            p_type, p_offset, p_vaddr, p_paddr, \
            p_filesz, p_memsz, p_flags, p_align \
                = cls.deserialize(elf, b)
        elif elf.unit == ELF64:
            p_type, p_flags, p_offset, p_vaddr, \
            p_paddr, p_filesz, p_memsz, p_align \
                = cls.deserialize(elf, b)
        else:
            raise AssertionError

        ph = ProgramHeader()
        try:
            ph.type = SEGMENT_TYPE(p_type)
        except ValueError:
            ph.type = p_type
        ph.offset = p_offset
        ph.vaddr = p_vaddr
        ph.paddr = p_paddr
        ph.filesz = p_filesz
        ph.memsz = p_memsz
        ph.flags = p_flags
        ph.align = p_align

        return ph

    def to_bytes(self, elf: Elf) -> bytes:
        if elf.unit == ELF32:
            return self.serialize(elf, int(self.type), self.offset, self.vaddr, self.paddr,
                                  self.filesz, self.memsz, self.flags, self.align)
        elif elf.unit == ELF64:
            return self.serialize(elf, int(self.type), self.flags, self.offset, self.vaddr,
                                  self.paddr, self.filesz, self.memsz, self.align)
        else:
            raise AssertionError

    def __str__(self):
        string = 'Program header (segment): '
        string += 'type: ' + str(self.type) + ', '
        string += 'offset: ' + hex(self.offset) + ', '
        string += 'vaddr: ' + hex(self.vaddr) + ', '
        string += 'paddr: ' + hex(self.paddr) + ', '
        string += 'filesz: ' + hex(self.filesz) + ', '
        string += 'memsz: ' + hex(self.memsz) + ', '
        string += 'flags: ' + hex(self.flags) + ', '
        string += 'align: ' + hex(self.align) + '.'

        return string


class ProgramHeaderTable(api.ProgramHeaderTable):
    def __str__(self):
        string = 'Program Header (Segment) Table: \n'
        for ph in self:
            string += str(ph) + '\n'
        return string
