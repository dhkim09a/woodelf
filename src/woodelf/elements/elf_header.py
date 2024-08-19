from __future__ import annotations

from typing import List, Union

# from ..editors.elf_header_editor import ElfHeaderEditor

from ..core.elf import Elf

from .e_ident import E_Ident
from ..constants import ELF_VERSION, ELF_MACHINE, ELF_TYPE, ELF32, ELF64
from ..core import Element


class ElfHeader(Element):
    ident: E_Ident
    typ: Union[ELF_TYPE, int]
    machine: Union[ELF_MACHINE, int]
    version: Union[ELF_VERSION, int]
    entry: int
    phoff: int
    shoff: int
    flags: int
    ehsize: int
    phentsize: int
    phnum: int
    shentsize: int
    shnum: int
    shstrndx: int


    def __init__(self, ident, typ, machine, version, entry, phoff, shoff, flags, ehsize,
                 phentsize, phnum, shentsize, shnum, shstrndx):
        self.ident = ident
        self.typ = typ
        self.machine = machine
        self.version = version
        self.entry = entry
        self.phoff = phoff
        self.shoff = shoff
        self.flags = flags
        self.ehsize = ehsize
        self.phentsize = phentsize
        self.phnum = phnum
        self.shentsize = shentsize
        self.shnum = shnum
        self.shstrndx = shstrndx

    @classmethod
    def size(cls, elf: Elf) -> int:
        return super(ElfHeader, cls).size(elf) + E_Ident.size()

    @classmethod
    def units(cls, elf: Elf) -> List[Union[ELF32, ELF64]]:
        return [elf.unit.Half, elf.unit.Half, elf.unit.Word, elf.unit.Addr,
                elf.unit.Off, elf.unit.Off, elf.unit.Word, elf.unit.Half,
                elf.unit.Half, elf.unit.Half, elf.unit.Half, elf.unit.Half,
                elf.unit.Half]

    @classmethod
    def from_bytes(cls, elf: Elf, b: bytes) -> ElfHeader | None:
        from ..editors.elf_header_editor import ElfHeaderEditor

        assert len(b) == cls.size(elf)

        # ident = elf.get_editor(EDITOR.ELF_HEADER).read_e_ident()
        elfh_editor = ElfHeaderEditor(elf)
        ident = elfh_editor.read_e_ident()
        if not ident:
            return
        pos = ident.size()

        r = cls.deserialize(elf, b[pos:])
        assert isinstance(r, tuple) and len(r) == 13

        e_type, e_machine, e_version, e_entry,\
        e_phoff, e_shoff, e_flags, e_ehsize,\
        e_phentsize, e_phnum, e_shentsize, e_shnum,\
        e_shstrndx = r

        typ = ELF_TYPE(e_type)
        machine = ELF_MACHINE(e_machine)
        version = ELF_VERSION(e_version)

        return ElfHeader(ident,
                         typ, machine, version, e_entry,
                         e_phoff, e_shoff, e_flags, e_ehsize,
                         e_phentsize, e_phnum, e_shentsize, e_shnum,
                         e_shstrndx)

    def to_bytes(self, elf: Elf):
        return self.ident.to_bytes() + self.serialize(elf,
            int(self.typ), int(self.machine), int(self.version), self.entry,
            self.phoff, self.shoff, self.flags, self.ehsize,
            self.phentsize, self.phnum, self.shentsize, self.shnum,
            self.shstrndx)

    def __str__(self):
        string = 'ELF HEADER{'
        string += str(self.ident) + ', '
        string += 'type: ' + str(self.typ) + ', '
        string += 'machine: ' + str(self.machine) + ', '
        string += 'version: ' + str(self.version) + ', '
        string += 'entry: ' + hex(self.entry) + ', '
        string += 'phoff: ' + hex(self.phoff) + ', '
        string += 'shoff: ' + hex(self.shoff) + ', '
        string += 'flags: ' + hex(self.flags) + ', '
        string += 'ehsize: ' + hex(self.ehsize) + ', '
        string += 'phentsize: ' + hex(self.phentsize) + ', '
        string += 'phnum: ' + hex(self.phnum) + ', '
        string += 'shentsize: ' + hex(self.shentsize) + ', '
        string += 'shnum: ' + hex(self.shnum) + ', '
        string += 'shstrndx: ' + hex(self.shstrndx) + '}'
        return string
