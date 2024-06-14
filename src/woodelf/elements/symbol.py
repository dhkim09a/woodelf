from typing import List, Union

from .. import Elf, ELF32, ELF64, EDITOR, SECTION, StrTabEditor, api, DynamicEntryEditor, SYMBOL_BIND, SYMBOL_TYPE, \
    SYMBOL_VISIBILITY
from ..core import Element


class Symbol(Element, api.Symbol):
    @classmethod
    def units(cls, elf: Elf) -> List[Union[ELF32, ELF64]]:
        if elf.unit == ELF32:
            return [elf.unit.Word, elf.unit.Addr, elf.unit.Word, elf.unit.uchar,
                    elf.unit.uchar, elf.unit.Half]
        elif elf.unit == ELF64:
            return [elf.unit.Word, elf.unit.uchar, elf.unit.uchar, elf.unit.Half,
                    elf.unit.Addr, elf.unit.Xword]
        else:
            raise AssertionError

    @classmethod
    def from_bytes(cls, elf: Elf, b: bytes):
        if elf.unit == ELF32:
            st_name, st_value, st_size, st_info, \
            st_other, st_shndx = cls.deserialize(elf, b)
        elif elf.unit == ELF64:
            st_name, st_info, st_other, st_shndx, \
            st_value, st_size = cls.deserialize(elf, b)
        else:
            raise AssertionError

        dynsym_editor: StrTabEditor = elf.get_editor(EDITOR.STRTAB, SECTION.DYNSTR)
        # dynent_editor: DynamicEntryEditor = elf.get_editor(EDITOR.DYNAMIC_ENTRY)
        # dyntab = dynent_editor.read_dynamic_entries()

        s = Symbol()
        s.name = dynsym_editor.get_str(st_name)
        s.value = st_value
        s.siz = st_size
        s.bind = SYMBOL_BIND(cls.__st_bind(st_info))
        s.typ = SYMBOL_TYPE(cls.__st_type(st_info))
        s.other = SYMBOL_VISIBILITY(st_other)
        s.shndx = st_shndx

        return s

    def to_bytes(self, elf: Elf) -> bytes:
        dynsym_editor: StrTabEditor = elf.get_editor(EDITOR.STRTAB, SECTION.DYNSTR)
        # dynent_editor: DynamicEntryEditor = elf.get_editor(EDITOR.DYNAMIC_ENTRY)
        # dyntab = dynent_editor.read_dynamic_entries()

        st_name = dynsym_editor.find(self.name)
        # st_info = -1
        # for i, de in enumerate(dyntab):
        #     if de.tag == self.info.tag and de.un == self.info.un:
        #         st_info = i
        #         break
        # if st_info < 0:
        #     raise AssertionError

        st_info = self.__st_info(int(self.bind), int(self.typ))

        if elf.unit == ELF32:
            return self.serialize(elf, st_name, self.value, self.siz, st_info,
                                  int(self.other), self.shndx)
        elif elf.unit == ELF64:
            return self.serialize(elf, st_name, st_info, int(self.other), self.shndx,
                                  self.value, self.siz)
        raise AssertionError

    def is_defined(self):
        return self.siz != 0 and self.shndx != 0

    def is_needed(self):
        return self.value == 0 and self.siz == 0 and self.shndx == 0

    @classmethod
    def __st_bind(cls, st_info: int) -> int:
        return st_info >> 4

    @classmethod
    def __st_type(cls, st_info: int) -> int:
        return st_info & 0xf

    @classmethod
    def __st_info(cls, st_bind: int, st_type: int) -> int:
        return (st_bind << 4) + (st_type & 0xf)

    def __str__(self):
        string = 'Symbol: '
        string += 'name: ' + str(self.name) + ', '
        string += 'value: ' + hex(self.value) + ', '
        string += 'size: ' + hex(self.siz) + ', '
        string += 'bind: ' + str(self.bind) + ', '
        string += 'type: ' + str(self.typ) + ', '
        string += 'other: ' + str(self.other) + ', '
        string += 'shndx: ' + hex(self.shndx) + '.'
        return string


class SymbolTable(api.SymbolTable):
    def defined_symbols(self):
        return filter(lambda e: e.is_defined(), self)

    def needed_symbols(self):
        return filter(lambda e: e.is_needed(), self)

    def __str__(self):
        string = 'SymbolTable:\n'
        for symbol in self:
            string += str(symbol) + '\n'

        return string
