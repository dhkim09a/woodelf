from typing import List, Union

# from ..editors.strtab_editor import StrTabEditor

from ..core.elf import Elf

from ..constants import ELF32, ELF64, SECTION, SYMBOL_BIND, SYMBOL_TYPE, \
    SYMBOL_VISIBILITY
from ..core import Element


class Symbol(Element):
    name: str
    value: int
    siz: int
    bind: SYMBOL_BIND
    typ: SYMBOL_TYPE
    other: SYMBOL_VISIBILITY
    shndx: int

    tag: SECTION

    @classmethod
    def units(cls, elf: Elf) -> List[Union[ELF32, ELF64]]:
        if elf.unit == ELF32:
            return [elf.unit.Word, elf.unit.Addr, elf.unit.Word, elf.unit.uchar,
                    elf.unit.uchar, elf.unit.Half]
        elif elf.unit == ELF64:
            return [elf.unit.Word, elf.unit.uchar, elf.unit.uchar, elf.unit.Half,
                    elf.unit.Addr, elf.unit.Xword]
        else:
            raise AssertionError(f'error: invalid elf unit: {elf.unit}')

    @classmethod
    def from_bytes(cls, elf: Elf, b: bytes, strsec: SECTION = SECTION.STRTAB):
        from ..editors.strtab_editor import StrTabEditor
        r = cls.deserialize(elf, b)
        assert isinstance(r, tuple) and len(r) == 6
        if elf.unit == ELF32:
            st_name, st_value, st_size, st_info, \
            st_other, st_shndx = r
        elif elf.unit == ELF64:
            st_name, st_info, st_other, st_shndx, \
            st_value, st_size = r
        else:
            raise AssertionError(f'error: invalid elf unit: {elf.unit}')

        # strtab_editor: StrTabEditor = elf.get_editor(EDITOR.STRTAB, strsec)
        strtab_editor = StrTabEditor(elf, strsec)
        # dynent_editor: DynamicEntryEditor = elf.get_editor(EDITOR.DYNAMIC_ENTRY)
        # dyntab = dynent_editor.read_dynamic_entries()

        s = Symbol()
        s.name = strtab_editor.get_str(st_name)
        s.value = st_value
        s.siz = st_size
        s.bind = SYMBOL_BIND(cls.__st_bind(st_info))
        s.typ = SYMBOL_TYPE(cls.__st_type(st_info))
        s.other = SYMBOL_VISIBILITY(st_other)
        s.shndx = st_shndx

        return s

    def to_bytes(self, elf: Elf, strsec: SECTION = SECTION.STRTAB) -> bytes:
        from ..editors.strtab_editor import StrTabEditor
        # strtab_editor: StrTabEditor = elf.get_editor(EDITOR.STRTAB, strsec)
        strtab_editor = StrTabEditor(elf, strsec)
        # dynent_editor: DynamicEntryEditor = elf.get_editor(EDITOR.DYNAMIC_ENTRY)
        # dyntab = dynent_editor.read_dynamic_entries()

        st_name = strtab_editor.find(self.name)
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
        raise AssertionError(f'error: invalid elf unit: {elf.unit}')

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


class SymbolTable(list[Symbol]):
    def defined_symbols(self):
        return filter(lambda e: e.is_defined(), self)

    def needed_symbols(self):
        return filter(lambda e: e.is_needed(), self)

    def __str__(self):
        string = 'SymbolTable:\n'
        for symbol in self:
            string += str(symbol) + '\n'

        return string
