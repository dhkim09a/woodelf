from typing import Union


from ..core.elf import Elf

from ..constants import DYNAMIC_ENTRY_TAG, STR_DT, PTR_DT, ELF32, ELF64, SECTION

from ..core.element import Element


class DynamicEntry(Element):
    tag: DYNAMIC_ENTRY_TAG
    un: Union[int, str, None]

    def __init__(self, tag: DYNAMIC_ENTRY_TAG, un: Union[str, int]):
        self.tag = tag
        self.un = un

    @classmethod
    def size(cls, elf: Elf) -> int:
        if elf.unit == ELF32:
            return int(elf.unit.Sword) + int(elf.unit.Word)
        elif elf.unit == ELF64:
            return int(elf.unit.Xword) * 2
        else:
            raise ValueError

    @classmethod
    def from_bytes(cls, elf: Elf, b: bytes):
        from ..editors.strtab_editor import StrTabEditor
        assert len(b) == DynamicEntry.size(elf)

        pos = 0

        if elf.unit == ELF32:
            d_tag = int.from_bytes(b[pos:(pos := pos + int(elf.unit.Sword))], byteorder=elf.endian, signed=True)
            d_un = int.from_bytes(b[pos:(pos := pos + int(elf.unit.Word))], byteorder=elf.endian, signed=False)
        elif elf.unit == ELF64:
            d_tag = int.from_bytes(b[pos:(pos := pos + int(elf.unit.Xword))], byteorder=elf.endian, signed=True)
            d_un = int.from_bytes(b[pos:(pos := pos + int(elf.unit.Xword))], byteorder=elf.endian, signed=False)
        else:
            raise ValueError

        tag = DYNAMIC_ENTRY_TAG(d_tag)

        # dynstr_editor: StrTabEditor = elf.get_editor(EDITOR.STRTAB, SECTION.DYNSTR)
        dynstr_editor = StrTabEditor(elf, SECTION.DYNSTR)

        if tag in STR_DT:
            un = dynstr_editor.get_str(d_un)
        else:
            un = d_un

        return DynamicEntry(tag, un)

    def __to_bytes(self, elf: Elf, tag_size: int, un_size: int) -> bytes:
        from ..editors.strtab_editor import StrTabEditor
        b = int(self.tag).to_bytes(tag_size, byteorder=elf.endian, signed=True)

        if isinstance(self.un, str):
            # dynstr_editor: StrTabEditor = elf.get_editor(EDITOR.STRTAB, SECTION.DYNSTR)
            dynstr_editor = StrTabEditor(elf, SECTION.DYNSTR)
            if (self.tag in STR_DT) and (off := dynstr_editor.find(self.un)) >= 0:
                b += off.to_bytes(un_size, byteorder=elf.endian, signed=True)
            else:
                raise ValueError
        elif isinstance(self.un, int):
            b += int(self.un).to_bytes(un_size, byteorder=elf.endian, signed=True)
        else:
            raise ValueError

        assert len(b) == DynamicEntry.size(elf)

        return b

    def to_bytes(self, elf: Elf):
        if elf.unit == ELF32:
            return self.__to_bytes(elf, int(elf.unit.Sword), int(elf.unit.Word))
        elif elf.unit == ELF64:
            return self.__to_bytes(elf, int(elf.unit.Xword), int(elf.unit.Xword))
        else:
            raise ValueError

    def __str__(self):
        string = str(self.tag.name)

        if self.tag in PTR_DT:
            assert isinstance(self.un, int)
            string += ', ptr: ' + hex(self.un)
        elif self.tag in STR_DT:
            string += ', val: ' + str(self.un)
        else:
            assert isinstance(self.un, int)
            string += ', val: ' + hex(self.un)
        return string
