# from woodelf.api import Elf
from .section_editor import SectionEditor
from ..core.elf import Elf
from ..constants import SECTION
from ..core import Editor
from ..elements import Symbol, SymbolTable


class SymbolEditor(Editor):
    __section: SECTION
    __str_section: SECTION

    def __init__(self, elf: Elf, section: SECTION):
        self.__section = section
        self.__str_section = (
            SECTION.STRTAB if section == SECTION.SYMTAB else
            SECTION.DYNSTR if section == SECTION.DYNSYM else
            SECTION.STRTAB
        )
        super().__init__(elf)

    def read_symbol_table(self, rev_idx: int = -1) -> SymbolTable | None:
        # sym_sec = self.elf.get_section(self.__section)
        sym_sec = SectionEditor(self.elf, self.__section)
        rev = self.elf.revisions[rev_idx]
        cache = self.elf.get_cache(rev, self.__section.name)

        if st := cache.lookup():
            return st

        if not sym_sec:
            return

        c = sym_sec.read_content(rev_idx=rev_idx)

        st = SymbolTable()

        symbol_size = Symbol.size(self.elf)

        while c:
            symbol = Symbol.from_bytes(self.elf, c[:symbol_size], strsec=self.__str_section)
            st.append(symbol)
            c = c[symbol_size:]
            # exit()

        cache.update(st)

        return st

    def write_symbol_table(self, st: SymbolTable) -> bool:
        # dynsym = self.elf.get_section(self.__section)
        dynsym = SectionEditor(self.elf, self.__section)
        rev = self.elf.get_current_revision()
        cache = self.elf.get_cache(rev, self.__section.name)

        if not dynsym:
            return False

        b = bytes()

        for s in st:
            s: Symbol
            b += s.to_bytes(self.elf, strsec=self.__str_section)

        dynsym.write_content(b)

        cache.invalidate()

        return True


# class SymtabEditor(SymbolEditor):
#     def __init__(self, elf: Elf):
#         super().__init__(elf, SECTION.SYMTAB)


# class DynsymEditor(SymbolEditor):
#     def __init__(self, elf: Elf):
#         super().__init__(elf, SECTION.DYNSYM)
