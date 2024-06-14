from .. import SECTION
from ..core import Editor
from ..elements import Symbol, SymbolTable


class SymbolEditor(Editor):
    def read_symbol_table(self, rev_idx: int = -1) -> SymbolTable:
        dynsym = self.elf.get_section(SECTION.DYNSYM)
        rev = self.elf.revisions[rev_idx]
        cache = self.elf.get_cache(rev, 'symbol')

        if st := cache.lookup():
            return st

        c = dynsym.read_content(rev_idx=rev_idx)

        st = SymbolTable()

        symbol_size = Symbol.size(self.elf)

        while c:
            symbol = Symbol.from_bytes(self.elf, c[:symbol_size])
            st.append(symbol)
            c = c[symbol_size:]

        cache.update(st)

        return st

    def write_symbol_table(self, st: SymbolTable):
        dynsym = self.elf.get_section(SECTION.DYNSYM)
        rev = self.elf.get_current_revision()
        cache = self.elf.get_cache(rev, 'symbol')

        b = bytes()

        for s in st:
            s: Symbol
            b += s.to_bytes(self.elf)

        dynsym.write_content(b)

        cache.invalidate()
