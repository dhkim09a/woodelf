
# from .. import api
from .section_editor import SectionEditor
from ..core import Editor, Elf
from ..constants import SECTION, DYNAMIC_ENTRY_TAG
from ..elements.dynamic_entry import DynamicEntry


class DynamicEntryEditor(Editor):
    elf: Elf

    def __init__(self, elf: Elf):
        super().__init__(elf)
        self.elf = elf

    def read_dynamic_entries(self, rev_idx: int = -1) -> list[DynamicEntry]:
        # dynamic = self.elf.get_section(SECTION.DYNAMIC)
        dynamic = SectionEditor(self.elf, SECTION.DYNAMIC)
        rev = self.elf.revisions[rev_idx]
        cache = self.elf.get_cache(rev, 'dyn_ents')

        if dynlist := cache.lookup():
            return dynlist
        
        if not dynamic:
            return []

        c = dynamic.read_content(rev_idx=rev_idx)

        dynlist = []
        while c:
            dyn_bytes = c[0:DynamicEntry.size(self.elf)]
            c = c[DynamicEntry.size(self.elf):]
            dyn = DynamicEntry.from_bytes(self.elf, dyn_bytes)
            dynlist.append(dyn)

        cache.update(dynlist)

        return dynlist

    def write_dynamic_entries(self, dynlist: list[DynamicEntry]) -> bool:
        rev = self.elf.get_current_revision()
        cache = self.elf.get_cache(rev, 'dyn_ents')

        b = bytes()
        for dyn in dynlist:
            b += dyn.to_bytes(self.elf)

        # if not (dynamic := self.elf.get_section(SECTION.DYNAMIC)):
        if not (dynamic := SectionEditor(self.elf, SECTION.DYNAMIC)):
            return False
        
        dynamic.write_content(b)

        cache.invalidate()

        return True

    def read_soname(self, rev_idx: int = -1) -> str | None:
        dyn_ents = self.read_dynamic_entries(rev_idx=rev_idx)
        soname_ents = [e for e in filter(lambda e: e.tag == DYNAMIC_ENTRY_TAG.DT_SONAME, dyn_ents)]

        if not soname_ents:
            return

        assert len(soname_ents) == 1, f'DT_SONAME is defined multiple times'

        soname = soname_ents[0].un

        assert isinstance(soname, str), f'DT_SONAME is not a str: {soname}'

        return soname

    def __str__(self) -> str:
        dynlist = self.read_dynamic_entries()
        string = '=======\nSection .dynamic\n-------\n'
        for dyn in dynlist:
            string += str(dyn) + '\n'
        return string
