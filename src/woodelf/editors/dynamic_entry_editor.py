from typing import List

from .. import api
from ..core import Editor, Elf
from ..constants import SECTION, DYNAMIC_ENTRY_TAG
from ..elements import DynamicEntry


class DynamicEntryEditor(Editor, api.DynamicEntryEditor):
    elf: Elf

    def __init__(self, elf: Elf):
        super().__init__(elf)
        self.elf = elf

    def read_dynamic_entries(self, rev_idx: int = -1) -> List[DynamicEntry]:
        dynamic = self.elf.get_section(SECTION.DYNAMIC)
        rev = self.elf.revisions[rev_idx]
        cache = self.elf.get_cache(rev, 'dyn_ents')

        if dynlist := cache.lookup():
            return dynlist

        c = dynamic.read_content(rev_idx=rev_idx)

        dynlist = []
        while c:
            dyn_bytes = c[0:DynamicEntry.size(self.elf)]
            c = c[DynamicEntry.size(self.elf):]
            dyn = DynamicEntry.from_bytes(self.elf, dyn_bytes)
            dynlist.append(dyn)

        cache.update(dynlist)

        return dynlist

    def write_dynamic_entries(self, dynlist: List[DynamicEntry]):
        rev = self.elf.get_current_revision()
        cache = self.elf.get_cache(rev, 'dyn_ents')

        b = bytes()
        for dyn in dynlist:
            b += dyn.to_bytes(self.elf)
        self.elf.get_section(SECTION.DYNAMIC).write_content(b)

        cache.invalidate()

    def read_soname(self, rev_idx: int = -1):
        dyn_ents = self.read_dynamic_entries(rev_idx=rev_idx)
        soname_ents = [e for e in filter(lambda e: e.tag == DYNAMIC_ENTRY_TAG.DT_SONAME, dyn_ents)]

        assert len(soname_ents) == 1

        soname = soname_ents[0].un

        assert isinstance(soname, str)

        return soname

    def __str__(self):
        dynlist = self.read_dynamic_entries()
        string = '=======\nSection .dynamic\n-------\n'
        for dyn in dynlist:
            string += str(dyn) + '\n'
        return string
