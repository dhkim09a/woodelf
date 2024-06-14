import shutil
import tempfile
from typing import List, Union

import sh

from .. import api, Elf, SectionHeaderEditor
from ..constants import SECTION, EDITOR
from ..util import readelf_hexdump_to_bytes


class Section(api.Section):
    elf: Elf
    readsection: callable

    def __init__(self, elf: Elf, section: SECTION):
        self.elf = elf
        self.name = section.value
        self.tag = section
        self.readsection = elf.readelf.bake(x=self.name)

    def read_content(self, rev_idx: int = -1) -> bytes:
        rev = self.elf.revisions[rev_idx]
        cache = self.elf.get_cache(rev, 'sec: ' + str(self.tag))

        if content := cache.lookup():
            return content

        if self.name == str(SECTION.SHSTRTAB):
            # Unfortunately, objdump cannot dump .shstrtab
            content = readelf_hexdump_to_bytes(self.readsection(rev))
            cache.update(content)
            return content

        tmpf = tempfile.mktemp(suffix=self.name, dir=self.elf.workdir.name)

        try:
            self.elf.objcopy('--dump-section', self.name + '=' + tmpf, rev)

            with open(tmpf, 'rb') as f:
                content = f.read()
        except (FileNotFoundError, sh.ErrorReturnCode):
            return readelf_hexdump_to_bytes(self.readsection(rev))

        cache.update(content)

        return content

    def write_content(self, content: bytes):
        current_rev = self.elf.get_current_revision()
        next_rev = tempfile.mktemp(dir=self.elf.workdir.name)

        if len(content) == len(self.read_content()):
            she: SectionHeaderEditor = self.elf.get_editor(EDITOR.SECTION_HEADER)
            shutil.copy2(current_rev, next_rev)
            with open(next_rev, 'r+b') as f:
                f.seek(she.read_section_header(self.tag).offset)
                f.write(content)
        else:
            tmpf = tempfile.mktemp(suffix=self.name, dir=self.elf.workdir.name)

            with open(tmpf, 'wb') as f:
                f.write(content)

            self.elf.objcopy('--update-section', self.name + '=' + tmpf,
                             current_rev, next_rev)

        self.elf.revisions.append(next_rev)

    def find(self, target: Union[bytes, str]) -> int:
        if isinstance(target, str):
            target = target.encode('ascii')

        return self.read_content().find(target)

    def __str__(self):
        return self.name
