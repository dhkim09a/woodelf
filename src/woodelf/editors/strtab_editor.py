from .. import api, Section
from ..core import Editor, Elf
from ..constants import SECTION


class StrTabEditor(Editor, api.StrTabEditor):
    elf: Elf
    section_type: SECTION
    section: Section

    def __init__(self, elf: Elf, section: SECTION, base_editor: api.Editor = None, _unsafe=False):
        super().__init__(elf)

        self.elf = elf
        self.section_type = section
        self.section = elf.get_section(section, _unsafe=_unsafe)

    def append(self, string: str):
        bstring = string.encode('ascii') + b'\0'
        content = self.section.read_content() + bstring
        self.section.write_content(content)

    def find(self, string: str) -> int:
        bstring = string.encode('ascii') + b'\0'
        return self.section.find(bstring)

    def has(self, string: str) -> bool:
        return self.find(string) >= 0

    def get_str(self, pos: int) -> str:
        c = self.section.read_content()
        end = c.find(b'\0', pos)

        return c[pos:end].decode(encoding='ascii')

    def __str__(self):
        string = '=======\nSection ' + self.section.name + '\n-------\n'
        string += self.section.read_content()
        return string
