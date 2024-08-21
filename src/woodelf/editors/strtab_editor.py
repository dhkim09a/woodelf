from .section_editor import SectionEditor
from ..core import Editor, Elf
from ..constants import SECTION


class StrTabEditor(SectionEditor):
    elf: Elf
    # section_type: SECTION
    # section: SectionEditor

    def __init__(self, elf: Elf, section: SECTION):
        super().__init__(elf, section)

        self.elf = elf
        # self.section_type = section
        # self.section = elf.get_section(section, _unsafe=_unsafe)

    def append(self, string: str):
        bstring = string.encode('ascii') + b'\0'
        content = (self.read_content() or b'') + bstring
        self.write_content(content)

    def find(self, string: str) -> int:
        bstring = string.encode('ascii') + b'\0'
        return super().find(bstring)

    def has(self, string: str) -> bool:
        return self.find(string) >= 0

    def get_str(self, pos: int, _unsafe=False) -> str:
        if not (c := self.read_content(no_ext_checking=_unsafe)):
            return ''
        end = c.find(b'\0', pos)

        return c[pos:end].decode(encoding='ascii')

    def __str__(self):
        string = '=======\nSection ' + self.name + '\n-------\n'
        string += str(self.read_content())
        return string
