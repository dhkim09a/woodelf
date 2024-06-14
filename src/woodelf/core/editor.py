from typing import List

from .. import api, Elf
from ..constants import SECTION


class Editor(api.Editor):
    elf: Elf

    def __init__(self, elf: Elf):
        self.elf = elf

    # def get_section(self, section: SECTION):
    #     return self.elf.get_section(self, section)
