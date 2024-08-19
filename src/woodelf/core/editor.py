# from typing import List

# from .. import api
# from ..constants import SECTION
from .elf import Elf


class Editor:
    elf: Elf

    def __init__(self, elf: Elf):
        self.elf = elf

    # def get_section(self, section: SECTION):
    #     return self.elf.get_section(self, section)
