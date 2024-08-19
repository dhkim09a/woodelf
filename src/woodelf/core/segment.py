
# from woodelf import Elf


from .elf import Elf


class Segment:
    elf: Elf

    def __init__(self, elf: Elf):
        self.elf = elf
