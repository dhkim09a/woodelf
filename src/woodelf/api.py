from .core.elf import Elf

from .util import MalformedElfError

def parse(path: str, toolchain_path: str | None = None, prefix: str = '') -> Elf | None:
    from .core import Elf
    return Elf.from_path(path,
               toolchain_path=toolchain_path,
               prefix=prefix)
