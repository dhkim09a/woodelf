import tempfile
from typing import List, Union, Dict, Tuple, Literal

from .constants import EDITOR, SECTION, DYNAMIC_ENTRY_TAG, ELF32, ELF64, SEGMENT_TYPE, SYMBOL_BIND, SYMBOL_TYPE, \
    SYMBOL_VISIBILITY, ELF_TYPE, ELF_MACHINE, ELF_VERSION


class ElfHeader:
    typ: Union[ELF_TYPE, int]
    machine: Union[ELF_MACHINE, int]
    version: Union[ELF_VERSION, int]
    entry: int
    phoff: int
    shoff: int
    flags: int
    ehsize: int
    phentsize: int
    phnum: int
    shentsize: hex
    shnum: int
    shstrndx: int


class Section:
    name: str

    def read_content(self, rev_idx: int = -1) -> bytes:
        raise NotImplementedError

    def write_content(self, content: bytes):
        raise NotImplementedError

    def find(self, target: Union[bytes, str]) -> int:
        raise NotImplementedError


class Editor:
    pass
    # def get_section(self, section: SECTION):
    #     raise NotImplementedError


class Elf:
    revisions: List[str]

    workdir: tempfile.TemporaryDirectory

    objcopy: callable
    objdump: callable
    readelf: callable

    unit: Union[type(ELF32), type(ELF64)]
    endian: Literal['little', 'big']

    cache: Dict[str, object]

    def get_editor(self, typ: EDITOR, *args, **kwargs) -> any:
        raise NotImplementedError

    def get_section(self, section: SECTION) -> Section:
        raise NotImplementedError

    def get_current_revision(self):
        raise NotImplementedError

    def iter_objdump_sections(self):
        class S:
            idx: int
            name: str
            size: int
            vma: int
            lma: int
            file_off: int
            align: int
        raise NotImplementedError

    def auto_adjust(self):
        raise NotImplementedError

    def write(self, path: str, auto_adjust: bool = True, mkdirs=True):
        raise NotImplementedError

    def close(self):
        raise NotImplementedError

    class Cache:
        key: str
        kv: dict

        def __init__(self, elf, key: str):
            self.key = key
            self.kv = elf.cache

        def lookup(self):
            try:
                return self.kv[self.key]
            except KeyError:
                return None

        def update(self, b: object):
            self.kv[self.key] = b

        def invalidate(self):
            if (key := self.key) in self.kv.keys():
                self.kv.pop(key)

    def get_cache(self, rev: str, key: str):
        return self.Cache(self, 'rev: ' + rev + ', extra: ' + key)


class ElfHeaderEditor:
    def read_elf_header(self, rev_idx: int = -1) -> ElfHeader:
        raise NotImplementedError

    def write_elf_header(self, elf_header: ElfHeader):
        raise NotImplementedError


class ProgramHeader:
    type: Union[SEGMENT_TYPE, int]
    offset: int
    vaddr: int
    paddr: int
    filesz: int
    memsz: int
    flags: int
    align: int


class ProgramHeaderTable(List[ProgramHeader]):
    pass


class ProgramHeaderEditor:
    def read_program_header_table(self, rev_idx: int = -1) -> ProgramHeaderTable:
        raise NotImplementedError

    def write_program_header_table(self, sht: ProgramHeaderTable):
        raise NotImplementedError


class SectionHeader:
    name: str
    type: int
    flags: int
    addr: int
    offset: int
    siz: int
    link: int
    info: int
    addralign: int
    entsize: int


class SectionHeaderTable(List[SectionHeader]):
    pass


class SectionHeaderEditor:
    def read_section_header_table(self, rev_idx: int = -1) -> SectionHeaderTable:
        raise NotImplementedError

    def read_section_header(self, section: SECTION, rev_idx: int = -1) -> SectionHeader:
        raise NotImplementedError

    def write_section_header_table(self, sht: SectionHeaderTable):
        raise NotImplementedError

    def write_section_header(self, section: SECTION, sh: SectionHeader):
        raise NotImplementedError


class Version:
    soname: str
    name: str

    def is_local(self):
        raise NotImplementedError

class Verdef:
    def update(self, new_version: str, ndx: int):
        raise NotImplementedError

    def get_ndx(self):
        raise NotImplementedError


class Verdaux:
    pass


class Verneed:
    pass


class Vernaux:
    other: int
    name: str


class VersionTable(List[Version]):
    pass


class VerdefTable:
    def __init__(self):
        raise NotImplementedError

    def __iter__(self):
        raise NotImplementedError

    def add_entry(self, vda_name: str) -> Verdef:
        raise NotImplementedError


class VerneedTable:
    def __init__(self):
        raise NotImplementedError

    def __iter__(self):
        raise NotImplementedError

    def add_entry(self, vn_file: str, vna_name: str):
        raise NotImplementedError


class SymbolVersionEditor(Editor):
    def read_versions(self, rev_idx: int = -1) -> VersionTable:
        raise NotImplementedError

    def read_version_definition(self, rev_idx: int = -1) -> VerdefTable:
        raise NotImplementedError

    def read_version_requirement(self, rev_idx: int = -1) -> VerneedTable:
        raise NotImplementedError

    def write(self, version_table: VersionTable = None, verdef_table: VerdefTable = None,
              verneed_table: VerneedTable = None):
        raise NotImplementedError

    def get_vername_soname_by_version(self, idx: int) -> Tuple[str, str]:
        raise NotImplementedError


class DynamicEntry:
    tag: Union[DYNAMIC_ENTRY_TAG, int]
    un: Union[int, str, None]


class DynamicEntryEditor(Editor):
    def read_dynamic_entries(self, rev_idx: int = -1) -> List[DynamicEntry]:
        raise NotImplementedError

    def write_dynamic_entries(self, dynlist):
        raise NotImplementedError

    def read_soname(self, rev_idx: int = -1):
        raise NotImplementedError


class StrTabEditor(Editor):
    def append(self, string: str):
        raise NotImplementedError

    def find(self, string: str) -> int:
        raise NotImplementedError

    def has(self, string: str) -> bool:
        raise NotImplementedError

    def get_str(self, pos: int) -> str:
        raise NotImplementedError


class Symbol:
    name: str
    value: int
    siz: int
    bind: SYMBOL_BIND
    typ: SYMBOL_TYPE
    other: SYMBOL_VISIBILITY
    shndx: int

    tag: SECTION

    def is_defined(self):
        raise NotImplementedError

    def is_needed(self):
        raise NotImplementedError


class SymbolTable(List[Symbol]):
    def defined_symbols(self):
        raise NotImplementedError

    def needed_symbols(self):
        raise NotImplementedError


class SymbolEditor:
    def read_symbol_table(self, rev_idx: int = -1) -> SymbolTable:
        raise NotImplementedError

    def write_symbol_table(self, st: SymbolTable):
        raise NotImplementedError


class GnuHash:
    nbuckets: int
    symndx: int
    maskwords: int
    shift2: int
    bloom_filter: List[int]
    buckets: List[int]
    values: List[int]


class NotAnElfError(Exception):
    pass


class NotFoundException(Exception):
    pass


class SectionNotFoundException(NotFoundException):
    pass


def parse(path: str, toolchain_path: str = None, prefix: str = '') -> Elf:
    from .core import Elf
    return Elf(path,
               toolchain_path=toolchain_path,
               prefix=prefix)
