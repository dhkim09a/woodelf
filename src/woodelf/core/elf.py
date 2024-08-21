from __future__ import annotations

import os
import re
import tempfile
from typing import Callable, Literal

import capstone
import sh
import shutil

# from ..elements.section_header import SectionHeader, SectionHeaderTable
# from ..elements.symbol import Symbol
# from ..editors.symbol_editor import SymbolEditor
# from ..elements.program_header import ProgramHeader
# from ..editors.elf_header_editor import ElfHeaderEditor
# from ..editors.program_header_editor import ProgramHeaderEditor
# from ..editors.dynamic_entry_editor import DynamicEntryEditor
# from ..editors.section_header_editor import SectionHeaderEditor

# from .editor import Editor

# from .. import Editor, DynamicEntryEditor, ElfHeader, SectionHeader, SectionHeaderTable, ProgramHeaderTable, \
#     ProgramHeader, SectionHeaderEditor, ProgramHeaderEditor, SymbolTable, ElfHeaderEditor, SymbolEditor, Symbol, \
#     SymbolVersionEditor, NotAnElfError
# from .section import Section
# from .segment import Segment
from ..constants import SECTION, DYNAMIC_ENTRY_TAG, ELF32, ELF64, ELF_CLASS, SEGMENT_TYPE
from ..util import unpack_bytes_to_ints


class Elf:
    revisions: list[str]

    workdir: tempfile.TemporaryDirectory

    objcopy: Callable
    objdump: Callable
    readelf: Callable

    unit: type[ELF32] | type[ELF64]
    endian: Literal['little', 'big']

    cache: dict[str, object]

    # def get_editor(self, typ: EDITOR, *args, **kwargs) -> Editor:
    #     from ..editors import SymbolVersionEditor, DynamicEntryEditor, StrTabEditor, ElfHeaderEditor, \
    #         SectionHeaderEditor, ProgramHeaderEditor, SymbolEditor

    #     if typ is EDITOR.SYMBOL_VERSION:
    #         editor = SymbolVersionEditor(self)
    #     elif typ is EDITOR.DYNAMIC_ENTRY:
    #         editor = DynamicEntryEditor(self)
    #     elif typ is EDITOR.STRTAB:
    #         editor = StrTabEditor(self, *args, **kwargs)
    #     elif typ is EDITOR.ELF_HEADER:
    #         editor = ElfHeaderEditor(self)
    #     elif typ is EDITOR.SECTION_HEADER:
    #         editor = SectionHeaderEditor(self)
    #     elif typ is EDITOR.PROGRAM_HEADER:
    #         editor = ProgramHeaderEditor(self)
    #     elif typ is EDITOR.SYMBOL:
    #         editor = SymbolEditor(self, *args, **kwargs)
    #     else:
    #         raise TypeError

    #     return editor

    def get_tmpdir(self) -> str | None:
        if os.path.isdir('/dev/shm'):
            return '/dev/shm'
        return None

    @classmethod
    def from_path(cls,
                 path: str,
                 toolchain_path: str | None = None,
                 prefix: str = '',
                 ) -> Elf | None:
        elf = Elf()
        elf.revisions = [path]
        # elf.lock = {}
        elf.workdir = tempfile.TemporaryDirectory(dir=elf.get_tmpdir(), prefix='woodelf-')

        if toolchain_path:
            elf.objcopy = sh.Command(prefix + 'objcopy', search_paths=[toolchain_path]).bake('--pure')
            elf.objdump = sh.Command(prefix + 'objdump', search_paths=[toolchain_path])
            elf.readelf = sh.Command(prefix + 'readelf', search_paths=[toolchain_path])
        else:
            elf.objcopy = sh.Command(prefix + 'objcopy').bake('--pure')
            elf.objdump = sh.Command(prefix + 'objdump')
            elf.readelf = sh.Command(prefix + 'readelf')

        elf.cache = {}

        from ..editors.elf_header_editor import ElfHeaderEditor
        # e_ident = self.get_editor(EDITOR.ELF_HEADER).read_e_ident()
        
        if not (e_ident := ElfHeaderEditor(elf).read_e_ident()):
            return

        if e_ident.cls == ELF_CLASS.CLASS32:
            elf.unit = ELF32
        elif e_ident.cls == ELF_CLASS.CLASS64:
            elf.unit = ELF64
        else:
            raise ValueError('Invalid ELF class type')

        elf.endian = e_ident.data.endian()

        return elf

    def get_current_revision(self):
        return self.revisions[-1]

    # def get_section(self, section: SECTION, _unsafe=False) -> 'Section' | None:
    #     from woodelf.editors.section_editor import SectionEditor
    #     from ..editors.section_header_editor import SectionHeaderEditor

    #     if (not _unsafe
    #         and (she := SectionHeaderEditor(self))
    #         and not she.read_section_header(section)):
    #         # raise SectionNotFoundException('Section ' + str(section) + ' does not exist')
    #         return

    #     return SectionEditor(self, section)

    # def get_segment(self, idx: int) -> 'Segment':
    #     from .segment import Segment
    #     return Segment(self, )

    # def num_segment(self) -> int:
    #     raise NotImplementedError

    def iter_objdump_sections(self):
        class S:
            idx: int
            name: str
            size: int
            vma: int
            lma: int
            file_off: int
            align: int

        lines: str = self.objdump('-h', self.get_current_revision())

        for line in lines.splitlines():
            try:
                idx, name, size, vma, lma, file_off, align = line.split(maxsplit=7)
            except ValueError:
                continue

            s = S()
            try:
                s.idx = int(idx)
                s.name = name
                s.size = int(size, 16)
                s.vma = int(vma, 16)
                s.lma = int(lma, 16)
                s.file_off = int(file_off, 16)
                s.align = int(eval(align))
            except ValueError or SyntaxError:
                continue

            yield s

    def write(self, path: str, auto_adjust: bool = True, mkdirs=True):
        # if auto_adjust:
        #     self.auto_adjust()
        if mkdirs:
            os.makedirs(os.path.dirname(path), exist_ok=True)
        shutil.copy2(self.get_current_revision(), path)

    def close(self):
        self.workdir.cleanup()

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