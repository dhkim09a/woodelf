import os
import re
import tempfile
from typing import List, Tuple

import capstone
import sh
import shutil

from hexdump import hexdump

from .. import api, Editor, DynamicEntryEditor, ElfHeader, SectionHeader, SectionHeaderTable, ProgramHeaderTable, \
    ProgramHeader, SectionHeaderEditor, ProgramHeaderEditor, SymbolTable, ElfHeaderEditor, SymbolEditor, Symbol, \
    SymbolVersionEditor, NotAnElfError
from .section import Section
from .segment import Segment
from ..constants import EDITOR, SECTION, DYNAMIC_ENTRY_TAG, ELF32, ELF64, ELF_CLASS, SEGMENT_TYPE
from ..util import unpack_bytes_to_ints


class Elf(api.Elf):

    def get_editor(self, typ: EDITOR, *args, **kwargs) -> any:
        from ..editors import SymbolVersionEditor, DynamicEntryEditor, StrTabEditor, ElfHeaderEditor, \
            SectionHeaderEditor, ProgramHeaderEditor, SymbolEditor

        if typ is EDITOR.SYMBOL_VERSION:
            editor = SymbolVersionEditor(self)
        elif typ is EDITOR.DYNAMIC_ENTRY:
            editor = DynamicEntryEditor(self)
        elif typ is EDITOR.STRTAB:
            editor = StrTabEditor(self, *args, **kwargs)
        elif typ is EDITOR.ELF_HEADER:
            editor = ElfHeaderEditor(self)
        elif typ is EDITOR.SECTION_HEADER:
            editor = SectionHeaderEditor(self)
        elif typ is EDITOR.PROGRAM_HEADER:
            editor = ProgramHeaderEditor(self)
        elif typ is EDITOR.SYMBOL:
            editor = SymbolEditor(self, *args, **kwargs)
        else:
            raise TypeError

        return editor

    def get_tmpdir(self):
        if os.path.isdir('/dev/shm'):
            return '/dev/shm'
        return None

    def __init__(self, path: str,
                 toolchain_path: str = None,
                 prefix: str = ''):
        self.revisions = [path]
        self.lock = {}
        self.workdir = tempfile.TemporaryDirectory(dir=self.get_tmpdir(), prefix='woodelf-')

        if toolchain_path:
            self.objcopy = sh.Command(prefix + 'objcopy', search_paths=[toolchain_path]).bake('--pure')
            self.objdump = sh.Command(prefix + 'objdump', search_paths=[toolchain_path])
            self.readelf = sh.Command(prefix + 'readelf', search_paths=[toolchain_path])
        else:
            self.objcopy = sh.Command(prefix + 'objcopy').bake('--pure')
            self.objdump = sh.Command(prefix + 'objdump')
            self.readelf = sh.Command(prefix + 'readelf')

        self.cache = {}

        e_ident = self.get_editor(EDITOR.ELF_HEADER).read_e_ident()

        if e_ident.cls == ELF_CLASS.CLASS32:
            self.unit = ELF32
        elif e_ident.cls == ELF_CLASS.CLASS64:
            self.unit = ELF64
        else:
            raise ValueError('Invalid ELF class type')

        self.endian = str(e_ident.data)

    def get_current_revision(self):
        return self.revisions[-1]

    def get_section(self, section: SECTION, _unsafe=False) -> Section:
        from woodelf.core.section import Section

        if not _unsafe:
            she: SectionHeaderEditor = self.get_editor(EDITOR.SECTION_HEADER)
            if not she.read_section_header(section):
                raise api.SectionNotFoundException('Section ' + str(section) + ' does not exist')

        return Section(self, section)

    def get_segment(self, idx: int) -> Segment:
        return Segment(self, )

    def num_segment(self) -> int:
        pass

    def __auto_adjust_dyn_ent_ptr(self):
        dyn_editor: DynamicEntryEditor = self.get_editor(EDITOR.DYNAMIC_ENTRY)
        dyn_entries = dyn_editor.read_dynamic_entries()

        def __update_dyn_ent(tag: DYNAMIC_ENTRY_TAG, un: int):
            for ent in filter(lambda e: e.tag == tag, dyn_entries):
                ent.un = un

        for s in self.iter_objdump_sections():
            try:
                tag: SECTION = SECTION(s.name)
            except ValueError:
                # skip unknown section
                continue

            if tag == SECTION.GOT_PLT:
                __update_dyn_ent(DYNAMIC_ENTRY_TAG.DT_PLTGOT, s.vma)
            elif tag == SECTION.RELA_PLT:
                __update_dyn_ent(DYNAMIC_ENTRY_TAG.DT_JMPREL, s.vma)
                __update_dyn_ent(DYNAMIC_ENTRY_TAG.DT_PLTRELSZ, s.size)
            elif tag == SECTION.RELA_DYN:
                __update_dyn_ent(DYNAMIC_ENTRY_TAG.DT_RELA, s.vma)
                __update_dyn_ent(DYNAMIC_ENTRY_TAG.DT_RELASZ, s.size)
                __update_dyn_ent(DYNAMIC_ENTRY_TAG.DT_ANDROID_RELA, s.vma)
                __update_dyn_ent(DYNAMIC_ENTRY_TAG.DT_ANDROID_RELASZ, s.size)
            elif tag == SECTION.DYNSYM:
                __update_dyn_ent(DYNAMIC_ENTRY_TAG.DT_SYMTAB, s.vma)
            elif tag == SECTION.DYNSTR:
                __update_dyn_ent(DYNAMIC_ENTRY_TAG.DT_STRTAB, s.vma)
                __update_dyn_ent(DYNAMIC_ENTRY_TAG.DT_STRSZ, s.size)
            elif tag == SECTION.GNU_HASH:
                __update_dyn_ent(DYNAMIC_ENTRY_TAG.DT_GNU_HASH, s.vma)
            elif tag == SECTION.INIT_ARRAY:
                __update_dyn_ent(DYNAMIC_ENTRY_TAG.DT_INIT_ARRAY, s.vma)
                __update_dyn_ent(DYNAMIC_ENTRY_TAG.DT_INIT_ARRAYSZ, s.size)
            elif tag == SECTION.FINI_ARRAY:
                __update_dyn_ent(DYNAMIC_ENTRY_TAG.DT_FINI_ARRAY, s.vma)
                __update_dyn_ent(DYNAMIC_ENTRY_TAG.DT_FINI_ARRAYSZ, s.size)
            elif tag == SECTION.GNU_VERSION:
                __update_dyn_ent(DYNAMIC_ENTRY_TAG.DT_VERSYM, s.vma)
            elif tag == SECTION.GNU_VERSION_D:
                __update_dyn_ent(DYNAMIC_ENTRY_TAG.DT_VERDEF, s.vma)
            elif tag == SECTION.GNU_VERSION_R:
                __update_dyn_ent(DYNAMIC_ENTRY_TAG.DT_VERNEED, s.vma)
            else:
                pass

        dyn_editor.write_dynamic_entries(dyn_entries)

    def __auto_adjust_section_vma(self):
        current_rev = self.get_current_revision()
        next_rev = tempfile.mktemp(dir=self.workdir.name)

        args = []
        after_eh_frame_hdr = False
        for s in self.iter_objdump_sections():
            if not after_eh_frame_hdr:
                if s.name == '.eh_frame_hdr':
                    after_eh_frame_hdr = True
                args.extend(['--change-section-address', s.name + '=' + str(s.lma)])
            # elif s.lma != 0:
            #     args.extend(['--change-section-address', s.name + '+' + str(s.file_off + 0x2000 - s.lma)])
            #     args.extend(['--change-section-vma', s.name + '=' + str(s.file_off)])
            #     args.extend(['--change-section-lma', s.name + '=' + str(s.file_off)])

        self.objcopy(*args, current_rev, next_rev)

        self.revisions.append(next_rev)

    def __auto_adjust_program_header(self):
        ph_editor: ProgramHeaderEditor = self.get_editor(EDITOR.PROGRAM_HEADER)
        elfhdr_editor = self.get_editor(EDITOR.ELF_HEADER)
        e = elfhdr_editor.read_elf_header()
        orig_progh = ph_editor.read_program_header_table(rev_idx=0)
        new_progh = ph_editor.read_program_header_table()

        for orig, new in zip(orig_progh, new_progh):
            orig: ProgramHeader
            new: ProgramHeader

            if orig.type == SEGMENT_TYPE.RELRO:
                sh_editor: SectionHeaderEditor = self.get_editor(EDITOR.SECTION_HEADER)
                fini_array = sh_editor.read_section_header(SECTION.FINI_ARRAY)
                data = sh_editor.read_section_header(SECTION.DATA)
                orig.offset = fini_array.offset
                orig.vaddr = fini_array.addr
                orig.paddr = fini_array.addr
                orig.filesz = data.offset - fini_array.offset
                orig.memsz = data.addr - fini_array.addr
                continue
            elif orig.type == SEGMENT_TYPE.PHDR:
                orig.offset = new.offset
                orig.vaddr = new.paddr  # paddr and vaddr must be the same
                orig.paddr = new.paddr
                # 200903 dhkim: We assume filesz and memsz are always the same (no compression)
                orig.filesz = len(orig_progh) * e.phentsize
                orig.memsz = len(orig_progh) * e.phentsize
                orig.align = new.align
                continue
            elif orig.type == SEGMENT_TYPE.STACK:
                orig.offset = new.offset
                orig.vaddr = new.paddr  # paddr and vaddr must be the same
                orig.paddr = new.paddr
                orig.filesz = new.filesz
                orig.memsz = new.memsz
                continue

            # default behavior
            if not orig or not new:
                continue

            assert orig.type == new.type

            orig.offset = new.offset
            orig.vaddr = new.paddr  # paddr and vaddr must be the same
            orig.paddr = new.paddr
            orig.filesz = new.filesz
            orig.memsz = new.memsz
            orig.align = new.align

        e.phnum = len(orig_progh)

        elfhdr_editor.write_elf_header(e)

        ph_editor.write_program_header_table(orig_progh)

    def __auto_adjust_elf_header(self):
        elfh_editor: ElfHeaderEditor = self.get_editor(EDITOR.ELF_HEADER)
        orig_elfh = elfh_editor.read_elf_header(rev_idx=0)

        elfh = elfh_editor.read_elf_header()

        elfh.flags = orig_elfh.flags

        elfh_editor.write_elf_header(elfh)

    def __auto_adjust_symbol_values(self):
        # FIXME: 240614 dhkim: Shouldn't we handle SECTION.SYMTAB too?
        st_editor: SymbolEditor = self.get_editor(EDITOR.SYMBOL, SECTION.DYNSYM)
        sh_editor: SectionHeaderEditor = self.get_editor(EDITOR.SECTION_HEADER)

        orig_st = st_editor.read_symbol_table(rev_idx=0)
        new_st = st_editor.read_symbol_table()

        orig_sht = sh_editor.read_section_header_table(rev_idx=0)
        new_sht = sh_editor.read_section_header_table()

        assert len(orig_st) == len(new_st)

        for orig_s, new_s in zip(orig_st, new_st):
            orig_s: Symbol
            new_s: Symbol

            if not new_s.is_defined():
                continue

            assert orig_s.shndx == new_s.shndx

            offset = new_sht[new_s.shndx].offset - orig_sht[orig_s.shndx].offset

            new_s.value = orig_s.value + offset

        st_editor.write_symbol_table(new_st)

    class __AddrTranslator:
        updated_sh_pairs: List[Tuple[SectionHeader, SectionHeader]]

        def __init__(self, elf: api.Elf):
            sh_editor: SectionHeaderEditor = elf.get_editor(EDITOR.SECTION_HEADER)

            orig_sht = sh_editor.read_section_header_table(rev_idx=0)
            new_sht = sh_editor.read_section_header_table()

            self.updated_sh_pairs = []
            for orig_sh, new_sh in zip(orig_sht, new_sht):
                if orig_sh.addr != new_sh.addr:
                    self.updated_sh_pairs.append((orig_sh, new_sh))
                    
        def __to_new(self, addr: int, reverse: bool = False):
            for orig_sh, new_sh in self.updated_sh_pairs:
                sh1: SectionHeader
                sh2: SectionHeader

                if reverse:
                    sh1 = new_sh
                    sh2 = orig_sh
                else:
                    sh1 = orig_sh
                    sh2 = new_sh

                if not (sh1.addr <= addr <= sh1.addr + sh1.siz):
                    continue

                new_addr = addr + sh2.addr - sh1.addr

                return new_addr

            return addr

        def to_new(self, orig_addr: int) -> int:
            return self.__to_new(orig_addr, reverse=False)

        def to_orig(self, new_addr: int) -> int:
            return self.__to_new(new_addr, reverse=True)

    def __auto_adjust_addrs_by_heuristic(self):
        trans = self.__AddrTranslator(self)

        # for tag in [SECTION.INIT_ARRAY, SECTION.FINI_ARRAY, SECTION.DATA, SECTION.RODATA,
        #             SECTION.RELA_DYN, SECTION.RELA_PLT, SECTION.TEXT, SECTION.PLT,
        #             SECTION.DATA_REL_RO, SECTION.GNU_HASH]:

        # https://stackoverflow.com/a/7031644
        for tag in [SECTION.INIT_ARRAY, # .init_array and .fini_array are pointer to instructions
                    SECTION.FINI_ARRAY,
                    SECTION.DATA, # .data and .rodata are app specific memory. we heuristically replace pointers
                    SECTION.RODATA,
                    SECTION.DATA_REL_RO,
                    SECTION.RELA_DYN, # I don't know why but i could find addresses here
                    # SECTION.PLT,
                    # SECTION.GOT_PLT
                    ]:
            try:
                section = self.get_section(tag)
            except TypeError:
                continue

            orig_contents = section.read_content(rev_idx=0)

            if (len(orig_contents) % int(self.unit.Addr)) != 0:
                # dee: DynamicEntryEditor = self.get_editor(EDITOR.DYNAMIC_ENTRY)
                # print(self, dee.read_soname())
                # print(section)
                # hexdump(orig_contents)
                continue

            new_contents = section.read_content()

            orig_addrs = unpack_bytes_to_ints(orig_contents, int(self.unit.Addr), self.endian, signed=False)

            contents_out = bytearray(new_contents)

            for i, orig_addr in enumerate(orig_addrs):
                _new_addr = trans.to_new(orig_addr)

                contents_out[i * int(self.unit.Addr):(i + 1) * int(self.unit.Addr)] \
                    = _new_addr.to_bytes(int(self.unit.Addr), self.endian, signed=False)
                # contents_out[i:i + int(self.unit.Addr)] \
                #     = _new_addr.to_bytes(int(self.unit.Addr), self.endian, signed=False)

            section.write_content(bytes(contents_out))

    def __auto_adjust_section_gap_inner(self):
        reference_section = SECTION.EH_FRAME_HDR
        target_sections = [SECTION.RELA_DYN, SECTION.RELA_PLT, SECTION.PLT, SECTION.TEXT, SECTION.RODATA, SECTION.EH_FRAME]

        sh_editor: SectionHeaderEditor = self.get_editor(EDITOR.SECTION_HEADER)

        orig_sht = sh_editor.read_section_header_table(rev_idx=0)
        new_sht = sh_editor.read_section_header_table()

        interested_names = [e for e in map(str, target_sections)]

        filter_interested = lambda sht: sorted(filter(lambda e: e.name in interested_names, sht),
                                               key=lambda e: e.offset, reverse=True)

        orig_refsh = sh_editor.read_section_header(reference_section, rev_idx=0)
        new_refsh = sh_editor.read_section_header(reference_section)

        for orig_sh, new_sh in zip(filter_interested(orig_sht), filter_interested(new_sht)):
            orig_sh: SectionHeader
            new_sh: SectionHeader

            assert orig_sh.name == new_sh.name

            orig_gap = orig_refsh.offset - orig_sh.offset
            new_gap = new_refsh.offset - new_sh.offset

            assert orig_gap > 0 and new_gap > 0

            if orig_gap == new_gap:
                continue

            assert orig_gap > new_gap

            sec = self.get_section(SECTION(orig_sh.name))
            content = sec.read_content()
            content += b'\0' * (orig_gap - new_gap)
            sec.write_content(content)

            return False
        return True

    def __auto_adjust_section_gap_upperhalf(self):
        while not self.__auto_adjust_section_gap_inner():
            pass

    def __auto_adjust_section_gap_lowerhalf(self):
        target_sections = [SECTION.RELA_DYN, SECTION.RELA_PLT, SECTION.PLT, SECTION.TEXT, SECTION.RODATA, SECTION.EH_FRAME]
        sh_editor: SectionHeaderEditor = self.get_editor(EDITOR.SECTION_HEADER)

        for section in target_sections:
            orig_sh = sh_editor.read_section_header(section, rev_idx=0)
            new_sh = sh_editor.read_section_header(section)
            if not new_sh:
                continue
            new_sh.siz = orig_sh.siz
            sh_editor.write_section_header(section, new_sh)

    def __auto_adjust_code_x86_64(self, addr: int, contents: bytes, trans: __AddrTranslator) -> bytes:
        # https://reverseengineering.stackexchange.com/a/22225
        # http://www.capstone-engine.org/lang_python.html

        out = bytes()
        oip = trans.to_orig(addr)
        nip = addr # instruction pointer

        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        md.detail = True

        for insn in md.disasm(contents, addr):
            # ip points the end of an instruction, not the beginning
            oip += len(insn.bytes)
            nip += len(insn.bytes)
            insn: capstone.CsInsn

            # desc = "0x%x:\t%s\t%s\t%s" % (insn.address, hexdump(insn.bytes, result='return'), insn.mnemonic, insn.op_str)

            b = insn.bytes

            for operand in insn.operands:
                if operand.type == capstone.x86.X86_OP_MEM \
                        and operand.value.mem.base == capstone.x86.X86_REG_RIP \
                        and (disp := operand.value.mem.disp) != 0:
                    optr = oip + disp
                    nptr = nip + disp
                    corret_ptr = trans.to_new(optr)

                    if nptr == corret_ptr:
                        continue

                    nb = (disp).to_bytes(4, self.endian, signed=False)
                    cb = (corret_ptr - nip).to_bytes(4, self.endian, signed=False)

                    b = b.replace(nb, cb)
                # if operand.type == capstone.x86.X86_OP_IMM

            out += b
        return out

    def __auto_adjust_code(self):
        trans = self.__AddrTranslator(self)

        sh_editor: SectionHeaderEditor = self.get_editor(EDITOR.SECTION_HEADER)

        for section in [SECTION.PLT, SECTION.TEXT]:
            sh = sh_editor.read_section_header(section)

            s = self.get_section(section)
            content = s.read_content()

            content = self.__auto_adjust_code_x86_64(sh.addr, content, trans)

            s.write_content(content)

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

    def auto_adjust(self):
        # call any adjust functions that potentially change section offset
        self.__auto_adjust_section_gap_upperhalf()

        # call any adjust functions that potentially change section address
        self.__auto_adjust_section_vma()

        # call any adjust functions that
        self.__auto_adjust_dyn_ent_ptr()
        self.__auto_adjust_program_header()
        # self.__auto_adjust_elf_header()
        self.__auto_adjust_symbol_values()
        self.__auto_adjust_addrs_by_heuristic()
        self.__auto_adjust_code()

        self.__auto_adjust_section_gap_lowerhalf()

    def write(self, path: str, auto_adjust: bool = True, mkdirs=True):
        if auto_adjust:
            self.auto_adjust()
        if mkdirs:
            os.makedirs(os.path.dirname(path), exist_ok=True)
        shutil.copy2(self.get_current_revision(), path)

    def close(self):
        self.workdir.cleanup()
