

import tempfile

import capstone

from .section_editor import SectionEditor

from ..util import unpack_bytes_to_ints

from ..core.elf import Elf

from ..elements.section_header import SectionHeader, SectionHeaderTable

from ..elements.symbol import Symbol

from .symbol_editor import SymbolEditor

from .section_header_editor import SectionHeaderEditor

from ..elements.program_header import ProgramHeader

from .elf_header_editor import ElfHeaderEditor

from .program_header_editor import ProgramHeaderEditor
from .dynamic_entry_editor import DynamicEntryEditor
from ..constants import DYNAMIC_ENTRY_TAG, SECTION, SEGMENT_TYPE
from ..core.editor import Editor


class AddrAutocorrectionEditor(Editor):

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

    def __auto_adjust_dyn_ent_ptr(self) -> bool:
        # dyn_editor: DynamicEntryEditor = self.elf.get_editor(EDITOR.DYNAMIC_ENTRY)
        if not (dyn_editor := DynamicEntryEditor(self.elf)):
            return False

        dyn_entries = dyn_editor.read_dynamic_entries()

        def __update_dyn_ent(tag: DYNAMIC_ENTRY_TAG, un: int):
            for ent in filter(lambda e: e.tag == tag, dyn_entries):
                ent.un = un

        for s in self.elf.iter_objdump_sections():
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

        return dyn_editor.write_dynamic_entries(dyn_entries)

    def __auto_adjust_section_vma(self):
        current_rev = self.elf.get_current_revision()
        next_rev = tempfile.mktemp(dir=self.elf.workdir.name)

        args = []
        after_eh_frame_hdr = False
        for s in self.elf.iter_objdump_sections():
            if not after_eh_frame_hdr:
                if s.name == '.eh_frame_hdr':
                    after_eh_frame_hdr = True
                args.extend(['--change-section-address', s.name + '=' + str(s.lma)])
            # elif s.lma != 0:
            #     args.extend(['--change-section-address', s.name + '+' + str(s.file_off + 0x2000 - s.lma)])
            #     args.extend(['--change-section-vma', s.name + '=' + str(s.file_off)])
            #     args.extend(['--change-section-lma', s.name + '=' + str(s.file_off)])

        self.elf.objcopy(*args, current_rev, next_rev)

        self.elf.revisions.append(next_rev)

    def __auto_adjust_program_header(self) -> bool:
        # ph_editor: ProgramHeaderEditor = self.get_editor(EDITOR.PROGRAM_HEADER)
        ph_editor = ProgramHeaderEditor(self.elf)
        # elfhdr_editor = self.elf.get_editor(EDITOR.ELF_HEADER)
        elfhdr_editor = ElfHeaderEditor(self.elf)
        e = elfhdr_editor.read_elf_header()
        if not e:
            return False
        orig_progh = ph_editor.read_program_header_table(rev_idx=0)
        new_progh = ph_editor.read_program_header_table()

        if not (orig_progh and new_progh):
            return False

        for orig, new in zip(orig_progh, new_progh):
            orig: ProgramHeader
            new: ProgramHeader

            if orig.type == SEGMENT_TYPE.RELRO:
                # sh_editor: SectionHeaderEditor = self.elf.get_editor(EDITOR.SECTION_HEADER)
                sh_editor = SectionHeaderEditor(self.elf)
                fini_array = sh_editor.read_section_header(SECTION.FINI_ARRAY)
                data = sh_editor.read_section_header(SECTION.DATA)
                if not (fini_array and data):
                    continue
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

        if not elfhdr_editor.write_elf_header(e):
            return False

        return ph_editor.write_program_header_table(orig_progh)

    def __auto_adjust_elf_header(self) -> bool:
        # elfh_editor: ElfHeaderEditor = self.elf.get_editor(EDITOR.ELF_HEADER)
        elfh_editor = ElfHeaderEditor(self.elf)
        orig_elfh = elfh_editor.read_elf_header(rev_idx=0)

        elfh = elfh_editor.read_elf_header()
        if not (elfh and orig_elfh):
            return False

        elfh.flags = orig_elfh.flags

        return elfh_editor.write_elf_header(elfh)

    def __auto_adjust_symbol_values(self) -> bool:
        # FIXME: 240614 dhkim: Shouldn't we handle SECTION.SYMTAB too?
        # st_editor: SymbolEditor = self.elf.get_editor(EDITOR.SYMBOL, SECTION.DYNSYM)
        # sh_editor: SectionHeaderEditor = self.elf.get_editor(EDITOR.SECTION_HEADER)
        st_editor = SymbolEditor(self.elf, SECTION.DYNSYM)
        sh_editor = SectionHeaderEditor(self.elf)

        orig_st = st_editor.read_symbol_table(rev_idx=0)
        new_st = st_editor.read_symbol_table()

        if not (orig_st and new_st):
            return False

        orig_sht = sh_editor.read_section_header_table(rev_idx=0)
        new_sht = sh_editor.read_section_header_table()

        if not (orig_sht and new_sht):
            return False

        assert len(orig_st) == len(new_st)

        for orig_s, new_s in zip(orig_st, new_st):
            orig_s: Symbol
            new_s: Symbol

            if not new_s.is_defined():
                continue

            assert orig_s.shndx == new_s.shndx

            offset = new_sht[new_s.shndx].offset - orig_sht[orig_s.shndx].offset

            new_s.value = orig_s.value + offset

        return st_editor.write_symbol_table(new_st)

    class __AddrTranslator:
        updated_sh_pairs: list[tuple[SectionHeader, SectionHeader]]

        def __init__(self, elf: Elf):
            # sh_editor: SectionHeaderEditor = elf.get_editor(EDITOR.SECTION_HEADER)
            sh_editor = SectionHeaderEditor(elf)

            orig_sht = sh_editor.read_section_header_table(rev_idx=0)
            new_sht = sh_editor.read_section_header_table()

            assert (orig_sht and new_sht)

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
        trans = self.__AddrTranslator(self.elf)

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
                # section = self.elf.get_section(tag)
                se = SectionEditor(self.elf, tag)
            except TypeError:
                continue
            if not se:
                continue

            orig_contents = se.read_content(rev_idx=0)

            assert orig_contents # FIXME: 082124 What should do for this case?

            if (len(orig_contents) % int(self.elf.unit.Addr)) != 0:
                # dee: DynamicEntryEditor = self.elf.get_editor(EDITOR.DYNAMIC_ENTRY)
                # print(self.elf, dee.read_soname())
                # print(section)
                # hexdump(orig_contents)
                continue

            new_contents = se.read_content()

            assert new_contents # FIXME: 082124 What should do for this case?

            orig_addrs = unpack_bytes_to_ints(orig_contents, int(self.elf.unit.Addr), self.elf.endian, signed=False)

            contents_out = bytearray(new_contents)

            for i, orig_addr in enumerate(orig_addrs):
                _new_addr = trans.to_new(orig_addr)

                contents_out[i * int(self.elf.unit.Addr):(i + 1) * int(self.elf.unit.Addr)] \
                    = _new_addr.to_bytes(int(self.elf.unit.Addr), self.elf.endian, signed=False)
                # contents_out[i:i + int(self.elf.unit.Addr)] \
                #     = _new_addr.to_bytes(int(self.elf.unit.Addr), self.elf.endian, signed=False)

            se.write_content(bytes(contents_out))

    def __auto_adjust_section_gap_inner(self) -> bool:
        reference_section = SECTION.EH_FRAME_HDR
        target_sections = [SECTION.RELA_DYN, SECTION.RELA_PLT, SECTION.PLT, SECTION.TEXT, SECTION.RODATA, SECTION.EH_FRAME]

        # sh_editor: SectionHeaderEditor = self.elf.get_editor(EDITOR.SECTION_HEADER)
        sh_editor = SectionHeaderEditor(self.elf)

        orig_sht = sh_editor.read_section_header_table(rev_idx=0)
        new_sht = sh_editor.read_section_header_table()

        if not (orig_sht and new_sht):
            return False

        interested_names = [e for e in map(str, target_sections)]

        # filter_interested = lambda sht: sorted(filter(lambda e: e.name in interested_names, sht),
        #                                        key=lambda e: e.offset, reverse=True)
        def filter_interested(sht: SectionHeaderTable) -> list[SectionHeader]:
            return sorted(filter(lambda e: e.name in interested_names, sht),
                                               key=lambda e: e.offset, reverse=True)

        orig_refsh = sh_editor.read_section_header(reference_section, rev_idx=0)
        new_refsh = sh_editor.read_section_header(reference_section)

        if not (orig_refsh and new_refsh):
            return False

        for orig_sh, new_sh in zip(filter_interested(orig_sht), filter_interested(new_sht)):
            # orig_sh: SectionHeader
            # new_sh: SectionHeader

            assert orig_sh.name == new_sh.name

            orig_gap = orig_refsh.offset - orig_sh.offset
            new_gap = new_refsh.offset - new_sh.offset

            assert orig_gap > 0 and new_gap > 0

            if orig_gap == new_gap:
                continue

            assert orig_gap > new_gap

            if not sh_editor.read_section_header(SECTION(orig_sh.name)):
                return False

            # sec = self.elf.get_section(SECTION(orig_sh.name))
            sec = SectionEditor(self.elf, SECTION(orig_sh.name))
            # if not sec:
            #     return False

            content = sec.read_content()
            assert content # FIXME: 082124 What should do for this case?

            content += b'\0' * (orig_gap - new_gap)
            sec.write_content(content)

            return False
        return True

    def __auto_adjust_section_gap_upperhalf(self):
        while not self.__auto_adjust_section_gap_inner():
            pass

    def __auto_adjust_section_gap_lowerhalf(self):
        target_sections = [SECTION.RELA_DYN, SECTION.RELA_PLT, SECTION.PLT, SECTION.TEXT, SECTION.RODATA, SECTION.EH_FRAME]
        # sh_editor: SectionHeaderEditor = self.get_editor(EDITOR.SECTION_HEADER)
        sh_editor = SectionHeaderEditor(self.elf)

        for section in target_sections:
            orig_sh = sh_editor.read_section_header(section, rev_idx=0)
            new_sh = sh_editor.read_section_header(section)
            if not (orig_sh and new_sh):
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

                    nb = (disp).to_bytes(4, self.elf.endian, signed=False)
                    cb = (corret_ptr - nip).to_bytes(4, self.elf.endian, signed=False)

                    b = b.replace(nb, cb)
                # if operand.type == capstone.x86.X86_OP_IMM

            out += b
        return out

    def __auto_adjust_code(self):
        trans = self.__AddrTranslator(self.elf)

        # sh_editor: SectionHeaderEditor = self.get_editor(EDITOR.SECTION_HEADER)
        sh_editor = SectionHeaderEditor(self.elf)

        for section in [SECTION.PLT, SECTION.TEXT]:
            sh = sh_editor.read_section_header(section)
            if not sh:
                continue

            # s = self.elf.get_section(section)
            s = SectionEditor(self.elf, section)

            if not s:
                continue

            content = s.read_content()

            assert content # FIXME: 082124 What should do for this case?

            content = self.__auto_adjust_code_x86_64(sh.addr, content, trans)

            s.write_content(content)