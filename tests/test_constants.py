from unittest import TestCase

from woodelf.constants import (
    DYNAMIC_ENTRY_TAG,
    ELF32,
    ELF64,
    ELF_CLASS,
    ELF_DATA,
    ELF_MACHINE,
    ELF_TYPE,
    ELF_VERSION,
    IntEnum,
    PTR_DT,
    SECTION,
    SEGMENT_TYPE,
    STR_DT,
    SYMBOL_BIND,
    SYMBOL_TYPE,
    SYMBOL_VISIBILITY,
)


class TestIntEnumProtocol(TestCase):
    def test_int_conversion_returns_value(self):
        self.assertEqual(int(ELF_CLASS.CLASS32), 1)
        self.assertEqual(int(ELF_CLASS.CLASS64), 2)
        self.assertEqual(int(ELF_TYPE.EXEC), 2)

    def test_int_enum_is_base_for_size_enums(self):
        self.assertIsInstance(ELF32.Addr, IntEnum)
        self.assertIsInstance(ELF64.Addr, IntEnum)


class TestElfClass(TestCase):
    def test_values(self):
        self.assertEqual(ELF_CLASS.CLASSNONE.value, 0)
        self.assertEqual(ELF_CLASS.CLASS32.value, 1)
        self.assertEqual(ELF_CLASS.CLASS64.value, 2)


class TestElfData(TestCase):
    def test_endian_lsb(self):
        self.assertEqual(ELF_DATA.DATA2LSB.endian(), 'little')

    def test_endian_msb(self):
        self.assertEqual(ELF_DATA.DATA2MSB.endian(), 'big')

    def test_str_is_endian(self):
        self.assertEqual(str(ELF_DATA.DATA2LSB), 'little')
        self.assertEqual(str(ELF_DATA.DATA2MSB), 'big')

    def test_endian_none_raises(self):
        with self.assertRaises(ValueError) as ctx:
            ELF_DATA.DATANONE.endian()
        self.assertIn('DATANONE', str(ctx.exception))


class TestElf32Sizes(TestCase):
    def test_addr_off_word_4_bytes(self):
        self.assertEqual(int(ELF32.Addr), 4)
        self.assertEqual(int(ELF32.Off), 4)
        self.assertEqual(int(ELF32.Word), 4)
        self.assertEqual(int(ELF32.Sword), 4)

    def test_half_2_bytes(self):
        self.assertEqual(int(ELF32.Half), 2)

    def test_uchar_1_byte(self):
        self.assertEqual(int(ELF32.uchar), 1)

    def test_xword_4_bytes(self):
        # documented as a convenience alias in this module
        self.assertEqual(int(ELF32.Xword), 4)
        self.assertEqual(int(ELF32.Sxword), 4)


class TestElf64Sizes(TestCase):
    def test_addr_off_xword_8_bytes(self):
        self.assertEqual(int(ELF64.Addr), 8)
        self.assertEqual(int(ELF64.Off), 8)
        self.assertEqual(int(ELF64.Xword), 8)
        self.assertEqual(int(ELF64.Sxword), 8)

    def test_word_4_bytes(self):
        self.assertEqual(int(ELF64.Word), 4)
        self.assertEqual(int(ELF64.Sword), 4)


class TestElfMachine(TestCase):
    def test_known_values(self):
        self.assertEqual(ELF_MACHINE.EM_X86_64.value, 62)
        self.assertEqual(ELF_MACHINE.EM_AARCH64.value, 183)
        self.assertEqual(ELF_MACHINE.EM_ARM.value, 40)
        self.assertEqual(ELF_MACHINE.EM_RISCV.value, 243)
        self.assertEqual(ELF_MACHINE.EM_NONE.value, 0)


class TestSegmentType(TestCase):
    def test_basic_types(self):
        self.assertEqual(int(SEGMENT_TYPE.NULL), 0)
        self.assertEqual(int(SEGMENT_TYPE.LOAD), 1)
        self.assertEqual(int(SEGMENT_TYPE.DYNAMIC), 2)

    def test_gnu_extensions(self):
        self.assertEqual(int(SEGMENT_TYPE.EH_FRAME), 0x6474e550)
        self.assertEqual(int(SEGMENT_TYPE.STACK), 0x6474e551)
        self.assertEqual(int(SEGMENT_TYPE.RELRO), 0x6474e552)


class TestSection(TestCase):
    def test_str_returns_section_name(self):
        self.assertEqual(str(SECTION.TEXT), '.text')
        self.assertEqual(str(SECTION.DYNAMIC), '.dynamic')
        self.assertEqual(str(SECTION.SYMTAB), '.symtab')

    def test_value_is_dotted_name(self):
        self.assertEqual(SECTION.DYNSYM.value, '.dynsym')
        self.assertEqual(SECTION.GNU_HASH.value, '.gnu.hash')


class TestDynamicEntryTag(TestCase):
    def test_int_known(self):
        self.assertEqual(int(DYNAMIC_ENTRY_TAG.DT_NULL), 0)
        self.assertEqual(int(DYNAMIC_ENTRY_TAG.DT_NEEDED), 1)
        self.assertEqual(int(DYNAMIC_ENTRY_TAG.DT_GNU_HASH), 0x6ffffef5)

    def test_str_dt_membership(self):
        for tag in [DYNAMIC_ENTRY_TAG.DT_NEEDED,
                    DYNAMIC_ENTRY_TAG.DT_SONAME,
                    DYNAMIC_ENTRY_TAG.DT_RPATH,
                    DYNAMIC_ENTRY_TAG.DT_RUNPATH]:
            self.assertIn(tag, STR_DT)

    def test_ptr_dt_membership(self):
        for tag in [DYNAMIC_ENTRY_TAG.DT_STRTAB,
                    DYNAMIC_ENTRY_TAG.DT_SYMTAB,
                    DYNAMIC_ENTRY_TAG.DT_HASH,
                    DYNAMIC_ENTRY_TAG.DT_GNU_HASH]:
            self.assertIn(tag, PTR_DT)


class TestSymbolBind(TestCase):
    def test_values(self):
        self.assertEqual(int(SYMBOL_BIND.STB_LOCAL), 0)
        self.assertEqual(int(SYMBOL_BIND.STB_GLOBAL), 1)
        self.assertEqual(int(SYMBOL_BIND.STB_WEAK), 2)


class TestSymbolType(TestCase):
    def test_values(self):
        self.assertEqual(int(SYMBOL_TYPE.STT_NOTYPE), 0)
        self.assertEqual(int(SYMBOL_TYPE.STT_FUNC), 2)
        self.assertEqual(int(SYMBOL_TYPE.STT_OBJECT), 1)


class TestSymbolVisibility(TestCase):
    def test_values(self):
        self.assertEqual(int(SYMBOL_VISIBILITY.STV_DEFAULT), 0)
        self.assertEqual(int(SYMBOL_VISIBILITY.STV_HIDDEN), 2)
        self.assertEqual(int(SYMBOL_VISIBILITY.STV_PROTECTED), 3)


class TestElfType(TestCase):
    def test_values(self):
        self.assertEqual(int(ELF_TYPE.NONE), 0)
        self.assertEqual(int(ELF_TYPE.REL), 1)
        self.assertEqual(int(ELF_TYPE.EXEC), 2)
        self.assertEqual(int(ELF_TYPE.DYN), 3)
        self.assertEqual(int(ELF_TYPE.CORE), 4)


class TestElfVersion(TestCase):
    def test_values(self):
        self.assertEqual(int(ELF_VERSION.NONE), 0)
        self.assertEqual(int(ELF_VERSION.CURRENT), 1)
