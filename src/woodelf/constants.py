from enum import Enum, auto

from typing import Literal


class IntEnum(Enum):
    def __int__(self):
        return self.value


class ELF_CLASS(IntEnum):
    CLASSNONE = 0
    CLASS32 = 1
    CLASS64 = 2

    # @classmethod
    # def _missing_(cls, value):
    #     return value


class ELF_DATA(IntEnum):
    DATANONE = 0
    DATA2LSB = 1
    DATA2MSB = 2

    # @classmethod
    # def _missing_(cls, value):
    #     return value

    def __str__(self) -> Literal['little', 'big']:
        if self == ELF_DATA.DATA2LSB:
            return 'little'
        elif self == ELF_DATA.DATA2MSB:
            return 'big'

        assert False, f'Unknown ELF_DATA: {self}'

class ELF_TYPE(IntEnum):
    NONE = 0
    REL = 1
    EXEC = 2
    DYN = 3
    CORE = 4

    # @classmethod
    # def _missing_(cls, value):
    #     return value


class ELF_MACHINE(IntEnum):
    EM_NONE = 0
    EM_M32 = 1
    EM_SPARC = 2
    EM_386 = 3
    EM_68K = 4
    EM_88K = 5
    EM_860 = 7
    EM_MIPS = 8
    EM_ARM = 40
    EM_X86_64 = 62
    EM_QDSP6 = 164
    EM_AARCH64 = 183
    UNKNOWN = -1

    # @classmethod
    # def _missing_(cls, value):
    #     return value


class ELF_VERSION(IntEnum):
    NONE = 0
    CURRENT = 1

    # @classmethod
    # def _missing_(cls, value):
    #     return value

# https://docs.oracle.com/cd/E19957-01/806-0641/6j9vuqujo/index.html


class ELF32(IntEnum):
    Addr = 4
    Half = 2
    Off = 4
    Sword = 4
    Word = 4
    uchar = 1

    # 200830: Xword and Sxword are added for convenience
    Xword = 4
    Sxword = 4


class ELF64(IntEnum):
    Addr = 8
    Half = 2
    Off = 8
    Sword = 4
    Word = 4
    Xword = 8
    Sxword = 8
    uchar = 1


class EDITOR(Enum):
    SYMBOL_VERSION = auto()
    DYNAMIC_ENTRY = auto()
    STRTAB = auto()
    ELF_HEADER = auto()
    SECTION_HEADER = auto()
    PROGRAM_HEADER = auto()
    SYMBOL = auto()


class SEGMENT_TYPE(IntEnum):
    NULL = 0
    LOAD = 1
    DYNAMIC = 2
    INTERP = 3
    NOTE = 4
    SHLIB = 5
    PHDR = 6

    EH_FRAME = 0x6474e550
    STACK = 0x6474e551
    RELRO = 0x6474e552

    # @classmethod
    # def _missing_(cls, value):
    #     return None


class SECTION(Enum):
    NOTE_ANDROID_IDENT = '.note.android.ident'
    NOTE_GNU_BUILD_ID = '.note.gnu.build-id'
    DYNSYM = '.dynsym'
    DYNSTR = '.dynstr'
    GNU_HASH = '.gnu.hash'
    GNU_VERSION = '.gnu.version'
    GNU_VERSION_D = '.gnu.version_d'
    GNU_VERSION_R = '.gnu.version_r'
    RELA_DYN = '.rela.dyn'
    RELA_PLT = '.rela.plt'
    PLT = '.plt'
    TEXT = '.text'
    RODATA = '.rodata'
    GCC_EXCEPT_TABLE = '.gcc_except_table'
    EH_FRAME = '.eh_frame'
    EH_FRAME_HDR = '.eh_frame_hdr'
    FINI_ARRAY = '.fini_array'
    INIT_ARRAY = '.init_array'
    DATA_REL_RO = '.data.rel.ro'
    DYNAMIC = '.dynamic'
    GOT = '.got'
    GOT_PLT = '.got.plt'
    DATA = '.data'
    BSS = '.bss'
    NOTE_GNU_GOLD_VERSION = '.note.gnu.gold-version'
    GNU_DEBUGDATA = '.gnu_debugdata'
    SHSTRTAB = '.shstrtab'
    SYMTAB = '.symtab'

    def __str__(self):
        return self.value


class DYNAMIC_ENTRY_TAG(Enum):
    DT_NULL = 0
    DT_NEEDED = 1
    DT_PLTRELSZ = 2
    DT_PLTGOT = 3
    DT_HASH = 4
    DT_STRTAB = 5
    DT_SYMTAB = 6
    DT_RELA = 7
    DT_RELASZ = 8
    DT_RELAENT = 9
    DT_STRSZ = 10
    DT_SYMENT = 11
    DT_INIT = 12
    DT_FINI = 13
    DT_SONAME = 14
    DT_RPATH = 15
    DT_SYMBOLIC = 16
    DT_REL = 17
    DT_RELSZ = 18
    DT_RELENT = 19
    DT_PLTREL = 20
    DT_DEBUG = 21
    DT_TEXTREL = 22
    DT_JMPREL = 23

    #/ *http: // www.sco.com / developers / gabi / latest / ch5.dynamic.html * /
    DT_BIND_NOW = 24
    DT_INIT_ARRAY = 25
    DT_FINI_ARRAY = 26
    DT_INIT_ARRAYSZ = 27
    DT_FINI_ARRAYSZ = 28
    DT_RUNPATH = 29
    DT_FLAGS = 30
    #/ *glibc and BSD disagree for DT_ENCODING; glibc looks wrong.* /
    DT_PREINIT_ARRAY = 32
    DT_PREINIT_ARRAYSZ = 33

    #/ *Experimental support for SHT_RELR sections.For details, see proposal
    # at https: // groups.google.com / forum /  # !topic/generic-abi/bX460iggiKg */
    DT_RELR = 0x6fffe000
    DT_RELRSZ = 0x6fffe001
    DT_RELRENT = 0x6fffe003
    DT_RELRCOUNT = 0x6fffe005

    # bionic/libc/include/elf.h
    DT_LOOS = 0x6000000d
    DT_ANDROID_REL = DT_LOOS + 2
    DT_ANDROID_RELSZ = DT_LOOS + 3
    DT_ANDROID_RELA = DT_LOOS + 4
    DT_ANDROID_RELASZ = DT_LOOS + 5

    DT_GNU_HASH = 0x6ffffef5
    DT_TLSDESC_PLT = 0x6ffffef6
    DT_TLSDESC_GOT = 0x6ffffef7

    # bionic/libc/kernel/uapi/linux/elf.h
    DT_VERSYM = 0x6ffffff0
    DT_RELACOUNT = 0x6ffffff9
    DT_RELCOUNT = 0x6ffffffa
    DT_FLAGS_1 = 0x6ffffffb
    DT_VERDEF = 0x6ffffffc
    DT_VERDEFNUM = 0x6ffffffd
    DT_VERNEED = 0x6ffffffe
    DT_VERNEEDNUM = 0x6fffffff

    DT_UNKNOWN = None

    def __int__(self):
        if self == DYNAMIC_ENTRY_TAG:
            return 0

        return self.value


STR_DT = [DYNAMIC_ENTRY_TAG.DT_NEEDED,
          DYNAMIC_ENTRY_TAG.DT_SONAME,
          DYNAMIC_ENTRY_TAG.DT_RPATH,
          DYNAMIC_ENTRY_TAG.DT_RUNPATH]

PTR_DT = [DYNAMIC_ENTRY_TAG.DT_PLTGOT,
          DYNAMIC_ENTRY_TAG.DT_HASH,
          DYNAMIC_ENTRY_TAG.DT_STRTAB,
          DYNAMIC_ENTRY_TAG.DT_SYMTAB,
          DYNAMIC_ENTRY_TAG.DT_RELA,
          DYNAMIC_ENTRY_TAG.DT_INIT,
          DYNAMIC_ENTRY_TAG.DT_FINI,
          DYNAMIC_ENTRY_TAG.DT_REL,
          DYNAMIC_ENTRY_TAG.DT_DEBUG,
          DYNAMIC_ENTRY_TAG.DT_JMPREL,
          DYNAMIC_ENTRY_TAG.DT_INIT_ARRAY,
          DYNAMIC_ENTRY_TAG.DT_FINI_ARRAY,
          DYNAMIC_ENTRY_TAG.DT_PREINIT_ARRAY,
          DYNAMIC_ENTRY_TAG.DT_ANDROID_REL,
          DYNAMIC_ENTRY_TAG.DT_ANDROID_RELA,
          DYNAMIC_ENTRY_TAG.DT_VERSYM,
          DYNAMIC_ENTRY_TAG.DT_VERDEF,
          DYNAMIC_ENTRY_TAG.DT_VERNEED,
          DYNAMIC_ENTRY_TAG.DT_GNU_HASH]


class SYMBOL_BIND(IntEnum):
    STB_LOCAL   = 0         #  Local symbol.
    STB_GLOBAL  = 1         #  Global symbol.
    STB_WEAK    = 2         #  Weak symbol.
    # STB_NUM     = 3		    #  Number of defined types.
    STB_LOOS	= 10		#  Start of OS-specific 
    STB_HIOS	= 12		#  End of OS-specific 
    STB_LOPROC	= 13		#  Start of processor-specific 
    STB_HIPROC	= 15		#  End of processor-specific 


class SYMBOL_TYPE(IntEnum):
    STT_NOTYPE	= 0		#  Symbol type is unspecified 
    STT_OBJECT	= 1		#  Symbol is a data object 
    STT_FUNC	= 2		#  Symbol is a code object 
    STT_SECTION	= 3		#  Symbol associated with a section 
    STT_FILE	= 4		#  Symbol's name is file name 
    STT_COMMON	= 5		#  Symbol is a common data object 
    STT_TLS		= 6		#  Symbol is thread-local data object
    # STT_NUM		= 7		#  Number of defined types.  
    STT_LOOS	= 10		#  Start of OS-specific 
    # STT_GNU_IFUNC	10		#  Symbol is indirect code object 
    STT_HIOS	= 12		#  End of OS-specific 
    STT_LOPROC	= 13		#  Start of processor-specific 
    STT_HIPROC	= 15		#  End of processor-specific 


class SYMBOL_VISIBILITY(IntEnum):
    STV_DEFAULT = 0
    STV_INTERNAL = 1
    STV_HIDDEN = 2
    STV_PROTECTED = 3
