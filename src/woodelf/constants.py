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

    def endian(self) -> Literal['little', 'big']:
        if self == ELF_DATA.DATA2LSB:
            return 'little'
        elif self == ELF_DATA.DATA2MSB:
            return 'big'

        # Use self.name to avoid triggering __str__, which would recurse here.
        raise ValueError(f'Unknown ELF_DATA: {self.name}')

    def __str__(self) -> str:
        return self.endian()

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
    UNKNOWN = -1

    EM_NONE	= 0	# No machine
    EM_M32	= 1	# AT&T WE 32100
    EM_SPARC	= 2	# SPARC
    EM_386	= 3	# Intel 80386
    EM_68K	= 4	# Motorola 68000
    EM_88K	= 5	# Motorola 88000
    EM_IAMCU	= 6	# Intel MCU
    EM_860	= 7	# Intel 80860
    EM_MIPS	= 8	# MIPS I Architecture
    EM_S370	= 9	# IBM System/370 Processor
    EM_MIPS_RS3_LE	= 10	# MIPS RS3000 Little-endian
    # reserved	11-14	Reserved for future use
    EM_PARISC	= 15	# Hewlett-Packard PA-RISC
    # reserved	= 16	# Reserved for future use
    EM_VPP500	= 17	# Fujitsu VPP500
    EM_SPARC32PLUS	= 18	# Enhanced instruction set SPARC
    EM_960	= 19	# Intel 80960
    EM_PPC	= 20	# PowerPC
    EM_PPC64	= 21	# 64-bit PowerPC
    EM_S390	= 22	# IBM System/390 Processor
    EM_SPU	= 23	# IBM SPU/SPC
    # reserved	24-35	Reserved for future use
    EM_V800	= 36	# NEC V800
    EM_FR20	= 37	# Fujitsu FR20
    EM_RH32	= 38	# TRW RH-32
    EM_RCE	= 39	# Motorola RCE
    EM_ARM	= 40	# ARM 32-bit architecture (AARCH32)
    EM_ALPHA	= 41	# Digital Alpha
    EM_SH	= 42	# Hitachi SH
    EM_SPARCV9	= 43	# SPARC Version 9
    EM_TRICORE	= 44	# Siemens TriCore embedded processor
    EM_ARC	= 45	# Argonaut RISC Core, Argonaut Technologies Inc.
    EM_H8_300	= 46	# Hitachi H8/300
    EM_H8_300H	= 47	# Hitachi H8/300H
    EM_H8S	= 48	# Hitachi H8S
    EM_H8_500	= 49	# Hitachi H8/500
    EM_IA_64	= 50	# Intel IA-64 processor architecture
    EM_MIPS_X	= 51	# Stanford MIPS-X
    EM_COLDFIRE	= 52	# Motorola ColdFire
    EM_68HC12	= 53	# Motorola M68HC12
    EM_MMA	= 54	# Fujitsu MMA Multimedia Accelerator
    EM_PCP	= 55	# Siemens PCP
    EM_NCPU	= 56	# Sony nCPU embedded RISC processor
    EM_NDR1	= 57	# Denso NDR1 microprocessor
    EM_STARCORE	= 58	# Motorola Star*Core processor
    EM_ME16	= 59	# Toyota ME16 processor
    EM_ST100	= 60	# STMicroelectronics ST100 processor
    EM_TINYJ	= 61	# Advanced Logic Corp. TinyJ embedded processor family
    EM_X86_64	= 62	# AMD x86-64 architecture
    EM_PDSP	= 63	# Sony DSP Processor
    EM_PDP10	= 64	# Digital Equipment Corp. PDP-10
    EM_PDP11	= 65	# Digital Equipment Corp. PDP-11
    EM_FX66	= 66	# Siemens FX66 microcontroller
    EM_ST9PLUS	= 67	# STMicroelectronics ST9+ 8/16 bit microcontroller
    EM_ST7	= 68	# STMicroelectronics ST7 8-bit microcontroller
    EM_68HC16	= 69	# Motorola MC68HC16 Microcontroller
    EM_68HC11	= 70	# Motorola MC68HC11 Microcontroller
    EM_68HC08	= 71	# Motorola MC68HC08 Microcontroller
    EM_68HC05	= 72	# Motorola MC68HC05 Microcontroller
    EM_SVX	= 73	# Silicon Graphics SVx
    EM_ST19	= 74	# STMicroelectronics ST19 8-bit microcontroller
    EM_VAX	= 75	# Digital VAX
    EM_CRIS	= 76	# Axis Communications 32-bit embedded processor
    EM_JAVELIN	= 77	# Infineon Technologies 32-bit embedded processor
    EM_FIREPATH	= 78	# Element 14 64-bit DSP Processor
    EM_ZSP	= 79	# LSI Logic 16-bit DSP Processor
    EM_MMIX	= 80	# Donald Knuth's educational 64-bit processor
    EM_HUANY	= 81	# Harvard University machine-independent object files
    EM_PRISM	= 82	# SiTera Prism
    EM_AVR	= 83	# Atmel AVR 8-bit microcontroller
    EM_FR30	= 84	# Fujitsu FR30
    EM_D10V	= 85	# Mitsubishi D10V
    EM_D30V	= 86	# Mitsubishi D30V
    EM_V850	= 87	# NEC v850
    EM_M32R	= 88	# Mitsubishi M32R
    EM_MN10300	= 89	# Matsushita MN10300
    EM_MN10200	= 90	# Matsushita MN10200
    EM_PJ	= 91	# picoJava
    EM_OPENRISC	= 92	# OpenRISC 32-bit embedded processor
    EM_ARC_COMPACT	= 93	# ARC International ARCompact processor (old spelling/synonym: EM_ARC_A5)
    EM_XTENSA	= 94	# Tensilica Xtensa Architecture
    EM_VIDEOCORE	= 95	# Alphamosaic VideoCore processor
    EM_TMM_GPP	= 96	# Thompson Multimedia General Purpose Processor
    EM_NS32K	= 97	# National Semiconductor 32000 series
    EM_TPC	= 98	# Tenor Network TPC processor
    EM_SNP1K	= 99	# Trebia SNP 1000 processor
    EM_ST200	= 100	# STMicroelectronics (www.st.com) ST200 microcontroller
    EM_IP2K	= 101	# Ubicom IP2xxx microcontroller family
    EM_MAX	= 102	# MAX Processor
    EM_CR	= 103	# National Semiconductor CompactRISC microprocessor
    EM_F2MC16	= 104	# Fujitsu F2MC16
    EM_MSP430	= 105	# Texas Instruments embedded microcontroller msp430
    EM_BLACKFIN	= 106	# Analog Devices Blackfin (DSP) processor
    EM_SE_C33	= 107	# S1C33 Family of Seiko Epson processors
    EM_SEP	= 108	# Sharp embedded microprocessor
    EM_ARCA	= 109	# Arca RISC Microprocessor
    EM_UNICORE	= 110	# Microprocessor series from PKU-Unity Ltd. and MPRC of Peking University
    EM_EXCESS	= 111	# eXcess: 16/32/64-bit configurable embedded CPU
    EM_DXP	= 112	# Icera Semiconductor Inc. Deep Execution Processor
    EM_ALTERA_NIOS2	= 113	# Altera Nios II soft-core processor
    EM_CRX	= 114	# National Semiconductor CompactRISC CRX microprocessor
    EM_XGATE	= 115	# Motorola XGATE embedded processor
    EM_C166	= 116	# Infineon C16x/XC16x processor
    EM_M16C	= 117	# Renesas M16C series microprocessors
    EM_DSPIC30F	= 118	# Microchip Technology dsPIC30F Digital Signal Controller
    EM_CE	= 119	# Freescale Communication Engine RISC core
    EM_M32C	= 120	# Renesas M32C series microprocessors
    # reserved	121-130	Reserved for future use
    EM_TSK3000	= 131	# Altium TSK3000 core
    EM_RS08	= 132	# Freescale RS08 embedded processor
    EM_SHARC	= 133	# Analog Devices SHARC family of 32-bit DSP processors
    EM_ECOG2	= 134	# Cyan Technology eCOG2 microprocessor
    EM_SCORE7	= 135	# Sunplus S+core7 RISC processor
    EM_DSP24	= 136	# New Japan Radio (NJR) 24-bit DSP Processor
    EM_VIDEOCORE3	= 137	# Broadcom VideoCore III processor
    EM_LATTICEMICO32	= 138	# RISC processor for Lattice FPGA architecture
    EM_SE_C17	= 139	# Seiko Epson C17 family
    EM_TI_C6000	= 140	# The Texas Instruments TMS320C6000 DSP family
    EM_TI_C2000	= 141	# The Texas Instruments TMS320C2000 DSP family
    EM_TI_C5500	= 142	# The Texas Instruments TMS320C55x DSP family
    EM_TI_ARP32	= 143	# Texas Instruments Application Specific RISC Processor, 32bit fetch
    EM_TI_PRU	= 144	# Texas Instruments Programmable Realtime Unit
    # reserved	145-159	Reserved for future use
    EM_MMDSP_PLUS	= 160	# STMicroelectronics 64bit VLIW Data Signal Processor
    EM_CYPRESS_M8C	= 161	# Cypress M8C microprocessor
    EM_R32C	= 162	# Renesas R32C series microprocessors
    EM_TRIMEDIA	= 163	# NXP Semiconductors TriMedia architecture family
    EM_QDSP6	= 164	# QUALCOMM DSP6 Processor
    EM_8051	= 165	# Intel 8051 and variants
    EM_STXP7X	= 166	# STMicroelectronics STxP7x family of configurable and extensible RISC processors
    EM_NDS32	= 167	# Andes Technology compact code size embedded RISC processor family
    EM_ECOG1	= 168	# Cyan Technology eCOG1X family
    EM_ECOG1X	= 168	# Cyan Technology eCOG1X family
    EM_MAXQ30	= 169	# Dallas Semiconductor MAXQ30 Core Micro-controllers
    EM_XIMO16	= 170	# New Japan Radio (NJR) 16-bit DSP Processor
    EM_MANIK	= 171	# M2000 Reconfigurable RISC Microprocessor
    EM_CRAYNV2	= 172	# Cray Inc. NV2 vector architecture
    EM_RX	= 173	# Renesas RX family
    EM_METAG	= 174	# Imagination Technologies META processor architecture
    EM_MCST_ELBRUS	= 175	# MCST Elbrus general purpose hardware architecture
    EM_ECOG16	= 176	# Cyan Technology eCOG16 family
    EM_CR16	= 177	# National Semiconductor CompactRISC CR16 16-bit microprocessor
    EM_ETPU	= 178	# Freescale Extended Time Processing Unit
    EM_SLE9X	= 179	# Infineon Technologies SLE9X core
    EM_L10M	= 180	# Intel L10M
    EM_K10M	= 181	# Intel K10M
    # reserved	= 182	# Reserved for future Intel use
    EM_AARCH64	= 183	# ARM 64-bit architecture (AARCH64)
    # reserved	= 184	# Reserved for future ARM use
    EM_AVR32	= 185	# Atmel Corporation 32-bit microprocessor family
    EM_STM8	= 186	# STMicroeletronics STM8 8-bit microcontroller
    EM_TILE64	= 187	# Tilera TILE64 multicore architecture family
    EM_TILEPRO	= 188	# Tilera TILEPro multicore architecture family
    EM_MICROBLAZE	= 189	# Xilinx MicroBlaze 32-bit RISC soft processor core
    EM_CUDA	= 190	# NVIDIA CUDA architecture
    EM_TILEGX	= 191	# Tilera TILE-Gx multicore architecture family
    EM_CLOUDSHIELD	= 192	# CloudShield architecture family
    EM_COREA_1ST	= 193	# KIPO-KAIST Core-A 1st generation processor family
    EM_COREA_2ND	= 194	# KIPO-KAIST Core-A 2nd generation processor family
    EM_ARC_COMPACT2	= 195	# Synopsys ARCompact V2
    EM_OPEN8	= 196	# Open8 8-bit RISC soft processor core
    EM_RL78	= 197	# Renesas RL78 family
    EM_VIDEOCORE5	= 198	# Broadcom VideoCore V processor
    EM_78KOR	= 199	# Renesas 78KOR family
    EM_56800EX	= 200	# Freescale 56800EX Digital Signal Controller (DSC)
    EM_BA1	= 201	# Beyond BA1 CPU architecture
    EM_BA2	= 202	# Beyond BA2 CPU architecture
    EM_XCORE	= 203	# XMOS xCORE processor family
    EM_MCHP_PIC	= 204	# Microchip 8-bit PIC(r) family
    EM_INTEL205	= 205	# Reserved by Intel
    EM_INTEL206	= 206	# Reserved by Intel
    EM_INTEL207	= 207	# Reserved by Intel
    EM_INTEL208	= 208	# Reserved by Intel
    EM_INTEL209	= 209	# Reserved by Intel
    EM_KM32	= 210	# KM211 KM32 32-bit processor
    EM_KMX32	= 211	# KM211 KMX32 32-bit processor
    EM_KMX16	= 212	# KM211 KMX16 16-bit processor
    EM_KMX8	= 213	# KM211 KMX8 8-bit processor
    EM_KVARC	= 214	# KM211 KVARC processor
    EM_CDP	= 215	# Paneve CDP architecture family
    EM_COGE	= 216	# Cognitive Smart Memory Processor
    EM_COOL	= 217	# Bluechip Systems CoolEngine
    EM_NORC	= 218	# Nanoradio Optimized RISC
    EM_CSR_KALIMBA	= 219	# CSR Kalimba architecture family
    EM_Z80	= 220	# Zilog Z80
    EM_VISIUM	= 221	# Controls and Data Services VISIUMcore processor
    EM_FT32	= 222	# FTDI Chip FT32 high performance 32-bit RISC architecture
    EM_MOXIE	= 223	# Moxie processor family
    EM_AMDGPU	= 224	# AMD GPU architecture
    EM_RISCV	= 243	# RISC-V

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


# class EDITOR(Enum):
#     SYMBOL_VERSION = auto()
#     DYNAMIC_ENTRY = auto()
#     STRTAB = auto()
#     ELF_HEADER = auto()
#     SECTION_HEADER = auto()
#     PROGRAM_HEADER = auto()
#     SYMBOL = auto()


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
    STRTAB = '.strtab'
    INTERP = '.interp'

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

    DT_UNKNOWN_1 = 1879048193
    DT_UNKNOWN_2 = 36
    DT_UNKNOWN_3 = 35
    DT_UNKNOWN_4 = 37

    DT_UNKNOWN = None

    def __int__(self) -> int:
        if self == DYNAMIC_ENTRY_TAG:
            return 0
        
        assert isinstance(self.value, int)

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
