def gnu_hash_binutils_bfd_elf(string: str):
    """ toolchain/binutils/binutils-2.27/bfd/elf.c

    /* Standard ELF hash function.  Do not change this function; you will
       cause invalid hash tables to be generated.  */

    unsigned long
    bfd_elf_hash (const char *namearg)
    {
      const unsigned char *name = (const unsigned char *) namearg;
      unsigned long h = 0;
      unsigned long g;
      int ch;

      while ((ch = *name++) != '\0')
        {
          h = (h << 4) + ch;
          if ((g = (h & 0xf0000000)) != 0)
        {
          h ^= g >> 24;
          /* The ELF ABI says `h &= ~g', but this is equivalent in
             this case and on some machines one insn instead of two.  */
          h ^= g;
        }
        }
      return h & 0xffffffff;
    }
    """
    h = 0
    for ch in list(string.encode(encoding='ascii')):
        h = (h << 4) + ch
        if (g := (h & 0xf0000000)) != 0:
            h ^= g >> 24
            h ^= g

    return h & 0xffffffff


def gnu_hash_bionic_linker_linker_sofinfo(string: str):
    """ bionic/linker/linker_soinfo.cpp

    uint32_t calculate_elf_hash(const char* name) {
      const uint8_t* name_bytes = reinterpret_cast<const uint8_t*>(name);
      uint32_t h = 0, g;

      while (*name_bytes) {
        h = (h << 4) + *name_bytes++;
        g = h & 0xf0000000;
        h ^= g;
        h ^= g >> 24;
      }

      return h;
    }
    """
    h = 0
    for ch in list(string.encode(encoding='ascii')):
        h = ((h << 4) + ch) & 0xffffffff
        g = h & 0xf0000000
        h ^= g
        h ^= g >> 24

    return h


def gnu_hash(string: str):
    return gnu_hash_bionic_linker_linker_sofinfo(string)
    # return gnu_hash_binutils_bfd_elf(string)


def readelf_hexdump_to_bytes(hexdump: str) -> bytes:
    b = bytes()
    for line in [e for e in hexdump.splitlines()][2:]:
        if len(line) == 0:
            continue
        if (end := line.find('  ', 2)) > 0:
            line = line[:end]
        addr, *words = line.split()
        try:
            for word in words[:4]:
                b += int(word, 16).to_bytes(int(len(word)/2), byteorder='big')
        except ValueError:
            raise AssertionError('error: Failed at parsing hexdump')

    return b


def unpack_bytes_to_ints(b: bytes, segment_size: int, byteorder: str, signed=False):
    assert (len(b) % segment_size) == 0
    return [int.from_bytes(b[i:i+segment_size], byteorder, signed=signed) for i in range(0, len(b), segment_size)]