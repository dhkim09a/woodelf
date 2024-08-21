from typing import Union

from .. import Elf, ELF32, ELF64, api
from ..core import Element


class GnuHash(Element):
    nbuckets: int
    symndx: int
    maskwords: int
    shift2: int
    bloom_filter: list[int]
    buckets: list[int]
    values: list[int]

    @classmethod
    def units(cls, elf: Elf) -> list[Union[ELF32, ELF64]]:
        return [elf.unit.Word, elf.unit.Word, elf.unit.Word, elf.unit.Word]

    @classmethod
    def from_bytes(cls, elf: Elf, b: bytes):
        r = cls.deserialize(elf, b[:int(elf.unit.Word) * 4])
        assert isinstance(r, tuple) and len(r) == 4

        nbuckets, symndx, maskwords, shift2 = r

        gnu_hash = GnuHash()
        gnu_hash.nbuckets = nbuckets
        gnu_hash.symndx = symndx
        gnu_hash.maskwords = maskwords
        gnu_hash.shift2 = shift2

        # FIXME: This is incomplete
        # https://blogs.oracle.com/solaris/gnu-hash-elf-sections-v2
        # https://www.gabriel.urdhr.fr/2015/09/28/elf-file-format/#gnu-hash-table


    def to_bytes(self, elf: Elf) -> bytes:
        raise NotImplementedError()
