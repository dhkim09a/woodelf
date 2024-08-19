from __future__ import annotations

from typing import Union, List

from ..constants import ELF64, ELF32
# from ..api import Elf
from .elf import Elf


class Element:
    @classmethod
    def units(cls, elf: Elf) -> list[ELF32 | ELF64]:
        raise NotImplementedError

    @classmethod
    def from_bytes(cls, elf: Elf, b: bytes) -> Element | None:
        raise NotImplementedError

    def to_bytes(self, elf: Elf) -> bytes:
        raise NotImplementedError

    @classmethod
    def __size(cls, elf: Elf) -> int:
        s = 0
        for unit in cls.units(elf):
            s += int(unit)
        return s

    @classmethod
    def size(cls, elf: Elf) -> int:
        return cls.__size(elf)

    @classmethod
    def deserialize(cls, elf: Elf, b: bytes) -> int | tuple[int, ...]:
        results: list[int] = []
        pos = 0

        # if len(b) != cls.__size(elf):
        #     print(f"Expected {cls.__size(elf)} bytes, got {len(b)}")

        assert len(b) == cls.__size(elf)

        for unit in cls.units(elf):
            signed = unit in [ELF32.Sword, ELF32.Sxword, ELF64.Sword, ELF64.Sxword]
            val = int.from_bytes(b[pos:(pos := pos + int(unit))], byteorder=elf.endian, signed=signed)
            results.append(val)

        if len(results) <= 0:
            raise ValueError
        elif len(results) == 1:
            return results[0]
        else:
            return tuple(results)

    @classmethod
    def serialize(cls, elf: Elf, *values: int) -> bytes:
        b = bytes()

        assert len(values) == len(cls.units(elf))

        for value, unit in zip(values, cls.units(elf)):
            signed = unit in [ELF32.Sword, ELF32.Sxword, ELF64.Sword, ELF64.Sxword]
            b += int(value).to_bytes(int(unit), byteorder=elf.endian, signed=signed)

        assert len(b) == cls.__size(elf)

        return b
