from __future__ import annotations

from typing import Generic, TypeVar, Union, List, Protocol

# from ..editors.symbol_version_editor import SymbolVersionEditor

from ..core.elf import Elf

from ..constants import SECTION, ELF64, ELF32
from ..util import gnu_hash
# from ..api import Elf, SymbolVersionEditor, StrTabEditor

from ..core.element import Element


class Veraux(Element):
    next: Veraux | None

    def __init__(self):
        self.next = None


class Ver(Veraux):
    cnt: int
    aux: Union[Veraux, None]

    veraux_table: Union[VerauxTable, None]

    def __init__(self):
        super().__init__()
        self.veraux_table = None

    def append_veraux(self, veraux: Veraux):
        if not self.veraux_table:
            self.veraux_table = VerauxTable()
            self.aux = veraux

        self.veraux_table.append(veraux)

        if self.cnt < len(self.veraux_table):
            self.cnt = len(self.veraux_table)

    def insert_veraux(self, index: int, veraux: Veraux):
        if not self.veraux_table:
            self.veraux_table = VerauxTable()
            self.aux = veraux

        self.veraux_table.insert(index, veraux)

        if self.cnt < len(self.veraux_table):
            self.cnt = len(self.veraux_table)


class Verdaux(Veraux):
    name: str
    next: Union[Veraux, None]

    def __init__(self, vda_name: str):
        super().__init__()
        self.name = vda_name

    @classmethod
    def size(cls, elf: Elf) -> int:
        return int(elf.unit.Word) * 2

    @classmethod
    def from_bytes(cls, elf: Elf, b: bytes) -> Verdaux | None:
        from ..editors.strtab_editor import StrTabEditor
        assert len(b) == Verdaux.size(elf)

        pos = 0
        vda_name = int.from_bytes(b[pos:(pos := pos + int(elf.unit.Word))], byteorder=elf.endian, signed=False)
        vda_next = int.from_bytes(b[pos:(pos := pos + int(elf.unit.Word))], byteorder=elf.endian, signed=False)

        if vda_next != 0 and vda_next != Verdaux.size(elf):
            print('error: weird vn_aux offset')

        if not (dynstr_editor := StrTabEditor(elf, SECTION.DYNSTR)):
            return None

        name = dynstr_editor.get_str(vda_name)

        verdaux = Verdaux(name)

        return verdaux

    def to_bytes(self, elf: Elf) -> bytes | None:
        from ..editors.strtab_editor import StrTabEditor
        if not (dynstr_editor := StrTabEditor(elf, SECTION.DYNSTR)):
            return None

        # dynstr_sec: lief.ELF.Section = elf.get_section('.dynstr')
        if (pos := dynstr_editor.find(self.name)) >= 0:
            b = pos.to_bytes(int(elf.unit.Word), byteorder=elf.endian, signed=False)
        else:
            b = (0).to_bytes(int(elf.unit.Word), byteorder=elf.endian, signed=False)
        if self.next:
            b += (Verdaux.size(elf)).to_bytes(int(elf.unit.Word), byteorder=elf.endian, signed=False)
        else:
            b += (0).to_bytes(int(elf.unit.Word), byteorder=elf.endian, signed=False)

        assert len(b) == Verdaux.size(elf)

        return b

    def __str__(self):
        return '(verdaux) name: ' + str(self.name) \
               + ' (gnu hash: ' + hex(gnu_hash(self.name)) + ')'


class Verdef(Ver):
    version: int
    flags: int
    ndx: int
    cnt: int
    hash: int
    aux: Union[Verdaux, None]
    next: Union[Veraux, None]

    def __init__(self, vda_name: str | None = None, vd_ndx: int = 1):
        super().__init__()

        self.version = 1
        self.flags = 0
        self.ndx = vd_ndx
        self.cnt = 0

        if vda_name:
            self.hash = gnu_hash(vda_name)
            verdaux = Verdaux(vda_name)
            self.append_veraux(verdaux)
        else:
            self.hash = 0

    @classmethod
    def units(cls, elf: Elf) -> List[Union[ELF32, ELF64]]:
        return [elf.unit.Half, elf.unit.Half, elf.unit.Half, elf.unit.Half,
                elf.unit.Word, elf.unit.Word, elf.unit.Word]

    @classmethod
    def from_bytes(cls, elf: Elf, b: bytes):
        r = cls.deserialize(elf, b)

        assert isinstance(r, tuple) and len(r) == 7

        vd_version, vd_flags, vd_ndx, vd_cnt, vd_hash, vd_aux, vd_next = r

        if vd_version != 1:
            print('error: vd_version must be 1')
        if vd_aux != 0 and vd_aux != Verdef.size(elf):
            print('error: weird vd_aux offset')

        verdef = Verdef()

        verdef.version = vd_version
        verdef.flags = vd_flags
        verdef.ndx = vd_ndx
        verdef.cnt = vd_cnt
        verdef.hash = vd_hash

        return verdef

    def to_bytes(self, elf: Elf):
        if self.aux:
            aux = Verdef.size(elf)
        else:
            aux = 0
        if self.next:
            nxt = Verdef.size(elf) + self.cnt * Verdaux.size(elf)
        else:
            nxt = 0

        return self.serialize(elf, self.version, self.flags, self.ndx, self.cnt, self.hash, aux, nxt)

    def __str__(self):
        return '(verdef) version: ' + str(self.version) \
               + ', flags: ' + str(self.flags) \
               + ', ndx: ' + str(self.ndx) \
               + ', cnt: ' + str(self.cnt) \
               + ', hash: ' + hex(self.hash)

    def update(self, new_version: str, ndx: int):
        self.hash = gnu_hash(new_version)
        self.ndx = ndx
        self.insert_veraux(0, Verdaux(new_version))

    def get_ndx(self):
        return self.ndx


class Vernaux(Veraux):
    hash: int
    flags: int
    next: Union[Veraux, None]

    def __init__(self, vna_name: str):
        super().__init__()

        # constants
        self.flags = 0

        # init from params
        self.name = vna_name
        self.other = 0
        self.hash = gnu_hash(vna_name)

    @classmethod
    def units(cls, elf: Elf) -> List[Union[ELF32, ELF64]]:
        return [elf.unit.Word, elf.unit.Half, elf.unit.Half, elf.unit.Word,
                elf.unit.Word]

    @classmethod
    def from_bytes(cls, elf: Elf, b: bytes) -> Vernaux | None:
        from ..editors.strtab_editor import StrTabEditor
        r = cls.deserialize(elf, b)

        assert isinstance(r, tuple) and len(r) == 5

        vna_hash, vna_flags, vna_other, vna_name, vna_next = r

        if vna_next != 0 and vna_next != Vernaux.size(elf):
            print('error: weird vn_aux offset')

        if not (dynstr_editor := StrTabEditor(elf, SECTION.DYNSTR)):
            return None

        name = dynstr_editor.get_str(vna_name)

        vernaux = Vernaux(name)

        vernaux.other = vna_other
        vernaux.hash = vna_hash
        vernaux.flags = vna_flags

        return vernaux

    def __str__(self) -> str:
        return '(vernaux) hash: ' + hex(self.hash) \
               + ', flags: ' + str(self.flags) \
               + ', other: ' + str(self.other) \
               + ', name: ' + str(self.name) \
               + ' (gnu hash: ' + hex(gnu_hash(self.name)) + ')'

    def to_bytes(self, elf: Elf) -> bytes | None:
        from ..editors.strtab_editor import StrTabEditor
        # dynstr_edit: StrTabEditor = elf.get_editor(EDITOR.STRTAB, SECTION.DYNSTR)
        if not (dynstr_edit := StrTabEditor(elf, SECTION.DYNSTR)):
            return None
        # symver_edit: SymbolVersionEditor = elf.get_editor(EDITOR.SYMBOL_VERSION)

        if (vna_name := dynstr_edit.find(self.name)) < 0:
            vna_name = 0

        if self.next:
            vna_next = Vernaux.size(elf)
        else:
            vna_next = 0

        return self.serialize(elf, self.hash, self.flags, self.other, vna_name, vna_next)


class Verneed(Ver):
    version: int
    cnt: int
    file: str
    aux: Union[Vernaux, None]
    next: Union[Veraux, None]

    @classmethod
    def size(cls, elf: Elf) -> int:
        return int(elf.unit.Half) * 2 + int(elf.unit.Word) * 3

    @classmethod
    def from_bytes(cls, elf: Elf, b: bytes) -> Verneed | None:
        from ..editors.strtab_editor import StrTabEditor
        assert len(b) == Verneed.size(elf)

        pos = 0

        vn_version = int.from_bytes(b[pos:(pos := pos + int(elf.unit.Half))], byteorder=elf.endian, signed=False)
        vn_cnt = int.from_bytes(b[pos:(pos := pos + int(elf.unit.Half))], byteorder=elf.endian, signed=False)
        vn_file = int.from_bytes(b[pos:(pos := pos + int(elf.unit.Word))], byteorder=elf.endian, signed=False)
        vn_aux = int.from_bytes(b[pos:(pos := pos + int(elf.unit.Word))], byteorder=elf.endian, signed=False)
        # vn_next = int.from_bytes(b[pos:(pos := pos + int(elf.unit.Word))], byteorder=elf.endian, signed=False)

        if vn_version != 1:
            print('error: vn_version must be 1')
        if vn_aux != 0 and vn_aux != Verneed.size(elf):
            print('error: weird vn_aux offset')

        if not (dynstr_editor := StrTabEditor(elf, SECTION.DYNSTR)):
            return None

        file = dynstr_editor.get_str(vn_file)

        verneed = Verneed(file)

        verneed.version = vn_version
        verneed.cnt = vn_cnt

        return verneed

    def __init__(self, vn_file: str):
        super().__init__()

        # constants
        self.version = 1

        # init from params
        self.file = vn_file

        # just init
        self.cnt = 0
        self.aux = None

    def __str__(self):
        return '(verneed) version: ' + str(self.version) \
               + ', cnt: ' + str(self.cnt) \
               + ', file: ' + str(self.file)

    def to_bytes(self, elf: Elf) -> bytes | None:
        from ..editors.strtab_editor import StrTabEditor
        if not (dynstr_editor := StrTabEditor(elf, SECTION.DYNSTR)):
            return None

        b = self.version.to_bytes(int(elf.unit.Half), byteorder=elf.endian, signed=False)
        b += self.cnt.to_bytes(int(elf.unit.Half), byteorder=elf.endian, signed=False)
        # dynstr_sec: lief.ELF.Section = elf.get_section('.dynstr')
        if (pos := dynstr_editor.find(self.file)) >= 0:
            b += pos.to_bytes(int(elf.unit.Word), byteorder=elf.endian, signed=False)
        else:
            b += (0).to_bytes(int(elf.unit.Word), byteorder=elf.endian, signed=False)
        if self.aux:
            b += (Verneed.size(elf)).to_bytes(int(elf.unit.Word), byteorder=elf.endian, signed=False)
        else:
            b += (0).to_bytes(4, byteorder=elf.endian, signed=False)
        if self.next:
            b += (Verneed.size(elf) + self.cnt * Vernaux.size(elf)).to_bytes(int(elf.unit.Word), byteorder=elf.endian,
                                                                             signed=False)
        else:
            b += (0).to_bytes(int(elf.unit.Word), byteorder=elf.endian, signed=False)

        assert len(b) == Verneed.size(elf)

        return b


V = TypeVar('V', Veraux, Ver, Verdaux, Verdef, Vernaux, Verneed)
N = TypeVar('N', Veraux, Ver, Verdaux, Verdef, Vernaux, Verneed)


class VerauxTable(Generic[V]):
    head: V | None
    size: int

    class __Iterator(Generic[N]):
        next: N | None

        def __init__(self, head: Union[N, None]):
            self.next = head

        def __next__(self) -> N:
            if self.next:
                cur = self.next
                if self.next.next:
                    assert isinstance(self.next.next, Veraux)
                    self.next = self.next.next
                else:
                    self.next = None
                return cur
            else:
                raise StopIteration

    def __init__(self):
        self.head = None
        self.size = 0

    def __iter__(self):
        return VerauxTable.__Iterator[V](self.head)

    def __len__(self):
        return self.size

    def __getitem__(self, key: int):
        if not isinstance(key, int):
            raise TypeError('list indices must be integers')

        if not (v := self.head) or not (0 <= key <= len(self)):
            raise IndexError('list index out of range')

        if key == 0:
            return self.head
        else:
            while (next_v := v.next) and (key := key - 1):
                v = next_v
            if not next_v:
                raise IndexError('list index out of range')
            return next_v

    def __setitem__(self, key: int, value: V):
        if not isinstance(key, int):
            raise TypeError('list indices must be integers')

        self.insert(key, value)

    def append(self, version: V):
        self.size += 1

        if not (v := self.head):
            self.head = version
            return

        while next_v := v.next:
            v = next_v

        v.next = version

    def insert(self, index: int, version: V):
        if not isinstance(version, Veraux):
            raise ValueError

        self.size += 1

        if not (v := self.head):
            self.head = version
            return

        if index > 0 and index % len(self) == 0:
            index = len(self)
        else:
            index = index % len(self)

        assert 0 <= index <= len(self)

        if index == 0:
            version.next = self.head
            self.head = version
        else:
            while (next_v := v.next) and (index := index - 1):
                v = next_v
            v.next = version
            version.next = next_v


class Version(Element):
    soname: str | None
    name: str | None

    @classmethod
    def units(cls, elf: Elf) -> List[Union[ELF32, ELF64]]:
        # This must be the same with vna_other
        return [elf.unit.Half]

    @classmethod
    def from_bytes(cls, elf: Elf, b: bytes):
        from ..editors.symbol_version_editor import SymbolVersionEditor

        # symver_editor: SymbolVersionEditor = elf.get_editor(EDITOR.SYMBOL_VERSION)
        symver_editor = SymbolVersionEditor(elf)
        ver = Version()
        vna_other = cls.deserialize(elf, b)
        assert isinstance(vna_other, int)
        if vna_other != 0:
            name, soname = symver_editor.get_vername_soname_by_version(vna_other)
            ver.name = name
            ver.soname = soname
        else:
            ver.name = ver.soname = None

        return ver

    def to_bytes(self, elf: Elf) -> bytes:
        from ..editors.symbol_version_editor import SymbolVersionEditor
        # symver_editor: SymbolVersionEditor = elf.get_editor(EDITOR.SYMBOL_VERSION)
        symver_editor = SymbolVersionEditor(elf)
        if self.name:
            value = symver_editor.get_version_by_name(self.name, self.soname)
        else:
            value = 0
        return self.serialize(elf, value)

    def is_local(self):
        return not self.name

    def __str__(self):
        if self.is_local():
            return 'LOCAL'
        string = self.name or ''
        if self.soname:
            string += ' (from ' + self.soname + ')'
        return string



class VersionTable(list[Version]):
    pass


class VerdefTable(VerauxTable[Verdef]):
    head: Union[Verdef, None]
    next: Union[Verdef, None]

    def add_entry(self, vda_name: str) -> Verdef:
        vd_ndx = self[len(self) - 1].ndx + 1
        if matches := [e for e in filter(lambda e: e.ndx == vd_ndx, self)]:
            assert len(matches) == 1
            verdef: Verdef = matches[0]
            verdef.update(vda_name, vd_ndx)
        else:
            verdef = Verdef(vda_name=vda_name, vd_ndx=vd_ndx)
            self.append(verdef)

        return verdef


class VerneedTable(VerauxTable[Verneed]):
    head: Union[Verneed, None]
    next: Union[Verneed, None]

    def add_entry(self, vn_file: str, vna_name: str):
        if matches := [e for e in filter(lambda e: e.file == vn_file, self)]:
            assert len(matches) == 1
            verneed: Verneed = matches[0]
            if matches := [e for e in filter(lambda e: e.name == vna_name, verneed.veraux_table)]:
                assert len(matches) == 1
            else:
                vernaux = Vernaux(vna_name)
                verneed.append_veraux(vernaux)
        else:
            verneed = Verneed(vn_file)
            vernaux = Vernaux(vna_name)
            verneed.append_veraux(vernaux)
            self.append(verneed)
