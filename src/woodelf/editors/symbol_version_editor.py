from typing import Union, List, Tuple

from .. import api, gnu_hash
from ..core import Editor, Elf, Section
from ..elements import Verdef, Verdaux, Verneed, Vernaux, DynamicEntry, VersionTable, VerdefTable, VerneedTable, Version
from ..constants import SECTION, EDITOR, DYNAMIC_ENTRY_TAG

from .dynamic_entry_editor import DynamicEntryEditor
from .strtab_editor import StrTabEditor


class SymbolVersionEditor(Editor, api.SymbolVersionEditor):
    version: Section
    version_d: Section
    version_r: Section

    dynent_editor: DynamicEntryEditor
    dynstr_editor: StrTabEditor

    def __init__(self, elf: Elf):
        super().__init__(elf)

        self.version = elf.get_section(SECTION.GNU_VERSION)
        self.version_d = elf.get_section(SECTION.GNU_VERSION_D)
        self.version_r = elf.get_section(SECTION.GNU_VERSION_R)

        self.dynent_editor = self.elf.get_editor(EDITOR.DYNAMIC_ENTRY)
        self.dynstr_editor = self.elf.get_editor(EDITOR.STRTAB, SECTION.DYNSTR)

    def read_versions(self, rev_idx: int = -1) -> VersionTable:
        version_table = VersionTable()

        c = self.version.read_content(rev_idx=rev_idx)

        while c:
            ver_bytes = c[0:Version.size(self.elf)]
            c = c[Version.size(self.elf):]
            ver = Version.from_bytes(self.elf, ver_bytes)
            version_table.append(ver)

        return version_table

    def read_version_definition(self, rev_idx: int = -1) -> VerdefTable:
        verdef_table = VerdefTable()

        c = self.version_d.read_content(rev_idx=rev_idx)

        while c:
            verdef_bytes = c[0:Verdef.size(self.elf)]
            c = c[Verdef.size(self.elf):]
            verdef = Verdef.from_bytes(self.elf, verdef_bytes)
            for i in range(verdef.cnt):
                verdaux_bytes = c[0:Verdaux.size(self.elf)]
                c = c[Verdaux.size(self.elf):]
                verdaux = Verdaux.from_bytes(self.elf, verdaux_bytes)
                verdef.append_veraux(verdaux)
            verdef_table.append(verdef)

        return verdef_table

    def read_version_requirement(self, rev_idx: int = -1) -> VerneedTable:
        verneed_table = VerneedTable()

        c = self.version_r.read_content(rev_idx=rev_idx)

        while c:
            verneed_bytes = c[0:Verneed.size(self.elf)]
            c = c[Verneed.size(self.elf):]
            verneed = Verneed.from_bytes(self.elf, verneed_bytes)
            for i in range(verneed.cnt):
                vernaux_bytes = c[0:Vernaux.size(self.elf)]
                c = c[Vernaux.size(self.elf):]
                vernaux = Vernaux.from_bytes(self.elf, vernaux_bytes)
                verneed.append_veraux(vernaux)
            verneed_table.append(verneed)

        return verneed_table

    def __adjust_DT_VERDEFNUM(self, verdef_table: VerdefTable):

        dynlist: List[DynamicEntry] = self.dynent_editor.read_dynamic_entries()

        for dyn in filter(lambda e: e.tag == DYNAMIC_ENTRY_TAG.DT_VERDEFNUM, dynlist):
            dyn.un = len(verdef_table)

        self.dynent_editor.write_dynamic_entries(dynlist)

    def __adjust_DT_VERNEEDNUM(self, verneed_table: VerneedTable):
        dynlist: List[DynamicEntry] = self.dynent_editor.read_dynamic_entries()

        for dyn in filter(lambda e: e.tag == DYNAMIC_ENTRY_TAG.DT_VERNEEDNUM, dynlist):
            dyn.un = len(verneed_table)

        self.dynent_editor.write_dynamic_entries(dynlist)

    def __adjust_VERSION_D_section_info(self, verdef_table: VerdefTable):
        sheditor = self.elf.get_editor(EDITOR.SECTION_HEADER)
        sh = sheditor.read_section_header(SECTION.GNU_VERSION_D)

        sh.info = len(verdef_table)

        sheditor.write_section_header(SECTION.GNU_VERSION_D, sh)

    def __adjust_VERSION_R_section_info(self, verneed_table: VerneedTable):
        sheditor = self.elf.get_editor(EDITOR.SECTION_HEADER)
        sh = sheditor.read_section_header(SECTION.GNU_VERSION_R)

        sh.info = len(verneed_table)

        sheditor.write_section_header(SECTION.GNU_VERSION_R, sh)
        
    def __write_versions(self, version_table: VersionTable):
        assert len(version_table) == len(self.read_versions())

        b = bytes()
        for ver in version_table:
            ver: Version
            b += ver.to_bytes(self.elf)

        self.version.write_content(b)

    def __write_version_definition(self, verdef_table: VerdefTable):
        b = bytes()
        for verdef in verdef_table:
            verdef: Verdef
            b += verdef.to_bytes(self.elf)
            if not verdef.veraux_table:
                continue
            for verdaux in verdef.veraux_table:
                if not self.dynstr_editor.has(verdaux.name):
                    self.dynstr_editor.append(verdaux.name)
                b += verdaux.to_bytes(self.elf)

        self.version_d.write_content(b)

        self.__adjust_DT_VERDEFNUM(verdef_table)
        self.__adjust_VERSION_D_section_info(verdef_table)

    def __write_version_requirement(self, verneed_table: VerneedTable):
        vna_other = len(self.read_version_definition())
        b = bytes()
        for verneed in verneed_table:
            verneed: Verneed
            b += verneed.to_bytes(self.elf)
            if not verneed.veraux_table:
                continue
            for vernaux in verneed.veraux_table:
                if not self.dynstr_editor.has(vernaux.name):
                    self.dynstr_editor.append(vernaux.name)
                vernaux.other = (vna_other := vna_other + 1)

                b += vernaux.to_bytes(self.elf)

        self.version_r.write_content(b)

        self.__adjust_DT_VERNEEDNUM(verneed_table)
        self.__adjust_VERSION_R_section_info(verneed_table)

    def write(self, version_table: VersionTable = None, verdef_table: VerdefTable = None,
              verneed_table: VerneedTable = None):

        if (version_table is None) and (verdef_table is None) and (verneed_table is None):
            return

        if version_table is None:
            version_table = self.read_versions()
        if verdef_table is None:
            verdef_table = self.read_version_definition()
        if verneed_table is None:
            verneed_table = self.read_version_requirement()

        # The order of writing definitions, requirements, and versions is important
        self.__write_version_definition(verdef_table)
        self.__write_version_requirement(verneed_table)
        self.__write_versions(version_table)

    def __get_version_from_verdeftab(self, vername: str) -> int:
        verdeftab = self.read_version_definition()
        for verdef in verdeftab:
            verdef: Verdef
            if verdef.hash == gnu_hash(vername):
                return verdef.ndx
        return -1

    def __get_version_from_verneedtab(self, vername: str, soname: str = None) -> int:
        # print(self.elf.get_editor(EDITOR.DYNAMIC_ENTRY).read_soname())
        # print(self)
        # print('__get_version_from_verneedtab')
        verneedtab = self.read_version_requirement()
        for verneed in verneedtab:
            verneed: Verneed
            # print(verneed)
            if soname and (verneed.file != soname):
                continue
            if not verneed.veraux_table:
                continue
            for vernaux in verneed.veraux_table:
                vernaux: Vernaux
                # print(vernaux)
                if vernaux.name == vername:
                    return vernaux.other
        return -1

    def get_version_by_name(self, vername: str, soname: str = None) -> int:
        dynent_edit: DynamicEntryEditor = self.elf.get_editor(EDITOR.DYNAMIC_ENTRY)
        if not soname:
            if (ver := self.__get_version_from_verdeftab(vername)) < 0:
                ver = self.__get_version_from_verneedtab(vername)
        elif soname == dynent_edit.read_soname():
            ver = self.__get_version_from_verdeftab(vername)
        else:
            ver = self.__get_version_from_verneedtab(vername, soname)
        if ver < 0:
            errstr = 'No proper version associated with version ' + vername
            if soname:
                errstr += ' from ' + soname
            raise KeyError(errstr)
        return ver

    def get_vername_soname_by_version(self, idx: int) -> Tuple[str, str]:
        if idx == 0:
            raise ValueError('Local symbols (indicated by zero version number) does not have associated vername and '
                             'soname')

        dynent_editor: DynamicEntryEditor = self.elf.get_editor(EDITOR.DYNAMIC_ENTRY)

        for verdef in self.read_version_definition():
            verdef: Verdef
            if verdef.get_ndx() == idx:
                verdaux: Verdaux = next(verdef.veraux_table.__iter__())
                return verdaux.name, dynent_editor.read_soname()

        for verneed in self.read_version_requirement():
            verneed: Verneed
            for vernaux in verneed.veraux_table:
                vernaux: Vernaux
                if vernaux.other == idx:
                    return vernaux.name, verneed.file

        raise KeyError

    def __str_version_definition(self):
        verdef_table = self.read_version_definition()
        string = '=======\nSection .gnu.version_d\n-------\n'
        for verdef in verdef_table:
            verdef: Verneed
            string += str(verdef) + '\n'
            if not verdef.veraux_table:
                continue
            for verdaux in verdef.veraux_table:
                string += str(verdaux) + '\n'
        return string

    def __str_version_requirement(self):
        verneed_table = self.read_version_requirement()
        string = '=======\nSection .gnu.version_r\n-------\n'
        for verneed in verneed_table:
            verneed: Verneed
            string += str(verneed) + '\n'
            if not verneed.veraux_table:
                continue
            for vernaux in verneed.veraux_table:
                string += str(vernaux) + '\n'
        return string

    def __str__(self):
        string = ''
        string += self.__str_version_definition()
        string += self.__str_version_requirement()

        # string += str(self.dynent_editor)
        return string
