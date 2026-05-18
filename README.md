# woodelf

Pure-Python ELF file parser and editor. Reads and rewrites 32/64-bit ELF binaries via a small set of editor classes, each scoped to one structural region of the file (header, section headers, symbols, dynamic entries, …).

Requires GNU `binutils` (`objcopy`, `objdump`, `readelf`) on `PATH`, plus `hexdump` and `sh`. Python ≥ 3.9.

## Install

```bash
pip install -e .
```

## Quick start

```python
import woodelf
from woodelf import (
    ElfHeaderEditor,
    SectionHeaderEditor,
    SymbolEditor,
    DynamicEntryEditor,
    SECTION,
)

elf = woodelf.parse("/path/to/binary")

# Inspect the ELF header
hdr = ElfHeaderEditor(elf).read_elf_header()
print(hdr.typ, hex(hdr.entry))

# Walk section headers
for sh in SectionHeaderEditor(elf).read_section_header_table():
    print(sh.name, hex(sh.addr), sh.siz)

# Mutate a symbol's value, then save to a new path
syms_editor = SymbolEditor(elf, SECTION.SYMTAB)
syms = syms_editor.read_symbol_table()
main = next(s for s in syms if s.name == "main")
main.value = 0x401234
syms_editor.write_symbol_table(syms)

elf.write("/path/to/output")
```

## API

```python
from woodelf import (
    parse, Elf, MalformedElfError, SECTION, gnu_hash,
    ElfHeaderEditor, SectionHeaderEditor, ProgramHeaderEditor,
    SymbolEditor, StrTabEditor, DynamicEntryEditor, SymbolVersionEditor,
)
```

### `parse(path, toolchain_path=None, prefix='') -> Elf | None`

Open and parse an ELF file. Returns `None` if the file isn't an ELF (bad magic, truncated e_ident). `toolchain_path` / `prefix` let `woodelf` shell out to a cross-toolchain (`prefix + 'readelf'`, `prefix + 'objcopy'`, …) when needed — useful for embedded targets.

### `Elf`

Handle to a parsed ELF. The class itself exposes file-level concerns; structural elements are accessed through their respective editors (see below).

| Attribute / method            | What it gives you                                              |
| ----------------------------- | -------------------------------------------------------------- |
| `Elf.from_path(path, ...)`    | Same as `parse(...)`                                           |
| `elf.unit`                    | `ELF32` or `ELF64` (size enum used for serialization)          |
| `elf.endian`                  | `'little'` or `'big'`                                          |
| `elf.revisions`               | List of file paths; each edit produces a new revision          |
| `elf.get_current_revision()`  | Path to the latest revision                                    |
| `elf.write(path)`             | Copy the current revision to `path` (creates parent dirs)      |
| `elf.iter_objdump_sections()` | Yields the section summary that `objdump -h` produces          |

### Editors

Each editor stages mutations against one region of the ELF. Read methods return element objects (`ElfHeader`, `SectionHeader`, `Symbol`, `DynamicEntry`, …); write methods serialize them back. Most write paths are in-place (direct file I/O); content-changing writes (e.g. resizing a section) go through `objcopy --update-section`, which appends a new revision to `elf.revisions`.

| Editor                  | Constructed as                                  | Edits                                        |
| ----------------------- | ----------------------------------------------- | -------------------------------------------- |
| `ElfHeaderEditor`       | `ElfHeaderEditor(elf)`                          | ELF header fields                            |
| `SectionHeaderEditor`   | `SectionHeaderEditor(elf)`                      | Section header table                         |
| `ProgramHeaderEditor`   | `ProgramHeaderEditor(elf)`                      | Program header table                         |
| `SymbolEditor`          | `SymbolEditor(elf, SECTION.SYMTAB)` or `.DYNSYM`| `.symtab` / `.dynsym` entries                |
| `StrTabEditor`          | `StrTabEditor(elf, SECTION.STRTAB)` etc.        | `.strtab` / `.dynstr` / `.shstrtab` strings  |
| `DynamicEntryEditor`    | `DynamicEntryEditor(elf)`                       | `.dynamic` entries                           |
| `SymbolVersionEditor`   | `SymbolVersionEditor(elf)`                      | `.gnu.version`, `.gnu.version_d/r`           |

### Elements

Concrete types returned by the editors (see `woodelf.elements`):

* Header: `ElfHeader`, `E_Ident`
* Sections / segments: `SectionHeader`, `SectionHeaderTable`, `ProgramHeader`
* Symbols: `Symbol`, `SymbolTable` (with `defined_symbols()` / `needed_symbols()` filters)
* Dynamic linker: `DynamicEntry`
* Symbol versioning: `Verdef`, `Verdaux`, `Verneed`, `Vernaux`, `Version`, `VerdefTable`, `VerneedTable`, `VerauxTable`, `VersionTable`
* Hashing: GNU hash via `woodelf.gnu_hash(name)`

### Errors

`MalformedElfError` — raised when the file fails structural validation (e.g. a section header table that runs past the end of the file).
