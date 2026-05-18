# woodelf

Pure-Python ELF file parser and editor. Reads, mutates, and writes 32/64-bit ELF binaries with transactional edits — every change is staged on an `Editor`, then committed in one atomic write.

Requires `hexdump`, `sh`. Python ≥ 3.9.

## Install

```bash
pip install -e .
```

## Quick start

```python
import woodelf

elf = woodelf.parse("/path/to/binary")

# Inspect
print(elf.header)
for sh in elf.section_headers:
    print(sh.name, hex(sh.addr), sh.size)

# Edit symbols transactionally
with woodelf.transaction(elf) as tx:
    sym = elf.symbols.find("main")
    sym.value = 0x401234

elf.save("/path/to/output")
```

## API

```python
from woodelf import parse, Elf, transaction, Transaction
```

### `parse(path, toolchain_path=None, prefix='') -> Elf | None`

Open and parse an ELF file. `toolchain_path` / `prefix` let `woodelf` shell out to a cross-toolchain (`readelf`, `objdump`, …) when needed.

### `Elf`

Top-level handle to a parsed ELF. Exposes the structural elements as attributes you can iterate and edit:

| Attribute                  | Type                                  |
| -------------------------- | ------------------------------------- |
| `header`                   | `ElfHeader`                           |
| `e_ident`                  | `E_Ident`                             |
| `section_headers`          | `SectionHeaderTable[SectionHeader]`   |
| `program_headers`          | iterable of `ProgramHeader`           |
| `symbols`                  | `SymbolTable[Symbol]`                 |
| `dynamic_entries`          | iterable of `DynamicEntry`            |
| `versions`                 | `VersionTable` (`Verdef`/`Verneed`/…) |

Class methods:

* `Elf.from_path(path, toolchain_path=None, prefix='')` — same as `parse`.
* `Elf.save(out_path)` — serialise the (possibly edited) ELF.

### Editors

Each `Editor` stages mutations against a portion of the ELF. The element classes wrap editors so you can use attribute assignment directly; reach for the raw editors only when you need explicit control.

| Editor                  | Edits                                        |
| ----------------------- | -------------------------------------------- |
| `ElfHeaderEditor`       | `Elf.header` fields                          |
| `SectionHeaderEditor`   | Section header table                         |
| `ProgramHeaderEditor`   | Program header table                         |
| `SymbolEditor`          | `.symtab` / `.dynsym` entries                |
| `StrTabEditor`          | `.strtab` / `.dynstr` strings                |
| `DynamicEntryEditor`    | `.dynamic` entries                           |
| `SymbolVersionEditor`   | `.gnu.version`, `.gnu.version_d/r`           |

### `Transaction` / `transaction(elf)`

Context manager that batches edits across multiple editors. Changes are applied on `__exit__` — exit with an exception and nothing is written. Use it when an edit touches several tables (e.g. adding a symbol that needs a new name in `.dynstr` and a new version mapping).

### Elements

Concrete types exposed by the package (see `woodelf.elements`):

* Header: `ElfHeader`, `E_Ident`
* Sections / segments: `SectionHeader`, `SectionHeaderTable`, `ProgramHeader`
* Symbols: `Symbol`, `SymbolTable`
* Dynamic linker: `DynamicEntry`
* Symbol versioning: `Verdef`, `Verdaux`, `Verneed`, `Vernaux`, `Version`, `VerdefTable`, `VerneedTable`, `VerauxTable`, `VersionTable`
* Hashing: GNU hash via `woodelf.gnu_hash(name)`

### Errors

`MalformedElfError` — raised when the file fails structural validation.
