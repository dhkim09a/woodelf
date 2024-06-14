from typing import Union

from woodelf import ELF_CLASS, ELF_DATA, ELF_VERSION, NotAnElfError


class E_Ident:
    magic: bytes
    cls: Union[ELF_CLASS, int]
    data: Union[ELF_DATA, int]
    version: Union[ELF_VERSION, int]
    padding: bytes

    def __init__(self, magic: bytes, cls: ELF_CLASS, data: ELF_DATA, version: ELF_VERSION, padding: bytes):
        self.magic = magic
        self.cls = cls
        self.data = data
        self.version = version
        self.padding = padding

    @classmethod
    def size(cls):
        return 16

    @classmethod
    def from_bytes(cls, b: bytes):
        if len(b) < cls.size():
            raise NotAnElfError('file is too small')

        assert len(b) == cls.size()

        ei_magic = b[0:4]
        ei_cls = b[4]
        ei_data = b[5]
        ei_version = b[6]
        ei_pad = b[7:]

        if ei_magic != '\x7fELF'.encode('ascii'):
            raise NotAnElfError('magic field does not match')

        return E_Ident(ei_magic,
                       ELF_CLASS(int(ei_cls)),
                       ELF_DATA(int(ei_data)),
                       ELF_VERSION(int(ei_version)),
                       ei_pad)

    def to_bytes(self):
        b = self.magic + bytes([int(self.cls), int(self.data), int(self.version)]) + self.padding

        assert len(b) == self.size()

        return b

    def __str__(self):
        string = 'E_IDENT{'
        string += 'magic: ' + self.magic.decode('ascii', errors='ignore') + ', '
        string += 'class: ' + str(self.cls) + ', '
        string += 'data: ' + str(self.data) + ', '
        string += 'version: ' + str(self.version) + ', '
        string += 'padding: ' + str(self.padding) + '}'
        return string
