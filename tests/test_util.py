from unittest import TestCase

from woodelf.util import (
    MalformedElfError,
    gnu_hash,
    gnu_hash_binutils_bfd_elf,
    gnu_hash_bionic_linker_linker_sofinfo,
    readelf_hexdump_to_bytearray,
    unpack_bytes_to_ints,
)


class TestGnuHashBionic(TestCase):
    # Reference values can be reproduced by running the C version of
    # bionic's calculate_elf_hash on these strings.

    def test_empty_string_returns_zero(self):
        self.assertEqual(gnu_hash_bionic_linker_linker_sofinfo(''), 0)

    def test_single_char(self):
        # h = (0 << 4) + ord('a') = 0x61, g = 0, return 0x61
        self.assertEqual(gnu_hash_bionic_linker_linker_sofinfo('a'), 0x61)

    def test_known_string_printf(self):
        # standard test vector reproduced from bionic source
        # h after 'printf': computed step-by-step
        self.assertEqual(
            gnu_hash_bionic_linker_linker_sofinfo('printf'),
            self._reference('printf'),
        )

    def test_result_fits_in_uint32(self):
        h = gnu_hash_bionic_linker_linker_sofinfo('a_long_symbol_name_that_overflows_things')
        self.assertGreaterEqual(h, 0)
        self.assertLessEqual(h, 0xFFFFFFFF)

    def test_gnu_hash_uses_bionic(self):
        for s in ['', 'a', 'printf', 'libc.so.6']:
            self.assertEqual(gnu_hash(s), gnu_hash_bionic_linker_linker_sofinfo(s))

    @staticmethod
    def _reference(name: str) -> int:
        h = 0
        for ch in name.encode('ascii'):
            h = ((h << 4) + ch) & 0xFFFFFFFF
            g = h & 0xF0000000
            h ^= g
            h ^= g >> 24
        return h


class TestGnuHashBinutils(TestCase):
    def test_empty_returns_zero(self):
        self.assertEqual(gnu_hash_binutils_bfd_elf(''), 0)

    def test_single_char(self):
        self.assertEqual(gnu_hash_binutils_bfd_elf('a'), 0x61)

    def test_result_fits_in_uint32(self):
        h = gnu_hash_binutils_bfd_elf('some_arbitrary_symbol_name')
        self.assertGreaterEqual(h, 0)
        self.assertLessEqual(h, 0xFFFFFFFF)


class TestReadelfHexdumpToBytearray(TestCase):
    def test_parses_typical_dump(self):
        # readelf -x output: two header lines, then "addr  w1 w2 w3 w4  ascii"
        dump = (
            "Hex dump of section '.foo':\n"
            "header line 2 is also skipped\n"
            "  0x00000000 deadbeef cafebabe 12345678 9abcdef0  ASCII\n"
        )
        result = readelf_hexdump_to_bytearray(dump)
        expected = bytes.fromhex('deadbeef' 'cafebabe' '12345678' '9abcdef0')
        self.assertEqual(bytes(result), expected)

    def test_skips_empty_lines(self):
        dump = (
            "Hex dump\n"
            "second header\n"
            "\n"
            "  0x00000000 00112233  ....\n"
        )
        result = readelf_hexdump_to_bytearray(dump)
        self.assertEqual(bytes(result), bytes.fromhex('00112233'))

    def test_returns_empty_for_no_data(self):
        result = readelf_hexdump_to_bytearray("hdr1\nhdr2\n")
        self.assertEqual(bytes(result), b'')

    def test_short_word_size(self):
        dump = "hdr1\nhdr2\n  0x00000000 abcd  ..\n"
        result = readelf_hexdump_to_bytearray(dump)
        self.assertEqual(bytes(result), bytes.fromhex('abcd'))


class TestUnpackBytesToInts(TestCase):
    def test_byte_segments_little_endian(self):
        b = bytes([1, 0, 2, 0, 3, 0, 4, 0])
        self.assertEqual(
            unpack_bytes_to_ints(b, segment_size=2, byteorder='little'),
            [1, 2, 3, 4],
        )

    def test_byte_segments_big_endian(self):
        b = bytes([0, 1, 0, 2, 0, 3])
        self.assertEqual(
            unpack_bytes_to_ints(b, segment_size=2, byteorder='big'),
            [1, 2, 3],
        )

    def test_signed_negative(self):
        b = (-1).to_bytes(4, 'little', signed=True)
        self.assertEqual(
            unpack_bytes_to_ints(b, segment_size=4, byteorder='little', signed=True),
            [-1],
        )

    def test_single_byte_segments(self):
        b = bytes([1, 2, 3, 4, 5])
        self.assertEqual(
            unpack_bytes_to_ints(b, segment_size=1, byteorder='little'),
            [1, 2, 3, 4, 5],
        )

    def test_size_mismatch_asserts(self):
        with self.assertRaises(AssertionError):
            unpack_bytes_to_ints(b'\x00\x01\x02', segment_size=2, byteorder='little')

    def test_empty_input_returns_empty(self):
        self.assertEqual(unpack_bytes_to_ints(b'', segment_size=4, byteorder='little'), [])


class TestMalformedElfError(TestCase):
    def test_is_exception_subclass(self):
        self.assertTrue(issubclass(MalformedElfError, Exception))

    def test_can_be_raised_with_message(self):
        with self.assertRaises(MalformedElfError) as ctx:
            raise MalformedElfError('bad magic')
        self.assertIn('bad magic', str(ctx.exception))
