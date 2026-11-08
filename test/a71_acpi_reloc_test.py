#!/usr/bin/env python3
"""Host regression tests: python3 test/a71_acpi_reloc_test.py [ACPI.bin ...]."""
import ctypes
import errno
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
IMAGES = [Path(p) for p in sys.argv[1:]]
BASE = 0x1ec82c020


def r32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def r64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def fix(b, o, n, c):
    b[o + c] = 0
    b[o + c] = -sum(b[o:o + n]) & 255


def table(b, o, sig, n):
    b[o:o + 4] = sig
    struct.pack_into("<I", b, o + 4, n)
    fix(b, o, n, 9)


def image(base=BASE, legacy=False):
    b = bytearray(0x1000)
    b[:8] = b"RSD PTR "
    b[15] = 2
    struct.pack_into("<I", b, 20, 36)
    struct.pack_into("<Q", b, 24, base + 0x40)
    fix(b, 0, 20, 8)
    fix(b, 0, 36, 32)
    table(b, 0x40, b"XSDT", 44)
    struct.pack_into("<Q", b, 0x40 + 36, base + 0xc0)
    fix(b, 0x40, 44, 9)
    b[0x80:0x84] = b"FACS"
    struct.pack_into("<I", b, 0x84, 64)
    table(b, 0xc0, b"FACP", 148)
    struct.pack_into("<QQ", b, 0xc0 + 132, base + 0x80, base + 0x200)
    if legacy:
        struct.pack_into("<II", b, 0xc0 + 36, base + 0x80, base + 0x200)
    fix(b, 0xc0, 148, 9)
    table(b, 0x200, b"DSDT", 36)
    return b


class RelocationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="a71-acpi-test-")
        cls.addClassCleanup(cls.tmp.cleanup)
        source = Path(cls.tmp.name) / "wrapper.c"
        source.write_text('#define A71_ACPI_HOST_TEST\n'
                          '#include "arch/arm/mach-snapdragon/a71_acpi_reloc.h"\n'
                          'int run(void *b, size_t n, u64 base, u64 *old) '
                          '{ return a71_acpi_relocate(b, n, base, old); }\n')
        shared = Path(cls.tmp.name) / "reloc.so"
        subprocess.run(["gcc", "-shared", "-fPIC", "-Wall", "-Wextra", "-Werror",
                        "-fsanitize=undefined", "-I", str(ROOT), str(source),
                        "-o", str(shared)], check=True)
        cls.lib = ctypes.CDLL(str(shared))
        cls.lib.run.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint64,
                                ctypes.POINTER(ctypes.c_uint64)]
        cls.lib.run.restype = ctypes.c_int

    def run_image(self, b, base=0):
        old = ctypes.c_uint64(0xdeadbeef)
        buf = (ctypes.c_ubyte * len(b)).from_buffer(b)
        return self.lib.run(buf, len(b), base, ctypes.byref(old)), old.value

    def reject_unchanged(self, b, base=0, expected=-errno.EINVAL):
        before = bytes(b)
        self.assertEqual(self.run_image(b, base), (expected, 0xdeadbeef))
        self.assertEqual(bytes(b), before)

    def check_relocation(self, b, old_base, new_base):
        before = bytes(b)
        self.assertEqual(self.run_image(b), (0, old_base))
        self.assertEqual(bytes(b), before)
        xoff = r64(b, 24) - old_base
        pointers = [r64(b, o) for o in range(xoff + 36, xoff + r32(b, xoff + 4), 8)]
        foff = next(p - old_base for p in pointers if b[p-old_base:p-old_base+4] == b"FACP")
        fptrs = [r32(b, foff + o) if o < 132 else r64(b, foff + o)
                 for o in (36, 40, 132, 140)]
        self.assertEqual(self.run_image(b, new_base), (0, old_base))
        self.assertEqual(self.run_image(b), (0, new_base))
        self.assertEqual(r64(b, 24), new_base + xoff)
        for i, p in enumerate(pointers):
            off = p - old_base
            self.assertEqual(r64(b, xoff + 36 + i * 8), new_base + off)
            self.assertEqual(sum(b[off:off + r32(b, off + 4)]) & 255, 0)
            if off != foff:
                self.assertEqual(b[off:off + r32(b, off + 4)], before[off:off + r32(b, off + 4)])
        for o, p in zip((36, 40, 132, 140), fptrs):
            self.assertEqual(r32(b, foff + o) if o < 132 else r64(b, foff + o),
                             new_base + p - old_base if p else 0)
        self.assertEqual(sum(b[:20]) & 255, 0)
        self.assertEqual(sum(b[:r32(b, 20)]) & 255, 0)
        self.assertEqual(sum(b[xoff:xoff + r32(b, xoff + 4)]) & 255, 0)
        relocated = bytes(b)
        self.assertEqual(self.run_image(b, new_base), (0, new_base))
        self.assertEqual(bytes(b), relocated)
        # Old full images used an unaligned bloblist payload. They remain
        # valid inputs, but must never be relocated back to a bad FACS address.
        facs = [p for o, p in zip((36, 40, 132, 140), fptrs)
                if o in (36, 132) and p]
        if any(p % 64 for p in facs):
            self.reject_unchanged(b, old_base)
        else:
            self.assertEqual(self.run_image(b, old_base), (0, new_base))
            self.assertEqual(bytes(b), before)

    def test_facs_physical_alignment(self):
        self.reject_unchanged(image(), 0x90000020)
        self.reject_unchanged(image(), BASE)
        b = image()
        self.assertEqual(self.run_image(b, 0x90000040), (0, BASE))
        xoff = r64(b, 24) - 0x90000040
        foff = r64(b, xoff + 36) - 0x90000040
        self.assertEqual(r64(b, foff + 132) % 64, 0)

    def test_single_root(self):
        for base in (0x90000000, 0x200000000):
            with self.subTest(base=hex(base)):
                self.check_relocation(image(), BASE, base)

    def test_obsolete_root(self):
        b = image()
        b[0x400:0x42c] = b[0x40:0x6c]
        stale = bytes(b[0x400:0x42c])
        self.check_relocation(b, BASE, 0x200000000)
        self.assertEqual(bytes(b[0x400:0x42c]), stale)

    def test_ambiguous_roots(self):
        b = image()
        for off, n in ((0x40, 44), (0x80, 64), (0xc0, 148), (0x200, 36)):
            b[off + 0x7c0:off + 0x7c0 + n] = b[off:off + n]
        self.reject_unchanged(b)

    def test_broken_graphs(self):
        mutations = {
            "rsdp checksum": lambda b: b.__setitem__(8, b[8] ^ 1),
            "xsdt checksum": lambda b: b.__setitem__(0x49, b[0x49] ^ 1),
            "dsdt checksum": lambda b: b.__setitem__(0x209, b[0x209] ^ 1),
            "facs signature": lambda b: b.__setitem__(0x80, 0),
            "fadt out of bounds": lambda b: (struct.pack_into("<Q", b, 0x64, BASE + len(b)), fix(b, 0x40, 44, 9)),
            "short fadt": lambda b: (struct.pack_into("<I", b, 0xc4, 36), fix(b, 0xc0, 36, 9)),
            "missing fadt": lambda b: (b.__setitem__(slice(0xc0, 0xc4), b"SSDT"), fix(b, 0xc0, 148, 9)),
            "duplicate entry": lambda b: (struct.pack_into("<I", b, 0x44, 52), struct.pack_into("<Q", b, 0x6c, BASE + 0xc0), fix(b, 0x40, 52, 9)),
            "legacy rsdt": lambda b: (struct.pack_into("<I", b, 16, 0x1234), fix(b, 0, 20, 8), fix(b, 0, 36, 32)),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                b = image()
                mutate(b)
                self.reject_unchanged(b, 0x90000000)

    def test_truncated_image(self):
        self.reject_unchanged(image()[:35])
        self.reject_unchanged(image()[:0x210])

    def test_relocation_overflow(self):
        self.reject_unchanged(image(), (1 << 64) - 16, -errno.ERANGE)
        self.reject_unchanged(image(0x80000000, legacy=True), 0x200000000, -errno.ERANGE)

    def test_legacy_pointers(self):
        self.check_relocation(image(0x80000000, legacy=True), 0x80000000, 0x90000000)

    def test_supplied_images(self):
        if not IMAGES:
            self.skipTest("pass ACPI image paths to test real files")
        for path in IMAGES:
            for base in (0x90000000, 0x200000000):
                with self.subTest(image=path.name, base=hex(base)):
                    b = bytearray(path.read_bytes())
                    self.check_relocation(b, BASE, base)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]], verbosity=2)
