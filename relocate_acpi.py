#!/usr/bin/env python3
from pathlib import Path
import struct, sys

OLD_BASE = 0x1ec8ab020
DEFAULT_NEW_BASE = 0x1ec82c020


def rd32(b, o): return struct.unpack_from('<I', b, o)[0]
def rd64(b, o): return struct.unpack_from('<Q', b, o)[0]
def wr32(b, o, v): struct.pack_into('<I', b, o, v)
def wr64(b, o, v): struct.pack_into('<Q', b, o, v)

def checksum_fix(buf, start, length, checksum_off):
    buf[checksum_off] = 0
    buf[checksum_off] = (-sum(buf[start:start+length])) & 0xff

def acpi_table_checksum_fix(buf, off):
    length = rd32(buf, off + 4)
    checksum_fix(buf, off, length, off + 9)

def reloc(v, old_base, new_base, size):
    if old_base <= v < old_base + size:
        return new_base + (v - old_base)
    return v

def relocate(src: bytes, old_base: int, new_base: int) -> bytes:
    b = bytearray(src)
    size = len(b)
    if b[:8] != b'RSD PTR ':
        raise ValueError('input does not start with RSDP')
    if b[15] < 2:
        raise ValueError('expected ACPI 2.0+ RSDP')

    # RSDP XSDT pointer
    xsdt_old = rd64(b, 24)
    xsdt_new = reloc(xsdt_old, old_base, new_base, size)
    wr64(b, 24, xsdt_new)

    # XSDT entries
    xsdt_off = xsdt_old - old_base
    if not (0 <= xsdt_off <= size - 36) or b[xsdt_off:xsdt_off+4] != b'XSDT':
        raise ValueError(f'XSDT not found at expected file offset 0x{xsdt_off:x}')
    xsdt_len = rd32(b, xsdt_off + 4)
    entries = (xsdt_len - 36) // 8
    table_ptrs_old = []
    for i in range(entries):
        p_off = xsdt_off + 36 + 8*i
        p_old = rd64(b, p_off)
        table_ptrs_old.append(p_old)
        wr64(b, p_off, reloc(p_old, old_base, new_base, size))
    acpi_table_checksum_fix(b, xsdt_off)

    # Find FADT via XSDT and relocate its FACS/DSDT pointers.
    fadt_off = None
    for p_old in table_ptrs_old:
        off = p_old - old_base
        if 0 <= off <= size - 4 and b[off:off+4] == b'FACP':
            fadt_off = off
            break
    if fadt_off is None:
        raise ValueError('FADT/FACP not found from XSDT')

    # ACPI FADT offsets: FirmwareCtrl 36, DSDT 40,
    # X_FirmwareCtrl 132, X_DSDT 140.
    for rel_off in (36, 40):
        old = rd32(b, fadt_off + rel_off)
        new = reloc(old, old_base, new_base, size)
        if new > 0xffffffff:
            raise ValueError('relocated 32-bit FADT pointer exceeds 4 GiB')
        wr32(b, fadt_off + rel_off, new)
    for rel_off in (132, 140):
        old = rd64(b, fadt_off + rel_off)
        wr64(b, fadt_off + rel_off, reloc(old, old_base, new_base, size))
    acpi_table_checksum_fix(b, fadt_off)

    # RSDP checksums: legacy first 20 bytes + extended full Length bytes.
    rsdp_len = rd32(b, 20)
    checksum_fix(b, 0, 20, 8)
    checksum_fix(b, 0, rsdp_len, 32)

    return bytes(b)


def main():
    if len(sys.argv) not in (3,4):
        print(f'usage: {sys.argv[0]} INPUT OUTPUT [NEW_BASE_HEX]', file=sys.stderr)
        return 2
    inp = Path(sys.argv[1])
    out = Path(sys.argv[2])
    new_base = int(sys.argv[3], 0) if len(sys.argv) == 4 else DEFAULT_NEW_BASE
    data = inp.read_bytes()
    fixed = relocate(data, OLD_BASE, new_base)
    out.write_bytes(fixed)
    print(f'wrote {out} ({len(fixed)} bytes), relocated 0x{OLD_BASE:x} -> 0x{new_base:x}')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
