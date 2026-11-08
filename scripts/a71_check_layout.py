#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0+
"""Reject invalid A71 image layouts before creating Android boot images."""

from pathlib import Path
import json
import struct
import sys


def validate(build):
    if not __debug__:
        raise ValueError('Layout checks require Python assertions; unset PYTHONOPTIMIZE')
    build = Path(build)
    elf = (build / 'u-boot').read_bytes()
    raw = (build / 'u-boot-nodtb.bin').read_bytes()
    assert elf[:6] == b'\x7fELF\x02\x01', 'Expected little-endian ELF64'
    assert struct.unpack_from('<H', elf, 18)[0] == 183, 'Expected AArch64'
    shoff = struct.unpack_from('<Q', elf, 40)[0]
    shentsize, shnum, shstrndx = struct.unpack_from('<HHH', elf, 58)
    assert shentsize == 64 and shnum and shstrndx < shnum
    assert shoff + shnum * shentsize <= len(elf), 'Truncated ELF section table'
    sections = [struct.unpack_from('<IIQQQQIIQQ', elf, shoff + i * shentsize)
                for i in range(shnum)]

    def payload(section):
        offset, size = section[4:6]
        assert offset + size <= len(elf), 'Truncated ELF section'
        return elf[offset:offset + size]

    names = payload(sections[shstrndx])
    name = lambda table, offset: table[offset:table.index(0, offset)].decode()
    by_name = {name(names, s[0]): s for s in sections}
    symbols = {}
    for section in sections:
        if section[1] != 2:  # SHT_SYMTAB
            continue
        strings = payload(sections[section[6]])
        assert section[9] == 24
        for offset in range(section[4], section[4] + section[5], 24):
            index, info, other, shndx, value, size = struct.unpack_from('<IBBHQQ', elf, offset)
            if index:
                symbols[name(strings, index)] = value

    start = symbols['_start']
    copy_end = symbols['__image_copy_end'] - start
    bss_start = symbols['__bss_start'] - start
    bss_end = symbols['__bss_end'] - start
    assert 0 < copy_end <= bss_start < bss_end, (
        f'BSS overlaps executable image: copy_end={copy_end:#x}, '
        f'bss={bss_start:#x}..{bss_end:#x}')
    assert not (bss_start & 7 or bss_end & 7), 'BSS bounds are not 8-byte aligned'
    # GNU ld's OVERLAY section is non-allocated PROGBITS; LLD uses NOBITS.
    # U-Boot clears it itself, so validate its addresses rather than its type.
    assert not by_name['.bss'][2] & 4, 'BSS must not be executable'
    assert by_name['.bss'][3] == symbols['__bss_start'], 'BSS section/symbol address mismatch'
    assert by_name['.bss'][5] == bss_end - bss_start, 'BSS size mismatch'
    assert len(raw) == symbols['_end'] - start, 'Flat binary is truncated or oversized'
    assert raw[56:60] == b'ARM\x64', 'Missing ARM64 image header'
    image_size = struct.unpack_from('<Q', raw, 16)[0]
    assert struct.unpack_from('<Q', raw, 72)[0] == len(raw), 'Binary end header mismatch'
    assert struct.unpack_from('<QQ', raw, 80) == (bss_start, bss_end), 'BSS header mismatch'
    assert image_size >= max(len(raw), bss_end), 'Image header understates memory use'
    config = (build / '.config').read_text().splitlines()
    stack_offset = int(next(line.split('=')[1] for line in config
                            if line.startswith('CONFIG_SYS_INIT_SP_BSS_OFFSET=')), 0)
    assert image_size == bss_start + max(bss_end - bss_start, stack_offset), 'Initial stack is outside advertised memory'
    if 'CONFIG_EFI_LOADER=y' in config:
        runtime_reloc = by_name['.efi_runtime_rel']
        assert runtime_reloc[5] > 0 and runtime_reloc[5] % 24 == 0, 'Missing EFI runtime relocations'
    dtb = (build / 'u-boot.dtb').read_bytes()
    assert dtb[:4] == b'\xd0\x0d\xfe\xed', 'Missing device-tree header'
    assert struct.unpack_from('>I', dtb, 4)[0] == len(dtb), 'Truncated device tree'
    assert b'samsung,a715f\0' in dtb, 'Device tree does not identify the Galaxy A71'
    reloc = by_name['.rela.dyn']
    assert reloc[5] % 24 == 0
    for offset in range(reloc[4], reloc[4] + reloc[5], 24):
        destination, info, addend = struct.unpack_from('<QQq', elf, offset)
        assert info & 0xffffffff in (0, 1027), 'Unsupported runtime relocation'
        if info & 0xffffffff:
            assert start <= destination <= start + copy_end - 8, 'Relocation writes outside copied image'
    return {
        'binary_size': len(raw), 'image_memory_size': hex(image_size),
        'copied_image_end': hex(copy_end),
        'bss_start': hex(bss_start), 'bss_end': hex(bss_end),
        'runtime_relocations': reloc[5] // 24,
        'device_tree_size': len(dtb),
    }


if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit('Usage: a71_check_layout.py BUILD_DIRECTORY')
    try:
        print(json.dumps(validate(sys.argv[1]), indent=2))
    except (AssertionError, KeyError, ValueError, struct.error, OSError, StopIteration) as error:
        sys.exit(f'REJECTED: {error}')
