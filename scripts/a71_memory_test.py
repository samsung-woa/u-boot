#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0+
"""Host checks of A71 reservations and the real bloblist allocation code.

Usage: python3 scripts/a71_memory_test.py FIXED.dtb BASELINE.dtb
No hardware is accessed. Production functions are compiled with host stubs.
"""
from pathlib import Path
import os
import re
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def function(source, name):
    match = re.search(r'(?m)^(?:static (?:inline )?)?'
                      r'(?:int|uint|ulong|bool|void|struct bloblist_rec|enum efi_memory_type)'
                      r'\s+\*?' + re.escape(name) + r'\(', source)
    if not match:
        raise ValueError(name)
    masked = re.sub(r'/\*[\s\S]*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"',
                    lambda m: ' ' * len(m[0]), source)
    start = masked.index('{', match.end())
    depth, end = 1, start + 1
    while depth:
        depth += (masked[end] == '{') - (masked[end] == '}')
        end += 1
    return source[match.start():end] + '\n'


def fdt(path):
    data = Path(path).read_bytes()
    magic, total, pos, strings_off, _, _, _, _, strings_len, size = struct.unpack_from('>10I', data)
    assert magic == 0xd00dfeed and total == len(data)
    end = pos + size
    strings = data[strings_off:strings_off + strings_len]
    stack, nodes = [], {}
    while pos < end:
        tag = struct.unpack_from('>I', data, pos)[0]
        pos += 4
        if tag == 1:
            terminator = data.index(0, pos)
            stack.append(data[pos:terminator].decode())
            pos = (terminator + 4) & ~3
            nodes['/'.join(stack)] = {}
        elif tag == 2:
            stack.pop()
        elif tag == 3:
            length, offset = struct.unpack_from('>II', data, pos)
            pos += 8
            name = strings[offset:strings.index(0, offset)].decode()
            nodes['/'.join(stack)][name] = data[pos:pos + length]
            pos = (pos + length + 3) & ~3
        elif tag == 9:
            break
        else:
            assert tag == 4
    return nodes


COMMON = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;
typedef unsigned int uint;
typedef unsigned long ulong;
typedef uint64_t phys_addr_t;
typedef uint64_t phys_size_t;
typedef unsigned long efi_status_t;
#define ALIGN(x,a) (((x)+(a)-1)&~((__typeof__(x))(a)-1))
#define round_up(x,a) ALIGN(x,a)
#define IS_ALIGNED(x,a) (!((x)&((a)-1)))
#define EFI_PAGE_SIZE 4096UL
#define EFI_PAGE_SHIFT 12
#define EFI_PAGE_MASK 4095UL
#define EFI_SUCCESS 0
#define EFI_ERROR_MASK (1UL<<63)
#undef __weak
#define __weak
#define log_err(...) do {} while (0)
#define log_msg_ret(msg,ret) (ret)
enum efi_memory_type { EFI_RESERVED_MEMORY_TYPE=0, EFI_BOOT_SERVICES_DATA=4,
    EFI_CONVENTIONAL_MEMORY=7, EFI_ACPI_RECLAIM_MEMORY=9, EFI_ACPI_MEMORY_NVS=10 };
'''


def run_native(source, name, temp):
    path = temp / (name + '.c')
    binary = temp / name
    path.write_text(COMMON + source)
    subprocess.run([os.environ.get('HOSTCC', 'cc'), '-std=gnu11', '-Wall', '-Wextra',
                    '-Wno-unused-parameter', '-Wno-sign-compare', '-Werror', '-fsanitize=undefined',
                    str(path), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=15)


def reservation_test(nodes, temp):
    rows = []
    for path, props in nodes.items():
        if not path.startswith('/reserved-memory/') or path.count('/') != 2 or 'reg' not in props:
            continue
        regs = list(struct.iter_unpack('>QQ', props['reg']))
        assert len(regs) <= 2
        entries = ','.join('{%dULL,%dULL}' % (base, base + size - 1)
                           for base, size in regs)
        rows.append('{%d,%d,%d,{%s}}' % (props.get('status') != b'disabled\0',
                    'reusable' in props, len(regs), entries))
    source = r'''
typedef int ofnode;
struct resource { u64 start, end; };
#define resource_size(r) ((r)->end-(r)->start+1)
struct node { bool enabled, reusable; uint count; struct resource resources[2]; };
static struct node nodes[] = { ROWS };
static int node_count=sizeof(nodes)/sizeof(nodes[0]), is_a71=1, map_count;
static struct {u64 start,size; int type;} maps[1024];
static bool of_machine_is_compatible(const char *s) { (void)s; return is_a71; }
static ofnode ofnode_path(const char *s) { (void)s; return 0; }
static bool ofnode_is_enabled(ofnode n) { return nodes[n].enabled; }
static bool ofnode_read_bool(ofnode n,const char *s) { (void)s; return nodes[n].reusable; }
static int ofnode_read_resource(ofnode n,uint i,struct resource *r) {
    if(i>=nodes[n].count) return -ENOENT; *r=nodes[n].resources[i]; return 0;
}
#define ofnode_for_each_subnode(n,p) for(n=0;(p)>=0&&n<node_count;++n)
static efi_status_t efi_add_memory_map(u64 start,u64 size,int type) {
    assert(map_count<1024); maps[map_count].start=start; maps[map_count].size=size;
    maps[map_count++].type=type; return EFI_SUCCESS;
}
static efi_status_t efi_update_memory_map(u64 start,u64 pages,int type,bool overlap,bool remove) {
    assert(!overlap&&!remove&&!(start&4095)); return efi_add_memory_map(start,pages*4096,type);
}
static void *map_sysmem(u64 addr,u64 size) { (void)size; return (void *)(uintptr_t)addr; }
static void unmap_sysmem(void *addr) { (void)addr; }
static u64 efi_size_in_pages(u64 size) { return (size+4095)/4096; }
enum lmb_map_op { LMB_MAP_OP_ADD,LMB_MAP_OP_RESERVE,LMB_MAP_OP_FREE };
'''.replace('ROWS', ',\n'.join(rows) + ',{0,0,1,{{0x120000000,0x120000fff}}},'
           '{1,1,1,{{0x130000000,0x130000fff}}},{1,0,1,{{0,UINT64_MAX}}}')
    board = (ROOT / 'arch/arm/mach-snapdragon/board.c').read_text()
    memory = (ROOT / 'lib/efi_loader/efi_memory.c').read_text()
    for name in ('a71_fixed_reservation', 'efi_add_known_memory',
                 'efi_board_lmb_memory_type', 'efi_acpi_blob_memory_type'):
        source += function(board, name)
    source += function(memory, 'efi_map_update_notify')
    source += r'''
int main(void) {
    int expected=0;
    for(int n=0;n<node_count;++n) for(uint i=0;i<nodes[n].count;++i) {
        struct resource r=nodes[n].resources[i];
        if(nodes[n].enabled&&!nodes[n].reusable&&resource_size(&r)) ++expected;
    }
    efi_add_known_memory(); assert(map_count==expected);
    for(int i=0;i<map_count;++i) assert(maps[i].type==EFI_RESERVED_MEMORY_TYPE&&maps[i].size);
    for(int n=0;n<node_count;++n) for(uint i=0;i<nodes[n].count;++i) {
        struct resource r=nodes[n].resources[i];
        bool fixed=nodes[n].enabled&&!nodes[n].reusable&&resource_size(&r);
        if(!resource_size(&r)) continue;
        assert(!efi_map_update_notify(r.start,resource_size(&r),LMB_MAP_OP_RESERVE));
        assert(maps[map_count-1].type==(fixed?EFI_RESERVED_MEMORY_TYPE:EFI_BOOT_SERVICES_DATA));
        assert(!efi_map_update_notify(r.start,resource_size(&r),LMB_MAP_OP_FREE));
        assert(maps[map_count-1].type==(fixed?EFI_RESERVED_MEMORY_TYPE:EFI_CONVENTIONAL_MEMORY));
    }
    /* Whole DRAM banks must remain usable, including banks containing carveouts. */
    assert(!efi_map_update_notify(0x80000000,0x80000000,LMB_MAP_OP_ADD));
    assert(maps[map_count-1].type==EFI_CONVENTIONAL_MEMORY);
    assert(!efi_map_update_notify(0x100000000,0xfcb00000,LMB_MAP_OP_ADD));
    assert(maps[map_count-1].type==EFI_CONVENTIONAL_MEMORY);
    assert(!efi_map_update_notify(0x1e0000000,4096,LMB_MAP_OP_RESERVE));
    assert(maps[map_count-1].type==EFI_BOOT_SERVICES_DATA);
    assert(efi_board_lmb_memory_type(UINT64_MAX,2,EFI_BOOT_SERVICES_DATA)==EFI_BOOT_SERVICES_DATA);
    assert(efi_acpi_blob_memory_type()==EFI_ACPI_MEMORY_NVS);
    int before=map_count; is_a71=0; efi_add_known_memory(); assert(map_count==before);
    assert(efi_acpi_blob_memory_type()==EFI_ACPI_RECLAIM_MEMORY);
    assert(efi_board_lmb_memory_type(0x85d00000,4096,EFI_BOOT_SERVICES_DATA)==EFI_BOOT_SERVICES_DATA);
    assert(efi_board_lmb_memory_type(0x85d00000,4096,EFI_CONVENTIONAL_MEMORY)==EFI_CONVENTIONAL_MEMORY);
    puts("PASS: fixed reservations, 64-bit addresses, repeat/free notifications, usable DRAM, non-A71 defaults");
}
'''
    run_native(source, 'reservations', temp)


def bloblist_test(temp):
    header = (ROOT / 'include/bloblist.h').read_text()
    source = ''.join(re.search(r'struct ' + name + r' \{[\s\S]*?\n\};', header)[0] + '\n'
                     for name in ('bloblist_hdr', 'bloblist_rec'))
    source += r'''
#define BLOBLIST_BLOB_ALIGN_LOG2 3
#define BLOBLISTT_VOID 0
#define BLOBLISTT_ACPI_TABLES 4
#define BLOBLISTR_HDR_SIZE_SHIFT 24
#define BLOBLISTR_HDR_SIZE_MASK 0xff000000U
#define BLOBLISTR_TAG_MASK 0xffffffU
#define BLOBLISTR_TAG_SHIFT 0
static u8 buffer[0x100000];
static u64 physical_base;
static struct {struct bloblist_hdr *bloblist;} storage, *gd=&storage;
static ulong map_to_sysmem(void *p) { return physical_base+(u8 *)p-buffer; }
static ulong bloblist_get_total_size(void) { return gd->bloblist->total_size; }
'''
    bloblist = (ROOT / 'common/bloblist.c').read_text()
    for name in ('bloblist_first_blob', 'rec_hdr_size', 'rec_tag',
                 'bloblist_blob_end_ofs', 'bloblist_next_blob'):
        source += function(bloblist, name)
    source += '#define foreach_rec(r,h) for(r=bloblist_first_blob(h);r;r=bloblist_next_blob(h,r))\n'
    for name in ('bloblist_findrec', 'bloblist_addrec', 'bloblist_ensurerec',
                 'bloblist_ensure_size', 'bloblist_get_blob'):
        source += function(bloblist, name)
    board = (ROOT / 'arch/arm/mach-snapdragon/board.c').read_text()
    start = board.index('\tblob_size = ALIGN(size, EFI_PAGE_SIZE);')
    end = board.index('\n\tmemcpy(blob,', start)
    source += 'static void allocate_acpi(ulong size,void **out) {\nulong blob_size;void *blob;int ret;*out=NULL;\n'
    source += board[start:end] + '\n*out=blob;\n}\n'
    source += r'''
int main(void) {
    const u64 bases[]={0x90000000,0x100000000,0x1ec82c000,0x1fffffff0};
    const uint sizes[]={440796,441112,880430};
    for(uint b=0;b<sizeof(bases)/sizeof(bases[0]);++b)
    for(uint s=0;s<sizeof(sizes)/sizeof(sizes[0]);++s) {
        memset(buffer,0xa5,sizeof(buffer)); physical_base=bases[b]; gd->bloblist=(void *)buffer;
        memset(gd->bloblist,0,sizeof(*gd->bloblist));
        gd->bloblist->hdr_size=sizeof(*gd->bloblist); gd->bloblist->used_size=sizeof(*gd->bloblist);
        gd->bloblist->total_size=sizeof(buffer); gd->bloblist->align_log2=3;
        void *acpi,*smbios; int found;
        allocate_acpi(sizes[s],&acpi); assert(acpi&&!(map_to_sysmem(acpi)&4095));
        assert(bloblist_get_blob(4,&found)==acpi&&found==(int)ALIGN(sizes[s],4096));
        for(uint i=sizes[s];i<(uint)found;++i) assert(!((u8 *)acpi)[i]);
        assert(!bloblist_ensure_size(0x201,2048,0,&smbios));
        assert(bloblist_get_blob(0x201,&found)==smbios&&found==2048);
        assert(map_to_sysmem(smbios)>=ALIGN(map_to_sysmem(acpi)+sizes[s],4096));
        assert(bloblist_get_blob(4,&found)==acpi);
        void *missing; allocate_acpi(sizeof(buffer)+1,&missing); assert(!missing);
    }
    puts("PASS: page-aligned ACPI records, preserved padding and following SMBIOS across 4-GB boundaries");
}
'''
    run_native(source, 'bloblist', temp)


def check_dtb(nodes, baseline):
    ranges = []
    for path, props in nodes.items():
        if path.startswith('/reserved-memory/') and 'reg' in props:
            ranges += [(base, base + size) for base, size in struct.iter_unpack('>QQ', props['reg']) if size]
    ranges.sort()
    assert all(a[1] <= b[0] for a, b in zip(ranges, ranges[1:])), 'Overlapping reservations'
    expected = [(0x85f40000, 0x85fff000), (0x9c000000, 0x9d800000),
                (0x9e300000, 0x9e400000), (0xa1100000, 0xa1300000),
                (0xa1400000, 0xa1c01000), (0xb0100000, 0xb1800000),
                (0xba000000, 0xc0000000), (0x100000000, 0x105900000)]
    for start, end in expected:
        cursor = start
        for lo, hi in ranges:
            if lo <= cursor < hi:
                cursor = hi
        assert cursor >= end, (hex(start), hex(end))
    for path, props in baseline.items():
        if path.startswith('/reserved-memory') or path == '/__symbols__':
            continue
        old = {k: v for k, v in props.items() if k != 'phandle'}
        new = {k: v for k, v in nodes[path].items() if k != 'phandle'}
        assert old == new, f'Unrelated DT properties changed: {path}'
    print('PASS: Samsung reservation coverage and no overlaps; other device-tree properties unchanged')


if __name__ == '__main__':
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    nodes = fdt(sys.argv[1])
    check_dtb(nodes, fdt(sys.argv[2]))
    with tempfile.TemporaryDirectory(prefix='a71-memory-') as directory:
        reservation_test(nodes, Path(directory))
        bloblist_test(Path(directory))
