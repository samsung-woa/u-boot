#!/usr/bin/env bash
make CROSS_COMPILE=aarch64-linux-gnu- -j$(nproc)
gzip -n -9 -c u-boot-nodtb.bin > u-boot-nodtb.bin.gz
cat u-boot-nodtb.bin.gz u-boot.dtb > u-boot-a71.gz-dtb
python3 ../mkbootimg/mkbootimg.py --header_version 1 --os_version 13.0.0 --os_patch_level 2022-10 --kernel u-boot-a71.gz-dtb --ramdisk ramdisk --pagesize 0x800 --base 0x00000000 --kernel_offset 0x10000000 --ramdisk_offset 0x10000000 --second_offset 0x00000000 --tags_offset 0x10000000 --board '' --cmdline '' --output boot.img
