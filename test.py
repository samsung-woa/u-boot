from pathlib import Path
import struct, hashlib, textwrap

BASE = 0x1EC8AB020
SRC = Path("/mnt/data/a71inspect/v3/DSDT-gpu-off.aml")
OUT = Path("/mnt/data/acpi.bin")
MANIFEST = Path("/mnt/data/acpi_manifest.txt")

# Layout is deliberately simple and deterministic. ACPI pointers are absolute
# physical addresses based on the address the user said U-Boot will use.
OFF = {
    "RSDP": 0x000,
    "XSDT": 0x040,
    "FACS": 0x080,
    "FADT": 0x0C0,
    "MADT": 0x200,
    "GTDT": 0x600,
    "DSDT": 0x680,
}

OEM_ID = b"SAMSNG"
OEM_TABLE = b"A715F   "
CREATOR = b"ALOHA"
CREATOR_REV = 0x00000001

assert SRC.exists(), f"Missing source DSDT: {SRC}"
dsdt = bytearray(SRC.read_bytes())
assert dsdt[:4] == b"DSDT"
assert int.from_bytes(dsdt[4:8], "little") == len(dsdt)
assert sum(dsdt) % 256 == 0

# The previous A71 DSDT variant was already patched to disable its known-bad
# SC8180 GPU resource block. We do not invent new device resources here.
# Correct only the table identity to match the A71 target.
dsdt[10:16] = OEM_ID
dsdt[16:24] = OEM_TABLE
dsdt[24:28] = struct.pack("<I", 1)
dsdt[28:32] = CREATOR
dsdt[32:36] = struct.pack("<I", CREATOR_REV)
dsdt[9] = 0
dsdt[9] = (-sum(dsdt)) & 0xFF
assert sum(dsdt) % 256 == 0

def checksum_table(blob: bytearray, checksum_offset=9):
    blob[checksum_offset] = 0
    blob[checksum_offset] = (-sum(blob)) & 0xFF
    assert sum(blob) % 256 == 0
    return blob

def header(sig, length, revision):
    h = bytearray(36)
    h[0:4] = sig
    struct.pack_into("<I", h, 4, length)
    h[8] = revision
    h[9] = 0
    h[10:16] = OEM_ID
    h[16:24] = OEM_TABLE
    struct.pack_into("<I", h, 24, 1)
    h[28:32] = CREATOR
    struct.pack_into("<I", h, 32, CREATOR_REV)
    return h

# FACS (ACPI 6.4): 64 bytes, no ACPI checksum.
facs = bytearray(64)
facs[0:4] = b"FACS"
struct.pack_into("<I", facs, 4, 64)
facs[32] = 2  # FACS Version 2

# MADT / GICv3
# ACPI 6.4 MADT revision 5.
madt_body = bytearray()
madt_body += struct.pack("<II", 0, 0)  # Local APIC addr / Flags, unused on ARM

GICD_BASE = 0x17A00000
GICR_BASE = 0x17A60000
GICR_LEN  = 0x00100000
PMU_GSIV = 16 + 5  # DT PPI 5 -> GSIV 21

mpidrs = [0x000, 0x100, 0x200, 0x300, 0x400, 0x500, 0x600, 0x700]
for uid, mpidr in enumerate(mpidrs):
    # ACPI 6.x MADT GICC structure.
    #
    # Offset  Size  Field
    # 0       1     Type
    # 1       1     Length
    # 2       2     Reserved
    # 4       4     CPU Interface Number
    # 8       4     ACPI Processor UID
    # 12      4     Flags
    # 16      4     Parking Protocol Version
    # 20      4     Performance Interrupt GSIV
    # 24      8     Parked Address
    # 32      8     Physical Base Address
    # 40      8     GICV
    # 48      8     GICH
    # 56      4     VGIC Maintenance Interrupt
    # 60      8     GICR Base Address
    # 68      8     MPIDR
    # 76      1     Processor Power Efficiency Class
    # 77      1     Reserved
    # 78      2     SPE Overflow Interrupt
    #
    # Total = 80 bytes.

    gicc = bytearray(80)

    gicc[0] = 0x0B       # GICC
    gicc[1] = 80         # Length

    struct.pack_into("<I", gicc, 4, uid)
    struct.pack_into("<I", gicc, 8, uid)

    # Enabled.
    struct.pack_into("<I", gicc, 12, 0x1)

    # Parking protocol.
    struct.pack_into("<I", gicc, 16, 0)

    # Performance interrupt.
    #
    # DON'T invent a PMU interrupt here until we've verified it against
    # the A71 DTS. Zero is preferable to claiming a wrong PPI.
    struct.pack_into("<I", gicc, 20, 0)

    # These are not used for a GICv3 system-register CPU interface.
    struct.pack_into("<Q", gicc, 24, 0)   # Parked Address
    struct.pack_into("<Q", gicc, 32, 0)   # Physical Base Address
    struct.pack_into("<Q", gicc, 40, 0)   # GICV
    struct.pack_into("<Q", gicc, 48, 0)   # GICH

    # No VGIC maintenance interrupt for our initial PE bring-up table.
    struct.pack_into("<I", gicc, 56, 0)

    # GICR is described by the separate GICR MADT entry below.
    struct.pack_into("<Q", gicc, 60, 0)

    # ARM MPIDR from the A71 CPU topology.
    struct.pack_into("<Q", gicc, 68, mpidr)

    # Efficiency class.
    gicc[76] = 0

    # Byte 77 reserved = 0.
    gicc[77] = 0

    # SPE / TRBE not being described yet.
    struct.pack_into("<H", gicc, 78, 0)

    assert len(gicc) == 80
    madt_body += gicc

gicd = struct.pack("<BBHIQI B3x",
                   0x0C, 24, 0, 0, GICD_BASE, 0, 0x03)
assert len(gicd) == 24
madt_body += gicd

gicr = struct.pack("<BBHQI", 0x0E, 16, 0, GICR_BASE, GICR_LEN)
assert len(gicr) == 16
madt_body += gicr

madt = header(b"APIC", 36 + len(madt_body), 5) + madt_body
madt = checksum_table(madt)

# ============================================================================
# GTDT - Generic Timer Description Table
# ============================================================================

GTDT_LEN = 104

# Allocate the EXACT table size.
gtdt = bytearray(104)

# Make absolutely sure nothing before this point can alter it.
assert len(gtdt) == 104

# -------------------------------------------------------------------------
# ACPI Description Header - written directly, no header() helper.
# -------------------------------------------------------------------------

gtdt[0:4] = b"GTDT"
struct.pack_into("<I", gtdt, 4, 104)
gtdt[8] = 3                  # GTDT revision
gtdt[9] = 0                  # checksum, calculated later
gtdt[10:16] = OEM_ID
gtdt[16:24] = OEM_TABLE
struct.pack_into("<I", gtdt, 24, 1)
gtdt[28:32] = CREATOR
struct.pack_into("<I", gtdt, 32, CREATOR_REV)

# IMPORTANT:
# Assert immediately after writing the header.
assert len(gtdt) == 104

# -------------------------------------------------------------------------
# Generic Timer fields
# -------------------------------------------------------------------------

# CntControlBasePhysicalAddress
#
# The A71 uses the ARM architected timer interface. There is no DT-described
# MMIO counter-control base for the arm,armv8-timer device.
#
# ACPI specifies FFFFFFFFFFFFFFFF when the field is not provided.
struct.pack_into(
    "<Q",
    gtdt,
    36,
    0xFFFFFFFFFFFFFFFF
)

# Reserved
struct.pack_into("<I", gtdt, 44, 0)

# The DTS uses 0xF08 for all four architected timer interrupts.
#
# For the Linux ARM interrupt spec:
#   0x01 = PPI
#   IRQ number is the second cell
#   0xF08 = interrupt flags
#
# PPI numbers become GSI 16 + PPI:
#
#   PPI 1 -> GSI 17
#   PPI 2 -> GSI 18
#   PPI 3 -> GSI 19
#   PPI 0 -> GSI 16
#
# ACPI Timer Flags:
#   Bit 0 = interrupt mode
#            0 = level
#   Bit 1 = polarity
#            1 = active-low
#
# The architected timer is therefore level/active-low.
TIMER_FLAGS = 0x02

# Secure EL1 timer
struct.pack_into("<I", gtdt, 48, 17)
struct.pack_into("<I", gtdt, 52, TIMER_FLAGS)

# Non-secure EL1 timer
struct.pack_into("<I", gtdt, 56, 18)
struct.pack_into("<I", gtdt, 60, TIMER_FLAGS)

# Virtual EL1 timer
struct.pack_into("<I", gtdt, 64, 19)
struct.pack_into("<I", gtdt, 68, TIMER_FLAGS)

# Non-secure EL2 timer
struct.pack_into("<I", gtdt, 72, 16)
struct.pack_into("<I", gtdt, 76, TIMER_FLAGS)

# Counter Read Base Address.
#
# Counter is accessed through ARM system registers, so there is no
# memory-mapped counter read base.
struct.pack_into(
    "<Q",
    gtdt,
    80,
    0xFFFFFFFFFFFFFFFF
)

# No MMIO platform timers in our ACPI table.
struct.pack_into("<I", gtdt, 88, 0)   # PlatformTimerCount
struct.pack_into("<I", gtdt, 92, 0)   # PlatformTimerOffset

# Virtual EL2 timer is not being described separately.
struct.pack_into("<I", gtdt, 96, 0)
struct.pack_into("<I", gtdt, 100, 0)

# -------------------------------------------------------------------------
# Checksum
# -------------------------------------------------------------------------

gtdt[9] = 0
gtdt[9] = (-sum(gtdt)) & 0xFF

# -------------------------------------------------------------------------
# Final validation
# -------------------------------------------------------------------------

print("GTDT length:", len(gtdt))
print("GTDT header length:", int.from_bytes(gtdt[4:8], "little"))
print("GTDT checksum:", hex(gtdt[9]))

assert len(gtdt) == 104
assert int.from_bytes(gtdt[4:8], "little") == 104
assert sum(gtdt) % 256 == 0

madt_body_size = len(madt_body)

print(
    "GTDT:",
    f"length={len(gtdt)}",
    f"secure={17}",
    f"nonsecure={18}",
    f"virtual={19}",
    f"el2={16}"
)

# FADT, ACPI 6.4 layout, 276 bytes.
def null_gas():
    return struct.pack("<BBBBQ", 0, 0, 0, 0, 0)

fadt = bytearray(276)
fadt[0:36] = header(b"FACP", 276, 6)
struct.pack_into("<I", fadt, 36, 0)                 # FirmwareCtrl (XFirmwareCtrl used)
struct.pack_into("<I", fadt, 40, 0)                 # Dsdt (32-bit field cannot hold >4GiB)
fadt[44] = 0                                        # Reserved
fadt[45] = 2                                        # Mobile
struct.pack_into("<H", fadt, 46, 0)                 # SCI
# Legacy PM/GPE blocks are all zero on HW-reduced ARM.
struct.pack_into("<H", fadt, 109, 0)                # IA-PC boot arch
struct.pack_into("<I", fadt, 113, 1 << 20)         # HW_REDUCED_ACPI
fadt[117:129] = null_gas()                          # ResetReg
fadt[129] = 0                                        # ResetValue
struct.pack_into("<H", fadt, 130, 0x0001)           # ARM_PSCI_COMPLIANT
fadt[132] = 4                                        # ACPI 6.4 minor revision
struct.pack_into("<Q", fadt, 133, BASE + OFF["FACS"])
struct.pack_into("<Q", fadt, 141, BASE + OFF["DSDT"])
gas_offs = [149, 161, 173, 185, 197, 209, 221, 233, 245, 257]
for off in gas_offs:
    fadt[off:off+12] = null_gas()
struct.pack_into("<Q", fadt, 268, 0)
fadt = checksum_table(fadt)

# XSDT contains FADT, MADT and GTDT. DSDT/FACS are referenced by FADT.
xsdt_entries = [
    BASE + OFF["FADT"],
    BASE + OFF["MADT"],
    BASE + OFF["GTDT"],
]
xsdt_len = 36 + 8 * len(xsdt_entries)
xsdt = header(b"XSDT", xsdt_len, 1)
for i, addr in enumerate(xsdt_entries):
    xsdt += struct.pack("<Q", addr)
xsdt = checksum_table(xsdt)

# RSDP v2 at the very start of the blob.
rsdp = bytearray(36)
rsdp[0:8] = b"RSD PTR "
rsdp[9:15] = OEM_ID
rsdp[15] = 2
struct.pack_into("<I", rsdp, 16, 0)               # no usable 32-bit RSDT
struct.pack_into("<I", rsdp, 20, 36)
struct.pack_into("<Q", rsdp, 24, BASE + OFF["XSDT"])
rsdp[8] = (-sum(rsdp[:20])) & 0xFF
rsdp[32] = (-sum(rsdp)) & 0xFF
assert sum(rsdp[:20]) % 256 == 0
assert sum(rsdp) % 256 == 0

# Assemble.
end = OFF["DSDT"] + len(dsdt)
blob = bytearray(end)
blob[OFF["RSDP"]:OFF["RSDP"]+len(rsdp)] = rsdp
blob[OFF["XSDT"]:OFF["XSDT"]+len(xsdt)] = xsdt
blob[OFF["FACS"]:OFF["FACS"]+len(facs)] = facs
blob[OFF["FADT"]:OFF["FADT"]+len(fadt)] = fadt
blob[OFF["MADT"]:OFF["MADT"]+len(madt)] = madt
blob[OFF["GTDT"]:OFF["GTDT"]+len(gtdt)] = gtdt
blob[OFF["DSDT"]:OFF["DSDT"]+len(dsdt)] = dsdt

OUT.write_bytes(blob)

# Final structural validation.
def u32(off): return int.from_bytes(blob[off:off+4], "little")
def u64(off): return int.from_bytes(blob[off:off+8], "little")
assert blob[0:8] == b"RSD PTR "
assert u64(24) == BASE + OFF["XSDT"]
assert blob[OFF["XSDT"]:OFF["XSDT"]+4] == b"XSDT"
assert u64(OFF["XSDT"]+36) == BASE + OFF["FADT"]
assert u64(OFF["XSDT"]+44) == BASE + OFF["MADT"]
assert u64(OFF["XSDT"]+52) == BASE + OFF["GTDT"]
assert u64(OFF["FADT"]+140) == BASE + OFF["DSDT"]
assert u64(OFF["FADT"]+132) == BASE + OFF["FACS"]
for name, off in OFF.items():
    if name in ("RSDP",):
        continue
    sig = bytes(blob[off:off+4])
    length = u32(off+4)
    if sig != b"FACS":
        assert sum(blob[off:off+length]) % 256 == 0, (name, sig)
assert bytes(blob[OFF["DSDT"]:OFF["DSDT"]+4]) == b"DSDT"
assert u32(OFF["DSDT"]) == 0x54445344

manifest = f"""A71 Windows ARM64 ACPI bundle
================================

Blob base address assumed by this build:
  0x{BASE:016X}

Tables:
  RSDP  @ +0x{OFF["RSDP"]:04X} = 0x{BASE+OFF["RSDP"]:016X}
  XSDT  @ +0x{OFF["XSDT"]:04X} = 0x{BASE+OFF["XSDT"]:016X}
  FACS  @ +0x{OFF["FACS"]:04X} = 0x{BASE+OFF["FACS"]:016X}
  FADT  @ +0x{OFF["FADT"]:04X} = 0x{BASE+OFF["FADT"]:016X}
  MADT  @ +0x{OFF["MADT"]:04X} = 0x{BASE+OFF["MADT"]:016X}
  GTDT  @ +0x{OFF["GTDT"]:04X} = 0x{BASE+OFF["GTDT"]:016X}
  DSDT  @ +0x{OFF["DSDT"]:04X} = 0x{BASE+OFF["DSDT"]:016X}

Source-of-truth hardware facts taken from the current A71 DTS:
  model: Samsung A71 PROJECT Rev0.6 / SM-A715F
  eight CPU MPIDRs: {", ".join(f"0x{x:X}" for x in mpidrs)}
  GICD:  0x{GICD_BASE:X}
  GICR:  0x{GICR_BASE:X}..+0x{GICR_LEN:X}
  timer GSIVs: secure EL1=17, non-secure EL1=18, virtual=19, EL2=16
  RAM: DTS describes 6 GiB total in two banks

DSDT handling:
  Used the existing A71 DSDT-gpu-off AML as a cautiously reused baseline.
  Its ACPI checksum and declared length were verified before use.
  Its known-bad SC8180 GPU device is disabled in that baseline.
  The table OEM identity was changed to SAMSNG/A715F for this bundle.
  No unverified Moorea device resources (including QCOM1427) were invented.

Display:
  This ACPI bundle does NOT try to describe the GOP framebuffer.
  UEFI GOP is exposed through the UEFI Graphics Output Protocol; ACPI is
  responsible for platform discovery/timers/GIC/etc. A Windows bootloader/PE
  image can therefore use the already-initialized GOP without an ACPI display
  driver description.

WinPE:
  WinPE can boot entirely from RAM, so a storage driver is not inherently
  required for the initial RAM-disk handoff when boot.wim is already loaded.
  Storage/network drivers become relevant once PE needs disks/network/etc.

Binary SHA-256:
  {hashlib.sha256(blob).hexdigest()}

Size:
  {len(blob)} bytes (0x{len(blob):X})
"""
MANIFEST.write_text(manifest, encoding="utf-8")

print(f"Created {OUT} ({len(blob)} bytes)")
print(f"SHA-256: {hashlib.sha256(blob).hexdigest()}")
print(f"ACPI base assumed: 0x{BASE:016X}")
print(f"RSDP/XSDT/FADT/MADT/GTDT/DSDT checksums: OK")
print(f"Manifest: {MANIFEST}")
