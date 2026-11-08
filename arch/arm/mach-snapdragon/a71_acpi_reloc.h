/* SPDX-License-Identifier: GPL-2.0-only */
/* Relocate an A71 full ACPI image, never dereferencing its old physical pointers.
 * NewBase=0 validates only. Only ACPI 2+ images with an XSDT and no RSDT are
 * accepted. All root/FADT targets must be within this bounded image.
 */
#ifndef A71_ACPI_RELOC_H
#define A71_ACPI_RELOC_H
#ifdef A71_ACPI_HOST_TEST
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;
#else
#include <linux/types.h>
#include <linux/string.h>
#include <linux/errno.h>
#endif
static u32 a71_ar32(const u8 *p)
{
	return (u32)p[0] | (u32)p[1] << 8 | (u32)p[2] << 16 | (u32)p[3] << 24;
}
static u64 a71_ar64(const u8 *p)
{
	return a71_ar32(p) | (u64)a71_ar32(p + 4) << 32;
}
static void a71_aw32(u8 *p, u32 v)
{
	unsigned int i;
	for (i = 0; i < 4; ++i)
		p[i] = v >> (i * 8);
}
static void a71_aw64(u8 *p, u64 v)
{
	a71_aw32(p, (u32)v);
	a71_aw32(p + 4, (u32)(v >> 32));
}
static u8 a71_asum(const u8 *p, size_t n)
{
	u8 sum = 0;
	while (n--)
		sum += *p++;
	return sum;
}
static void a71_afix(u8 *p, size_t n, size_t checksum)
{
	p[checksum] = 0;
	p[checksum] = (u8)(0 - a71_asum(p, n));
}
static bool a71_atable(const u8 *b, size_t size, size_t off)
{
	u32 len;
	if (off > size || size - off < 36)
		return false;
	len = a71_ar32(b + off + 4);
	return len >= 36 && len <= size - off && !a71_asum(b + off, len);
}
static bool a71_aoffset(u64 p, u64 base, size_t size, size_t *off)
{
	if (p < base || p - base >= size)
		return false;
	*off = (size_t)(p - base);
	return true;
}
/* A candidate is active only if all of its links fit the inferred base. */
static int a71_acpi_validate_root(const u8 *b, size_t size, size_t xoff,
                                 u64 old, u64 new_base)
{
	size_t off, i, j, count, len, target;
	u64 p, v;
	unsigned int fadts = 0, k;
	const unsigned int fptr[4] = {36, 40, 132, 140};

	if (old > ~(u64)0 - size || (new_base && new_base > ~(u64)0 - size))
		return -ERANGE;
	len = a71_ar32(b + xoff + 4);
	if ((len - 36) % 8)
		return -EINVAL;
	count = (len - 36) / 8;
	if (!count)
		return -EINVAL;

	/* Validate everything before changing any bytes. */
	for (i = 0; i < count; ++i) {
		p = a71_ar64(b + xoff + 36 + i * 8);
		if (!a71_aoffset(p, old, size, &off) || !a71_atable(b, size, off))
			return -EINVAL;
		for (j = 0; j < i; ++j)
			if (p == a71_ar64(b + xoff + 36 + j * 8))
				return -EINVAL;
		if (memcmp(b + off, "FACP", 4))
			continue;
		++fadts;
		if (a71_ar32(b + off + 4) < 148)
			return -EINVAL;
		for (k = 0; k < 4; ++k) {
			v = k < 2 ? a71_ar32(b + off + fptr[k]) :
				    a71_ar64(b + off + fptr[k]);
			if (!v)
				continue;
			if (!a71_aoffset(v, old, size, &target))
				return -EINVAL;
			if (k % 2 == 0) {
				if (size - target < 8 || memcmp(b + target, "FACS", 4) ||
				    a71_ar32(b + target + 4) < 64 ||
				    a71_ar32(b + target + 4) > size - target)
					return -EINVAL;
			} else if (!a71_atable(b, size, target) || memcmp(b + target, "DSDT", 4)) {
				return -EINVAL;
			}
			if (new_base && k < 2 && new_base + target > 0xffffffffULL)
				return -ERANGE;
		}
	}
	if (fadts != 1)
		return -EINVAL;
	return 0;
}
static int a71_acpi_relocate(void *image, size_t size, u64 new_base, u64 *old_out)
{
	u8 *b = image;
	size_t xoff = 0, off, i, count, len;
	u64 old, xp, p, v;
	unsigned int found = 0, k;
	const unsigned int fptr[4] = {36, 40, 132, 140};
	int ret;

	if (size < 36 || size > 0x1000000 || memcmp(b, "RSD PTR ", 8) || b[15] < 2)
		return -EINVAL;
	len = a71_ar32(b + 20);
	if (len < 36 || len > size || a71_asum(b, 20) || a71_asum(b, len))
		return -EINVAL;
	if (a71_ar32(b + 16)) /* Cannot leave a legacy RSDT with stale 32-bit pointers. */
		return -EINVAL;
	xp = a71_ar64(b + 24);
	/* Patched images can retain an obsolete XSDT. Infer the base from each
	 * candidate and require exactly one complete, consistent table graph.
	 */
	for (off = 0; off + 36 <= size; off += 16) {
		if (memcmp(b + off, "XSDT", 4) || !a71_atable(b, size, off) || xp < off)
			continue;
		if (a71_acpi_validate_root(b, size, off, xp - off, 0))
			continue;
		xoff = off;
		if (++found > 1)
			return -EINVAL;
	}
	if (!found)
		return -EINVAL;
	old = xp - xoff;
	ret = a71_acpi_validate_root(b, size, xoff, old, new_base);
	if (ret)
		return ret;
	len = a71_ar32(b + xoff + 4);
	count = (len - 36) / 8;
	if (old_out)
		*old_out = old;
	if (!new_base || new_base == old)
		return 0;

	for (i = 0; i < count; ++i) {
		p = a71_ar64(b + xoff + 36 + i * 8);
		off = (size_t)(p - old);
		a71_aw64(b + xoff + 36 + i * 8, new_base + off);
		if (memcmp(b + off, "FACP", 4))
			continue;
		for (k = 0; k < 4; ++k) {
			v = k < 2 ? a71_ar32(b + off + fptr[k]) :
				    a71_ar64(b + off + fptr[k]);
			if (!v)
				continue;
			if (k < 2)
				a71_aw32(b + off + fptr[k], (u32)(new_base + v - old));
			else
				a71_aw64(b + off + fptr[k], new_base + v - old);
		}
		a71_afix(b + off, a71_ar32(b + off + 4), 9);
	}
	a71_afix(b + xoff, len, 9);
	a71_aw64(b + 24, new_base + xoff);
	a71_afix(b, 20, 8);
	a71_afix(b, a71_ar32(b + 20), 32);
	return 0;
}
#endif
