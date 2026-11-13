/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (c) 2026 Zulian61
 * OSM LUT/boost algorithm derived from the accompanying A71CpuPerf driver
 * and Qualcomm/Linux OSM drivers. For samsung,a715f only.
 */
#ifndef A71_CPU_BOOT_H
#define A71_CPU_BOOT_H

struct a71_boot_domain {
    void __iomem *base;
    u32 rows, slots, target, khz, saved[6];
};

static bool a71_boot_rate_allowed(unsigned int domain, u32 khz)
{
    static const u32 little[] = {300000, 576000, 768000, 1017600,
        1248000, 1324800, 1497600, 1612800, 1708800, 1804800};
    static const u32 big[] = {300000, 652800, 806400, 979200,
        1094400, 1209600, 1324800, 1555200, 1708800, 1843200,
        1939200, 2169600, 2208000};
    const u32 *rates = domain ? big : little;
    unsigned int count = domain ? ARRAY_SIZE(big) : ARRAY_SIZE(little);
    unsigned int i;

    if (domain == 2)
        return true;
    for (i = 0; i < count; i++)
        if (rates[i] == khz)
            return true;
    return false;
}

static int a71_boot_load(struct a71_boot_domain *d, unsigned int domain)
{
    u32 previous = 0, previous_cores = 0, previous_uv = 0;
    u32 i, word, khz, cores, uv;

    if (!(readl(d->base) & 1))
        return -ENODEV;
    d->slots = domain != 2 && (readl(d->base + 0xbc) & 1) ?
        (domain ? 2 : 6) : 1;
    d->target = ~0U;
    d->rows = 0;
    for (i = 0; i < 40; i++) {
        word = readl(d->base + 0x110 + 32 * i);
        khz = word >> 30 ? (word & 255) * 19200 : 300000;
        cores = (word >> 16) & 7;
        uv = domain == 2 ? 0 : (readl(d->base + 0x114 + 32 * i) & 0xfff) * 1000;
        if (i && khz == previous) {
            /* The final single-core row is firmware's boost request. OSM
             * retains responsibility for active-core and thermal limits.
             */
            if (domain != 2 && previous_cores == 1 &&
                (previous_uv || uv) && a71_boot_rate_allowed(domain, previous)) {
                d->target = i - 1;
                d->khz = previous;
            }
            break;
        }
        if (!khz || (i && khz < previous))
            return -EINVAL;
        if (a71_boot_rate_allowed(domain, khz) &&
            (domain == 2 || (cores != 1 && uv))) {
            d->target = i;
            d->khz = khz;
        }
        previous = khz;
        previous_cores = cores;
        previous_uv = uv;
        d->rows++;
    }
    if (d->rows < 2 || d->target == ~0U)
        return -EINVAL;
    for (i = 0; i < d->slots; i++) {
        d->saved[i] = readl(d->base + 0x920 + 4 * i);
        if (d->saved[i] >= d->rows)
            return -EINVAL;
    }
    return 0;
}

static int a71_boot_write(struct a71_boot_domain *d, bool restore)
{
    u32 i, retry;
    bool match;

    for (i = 0; i < d->slots; i++)
        writel(restore ? d->saved[i] : d->target, d->base + 0x920 + 4 * i);
    for (retry = 0; retry < 50; retry++) {
        match = true;
        for (i = 0; i < d->slots; i++)
            if (readl(d->base + 0x920 + 4 * i) !=
                (restore ? d->saved[i] : d->target))
                match = false;
        if (match)
            return 0;
        udelay(10);
    }
    return -EIO;
}

static void a71_cpu_boot_prepare(void)
{
    struct a71_boot_domain d[3] = {
        {.base = (void __iomem *)0x18323000UL},
        {.base = (void __iomem *)0x18325800UL},
        {.base = (void __iomem *)0x18321000UL},
    };
    unsigned int i;
    bool cpu_restored;

    if (!of_machine_is_compatible("samsung,a715f"))
        return;
    /* All three firmware tables and existing requests are checked before the
     * first write. Never initialize a disabled controller, PLL or regulator.
     */
    for (i = 0; i < 3; i++)
        if (a71_boot_load(&d[i], i)) {
            printf("A71 CPU boot: invalid/disabled OSM domain %u; unchanged\n", i);
            return;
        }
    /* Raise the dependent L3 vote before either CPU domain. */
    if (a71_boot_write(&d[2], false) || a71_boot_write(&d[0], false) ||
        a71_boot_write(&d[1], false)) {
        cpu_restored = !a71_boot_write(&d[0], true);
        cpu_restored = !a71_boot_write(&d[1], true) && cpu_restored;
        /* Do not lower L3 if a CPU request could not be restored. */
        if (cpu_restored)
            a71_boot_write(&d[2], true);
        printf("A71 CPU boot: request readback failed; rollback attempted\n");
        return;
    }
    mdelay(20);
    printf("A71 CPU boot: firmware OSM requests %u/%u kHz before Windows\n",
           d[0].khz, d[1].khz);
}
#endif
