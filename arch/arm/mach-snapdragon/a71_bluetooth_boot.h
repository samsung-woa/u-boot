/* SPDX-License-Identifier: GPL-2.0+ */
#ifndef A71_BLUETOOTH_BOOT_H
#define A71_BLUETOOTH_BOOT_H
/* The Windows D0 path owns UART3 clocks, pinmux and controller bootstrap.
 * Do not access GENI, PMIC/RPMh, shared WCN supplies or modem/WLAN here.
 * A stuck peripheral must not prevent reaching the Windows boot manager.
 */
static void a71_prepare_bluetooth(void)
{
    if (!of_machine_is_compatible("samsung,a715f"))
        return;
    env_set("a71_bt_stage", "windows-D0");
    printf("A71 Bluetooth v0.4: initialization owned by Windows D0\n");
}
#endif
