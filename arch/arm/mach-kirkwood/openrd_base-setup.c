/*
 * arch/arm/mach-kirkwood/openrd_base-setup.c
 *
 * Marvell OpenRD Base Board Setup
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2.  This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/platform_device.h>
#include <linux/mtd/partitions.h>
#include <linux/ata_platform.h>
#include <linux/mv643xx_eth.h>
#include <linux/io.h>
#include <linux/gpio.h>
#include <asm/mach-types.h>
#include <asm/mach/arch.h>
#include <mach/kirkwood.h>
#include <plat/mvsdio.h>
#include "common.h"
#include "mpp.h"

static struct mtd_partition openrd_base_nand_parts[] = {
	{
		.name = "u-boot",
		.offset = 0,
		.size = SZ_1M
	}, {
		.name = "uImage",
		.offset = MTDPART_OFS_NXTBLK,
		.size = SZ_4M
	}, {
		.name = "root",
		.offset = MTDPART_OFS_NXTBLK,
		.size = MTDPART_SIZ_FULL
	},
};

static struct mv643xx_eth_platform_data openrd_base_ge00_data = {
	.phy_addr	= MV643XX_ETH_PHY_ADDR(8),
};

static struct mv_sata_platform_data openrd_base_sata_data = {
	.n_ports	= 2,
};

static struct mvsdio_platform_data openrd_base_mvsdio_data = {
	.gpio_card_detect = 29,	/* MPP29 used as SD card detect */
};

static unsigned int openrd_base_mpp_config[] __initdata = {
	MPP12_SD_CLK,
	MPP13_SD_CMD,
	MPP14_SD_D0,
	MPP15_SD_D1,
	MPP16_SD_D2,
	MPP17_SD_D3,
	MPP29_GPIO,
	MPP29_GPIO,
	0
};

static int uart1;

static void sd_uart_selection(void)
{
	char *ptr = NULL;

	/* Parse boot_command_line string uart=no/232 */
	ptr = strstr(boot_command_line, "uart=");

	/* Default is SD. Change if required, for UART */
	if (ptr != NULL) {
		if (!strncmp(ptr + 5, "232", 3)) {
			/* Configure MPP for UART */
			openrd_base_mpp_config[1] = MPP13_UART1_TXD;
			openrd_base_mpp_config[2] = MPP14_UART1_RXD;

			uart1 = 232;
		}
	}
}

static void __init openrd_base_init(void)
{
	/*
	 * Basic setup. Needs to be called early.
	 */
	kirkwood_init();

	/* This function modifies MPP config according to boot argument */
	sd_uart_selection();

	kirkwood_mpp_conf(openrd_base_mpp_config);

	kirkwood_uart0_init();
	kirkwood_nand_init(ARRAY_AND_SIZE(openrd_base_nand_parts), 25);

	kirkwood_ehci_init();

	kirkwood_ge00_init(&openrd_base_ge00_data);
	kirkwood_sata_init(&openrd_base_sata_data);

	if (!uart1) {
		/* Select SD
		 * Pin # 34: 0 => UART1, 1 => SD */
		writel(readl(GPIO_OUT(34)) | 4, GPIO_OUT(34));

		kirkwood_sdio_init(&openrd_base_mvsdio_data);
	} else {
		/* Select UART1
		 * Pin # 34: 0 => UART1, 1 => SD */
		writel(readl(GPIO_OUT(34)) & ~(4), GPIO_OUT(34));

		kirkwood_uart1_init();
	}

	kirkwood_i2c_init();
}

static int __init openrd_base_pci_init(void)
{
	if (machine_is_openrd_base())
		kirkwood_pcie_init();

	return 0;
 }
subsys_initcall(openrd_base_pci_init);


MACHINE_START(OPENRD_BASE, "Marvell OpenRD Base Board")
	/* Maintainer: Dhaval Vasa <dhaval.vasa@einfochips.com> */
	.phys_io	= KIRKWOOD_REGS_PHYS_BASE,
	.io_pg_offst	= ((KIRKWOOD_REGS_VIRT_BASE) >> 18) & 0xfffc,
	.boot_params	= 0x00000100,
	.init_machine	= openrd_base_init,
	.map_io		= kirkwood_map_io,
	.init_irq	= kirkwood_init_irq,
	.timer		= &kirkwood_timer,
MACHINE_END
