/*
 * arch/arm/mach-kirkwood/openrd_client-setup.c
 *
 * Marvell OpenRD Base Client Setup
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
#include <linux/gpio.h>
#include <asm/mach-types.h>
#include <asm/mach/arch.h>
#include <mach/kirkwood.h>
#include <plat/mvsdio.h>
#include "common.h"
#include "mpp.h"

static struct mtd_partition openrd_client_nand_parts[] = {
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

static struct mv643xx_eth_platform_data openrd_client_ge00_data = {
	.phy_addr	= MV643XX_ETH_PHY_ADDR(8),
};

static struct mv643xx_eth_platform_data openrd_client_ge01_data = {
	.phy_addr	= MV643XX_ETH_PHY_ADDR(24),
};

static struct mv_sata_platform_data openrd_client_sata_data = {
	.n_ports	= 2,
};

static struct mvsdio_platform_data openrd_client_mvsdio_data = {
	.gpio_card_detect = 29,	/* MPP29 used as SD card detect */
};

static unsigned int openrd_client_mpp_config[] __initdata = {
	MPP29_GPIO,
	0
};

static void __init openrd_client_init(void)
{
	/*
	 * Basic setup. Needs to be called early.
	 */
	kirkwood_init();
	kirkwood_mpp_conf(openrd_client_mpp_config);

	kirkwood_uart0_init();
	kirkwood_uart1_init();
	kirkwood_nand_init(ARRAY_AND_SIZE(openrd_client_nand_parts), 25);

	kirkwood_ehci_init();

	/* initialize gbe0 and gbe1 */
	kirkwood_ge00_init(&openrd_client_ge00_data);
	kirkwood_ge01_init(&openrd_client_ge01_data);

	kirkwood_sata_init(&openrd_client_sata_data);
	kirkwood_sdio_init(&openrd_client_mvsdio_data);

	kirkwood_i2c_init();
}

static int __init openrd_client_pci_init(void)
{
if (machine_is_openrd_client())
		kirkwood_pcie_init();

	return 0;
}
subsys_initcall(openrd_client_pci_init);




MACHINE_START(OPENRD_CLIENT, "Marvell OpenRD Client Board")
	/* Maintainer: Dhaval Vasa <dhaval.vasa@einfochips.com> */
	.phys_io	= KIRKWOOD_REGS_PHYS_BASE,
	.io_pg_offst	= ((KIRKWOOD_REGS_VIRT_BASE) >> 18) & 0xfffc,
	.boot_params	= 0x00000100,
	.init_machine	= openrd_client_init,
	.map_io		= kirkwood_map_io,
	.init_irq	= kirkwood_init_irq,
	.timer		= &kirkwood_timer,
MACHINE_END
