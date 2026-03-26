/*
 * kernel_driver.c
 *
 * Ported from Vitis 2019.2 (Ultra96) to Vitis 2023.2 (Zuboard 1CG)
 */

#include "kernel_driver.h"
#include "xil_cache.h"
#include <stdio.h>
#include "xil_io.h"
#include "xil_printf.h"
#include "sd_driver.h"

/**
 * Stall until the flag in shared memory is set
 */
void wait_for_kernel(void)
{
	while (Xil_In8(SHARED_MEM_BASE + FLAG_OFFSET) == 0)
		;
	return;
}

/**
 * Signal the kernel
 * Assumes that the DCache is disabled
 */
void signal_kernel(void)
{
	Xil_Out8(SHARED_MEM_BASE + FLAG_OFFSET, 0x00);
	return;
}

/**
 * Given a nonce provided by the user, command the kernel to generate an
 * attestation + signature placed into shared memory
 *
 * precondition: the verifier's nonce and PK are written to shared memory
 */
void get_attestation(void)
{
	Xil_DCacheFlush();
	Xil_DCacheDisable();

	/* Wait for the kernel to be ready */
	wait_for_kernel();

	xil_printf("Kernel ready\r\n");

	/* Write the flag to signal the kernel to finish */
	signal_kernel();
	xil_printf("wrote nonce + verifier pk\r\n");

	/* Wait for the kernel to generate the attestation */
	wait_for_kernel();

	Xil_DCacheEnable();
	return;
}

/**
 * Load the bitstream from the SD card into DDR. Signal the kernel that
 * bitstream loading has completed
 */
void load_bitstream(void)
{
	u32 bitstream_size = read_sd_bitstream((u8 *)(SD_TEMP_BITSTREAM_LOAD_ADDR + 4));

	xil_printf("Loaded bitstream into DDR - %08x bytes\r\n", bitstream_size);

	Xil_DCacheFlush();
	Xil_DCacheDisable();

	Xil_Out32(SD_TEMP_BITSTREAM_LOAD_ADDR, bitstream_size);

	signal_kernel();

	Xil_DCacheEnable();
}
