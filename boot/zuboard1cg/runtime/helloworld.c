/******************************************************************************
 * Copyright (C) 2023 Advanced Micro Devices, Inc. All Rights Reserved.
 * SPDX-License-Identifier: MIT
 ******************************************************************************/

/*
 * Runtime application for SHEF attestation
 *
 * Ported from Vitis 2019.2 (Ultra96) to Vitis 2023.2 (Zuboard 1CG)
 */

#include <stdio.h>
#include "platform.h"
#include "xil_printf.h"
#include "sleep.h"
#include "kernel_driver.h"
#include "xil_cache.h"
#include "uart_driver.h"

int main(void)
{
	init_platform();

	sleep(5);

	xil_printf("Runtime: waiting for host over UART (PK+nonce)...\r\n");

	/* First, wait for the remote verifier to send its nonce and PK to us */
	u32 status;
	status = handle_uart_cmd();

	if (status != UART_RETURN_PK_NONCE) {
		return -1;
	}

	/* Using the nonce+pk, tell the security kernel to generate the attestation */
	get_attestation();

	/* Send the attestation to the remote user
	 * Block until the user sends the decryption key for the bitstream,
	 * which is written to shared memory */
	status = handle_uart_cmd();
	if (status != UART_RETURN_BITSTREAM_KEY) {
		return -1;
	}

	/* Load bitstream into shared memory, and signal the security kernel to
	 * program it using the provided decryption key */
	load_bitstream();

	/* Wait for the kernel to finish loading the bitstream */
	Xil_DCacheFlush();
	Xil_DCacheDisable();
	wait_for_kernel();
	Xil_DCacheEnable();

	/* Handle commands from UART */
	sleep(1);
	xil_printf("Ready to process host commands:\r\n");
	handle_uart_cmd();

	cleanup_platform();
	return 0;
}
