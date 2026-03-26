/*
 * sd_driver.c
 *
 * Ported from Vitis 2019.2 (Ultra96) to Vitis 2023.2 (Zuboard 1CG)
 *
 * Contains functions to read SD card, load bitstream.
 */

#include "xparameters.h"
#include "xsdps.h"
#include "xil_printf.h"
#include "ff.h"
#include "xil_cache.h"
#include "xplatform_info.h"

#include "sd_driver.h"

static FIL fil;		/* File object */
static FATFS fatfs;

static char bitname[32] = "bitstr.bin";
static char *sd_file;
u8 sd_bitstream_hash[48];
u32 platform;

/**
 * Given an address, load the bitstream in the SD card to the
 * linear address range starting at load_addr
 *
 * returns size of the bitstream.
 */
u32 read_sd_bitstream(u8 *load_addr)
{
	UINT bytes_read;
	FRESULT res;
	u32 bitstream_size = 0;

	/* Read in the bitstream from the SD card */
	/* Logical drive 0 */
	TCHAR *path = "0:/";
	res = f_mount(&fatfs, path, 0);
	if (res != FR_OK) {
		xil_printf("RPU: Failed to mount SD card\r\n");
		return 0;
	}

	/* Open file */
	sd_file = (char *)bitname;

	res = f_open(&fil, sd_file, FA_READ);
	if (res) {
		xil_printf("RPU: Failed to open file\r\n");
		return 0;
	}

	/* Pointer to beginning of file */
	res = f_lseek(&fil, 0);
	if (res) {
		xil_printf("RPU: Failed to seek to beginning of file\r\n");
		return 0;
	}

	/* Use f_size() macro for FatFS compatibility */
	bitstream_size = f_size(&fil);

	res = f_read(&fil, (void *)load_addr, bitstream_size, &bytes_read);
	if (res) {
		xil_printf("RPU: Failed to read file\r\n");
		return 0;
	}

	xil_printf("RPU: Read %d bytes from SD card \r\n", bitstream_size);

	res = f_close(&fil);
	if (res) {
		xil_printf("Runtime: Unable to close file\r\n");
		return 0;
	}

	return bitstream_size;
}
