/*
 * kernel_driver.h
 *
 * Ported from Vitis 2019.2 (Ultra96) to Vitis 2023.2 (Zuboard 1CG)
 */

#ifndef SRC_KERNEL_DRIVER_H_
#define SRC_KERNEL_DRIVER_H_

#include "xil_types.h"
#include "shef_env.h"

#define SHARED_MEM_BASE SHEF_SHARED_MEM_BASE
#define ATTESTATION_OFFSET 0x0
#define ATTESTATION_SIZE 0x2B0
#define NONCE_OFFSET 0x0
#define NONCE_SIZE 0x20
#define ATTEST_PK_OFFSET 0x20
#define ATTEST_PK_SIZE 0x20
#define KERNEL_CERT_HASH_OFFSET 0x40
#define KERNEL_CERT_HASH_SIZE 0x30
#define KERNEL_CERT_SIG_OFFSET 0x70
#define KERNEL_CERT_SIG_SIZE 0x200
#define ATTEST_SIG_OFFSET 0x270
#define ATTEST_SIG_SIZE 0x40
#define SHARED_SECRET_SIG_OFFSET 0x2B0
#define SHARED_SECRET_SIG_SIZE 0x40
#define VERIFIER_PK_OFFSET 0x2F0
#define VERIFIER_PK_SIZE 0x20
#define FLAG_OFFSET 0x310

#define BITSTREAM_KEY_OFFSET 0x324
#define BITSTREAM_KEY_SIZE 0x3C

#define SHARED_MEM_SIZE 0x360

#define FPGA_AXI_BASE_ADDR SHEF_FPGA_AXI_BASE

void wait_for_kernel(void);
void signal_kernel(void);
void get_attestation(void);
void load_bitstream(void);

#endif /* SRC_KERNEL_DRIVER_H_ */
