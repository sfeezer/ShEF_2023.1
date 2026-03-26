#ifndef IPI_H_
#define IPI_H_

#include "xparameters.h"
#include "xinterrupt_wrap.h"
#include "xscugic.h"
#include "xttcps.h"
#include "xipipsu.h"

#ifndef XPAR_XIPIPSU_0_BASEADDR
#error "XPAR_XIPIPSU_0_BASEADDR is missing from xparameters.h. Regenerate the BSP."
#endif

#ifndef XPAR_XIPIPSU_0_INTERRUPTS
#error "XPAR_XIPIPSU_0_INTERRUPTS is missing from xparameters.h. Regenerate the BSP."
#endif

#ifndef XPAR_XSCUGIC_0_BASEADDR
#error "XPAR_XSCUGIC_0_BASEADDR is missing from xparameters.h. Regenerate the BSP."
#endif

/*
 * Vitis 2023.2 compatibility: The BSP no longer defines the old
 * XPAR_XIPIPS_TARGET_PSU_PMU_* macros. Map them to the new IPI target bitmasks.
 * These values come from the R5 BSP xparameters.h (IPI1 target list).
 * PMU IPI channels use masks 0x10000-0x80000.
 */
#ifndef XPAR_XIPIPS_TARGET_PSU_PMU_0_CH0_MASK
#define XPAR_XIPIPS_TARGET_PSU_PMU_0_CH0_MASK   0x10000U  /* PMU IPI0 mask */
#endif

/*
 * PMUFW uses two IPI instances:
 * - PMU IPI-0 for master->PMU requests (source mask 0x10000 on the receiver)
 * - PMU IPI-1 for PMU-initiated messages (source mask 0x20000 on the receiver)
 *
 * The security kernel receives the async signature on PMU IPI-1.
 */
#ifndef XPAR_XIPIPS_TARGET_PSU_PMU_0_CH1_MASK
#ifdef XPAR_XIPIPS_TARGET_PSU_PMU_1_CH0_MASK
#define XPAR_XIPIPS_TARGET_PSU_PMU_0_CH1_MASK   XPAR_XIPIPS_TARGET_PSU_PMU_1_CH0_MASK
#else
#define XPAR_XIPIPS_TARGET_PSU_PMU_0_CH1_MASK   0x20000U  /* PMU IPI1 mask */
#endif
#endif

#define IPI_PMU_PM_INT_MASK_SEND		XPAR_XIPIPS_TARGET_PSU_PMU_0_CH0_MASK
#define IPI_PMU_PM_INT_MASK_RECV		XPAR_XIPIPS_TARGET_PSU_PMU_0_CH1_MASK
/* Convert raw device tree interrupt specifier to GIC interrupt ID:
 * XGet_IntrId extracts SPI number, XGet_IntrOffset adds 32 for SPI type.
 * For IPI1 (R5-0): 0x4021 -> SPI 33 -> GIC ID 65 */
#define SECURITY_KERNEL_IPI_INT_ID		(XGet_IntrId(XPAR_XIPIPSU_0_INTERRUPTS) + XGet_IntrOffset(XPAR_XIPIPSU_0_INTERRUPTS))
#define IPI_MSG_LEN									8U
#define IPI_HEADER_OFFSET						0x0U
#define PMU_IPI_HEADER							0x1E0000 /* Sec Module ID in PMUFW */

#define IPI_CH1_IER									(XPAR_XIPIPSU_0_BASEADDR + 0x18U)
#define IPI_CH1_ISR									(XPAR_XIPIPSU_0_BASEADDR + 0x10U)

#define RSA_SIZE						512
#define SHA3_SIZE						48

#define IPI_BITSTREAM_HASH_MASK			0xF0F0F0F0

#define FLIP_ENDIAN(a) ((a>>24)&0xff) | ((a<<8)&0xff0000) | \
						((a>>8)&0xff00) | ((a<<24)&0xff000000)


////Extern variables to store certificate of attestation key
//extern volatile u8 attest_signature[RSA_SIZE];
//extern volatile u32 attest_signature_bytes_read;
//extern volatile u8 bitstream_hash[SHA3_SIZE];
//extern volatile u32 bitstream_hash_bytes_read;
extern volatile u8 kernel_cert_sig[RSA_SIZE];
extern volatile u32 kernel_cert_sig_bytes_read;

//Instance Variables for drivers
extern XScuGic gic_inst;
extern XIpiPsu ipi_inst;

u32 rpu_gic_init(XScuGic *intc_inst_ptr, u32 int_id,
		Xil_ExceptionHandler handler, void *periph_inst_ptr);
u32 rpu_ipi_init(XIpiPsu *ipi_inst_ptr);
void rpu_ipi_handler(void *callback_ref);
int send_ipi_pmu(u32* msg_buf, u32* resp_buf, u32 len);
u32 get_kernel_certificate_signature(unsigned char* cert_hash);
//u32 send_pk_pmu(unsigned char* attest_pk);
//u32 send_load_bitstream_pmu(u8* bitstream_addr, u32 bitstream_size);
//int test_ipi(void);
#endif /* IPI_H_ */
