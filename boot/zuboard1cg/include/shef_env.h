/*
 * shef_env.h - ShEF Environment Bridge
 * This file allows the user to toggle between using the auto-generated 
 * Xilinx parameters and the specialized "Known-Working" ShEF fix.
 */

#ifndef SHEF_ENV_H_
#define SHEF_ENV_H_

/* ALWAYS include xparameters.h to maintain standard system definitions (UART, GIC, etc.) */
#include "xparameters.h"

#ifdef USE_SHEF_FIXED_CONFIG
    /* 
     * TOGGLE ON: The user wants our "Known-Working" ZuBoard fix.
     * This will override the Vitis-generated defaults with verified hard-coded values.
     */
    #include "shef_config.h"
#else
    /* 
     * TOGGLE OFF (Default): Use standard Vitis-generated parameters from xparameters.h.
     * Note: Some custom ShEF offsets might still require fallbacks if not in xparameters.h.
     */

    /* --- Memory Map (Mapping to Vitis Defaults) --- */
    #ifdef XPAR_PSU_OCM_0_BASEADDR
        #define SHEF_SHARED_MEM_BASE    XPAR_PSU_OCM_0_BASEADDR
    #else
        #define SHEF_SHARED_MEM_BASE    0x00300000U // Generic fallback
    #endif

    #define SHEF_SHARED_MEM_SIZE       0x00000360U
    #define SHEF_OCM_SEC_BUFFER        0xFFFFFE00U

    /* --- Communication (IPI) --- */
    #ifdef XPAR_XIPIPS_TARGET_PSU_PMU_0_CH0_MASK
        #define SHEF_IPI_PMU_MASK_IPI0     XPAR_XIPIPS_TARGET_PSU_PMU_0_CH0_MASK
    #else
        #define SHEF_IPI_PMU_MASK_IPI0     0x00010000U // Generic fallback
    #endif

    #ifdef XPAR_XIPIPS_TARGET_PSU_PMU_0_CH1_MASK
        #define SHEF_IPI_PMU_MASK_IPI1     XPAR_XIPIPS_TARGET_PSU_PMU_0_CH1_MASK
    #else
        #define SHEF_IPI_PMU_MASK_IPI1     0x00020000U // Generic fallback
    #endif

    #define SHEF_MODULE_ID_PMU         0x001E0000U // ShEF ID in PMUFW

    /* --- Hardware Peripheral Bases --- */
    #define SHEF_ADMA_CH0_BASE         XPAR_XADMA_0_BASEADDR
    #define SHEF_CSU_BASE              XPAR_XCSU_0_BASEADDR
    #define SHEF_PMU_GLOBAL_BASE       XPAR_XPMU_GLOBAL_0_BASEADDR
    #define SHEF_FPGA_AXI_BASE         XPAR_XFPGA_0_BASEADDR

    #define SHEF_GPIO_BASE             XPAR_PSU_GPIO_0_BASEADDR

    #define SHEF_ROOT_PK_EXP           0x1000100U

#endif

#endif /* SHEF_ENV_H_ */
