/******************************************************************************
 * Copyright (C) 2017 Xilinx, Inc.  All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * Use of the Software is limited solely to applications:
 * (a) running on a Xilinx device, or
 * (b) that interact with a Xilinx device through a bus or interconnect.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * XILINX  BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF
 * OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * Except as contained in this notice, the name of the Xilinx shall not be used
 * in advertising or otherwise to promote the sale, use or other dealings in
 * this Software without prior written authorization from Xilinx.
 ******************************************************************************/

#include "xpfw_default.h"
#include "xpfw_config.h"
#include "xpfw_core.h"
#include "xpfw_events.h"
#include "xpfw_module.h"
#include "xparameters.h"
#include "xsecure_rsa.h"
#include "xsecure_sha.h"
#include "xilfpga.h"

#include "xpfw_ipi_manager.h"
#include "xpfw_mod_sec.h"
#include "shef_env.h"

/* Exponent of private key */
u8 root_sk[RSA_SIZE] = SHEF_ROOT_SK;

/* Exponent of Public key */
u32 root_pk = SHEF_ROOT_PK_EXP; //CSU requires '0' byte at end for some reason?

/* Modulus */
u8 root_mod[RSA_SIZE] = SHEF_ROOT_PK_MOD;

/* Hash with PKCS padding */
/*
 * MSB  ------------------------------------------------------------LSB
 * 0x0 || 0x1 || 0xFF(for 202 bytes) || 0x0 || T_padding || SHA384 Hash
 */
u8 kernel_cert[RSA_SIZE] = {
	 0x00,0x01,
	 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	 0x00,
	 /* T_Padding */
	 0x30,0x41,0x30,0x0D,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,
	 0x04,0x02,0x09,0x05,0x00,0x04,0x30,
	 /* SHA 3 Hash */
	 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
};


const XPfw_Module_t* sec_ipi_mod_ptr;
static volatile unsigned char cert_hash[48];
XSecure_Rsa secure_rsa;
XSecure_Sha3 secure_sha3;
XCsuDma csu_dma;
u8 kernel_cert_sig[RSA_SIZE];
u8 encrypt_sig_out[RSA_SIZE];
u32 size = RSA_SIZE;

volatile u8* bitstream_addr = NULL;
volatile u32 bitstream_size = 0;

/**
*	Once the attestation PK is received, this function is scheduled.
* This function signs the attestation PK with the device sk, and sends it
* back to the security monitor through IPI
*/
static void sec_sign_cert(void){
	//XPfw_Printf(DEBUG_DETAILED, "PMU: Attestation Key received. Signing with dev_sk\r\n");

	u32 status;
	u32 index;
	u32 msg_buf[8]; //Buffer to hold message to PMUFW
	u32 resp_buf[2] = {0};
	u16 bytes_sent = 0U;
	//u8 attest_pk_digest[48];

	//Echo the attestation key
	//XPfw_Printf(DEBUG_DETAILED,"PMU: Attestation PK\r\n");
	//for(index = 0; index < 32; index++){
	//	XPfw_Printf(DEBUG_DETAILED, "%02x", attest_pk[index]);
	//}
	//XPfw_Printf(DEBUG_DETAILED, "\r\n");

	//Hash the attestation key with SHA3 KECCAK
	XCsuDma_Config *csu_config;
	csu_config = XCsuDma_LookupConfig(XPAR_CSUDMA_0_BASEADDR);
	if (csu_config == NULL){
		XPfw_Printf(DEBUG_ERROR, "PMU: Failed to configure CSU\r\n");
		return;
	}
	status = XCsuDma_CfgInitialize(&csu_dma, csu_config, csu_config->BaseAddress);
	if (status != XST_SUCCESS){
		XPfw_Printf(DEBUG_ERROR, "PMU: Failed to initialize CSU\r\n");
		return;
	}
//	XSecure_Sha3Initialize(&secure_sha3, &csu_dma);
//	XSecure_Sha3Digest(&secure_sha3, cert_hash, 64, attest_pk_digest);

	//XPfw_Printf(DEBUG_DETAILED, "PMU: Calculated attest pk digest\r\n");
	//for (index = 0; index < SHA3_SIZE; index++){
	//	XPfw_Printf(DEBUG_DETAILED, "%02x", attest_pk_digest[index]);
	//}
	//XPfw_Printf(DEBUG_DETAILED, "\r\n");

	//Write the padded hash that will be signed
	for (index = RSA_SIZE-SHA3_SIZE; index < RSA_SIZE; index++){
		kernel_cert[index] = cert_hash[index-(RSA_SIZE-SHA3_SIZE)];
	}
	//XPfw_Printf(DEBUG_DETAILED, "PMU: Padded attest pk hash\r\n");
	//for (index = 0; index < RSA_SIZE; index++){
	//	XPfw_Printf(DEBUG_DETAILED, "%02x", attest_pk_hash[index]);
	//}
	//XPfw_Printf(DEBUG_DETAILED, "\r\n");

	//Sign the data with the root private key.
	XSecure_RsaInitialize(&secure_rsa, root_mod, NULL, root_sk);
	if(XST_SUCCESS != XSecure_RsaPrivateDecrypt(&secure_rsa, kernel_cert,
			size, kernel_cert_sig)){
		XPfw_Printf(DEBUG_ERROR, "PMU: Failed to sign Kernel Certificate\r\n");
		return;
	}

	XPfw_Printf(DEBUG_DETAILED, "PMU: Generated Kernel Certificate signature\r\n");

	//for(index = 0; index < size; index++){
	//	XPfw_Printf(DEBUG_DETAILED, "%02x", attest_signature[index]);
	//}
	//XPfw_Printf(DEBUG_DETAILED, "\r\n");


	//Verify the signature
	XSecure_RsaInitialize(&secure_rsa, root_mod, NULL, (u8 *)&root_pk);
	if(XST_SUCCESS != XSecure_RsaPublicEncrypt(&secure_rsa, kernel_cert_sig, size, encrypt_sig_out)){
		XPfw_Printf(DEBUG_ERROR, "PMU: Failed to verify Kernel Cert Signature\r\n");
		return;
	}
	XPfw_Printf(DEBUG_DETAILED, "PMU: Generated attestation key data\r\n");
	for(index = 0; index < size; index++){
		XPfw_Printf(DEBUG_DETAILED, "%02x", kernel_cert_sig[index]);
	}
	XPfw_Printf(DEBUG_DETAILED, "\r\n");
	for(index = 0; index < size; index++){
		if(encrypt_sig_out[index] != kernel_cert[index]){
			XPfw_Printf(DEBUG_ERROR, "PMU: Failed to verify Kernel CertSignature\r\n");
			return;
		}
	}

	XPfw_Printf(DEBUG_DETAILED, "Sending Signature to RPU\r\n");

	//Send the signature back to the Security Monitor
	while(bytes_sent < RSA_SIZE){
		/* Each packet is formatted with the first word as the header.
		 * The next word contains the start and end index of the corresponding
		 * bytes of the attestation PK signature.
		 * Finally, the next four words (word 2-5) contain the actual attestation PK
		 * chunk.
		 */
		u16 start_index = bytes_sent;
		u16 end_index = bytes_sent + 16U;
		msg_buf[1] = (bytes_sent << 16) | end_index;

		//Send 16 bytes of the signature

		//memcpy causes an endianness flip. For now, do it this way
		for(index = 0; index < 4; index++){ //Four words in message
			u32 msg_word = (kernel_cert_sig[bytes_sent] << 24) |
							(kernel_cert_sig[bytes_sent+1] << 16) |
							(kernel_cert_sig[bytes_sent+2] << 8) |
							(kernel_cert_sig[bytes_sent+3]);
			bytes_sent += 4;

			msg_buf[index+2] = msg_word;
		}


		//Send the IPI
		//XPfw_Printf(DEBUG_ERROR, "PMU: Sending cert\r\n");
		status = XPfw_IpiWriteMessage(sec_ipi_mod_ptr, IPI_PMU_0_IER_RPU_0_MASK,
				msg_buf, 8);
		if(status != XST_SUCCESS){
			XPfw_Printf(DEBUG_ERROR, "PMU: IPI Write Message Failed \r\n");
			return;
		}
		status = XPfw_IpiTrigger(IPI_PMU_0_IER_RPU_0_MASK);
		if(status != XST_SUCCESS){
			XPfw_Printf(DEBUG_ERROR, "PMU: IPI Trigger failed \r\n");
			return;
		}
		status = XPfw_IpiPollForAck(IPI_PMU_0_IER_RPU_0_MASK, (~0));
		if(status != XST_SUCCESS){
			XPfw_Printf(DEBUG_ERROR, "PMU: IPI Poll for Ack Failed \r\n");
			return;
		}
		status = XPfw_IpiReadResponse(sec_ipi_mod_ptr, IPI_PMU_0_IER_RPU_0_MASK,
				resp_buf, 2);
		if(status != XST_SUCCESS){
			XPfw_Printf(DEBUG_ERROR, "PMU: IPI Read Response failed \r\n");
			return;
		}


		//Check that the expected indices match up
		if(resp_buf[1] != ((start_index << 16) | (end_index))){
			XPfw_Printf(DEBUG_ERROR, "PMU: RPU failed to ack byte indices\r\n");
			return;
		}
	}

	return;
}

/**
 * Code to load a bitstream onto the FPGA through PCAP.
 * This should be called by the IPI handler and given some
 * linear DRAM address that contains the bitstream as a .bin file.
 *
 * The sender of the IPI must load the bitstream into DRAM.
 *
 * This function sends back an IPI to the sender with the hash of
 * the bitstream binary loaded into memory.
 */
static void sec_load_bitstream(){
	u32 status;
	u32 fpga_status;
	u8 bitstream_digest[48];
	u32 msg_buf[8]; //Buffer to hold message to R5
	u32 resp_buf[2] = {0};
	u32 i;
	u32 bytes_sent = 0;
	XFpga XFpgaInstance = {0U};

	if(bitstream_size == 0 || bitstream_addr == NULL){
		XPfw_Printf(DEBUG_ERROR, "PMU: Bitstream address or size\r\n");
		return;
	}


	//XPfw_Printf(DEBUG_DETAILED, "PMU: Loading bitstream from address 0x%08x\r\n",
	//		bitstream_addr);
	//XPfw_Printf(DEBUG_DETAILED, "PMU: bitstream size %d\r\n", bitstream_size);

//	for(i = 0; i < bitstream_size; i++){
//		XPfw_Printf(DEBUG_DETAILED, "%02x", bitstream_addr[i]);
//	}
//	XPfw_Printf(DEBUG_DETAILED, "\r\n");

	//Hash the bitstream first with SHA3
	XCsuDma_Config *csu_config;
	csu_config = XCsuDma_LookupConfig(XPAR_CSUDMA_0_BASEADDR);
	if (csu_config == NULL){
		XPfw_Printf(DEBUG_ERROR, "PMU: Failed to configure CSU\r\n");
		return;
	}
	status = XCsuDma_CfgInitialize(&csu_dma, csu_config, csu_config->BaseAddress);
	if (status != XST_SUCCESS){
		XPfw_Printf(DEBUG_ERROR, "PMU: Failed to initialize CSU\r\n");
		return;
	}
	XSecure_Sha3Initialize(&secure_sha3, &csu_dma);
	if (status != XST_SUCCESS){
		XPfw_Printf(DEBUG_ERROR, "PMU: Failed to initialize SHA3\r\n");
		return;
	}
	XSecure_Sha3Digest(&secure_sha3, bitstream_addr, bitstream_size, bitstream_digest);

	//Load the bitstream through PCAP using 2023.2 API
	fpga_status = XFpga_Initialize(&XFpgaInstance);
	if (fpga_status != XST_SUCCESS){
		XPfw_Printf(DEBUG_ERROR, "PMU: Failed to initialize XFpga\r\n");
		return;
	}
	fpga_status = XFpga_BitStream_Load(&XFpgaInstance, (UINTPTR)bitstream_addr, 0U, 0U, 0U);
	if(fpga_status == XST_SUCCESS){
		XPfw_Printf(DEBUG_DETAILED, "PMU: PL Configuration successful\r\n");
	}
	else{
		XPfw_Printf(DEBUG_DETAILED, "PMU: PL Configuration failed\r\n");
	}

	//Send an IPI to the sender (R5_0) containing the hash of the bitstream
//	XPfw_Printf(DEBUG_DETAILED, "PMU: Bitstream hash is 0x");
//	for(i = 0; i < 48; i++){
//		XPfw_Printf(DEBUG_DETAILED, "%02x", bitstream_digest[i]);
//	}
//	XPfw_Printf(DEBUG_DETAILED, "\r\n");



	while(bytes_sent < SHA3_SIZE){
		msg_buf[1] = IPI_BITSTREAM_HASH_MASK;
		memcpy(&msg_buf[2], &bitstream_digest[bytes_sent], 16);

		status = XPfw_IpiWriteMessage(sec_ipi_mod_ptr, IPI_PMU_0_IER_RPU_0_MASK,
				msg_buf, 8);
		if(status != XST_SUCCESS){
			XPfw_Printf(DEBUG_ERROR, "PMU: IPI Write Message Failed \r\n");
			return;
		}
		status = XPfw_IpiTrigger(IPI_PMU_0_IER_RPU_0_MASK);
		if(status != XST_SUCCESS){
			XPfw_Printf(DEBUG_ERROR, "PMU: IPI Trigger failed \r\n");
			return;
		}
		status = XPfw_IpiPollForAck(IPI_PMU_0_IER_RPU_0_MASK, (~0));
		if(status != XST_SUCCESS){
			XPfw_Printf(DEBUG_ERROR, "PMU: IPI Poll for Ack Failed \r\n");
			return;
		}
		status = XPfw_IpiReadResponse(sec_ipi_mod_ptr, IPI_PMU_0_IER_RPU_0_MASK,
				resp_buf, 2);
		if(status != XST_SUCCESS){
			XPfw_Printf(DEBUG_ERROR, "PMU: IPI Read Response failed \r\n");
			return;
		}


		//Check that the expected reply matches
		if(resp_buf[1] != IPI_BITSTREAM_HASH_MASK){
			XPfw_Printf(DEBUG_ERROR, "PMU: RPU failed to ack hash command\r\n");
			return;
		}
		bytes_sent += 16;
	}
	return;
}


/**
* Code to handle the incoming IPI message from the security monitor
*/
static void sec_ipi_handler(const XPfw_Module_t* mod_ptr, u32 ipi_num, u32 src_mask,
		const u32* payload, u8 len){
	u32 status;
	u32 resp_buf[2] = {0};
	u32 cmd;

	//First, check if the ipi is on the correct channel (i.e. channel 0)
	if (ipi_num > 0){
		XPfw_Printf(DEBUG_ERROR, "PMU: Error: sec_ipi_handler only handles IPI on PMU-0\r\n");
		return;
	}


	//For debug, print out the payload
//	XPfw_Printf(DEBUG_DETAILED, "PMU: Payload Received len %d:",len);
	int i;
//	for(i = 0; i < len; i++){
//		XPfw_Printf(DEBUG_DETAILED, "i:%d,%x \r\n", i, payload[i]);
//	}
//	XPfw_Printf(DEBUG_DETAILED, "\r\n");

	//Redirect the interrupt to the appropriate callback
	memcpy(&cmd, &payload[1], 4);

	//XPfw_Printf(DEBUG_DETAILED, "PMU: Received command 0x%08x", cmd);
	if(cmd == IPI_BITSTREAM_HASH_MASK){
		//Load bitstream addr and size into global variables
		memcpy(&bitstream_addr, &payload[2], 4);
		memcpy(&bitstream_size, &payload[3], 4);

		//XPfw_Printf(DEBUG_DETAILED, "PMU: Received FPGA Program cmd \r\n");

		//Schedule the task to load the bitstream into FPGA
		status = XPfw_CoreScheduleTask(mod_ptr, 0U, sec_load_bitstream);
	}
	else{ //Certificate hash case

		//Store the attestation PK in local memory
		//Check the bounds on the payload
		u16 start_index = payload[1] >> 16;
		if (start_index % 16U != 0){
			XPfw_Printf(DEBUG_ERROR, "PMU:Error: invalid index for cert hash\r\n");
			return;
		}
		memcpy(&cert_hash[start_index], &payload[2], 16);

		//Check if the full attestation PK has been received.
		if(start_index == (u16)32U){
//			XPfw_Printf(DEBUG_DETAILED, "PMU:Received full attestation key:0x");
//			for(i = 0; i < 32; i++){
//				XPfw_Printf(DEBUG_DETAILED, "%x", attest_pk[i]);
//			}
//			XPfw_Printf(DEBUG_DETAILED, "\r\n");
			//If so, schedule the task to sign the attestation key.
			status = XPfw_CoreScheduleTask(mod_ptr, 0U, sec_sign_cert);
			if (status == XST_FAILURE){
				XPfw_Printf(DEBUG_ERROR, "PMU: Failed to schedule sign cert\r\n");
			}
		}
	}
	//Write the response
	resp_buf[1] = payload[1];
	XPfw_IpiWriteResponse(mod_ptr, src_mask, resp_buf, 2);


	return;
}

/**
* Initializes the configuration. Schedules periodic tasks.
*/
static void sec_ipi_cfg_init(const XPfw_Module_t* mod_ptr, const u32* cfg_data, u32 Len){
	//Schedule any periodic tasks here.
	return;
}


/**
* This function is called from xpfw_user_startup.c. Initializes and registers this
* module and associated handlers.
*/
void sec_ipi_mod_init(void){
	sec_ipi_mod_ptr = XPfw_CoreCreateMod();

	if (XPfw_CoreSetCfgHandler(sec_ipi_mod_ptr, sec_ipi_cfg_init) != XST_SUCCESS){
		XPfw_Printf(DEBUG_DETAILED, "PMU: Warning: sec_ipi_mod_ptr: Failed to set cfg_handler \r\n");
	}

	(void)XPfw_CoreSetIpiHandler(sec_ipi_mod_ptr, sec_ipi_handler, SEC_MOD_IPI_HANDLER_ID);
}


