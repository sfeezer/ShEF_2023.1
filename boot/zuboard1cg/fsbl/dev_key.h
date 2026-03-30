/*
 * dev_key.h
 *
 *  Created on: Mar 7, 2019
 *      Author: myzhao
 *
 *  Ported to ZuBoard 1CG FSBL (Vitis 2023.2)
 */

#ifndef SRC_DEV_KEY_H_
#define SRC_DEV_KEY_H_

#include "shef_config.h"

/* Exponent of private key */
static const u8 root_sk[512] = SHEF_ROOT_SK;

/* Exponent of Public key */
static const u32 root_pk = SHEF_ROOT_PK_EXP;

/* Modulus */
static const u8 root_mod[512] = SHEF_ROOT_PK_MOD;

#endif /* SRC_DEV_KEY_H_ */
