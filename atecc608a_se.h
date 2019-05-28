/**
 * \file atecc608a_se.h
 * \brief Secure element driver structure for ATECC508A and ATECC509A.
 */

/*
 *  Copyright (C) 2019, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifndef ATECC608A_SE_H
#define ATECC608A_SE_H

#include "psa/crypto_se_driver.h"
#include "atca_basic.h"

extern psa_drv_se_info_t atecc608a_drv_info;
extern ATCAIfaceCfg atca_iface_config;

psa_status_t atecc608a_to_psa_error(ATCA_STATUS ret);

#define ATCAB_INIT()                                        \
    do                                                      \
    {                                                       \
        if (atcab_init(&atca_iface_config) != ATCA_SUCCESS) \
        {                                                   \
            status = PSA_ERROR_HARDWARE_FAILURE;            \
            goto exit;                                      \
        }                                                   \
    } while(0)

/** `atcab_release()` might return `ATCA_BAD_PARAM` if there is no global device
 *  initialized via `atcab_init()`. HAL might return an error if an i2c device
 *  cannot be released, but in current implementations it always returns
 *  `ATCA_SUCCESS` - therefore we are ignoring the return code. */
#define ATCAB_DEINIT()    \
    do                    \
    {                     \
        atcab_release();  \
    } while(0)

        
#endif /* ATECC608A_SE_H */
