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

#define PSA_ATECC608A_LIFETIME 0xf0
extern psa_drv_se_t atecc608a_drv_info;

psa_status_t atecc608a_to_psa_error(ATCA_STATUS ret);

psa_status_t atecc608a_init();

psa_status_t atecc608a_deinit();

/** Read from a given slot at an offset. Data zone has to be locked for this
 *  function to work. */
psa_status_t atecc608a_read(uint16_t slot, size_t offset, uint8_t *data, size_t length);

/** Write to a given slot at an offset. If the data zone is locked, offset and
 *  length must be multiples of a word (4 bytes). If the data zone is unlocked,
 *  only 32-byte writes are allowed, and the offset and length must be
 *  multiples of 32. */
psa_status_t atecc608a_write(uint16_t slot, size_t offset, const uint8_t *data, size_t length);

#endif /* ATECC608A_SE_H */
