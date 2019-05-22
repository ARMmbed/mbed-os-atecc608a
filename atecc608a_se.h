/**
 * \file atecc608a_se.h
 * \brief Secure element implementation for ATECC508A and ATECC509A
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

#include "psa/crypto.h"

psa_status_t atecc608a_get_serial_number(uint8_t* buffer, size_t buffer_size);
psa_status_t atecc608a_check_config_locked();
psa_status_t atecc608a_export_public_key(psa_key_slot_number_t key, uint8_t *p_data,
                                         size_t data_size, size_t *p_data_length);
psa_status_t atecc608a_asymmetric_sign(psa_key_slot_number_t key_slot,
                                       psa_algorithm_t alg,
                                       const uint8_t *p_hash,
                                       size_t hash_length,
                                       uint8_t *p_signature,
                                       size_t signature_size,
                                       size_t *p_signature_length);

#endif /* ATECC608A_SE_H */
