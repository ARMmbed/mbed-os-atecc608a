/**
 * \file atecc608a_se.c
 * \brief Secure element driver implementation for ATECC508A and ATECC509A.
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
#include "atecc608a_se.h"
#include "atca_helpers.h"

#ifdef DEBUG_PRINT
#include <stdio.h>
#endif

#include <stdbool.h>
#include <stdint.h>

/* Uncomment to print results on success */
//#define DEBUG_PRINT

/** This macro checks if the result of an `expression` is equal to an
 *  `expected` value and sets a `status` variable of type `psa_status_t` to
 *  `PSA_SUCCESS`. If they are not equal, the `status` is set to
 *  `psa_error instead`, and the code jumps to the `exit` label. */
#define ASSERT_STATUS(expression, expected, psa_error)          \
    do                                                          \
    {                                                           \
        ATCA_STATUS ASSERT_result = (expression);               \
        ATCA_STATUS ASSERT_expected = (expected);               \
        if ((ASSERT_result) != (ASSERT_expected))               \
        {                                                       \
            status = (psa_error);                               \
            goto exit;                                          \
        }                                                       \
        status = PSA_SUCCESS;                                   \
    } while(0)

/** Check if an ATCA operation is successful, translate the error otherwise. */
#define ASSERT_SUCCESS(expression) ASSERT_STATUS(expression, ATCA_SUCCESS, \
                                      atecc608a_to_psa_error(ASSERT_result))

/** Does the same as the macro above, but without the error translation and for
 *  the PSA return code - PSA_SUCCESS.*/
#define ASSERT_SUCCESS_PSA(expression) ASSERT_STATUS(expression, PSA_SUCCESS, \
                                                     ASSERT_result)

static ATCAIfaceCfg atca_iface_config = {
    .iface_type = ATCA_I2C_IFACE,
    .devtype = ATECC508A,
    .atcai2c.slave_address = 0xC0,
    .atcai2c.bus = 2,
    .atcai2c.baud = 400000,
    .wake_delay = 1500,
    .rx_retries = 20,
};

psa_status_t atecc608a_to_psa_error(ATCA_STATUS ret)
{
    switch (ret)
    {
    case ATCA_SUCCESS:
    case ATCA_RX_NO_RESPONSE:
    case ATCA_WAKE_SUCCESS:
        return PSA_SUCCESS;
    case ATCA_BAD_PARAM:
    case ATCA_INVALID_ID:
        return PSA_ERROR_INVALID_ARGUMENT;
    case ATCA_ASSERT_FAILURE:
        return PSA_ERROR_TAMPERING_DETECTED;
    case ATCA_SMALL_BUFFER:
        return PSA_ERROR_BUFFER_TOO_SMALL;
    case ATCA_RX_CRC_ERROR:
    case ATCA_RX_FAIL:
    case ATCA_STATUS_CRC:
    case ATCA_RESYNC_WITH_WAKEUP:
    case ATCA_PARITY_ERROR:
    case ATCA_TX_TIMEOUT:
    case ATCA_RX_TIMEOUT:
    case ATCA_TOO_MANY_COMM_RETRIES:
    case ATCA_COMM_FAIL:
    case ATCA_TIMEOUT:
    case ATCA_TX_FAIL:
    case ATCA_NO_DEVICES:
        return PSA_ERROR_COMMUNICATION_FAILURE;
    case ATCA_UNIMPLEMENTED:
        return PSA_ERROR_NOT_SUPPORTED;
    case ATCA_ALLOC_FAILURE:
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    case ATCA_BAD_OPCODE:
    case ATCA_CONFIG_ZONE_LOCKED:
    case ATCA_DATA_ZONE_LOCKED:
    case ATCA_NOT_LOCKED:
    case ATCA_WAKE_FAILED:
    case ATCA_STATUS_UNKNOWN:
    case ATCA_STATUS_ECC:
    case ATCA_STATUS_SELFTEST_ERROR:
    case ATCA_CHECKMAC_VERIFY_FAILED:
    case ATCA_PARSE_ERROR:
    case ATCA_FUNC_FAIL:
    case ATCA_GEN_FAIL:
    case ATCA_EXECUTION_ERROR:
    case ATCA_HEALTH_TEST_ERROR:
    case ATCA_INVALID_SIZE:
    default:
        return PSA_ERROR_HARDWARE_FAILURE;
    }
}

psa_status_t atecc608a_init()
{
    return atecc608a_to_psa_error(atcab_init(&atca_iface_config));
}

psa_status_t atecc608a_deinit()
{
    return atecc608a_to_psa_error(atcab_release());
}

static psa_status_t atecc608a_export_public_key(psa_key_slot_number_t key,
                                                uint8_t *p_data, size_t data_size,
                                                size_t *p_data_length)
{
    const size_t key_data_len = 65;
    const uint16_t slot = key;
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;

    if (data_size < key_data_len)
    {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    ASSERT_SUCCESS_PSA(atecc608a_init());

    /* atcab_get_pubkey returns concatenated x and y values, and the desired
       format is 0x04 + x + y. We start at &p_data[1] and add a 0x04 at p_data[0]. */
    ASSERT_SUCCESS(atcab_get_pubkey(slot, &p_data[1]));

    p_data[0] = 4;
    *p_data_length = key_data_len;

#ifdef DEBUG_PRINT
    printf("atecc608a_export_key - pubkey size %d:\n", *p_data_length);
    atcab_printbin_sp(p_data, *p_data_length);
#endif

exit:
    atecc608a_deinit();
    return status;
}
static psa_status_t atecc608a_import_public_key(psa_key_slot_number_t key_slot,
                                                psa_key_lifetime_t lifetime,
                                                psa_key_type_t type,
                                                psa_algorithm_t alg,
                                                psa_key_usage_t usage,
                                                const uint8_t *p_data,
                                                size_t data_length)
{
    const uint16_t key_id = key_slot;
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;

    /* Keys 8 to 15 can store public keys. Slots 1-7 are too small. */
    if (key_id < 7 || key_id > 15 || data_length != ATCA_PUB_KEY_SIZE)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (!PSA_KEY_TYPE_IS_PUBLIC_KEY(type))
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* We can only do ECDSA on SHA-256 */
    if (alg != PSA_ALG_ECDSA(PSA_ALG_SHA_256) && alg != PSA_ALG_ECDSA_ANY)
    {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    ASSERT_SUCCESS_PSA(atecc608a_init());

    /* Signature format is R and S integers in big-endian format.
     * 64 bytes for P256 curve. */
    ASSERT_SUCCESS(atcab_write_pubkey(key_id, p_data));
exit:
    atecc608a_deinit();
    return status;
}

static psa_status_t atecc608a_asymmetric_sign(psa_key_slot_number_t key_slot,
                                              psa_algorithm_t alg,
                                              const uint8_t *p_hash,
                                              size_t hash_length,
                                              uint8_t *p_signature,
                                              size_t signature_size,
                                              size_t *p_signature_length)
{
    const uint16_t key_id = key_slot;
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;

    /* We can only do ECDSA on SHA-256 */
    if (alg != PSA_ALG_ECDSA(PSA_ALG_SHA_256) && alg != PSA_ALG_ECDSA_ANY)
    {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (hash_length != 32)
    {
        /* The driver only supports signing things of length 32. */
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (signature_size < ATCA_SIG_SIZE)
    {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    ASSERT_SUCCESS_PSA(atecc608a_init());

    /* Signature will be returned here. Format is R and S integers in
     * big-endian format. 64 bytes for P256 curve. */
    ASSERT_SUCCESS(atcab_sign(key_id, p_hash, p_signature));

    *p_signature_length = ATCA_SIG_SIZE;

#ifdef DEBUG_PRINT
    printf("atecc608a_asymmetric_sign - signature size %d:\n", *p_signature_length);
    atcab_printbin_sp(p_signature, *p_signature_length);
#endif

exit:
    atecc608a_deinit();
    return status;
}

psa_status_t atecc608a_asymmetric_verify(psa_key_slot_number_t key_slot,
                                         psa_algorithm_t alg,
                                         const uint8_t *p_hash,
                                         size_t hash_length,
                                         const uint8_t *p_signature,
                                         size_t signature_length)
{
    const uint16_t key_id = key_slot;
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    bool is_verified = false;

    /* Keys 8 to 15 can store public keys. */
    if (key_id < 7 || key_id > 15)
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* We can only do ECDSA on SHA-256 */
    if (alg != PSA_ALG_ECDSA(PSA_ALG_SHA_256) && alg != PSA_ALG_ECDSA_ANY)
    {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (hash_length != 32)
    {
        /* The driver only supports hashes of length 32. */
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (signature_length != ATCA_SIG_SIZE)
    {
        /* The driver only supports signatures of length 64. */
        return PSA_ERROR_NOT_SUPPORTED;
    }

    ASSERT_SUCCESS_PSA(atecc608a_init());

    ASSERT_SUCCESS(atcab_verify_stored(p_hash, p_signature, key_id, &is_verified));

exit:
    atecc608a_deinit();
    return status;
}

#define PSA_ATECC608A_LIFETIME 0xdeadbeefU

static psa_drv_se_asymmetric_t atecc608a_asymmetric =
{
    .p_sign = &atecc608a_asymmetric_sign,
    .p_verify = &atecc608a_asymmetric_verify,
    .p_encrypt = 0,
    .p_decrypt = 0,
};

static psa_drv_se_key_management_t atecc608a_key_management =
{
    /* So far there is no public key import function in the API, so use this instead */
    .p_import = &atecc608a_import_public_key,
    .p_generate = 0,
    .p_destroy = 0,
    /* So far there is no public key export function in the API, so use this instead */
    .p_export = &atecc608a_export_public_key,
};

psa_drv_se_info_t atecc608a_drv_info =
{
    .lifetime = PSA_ATECC608A_LIFETIME,
    .p_key_management = &atecc608a_key_management,
    .p_mac = 0,
    .p_cipher = 0,
    .p_asym = &atecc608a_asymmetric,
    .p_aead = 0,
    .p_derive = 0,
    .slot_min = 0,
    .slot_max = 0,
};
