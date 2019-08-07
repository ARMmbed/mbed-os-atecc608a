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

#include "psa/crypto.h"

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
    switch (ret) {
        case ATCA_SUCCESS:
        case ATCA_RX_NO_RESPONSE:
        case ATCA_WAKE_SUCCESS:
            return PSA_SUCCESS;
        case ATCA_BAD_PARAM:
        case ATCA_INVALID_ID:
            return PSA_ERROR_INVALID_ARGUMENT;
        case ATCA_ASSERT_FAILURE:
            return PSA_ERROR_CORRUPTION_DETECTED;
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

/* The driver works with pubkeys as concatenated x and y values, and the PSA
 * format for pubkeys is 0x04 + x + y. Always use a pubkey buffer in PSA
 * format, with enough space for the PSA format. To translate this buffer for
 * use with cryptoauthlib, use pubkey_for_driver(). To ensure the buffer is in
 * valid PSA format after cryptoauthlib operations, call pubkey_for_psa(). */
static uint8_t *pubkey_for_driver(uint8_t *data)
{
    return &data[1];
}

static void pubkey_for_psa(uint8_t *data)
{
    data[0] = 0x4;
}

static psa_status_t is_public_key_slot(uint16_t key_slot)
{
    /* Keys 8 to 15 can store public keys. Slots 1-7 are too small. */
    return ((key_slot >= 8 && key_slot <= 15) ? PSA_SUCCESS : PSA_ERROR_INVALID_ARGUMENT);
}

psa_status_t atecc608a_init()
{
    return atecc608a_to_psa_error(atcab_init(&atca_iface_config));
}

psa_status_t atecc608a_deinit()
{
    return atecc608a_to_psa_error(atcab_release());
}

static psa_status_t atecc608a_export_public_key(psa_drv_se_context_t *drv_context,
                                                psa_key_slot_number_t key,
                                                uint8_t *p_data,
                                                size_t data_size,
                                                size_t *p_data_length)
{
    const size_t key_data_len = PSA_KEY_EXPORT_MAX_SIZE(
                                    PSA_KEY_TYPE_ECC_PUBLIC_KEY(
                                        PSA_ECC_CURVE_SECP256R1),
                                    256);
    const uint16_t slot = key;
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;

    if (data_size < key_data_len) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    ASSERT_SUCCESS_PSA(atecc608a_init());

    ASSERT_SUCCESS(atcab_get_pubkey(slot, pubkey_for_driver(p_data)));
    pubkey_for_psa(p_data);

    *p_data_length = key_data_len;

#ifdef DEBUG_PRINT
    printf("atecc608a_export_key - pubkey size %d:\n", *p_data_length);
    atcab_printbin_sp(p_data, *p_data_length);
#endif

exit:
    atecc608a_deinit();
    return status;
}
static psa_status_t atecc608a_import_public_key(
    psa_drv_se_context_t *drv_context,
    psa_key_slot_number_t key_slot,
    const psa_key_attributes_t *attributes,
    const uint8_t *data,
    size_t data_length,
    size_t *bits)
{
    const uint16_t key_id = key_slot;
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    psa_key_type_t type = psa_get_key_type(attributes);
    psa_algorithm_t alg = psa_get_key_algorithm(attributes);

    ASSERT_SUCCESS_PSA(is_public_key_slot(key_id));

    /* Check if the key has a size of 65 {0x04, X, Y}. */
    if (data_length != PSA_KEY_EXPORT_MAX_SIZE(PSA_KEY_TYPE_ECC_PUBLIC_KEY(
                                                   PSA_ECC_CURVE_SECP256R1),
                                               256)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (type != PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_CURVE_SECP256R1)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    /* The driver can only do randomized ECDSA on SHA-256 */
    if (alg != PSA_ALG_ECDSA(PSA_ALG_SHA_256) && alg != PSA_ALG_ECDSA_ANY) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    ASSERT_SUCCESS_PSA(atecc608a_init());

    ASSERT_SUCCESS(atcab_write_pubkey(key_id, pubkey_for_driver((uint8_t *) data)));

    if (bits != NULL) {
        /* The 64-byte key is written as 72 bytes. See atcab_write_pubkey() for
         * why 72 bytes. */
        *bits = PSA_BYTES_TO_BITS(72);
    }

exit:
    atecc608a_deinit();
    return status;
}

static psa_status_t atecc608a_generate_key(
    psa_drv_se_context_t *drv_context,
    psa_key_slot_number_t key_slot,
    const psa_key_attributes_t *attributes,
    uint8_t *pubkey, size_t pubkey_size, size_t *pubkey_length)
{
    const uint16_t key_id = key_slot;
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    psa_key_type_t type = psa_get_key_type(attributes);
    size_t bits = psa_get_key_bits(attributes);

    /* The hardware has slots 0-15 */
    if (key_slot > 15) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (type != PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_CURVE_SECP256R1)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (bits != PSA_BYTES_TO_BITS(ATCA_PRIV_KEY_SIZE)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (pubkey != NULL && pubkey_size < 1 + ATCA_PUB_KEY_SIZE) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    ASSERT_SUCCESS_PSA(atecc608a_init());

    if (pubkey != NULL) {
        ASSERT_SUCCESS(atcab_genkey(key_id, pubkey_for_driver(pubkey)));
        pubkey_for_psa(pubkey);
    } else {
        ASSERT_SUCCESS(atcab_genkey(key_id, NULL));
    }

    if (pubkey_length != NULL) {
        *pubkey_length = 1 + ATCA_PUB_KEY_SIZE;
    }

exit:
    atecc608a_deinit();
    return status;
}

static psa_status_t atecc608a_asymmetric_sign(psa_drv_se_context_t *drv_context,
                                              psa_key_slot_number_t key_slot,
                                              psa_algorithm_t alg,
                                              const uint8_t *p_hash,
                                              size_t hash_length,
                                              uint8_t *p_signature,
                                              size_t signature_size,
                                              size_t *p_signature_length)
{
    const uint16_t key_id = key_slot;
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;

    /* The driver can only do randomized ECDSA on SHA-256 */
    if (alg != PSA_ALG_ECDSA(PSA_ALG_SHA_256) && alg != PSA_ALG_ECDSA_ANY) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (hash_length != PSA_HASH_SIZE(PSA_ALG_SHA_256)) {
        /* The driver only supports signing things of length 32. */
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (signature_size < ATCA_SIG_SIZE) {
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

psa_status_t atecc608a_asymmetric_verify(psa_drv_se_context_t *drv_context,
                                         psa_key_slot_number_t key_slot,
                                         psa_algorithm_t alg,
                                         const uint8_t *p_hash,
                                         size_t hash_length,
                                         const uint8_t *p_signature,
                                         size_t signature_length)
{
    const uint16_t key_id = key_slot;
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    bool is_verified = false;

    ASSERT_SUCCESS_PSA(is_public_key_slot(key_id));

    /* The driver can only do randomized ECDSA on SHA-256 */
    if (alg != PSA_ALG_ECDSA(PSA_ALG_SHA_256) && alg != PSA_ALG_ECDSA_ANY) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (hash_length != PSA_HASH_SIZE(PSA_ALG_SHA_256)) {
        /* The driver only supports hashes of length 32. */
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (signature_length != ATCA_SIG_SIZE) {
        /* The driver only supports signatures of length 64. */
        return PSA_ERROR_INVALID_SIGNATURE;
    }

    ASSERT_SUCCESS_PSA(atecc608a_init());

    ASSERT_SUCCESS(atcab_verify_stored(p_hash, p_signature, key_id, &is_verified));

exit:
    atecc608a_deinit();
    return status;
}

psa_status_t atecc608a_write(uint16_t slot, size_t offset, const uint8_t *data, size_t length)
{
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;

    /* The hardware has slots 0-15 */
    if (slot > 15) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    ASSERT_SUCCESS_PSA(atecc608a_init());
    ASSERT_SUCCESS(atcab_write_bytes_zone(ATCA_ZONE_DATA, slot, offset, data, length));

exit:
    atecc608a_deinit();
    return status;
}

psa_status_t atecc608a_read(uint16_t slot, size_t offset, uint8_t *data, size_t length)
{
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;

    /* The hardware has slots 0-15 */
    if (slot > 15) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    ASSERT_SUCCESS_PSA(atecc608a_init());
    ASSERT_SUCCESS(atcab_read_bytes_zone(ATCA_ZONE_DATA, slot, offset, data, length));

exit:
    atecc608a_deinit();
    return status;
}

static psa_status_t atecc608a_validate_slot_number(
    psa_drv_se_context_t *drv_context,
    const psa_key_attributes_t *attributes,
    psa_key_creation_method_t method,
    psa_key_slot_number_t key_slot)
{
    psa_key_type_t type = psa_get_key_type(attributes);
    if (PSA_KEY_TYPE_IS_ECC_KEY_PAIR(type)) {
        if (key_slot <= 15) {
            return PSA_SUCCESS;
        }
    } else if (PSA_KEY_TYPE_IS_ECC_PUBLIC_KEY(type)) {
        if (key_slot >= 8 && key_slot <= 15) {
            return PSA_SUCCESS;
        }
    }
    return PSA_ERROR_NOT_SUPPORTED;
}

static psa_status_t atecc608a_allocate_key(
    psa_drv_se_context_t *drv_context,
    void *persistent_data,
    const psa_key_attributes_t *attributes,
    psa_key_creation_method_t method,
    psa_key_slot_number_t *key_slot)
{
    return PSA_SUCCESS;
}

static psa_drv_se_asymmetric_t atecc608a_asymmetric = {
    .p_sign = atecc608a_asymmetric_sign,
    .p_verify = atecc608a_asymmetric_verify,
    .p_encrypt = 0,
    .p_decrypt = 0,
};

static psa_drv_se_key_management_t atecc608a_key_management = {
    /* So far there is no public key import function in the API, so use this instead */
    .p_allocate = atecc608a_allocate_key,
    .p_validate_slot_number = atecc608a_validate_slot_number,
    .p_import = atecc608a_import_public_key,
    .p_generate = atecc608a_generate_key,
    .p_destroy = 0,
    .p_export = 0,
    .p_export_public = atecc608a_export_public_key,
};

psa_drv_se_t atecc608a_drv_info = {
    .key_management = &atecc608a_key_management,
    .mac = 0,
    .cipher = 0,
    .asymmetric = &atecc608a_asymmetric,
    .aead = 0,
    .derivation = 0,
    .hal_version = PSA_DRV_SE_HAL_VERSION
};
