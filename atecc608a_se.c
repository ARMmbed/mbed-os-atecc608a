#include "atecc608a_se.h"

#include "atca_status.h"
#include "atca_devtypes.h"
#include "atca_iface.h"
#include "atca_command.h"
#include "atca_basic.h"
#include "atca_helpers.h"

/* Uncomment to print results on success */
//#define DEBUG_PRINT

#ifdef DEBUG_PRINT
#include <stdio.h>
#endif
#include <stdbool.h>

#define ATCAB_INIT()                                        \
    do                                                      \
    {                                                       \
        if (atcab_init(&atca_iface_config) != ATCA_SUCCESS) \
        {                                                   \
            status = PSA_ERROR_HARDWARE_FAILURE;            \
            goto exit;                                      \
        }                                                   \
    } while(0)

#define ATCAB_DEINIT()    \
    do                    \
    {                     \
        atcab_release();  \
    } while(0)

#define ASSERT_STATUS(expression, expected, result)             \
    do                                                          \
    {                                                           \
        status = (expression);                                  \
        int ASSERT_STATUS_expected = (expected);                \
        if ((status) != (ASSERT_STATUS_expected))               \
        {                                                       \
            status = (result);                                  \
            goto exit;                                          \
        }                                                       \
    } while(0)

#define ASSERT_SUCCESS(operation, result) ASSERT_STATUS(operation,    \
                                                        ATCA_SUCCESS, \
                                                        result)
ATCAIfaceCfg atca_iface_config = {
    .iface_type = ATCA_I2C_IFACE,
    .devtype = ATECC608A,
    .atcai2c.slave_address = 0xC0,
    .atcai2c.bus = 2,
    .atcai2c.baud = 400000,
    .wake_delay = 1500,
    .rx_retries = 20,
};

static psa_status_t atecc608a_to_psa_error(ATCA_STATUS ret)
{
    switch (ret)
    {
    case ATCA_SUCCESS:
    case ATCA_RX_NO_RESPONSE:
    case ATCA_WAKE_SUCCESS:
        return PSA_SUCCESS;
    case ATCA_BAD_PARAM:
    case ATCA_INVALID_ID:
    case ATCA_INVALID_SIZE:
    case ATCA_SMALL_BUFFER:
    case ATCA_BAD_OPCODE:
    case ATCA_ASSERT_FAILURE:
        return PSA_ERROR_INVALID_ARGUMENT;
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
    default:
        return PSA_ERROR_HARDWARE_FAILURE;
    }
}

psa_status_t atecc608a_get_serial_number(uint8_t* buffer, size_t buffer_size,
                                         size_t *buffer_length)
{
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;

    if (buffer_size < ATCA_SERIAL_NUM_SIZE)
    {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    ATCAB_INIT();

    ASSERT_SUCCESS(atcab_read_serial_number(buffer), PSA_ERROR_HARDWARE_FAILURE);
    *buffer_length = ATCA_SERIAL_NUM_SIZE;

    exit:
    ATCAB_DEINIT();
    return status;
}

psa_status_t atecc608a_check_config_locked()
{
    bool config_locked;
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    
    ATCAB_INIT();

    ASSERT_SUCCESS(atcab_is_locked(LOCK_ZONE_CONFIG, &config_locked), PSA_ERROR_HARDWARE_FAILURE);

    exit:
    ATCAB_DEINIT();
    if(status == PSA_SUCCESS)
    {
        status = config_locked? PSA_SUCCESS : PSA_ERROR_HARDWARE_FAILURE;
    }
    return status;        
}

psa_status_t atecc608a_export_public_key(psa_key_slot_number_t key,
                                         uint8_t *p_data, size_t data_size,
                                         size_t *p_data_length)
{
    const size_t key_data_len = 65;
    const uint16_t slot = key;
    ATCA_STATUS ret = ATCA_GEN_FAIL;
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;

    if (data_size < key_data_len)
    {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    ATCAB_INIT();

    /* atcab_get_pubkey returns concatenated x and y values, and the desired 
       format is 0x04 + x + y. We start at &p_data[1] and add a 0x04 at p_data[0]. */
    ASSERT_SUCCESS((ret = atcab_get_pubkey(slot, &p_data[1])), atecc608a_to_psa_error(ret));

    p_data[0] = 4;
    *p_data_length = key_data_len;

#ifdef DEBUG_PRINT
    printf("atecc608a_export_key - pubkey size %d:\n", *p_data_length);
    atcab_printbin_sp(p_data, *p_data_length);
#endif

    exit:
    ATCAB_DEINIT();
    return status;
}

psa_status_t atecc608a_asymmetric_sign(psa_key_slot_number_t key_slot,
                                       psa_algorithm_t alg,
                                       const uint8_t *p_hash,
                                       size_t hash_length,
                                       uint8_t *p_signature,
                                       size_t signature_size,
                                       size_t *p_signature_length)
{
    ATCA_STATUS ret = ATCA_GEN_FAIL;
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

    if(signature_size < ATCA_SIG_SIZE)
    {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    ATCAB_INIT();

    /* Signature will be returned here. Format is R and S integers in
     * big-endian format. 64 bytes for P256 curve. */
    ASSERT_SUCCESS((ret = atcab_sign(key_id, p_hash, p_signature)),
                   atecc608a_to_psa_error(ret));
         
    *p_signature_length = ATCA_SIG_SIZE;

#ifdef DEBUG_PRINT
    printf("atecc608a_asymmetric_sign - signature size %d:\n", *p_signature_length);
    atcab_printbin_sp(p_signature, *p_signature_length);
#endif

    exit:
    ATCAB_DEINIT();
    return status;
}
