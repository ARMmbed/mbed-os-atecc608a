#include "psa/crypto.h"
#include "psa_crypto_driver.h" // XXX
#include "ATCAFactory.h"

static psa_status_t atca_to_psa_error( ATCAError err )
{
    switch(err)
    {
        case ATCA_SUCCESS:
            return( PSA_SUCCESS );
        case ATCA_ERR_CHECK_MAC_OR_VERIFY_FAIL:
            return( PSA_ERROR_INVALID_SIGNATURE );
        case ATCA_ERR_DEVICE_ERROR:
        case ATCA_ERR_WAKE_TOKEN_RECVD:
        case ATCA_ERR_WATCHDOG_WILL_EXPIRE:
        case ATCA_ERR_COMMUNICATION:
        case ATCA_ERR_DEVICE_ALREADY_INITIALIZED:
        case ATCA_ERR_I2C_READ_ERROR:
        case ATCA_ERR_I2C_WRITE_ERROR:
            return( PSA_ERROR_HARDWARE_FAILURE );
        case ATCA_ERR_UNSUPPORTED_DEVICE_REVISION:
        case ATCA_ERR_NO_I2C:
            return( PSA_ERROR_NOT_SUPPORTED );
        case ATCA_ERR_BUFFER_TOO_SMALL:
            return( PSA_ERROR_BUFFER_TOO_SMALL );
        case ATCA_ERR_INVALID_PARAM:
        case ATCA_ERR_SLOT_NOT_PRIV_KEY:
            return( PSA_ERROR_INVALID_ARGUMENT );
        case ATCA_ERR_MEM_ALLOC_FAILURE:
            return( PSA_ERROR_INSUFFICIENT_MEMORY );
        default:
            return( PSA_ERROR_UNKNOWN_ERROR );
    }
}

static ATCAError atca_get_key( ATCAKeyID key_id, ATCAKey *&atca_key )
{
    ATCAError atca_err = ATCA_SUCCESS;
    ATCADevice *atca_device = ATCAFactory::GetDevice( atca_err );
    if ( ATCA_SUCCESS == atca_err )
        atca_err = atca_device->GetKeyToken( (ATCAKeyID) key_id, atca_key );
    return atca_err;
}

#if DIRECT_IMPLEMENTATION

psa_status_t psa_asymmetric_sign( psa_key_slot_t key,
                                  psa_algorithm_t alg,
                                  const uint8_t *hash,
                                  size_t hash_length,
                                  uint8_t *signature,
                                  size_t signature_size,
                                  size_t *signature_length )
{
    ATCAError atca_err = ATCA_SUCCESS;
    ATCAKey *atca_key = NULL;

    if( ! PSA_ALG_IS_ECDSA( alg ) )
        return( PSA_ERROR_INVALID_ARGUMENT );

    atca_err = atca_get_key( (ATCAKeyID) key, atca_key );
    if( ATCA_SUCCESS == atca_err )
    {
        atca_err = atca_key->Sign( hash, hash_length,
                                   signature, signature_size,
                                   signature_length );
        delete( atca_key );
    }
    return( atca_to_psa_error( atca_err ) );
}

psa_status_t psa_asymmetric_verify( psa_key_slot_t key,
                                    psa_algorithm_t alg,
                                    const uint8_t *hash,
                                    size_t hash_length,
                                    const uint8_t *signature,
                                    size_t signature_length )
{
    ATCAError atca_err = ATCA_SUCCESS;
    ATCAKey *atca_key = NULL;

    if( ! PSA_ALG_IS_ECDSA( alg ) )
        return( PSA_ERROR_INVALID_ARGUMENT );

    atca_err = atca_get_key( (ATCAKeyID) key, atca_key );
    if( ATCA_SUCCESS == atca_err )
    {
        atca_err = atca_key->Verify( hash, hash_length,
                                     signature, signature_length );
        delete( atca_key );
    }
    return( atca_to_psa_error( atca_err ) );
}

#else

// Driver API implementation

static psa_status_t atca_asymmetric_opaque_sign( psa_key_slot_t key,
                                          psa_algorithm_t alg,
                                          const uint8_t *p_hash,
                                          size_t hash_length,
                                          uint8_t *p_signature,
                                          size_t signature_size,
                                          size_t *p_signature_length )
{
    ATCAError atca_err = ATCA_SUCCESS;
    ATCAKey *atca_key = NULL;

    if( ! PSA_ALG_IS_ECDSA( alg ) )
        return( PSA_ERROR_INVALID_ARGUMENT );

    atca_err = atca_get_key( (ATCAKeyID) key, atca_key );
    if( ATCA_SUCCESS == atca_err )
    {
        atca_err = atca_key->Sign( hash, hash_length,
                                   signature, signature_size,
                                   signature_length );
        delete( atca_key );
    }
    return( atca_to_psa_error( atca_err ) );
}

static psa_status_t atca_asymmetric_opaque_verify( psa_key_slot_t key,
                                            psa_algorithm_t alg,
                                            const uint8_t *p_hash,
                                            size_t hash_length,
                                            const uint8_t *p_signature,
                                            size_t signature_length )
{
    ATCAError atca_err = ATCA_SUCCESS;
    ATCAKey *atca_key = NULL;

    if( ! PSA_ALG_IS_ECDSA( alg ) )
        return( PSA_ERROR_NOT_SUPPORTED );

    atca_err = atca_get_key( (ATCAKeyID) key, atca_key );
    if( ATCA_SUCCESS == atca_err )
    {
        atca_err = atca_key->Verify( hash, hash_length,
                                     signature, signature_length );
        delete( atca_key );
    }
    return( atca_to_psa_error( atca_err ) );
}

extern "C" {

/* Naming order is inconsistent between asymmetric_opaque and opaque_mac.
 * Should be opaque_asymmetric. */

/* Mbed OS can't be linked into Mbed Crypto. Both Mbed Crypto and Mbed OS are
 * linked together at the same time. Our driver requires use of Mbed OS
 * (for SPI). Expose the table as a global. Not sure how our functions are
 * discovered by Mbed Crypto yet. */

struct pcd_opaque_asymmetric_t atca_opaque_asymmetric = {
    .p_sign = atca_asymmetric_opaque_sign,
    .p_verify = atca_asymmetric_opaque_sign,
};


/* XXX Something like this would be inside Mbed Crypto already... We wouldn't
 * have to call our own functions like this. */
psa_status_t psa_asymmetric_sign( psa_key_slot_t key,
                                  psa_algorithm_t alg,
                                  const uint8_t *hash,
                                  size_t hash_length,
                                  uint8_t *signature,
                                  size_t signature_size,
                                  size_t *signature_length )
{
    return atca_opaque_asymmetric.p_sign(key, alg, hash, hash_length, signature, signature_size, signature_length);
}

psa_status_t psa_asymmetric_verify( psa_key_slot_t key,
                                    psa_algorithm_t alg,
                                    const uint8_t *hash,
                                    size_t hash_length,
                                    const uint8_t *signature,
                                    size_t signature_length )
{
    return atca_opaque_asymmetric.p_verify(key, alg, hash, hash_length, signature, signature_length);
}

/* XXX How can you import an opaque key into ATECC608A? */

};
