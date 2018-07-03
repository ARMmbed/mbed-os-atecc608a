#include "psa/crypto.h"
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

psa_status_t psa_asymmetric_sign( psa_key_slot_t key,
                                  psa_algorithm_t alg,
                                  const uint8_t *hash,
                                  size_t hash_length,
                                  const uint8_t *salt,
                                  size_t salt_length,
                                  uint8_t *signature,
                                  size_t signature_size,
                                  size_t *signature_length )
{
    ATCAError atca_err = ATCA_SUCCESS;
    ATCAKey *atca_key = NULL;

    (void) salt;
    (void) salt_length;

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
                                    const uint8_t *salt,
                                    size_t salt_length,
                                    const uint8_t *signature,
                                    size_t signature_length )
{
    ATCAError atca_err = ATCA_SUCCESS;
    ATCAKey *atca_key = NULL;

    (void) salt;
    (void) salt_length;

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
