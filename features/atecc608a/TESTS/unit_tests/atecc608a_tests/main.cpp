#include "mbed.h"
#include "greentea-client/test_env.h"
#include "unity.h"
#include "utest.h"
#include "psa/crypto.h"

using namespace utest::v1;

#define ATCA_ECC_KEY_BIT_LEN 256

void test_ecdsa_sign_and_verify_good(void)
{
    const uint8_t hash[PSA_HASH_SIZE(PSA_ALG_SHA_256)] = "message";
    uint8_t sig[PSA_ECDSA_SIGNATURE_SIZE(ATCA_ECC_KEY_BIT_LEN)] = {0};
    size_t sig_len = 0;

    TEST_ASSERT(psa_asymmetric_sign(0, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                hash, sizeof(hash), NULL, 0,
                sig, sizeof(sig), &sig_len) == PSA_SUCCESS);

    TEST_ASSERT(PSA_ECDSA_SIGNATURE_SIZE(ATCA_ECC_KEY_BIT_LEN) ==
                sig_len);

    TEST_ASSERT(psa_asymmetric_verify(0, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                hash, sizeof(hash), NULL, 0,
                (const uint8_t*) sig, sig_len) == PSA_SUCCESS);
}

void test_ecdsa_sign_fail_hash_buf_too_big(void)
{
    const uint8_t hash[PSA_HASH_SIZE(PSA_ALG_SHA_256) + 1] = "message";
    uint8_t sig[PSA_ECDSA_SIGNATURE_SIZE(ATCA_ECC_KEY_BIT_LEN)] = {0};
    size_t sig_len = 0;

    TEST_ASSERT(psa_asymmetric_sign(0, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                hash, sizeof(hash), NULL, 0,
                sig, sizeof(sig), &sig_len) == PSA_ERROR_INVALID_ARGUMENT);
}

void test_ecdsa_sign_fail_hash_buf_too_small(void)
{
    const uint8_t hash[PSA_HASH_SIZE(PSA_ALG_SHA_256 - 1)] = "message";
    uint8_t sig[PSA_ECDSA_SIGNATURE_SIZE(ATCA_ECC_KEY_BIT_LEN)] = {0};
    size_t sig_len = 0;

    TEST_ASSERT(psa_asymmetric_sign(0, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                hash, sizeof(hash), NULL, 0,
                sig, sizeof(sig), &sig_len) == PSA_ERROR_INVALID_ARGUMENT);
}

void test_ecdsa_sign_fail_sig_buf_too_small(void)
{
    const uint8_t hash[PSA_HASH_SIZE(PSA_ALG_SHA_256)] = "message";
    uint8_t sig[PSA_ECDSA_SIGNATURE_SIZE(ATCA_ECC_KEY_BIT_LEN) - 1] = {0};
    size_t sig_len = 0;

    TEST_ASSERT(psa_asymmetric_sign(0, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                hash, sizeof(hash), NULL, 0,
                sig, sizeof(sig), &sig_len) == PSA_ERROR_BUFFER_TOO_SMALL);
}

void test_ecdsa_sign_fail_invalid_alg(void)
{
    const uint8_t hash[PSA_HASH_SIZE(PSA_ALG_SHA_256)] = "message";
    uint8_t sig[PSA_ECDSA_SIGNATURE_SIZE(ATCA_ECC_KEY_BIT_LEN)] = {0};
    size_t sig_len = 0;

    TEST_ASSERT(psa_asymmetric_sign(0,
                PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256),
                hash, sizeof(hash), NULL, 0,
                sig, sizeof(sig), &sig_len) == PSA_ERROR_INVALID_ARGUMENT);
}

void test_ecdsa_verify_fail_sig_tampered(void)
{
    const uint8_t hash[PSA_HASH_SIZE(PSA_ALG_SHA_256)] = "message";
    uint8_t sig[PSA_ECDSA_SIGNATURE_SIZE(ATCA_ECC_KEY_BIT_LEN)] = {0};
    size_t sig_len = 0;

    osDelay(100);

    TEST_ASSERT(psa_asymmetric_sign(0, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                hash, sizeof(hash), NULL, 0,
                sig, sizeof(sig), &sig_len) == PSA_SUCCESS);

    TEST_ASSERT(PSA_ECDSA_SIGNATURE_SIZE(ATCA_ECC_KEY_BIT_LEN) ==
                sig_len);

    memset((void*)&sig[10], 7, 10); /* modify the signature */

    TEST_ASSERT(psa_asymmetric_verify(0, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                hash, sizeof(hash), NULL, 0,
                (const uint8_t*) sig, sig_len) == PSA_ERROR_INVALID_SIGNATURE);
}

void test_ecdsa_verify_fail_sig_buf_too_big(void)
{
    const uint8_t hash[PSA_HASH_SIZE(PSA_ALG_SHA_256)] = "message";
    const uint8_t sig[PSA_ECDSA_SIGNATURE_SIZE(ATCA_ECC_KEY_BIT_LEN) + 1] = {0};

    TEST_ASSERT(psa_asymmetric_verify(0, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                hash, sizeof(hash), NULL, 0,
                sig, sizeof(sig)) == PSA_ERROR_INVALID_ARGUMENT);
}

void test_ecdsa_verify_fail_sig_buf_too_small(void)
{
    const uint8_t hash[PSA_HASH_SIZE(PSA_ALG_SHA_256)] = "message";
    const uint8_t sig[PSA_ECDSA_SIGNATURE_SIZE(ATCA_ECC_KEY_BIT_LEN) - 1] = {0};

    TEST_ASSERT(psa_asymmetric_verify(0, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                hash, sizeof(hash), NULL, 0,
                sig, sizeof(sig)) == PSA_ERROR_INVALID_ARGUMENT);
}

void test_ecdsa_verify_fail_hash_buf_too_big(void)
{
    const uint8_t hash[PSA_HASH_SIZE(PSA_ALG_SHA_256) + 1] = "message";
    const uint8_t sig[PSA_ECDSA_SIGNATURE_SIZE(ATCA_ECC_KEY_BIT_LEN)] = {0};

    TEST_ASSERT(psa_asymmetric_verify(0, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                hash, sizeof(hash), NULL, 0,
                sig, sizeof(sig)) == PSA_ERROR_INVALID_ARGUMENT);
}

void test_ecdsa_verify_fail_hash_buf_too_small(void)
{
    const uint8_t hash[PSA_HASH_SIZE(PSA_ALG_SHA_256) - 1] = "message";
    const uint8_t sig[PSA_ECDSA_SIGNATURE_SIZE(ATCA_ECC_KEY_BIT_LEN)] = {0};

    TEST_ASSERT(psa_asymmetric_verify(0, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                hash, sizeof(hash), NULL, 0,
                sig, sizeof(sig)) == PSA_ERROR_INVALID_ARGUMENT);
}

void test_ecdsa_verify_fail_invalid_alg(void)
{
    const uint8_t hash[PSA_HASH_SIZE(PSA_ALG_SHA_256)] = "message";
    const uint8_t sig[PSA_ECDSA_SIGNATURE_SIZE(ATCA_ECC_KEY_BIT_LEN)] = {0};

    TEST_ASSERT(psa_asymmetric_verify(0,
                PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256),
                hash, sizeof(hash), NULL, 0,
                sig, sizeof(sig)) == PSA_ERROR_INVALID_ARGUMENT);
}

utest::v1::status_t test_setup(const size_t number_of_cases)
{
    GREENTEA_SETUP(40, "default_auto");
    return verbose_test_setup_handler(number_of_cases);
}

Case cases[] =
{
    Case("ecdsa sign and verify good",
         test_ecdsa_sign_and_verify_good),

    Case("ecdsa sign fail - hash buf too big",
         test_ecdsa_sign_fail_hash_buf_too_big),

    Case("ecdsa sign fail - hash buf too small",
         test_ecdsa_sign_fail_hash_buf_too_small),

    Case("ecdsa sign fail - sig buf too small",
         test_ecdsa_sign_fail_sig_buf_too_small),

    Case("ecdsa sign fail - invalid alg",
         test_ecdsa_sign_fail_invalid_alg),

    Case("ecdsa verify fail - sig tampered",
         test_ecdsa_verify_fail_sig_tampered),

    Case("ecdsa verify fail - sig buf too big",
         test_ecdsa_verify_fail_sig_buf_too_big),

    Case("ecdsa verify fail - sig buf too small",
         test_ecdsa_verify_fail_sig_buf_too_small),

    Case("ecdsa verify fail - hash buf too big",
         test_ecdsa_verify_fail_hash_buf_too_big),

    Case("ecdsa verify fail - hash buf too small",
         test_ecdsa_verify_fail_hash_buf_too_small),

    Case("ecdsa verify fail - invalid alg",
         test_ecdsa_verify_fail_invalid_alg)
};

Specification specification(test_setup, cases);

int main(void)
{
    return !Harness::run(specification);
}
