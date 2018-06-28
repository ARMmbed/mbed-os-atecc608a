#include "mbed.h"
#include "greentea-client/test_env.h"
#include "unity.h"
#include "utest.h"

using namespace utest::v1;

void test_ecdsa_sign()
{
    TEST_ASSERT(true);
}

void test_ecdsa_verify()
{
    TEST_ASSERT(true);
}

utest::v1::status_t test_setup(const size_t number_of_cases) {
    GREENTEA_SETUP(40, "default_auto");
    return verbose_test_setup_handler(number_of_cases);
}

Case cases[] =
{
    Case("ecdsa_sign", test_ecdsa_sign),
    Case("ecdsa_verify", test_ecdsa_verify)
};

Specification specification(test_setup, cases);

int main()
{
    return !Harness::run(specification);
}
