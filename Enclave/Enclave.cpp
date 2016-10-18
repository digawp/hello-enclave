#include "Enclave_t.h"
#include "sgx_trts.h"

int generate_random_number() {
    ocall_print("Processing random number generation...");
    return 42;
}
