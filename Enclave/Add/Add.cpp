#include "Enclave_t.h"


/*
 *@brief      Performs a simple addition in the enclave
 *
 * @param      a      The first input for our simple addition
 * @param      b      The second input for our simple addition
 *
 * @return     Truthy if addition successful, falsy otherwise.
 */
int ecall_add(int a, int b) {
    return a + b;
}
