#include <string>

#include "./enclave_t.h"
#include "enclave/enclave.h"

#include "./kubetee.pb.h"

void ecall_say_hello() {
  ocall_print_string("Welcome to enclave!\n");
}
