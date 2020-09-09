#ifndef ENCLAVE_SAMPLES_REMOTE_ATTESTATION_APP_APP_H_
#define ENCLAVE_SAMPLES_REMOTE_ATTESTATION_APP_APP_H_

#include <assert.h>
#include <stdio.h>

#include "./sgx_eid.h"    // sgx_enclave_id_t
#include "./sgx_error.h"  // sgx_status_t

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#define ENCLAVE_FILENAME "enclave_remote_attestation.signed.so"

#if defined(__cplusplus)
extern "C" {
#endif

#if defined(__cplusplus)
}
#endif

#endif  // ENCLAVE_SAMPLES_REMOTE_ATTESTATION_APP_APP_H_
