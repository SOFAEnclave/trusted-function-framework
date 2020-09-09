#include <iostream>
#include <string>

#include "./sgx_urts.h"

#include "tee/untrusted/enclave/untrusted_enclave.h"
#include "tee/untrusted/ra/untrusted_challenger.h"
#include "tee/untrusted/ra/untrusted_ias.h"
#include "tee/untrusted/untrusted_pbcall.h"

#include "./enclave_u.h"
#include "./kubetee.pb.h"
#include "app/app.h"

// OCall functions for this applicaiton
void ocall_print_string(const char* str) {
  printf("%s", str);
}

int SGX_CDECL main(void) {
  // Step 1: Create and initialize the enclave
  std::string enclave_name = "SampleRemoteAttestation";
  EnclaveInstance* enclave = EnclavesManager::GetInstance().CreateEnclave(
      enclave_name, ENCLAVE_FILENAME);
  if (!enclave) {
    printf("Fail to creates enclave %s", enclave_name.c_str());
    return TEE_ERROR_CREATE_ENCLAVE;
  }

  // Step 2: Try to load cached report or create new quote and report
  TeeErrorCode ret = enclave->FetchIasReport();
  if (ret != TEE_SUCCESS) {
    printf("Fail to get IAS report: 0x%x\n", ret);
    return ret;
  }

  // Step 3: If fetch new report successfully, then verify it.
  // Here, use the verify settings from configuration file
  ret = VerifyRaReport(enclave->GetPublicKey(), enclave->GetLocalIasReport());
  printf("Verify RA report by config file settings: 0x%08x\n", ret);

  return ret;
}
