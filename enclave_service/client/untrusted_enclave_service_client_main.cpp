#include <string>

#include "tee/common/log.h"
#include "tee/untrusted/enclave/untrusted_enclave.h"

#include "untrusted/untrusted_enclave_service_client.h"
#include "untrusted/untrusted_enclave_service_server.h"

#define ENCLAVE_FILENAME "enclave_service.signed.so"

int SGX_CDECL main(int argc, char** argv) {
  if (argc < 3) {
    printf("Usage: %s <function-name> [args ...]\n", argv[0]);
    return TEE_ERROR_PARAMETERS;
  }

  // Create and initialize the enclave
  std::string enclave_name = "EnclaveServiceClient";
  EnclaveInstance* enclave = EnclavesManager::GetInstance().CreateEnclave(
      enclave_name, ENCLAVE_FILENAME);
  if (!enclave) {
    printf("Fail to create enclave\n");
    return TEE_ERROR_CREATE_ENCLAVE;
  }

  // Call the remote trusted function
  tee::PbTeeRunRemoteRequest req;
  tee::PbTeeRunRemoteResponse res;
  req.set_function_name(argv[1]);
  for (int i = 2; i < argc; i++) {
    req.mutable_function_param()->add_argv(argv[i]);
  }

  tee::untrusted::EnclaveServiceClient es_client(enclave);
  TeeErrorCode ret = es_client.TeeRunRemote(&req, &res);
  if (res.result().result_size()) {
    printf("Result: %s\n", res.result().result()[0].c_str());
  }

  return ret;
}
