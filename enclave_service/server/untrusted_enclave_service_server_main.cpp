#include <signal.h>

#include <string>

#include "tee/common/log.h"
#include "tee/untrusted/enclave/untrusted_enclave.h"

#include "untrusted/untrusted_enclave_service_server.h"

#define ENCLAVE_FILENAME "enclave_service.signed.so"

static EnclaveInstance* g_enclave = nullptr;

void sig_handler(int signum) {
  if (signum == SIGINT) {
    EnclavesManager::GetInstance().DestroyEnclave(g_enclave);
    exit(signum);
  }
}

int SGX_CDECL main(void) {
  // Create and initialize the enclave
  std::string enclave_name = "EnclaveServiceServer";
  g_enclave = EnclavesManager::GetInstance().CreateEnclave(enclave_name,
                                                           ENCLAVE_FILENAME);
  if (!g_enclave) {
    return TEE_ERROR_CREATE_ENCLAVE;
  }

  signal(SIGINT, sig_handler);

  // Initialize the enclave service server
  tee::untrusted::EnclaveServiceServer es_server;
  TeeErrorCode ret = es_server.InitServer(g_enclave);
  if (ret != TEE_SUCCESS) {
    return ret;
  }

  // Run as enclave service server and wait for the sync requests
  return es_server.RunServer();
}
