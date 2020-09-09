#include <string>

#include "tee/untrusted/enclave/untrusted_enclave.h"
#include "tee/untrusted/untrusted_pbcall.h"

#include "./enclave_u.h"
#include "./kubetee.pb.h"
#include "app/app.h"

#ifdef __cplusplus
extern "C" {
#endif

TeeErrorCode PrintMessage(const std::string& req_str, std::string* res_str) {
  tee::PbGenericRequest req;
  tee::PbGenericResponse res;

  PB_PARSE(req, req_str);
  printf("PrintMessage: %s\n", req.argv()[0].c_str());
  PB_SERIALIZE(res, res_str);

  return TEE_SUCCESS;
}

TeeErrorCode RegisterUntrustedPbFunctionsEx() {
  ELOG_DEBUG("Register application untrusted protobuf call funtions");
  ADD_UNTRUSTED_PBCALL_FUNCTION(PrintMessage);
  return TEE_SUCCESS;
}

#ifdef __cplusplus
}
#endif

int main(void) {
  TeeErrorCode ret = TEE_ERROR_GENERIC;

  // Create and initialize the enclave
  std::string enclave_name = "SamplePbCall";
  EnclavesManager& em = EnclavesManager::GetInstance();
  EnclaveInstance* enclave = em.CreateEnclave(enclave_name, ENCLAVE_FILENAME);
  if (!enclave) {
    printf("Fail to creates enclave %s", enclave_name.c_str());
    return TEE_ERROR_CREATE_ENCLAVE;
  }

  // Try to do something else before destroy enclave and exit
  tee::PbGenericRequest req;
  tee::PbGenericResponse res;
  req.add_argv("Protobuf Call");
  ret = enclave->TeeRun("SayHello", req, &res);
  if (ret != TEE_SUCCESS) {
    printf("Fail to run trusted function: SayHello\n");
    return ret;
  }

  if (res.result().size()) {
    printf("%s\n", res.result()[0].c_str());
  }

  // Destroy the enclave explicitly, this is optional.
  EnclavesManager::GetInstance().DestroyEnclave(enclave);

  return ret;
}
