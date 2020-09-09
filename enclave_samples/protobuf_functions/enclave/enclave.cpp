#include <string>

#include "tee/common/log.h"
#include "tee/trusted/trusted_instance.h"
#include "tee/trusted/trusted_pbcall.h"

#include "./enclave_t.h"
#include "./kubetee.pb.h"

#include "enclave/enclave.h"

#ifdef __cplusplus
extern "C" {
#endif

TeeErrorCode SayHello(const std::string& req_str, std::string* res_str) {
  using tee::PbGenericRequest;
  using tee::PbGenericResponse;
  PbGenericRequest req;
  PbGenericResponse res;

  PB_PARSE(req, req_str);

  // Call untrusted pbcall function in trusted pbcall function
  PbGenericRequest ocall_req = req;
  PbGenericResponse ocall_res;
  TEE_CHECK_RETURN(tee::trusted::TeeInstance::GetInstance().ReeRun(
      "PrintMessage", ocall_req, &ocall_res));

  std::string welcome = "Welcome to enclave, ";
  res.add_result(welcome + req.argv()[0]);
  PB_SERIALIZE(res, res_str);

  return TEE_SUCCESS;
}

TeeErrorCode RegisterTrustedPbFunctionsEx() {
  ELOG_DEBUG("Register application trusted protobuf call funtions");
  ADD_TRUSTED_PBCALL_FUNCTION(SayHello);
  return TEE_SUCCESS;
}

#ifdef __cplusplus
}
#endif
