#include <string>
#include <vector>

#include "./sgx_trts.h"

#include "tee/common/aes.h"
#include "tee/common/bytes.h"
#include "tee/common/challenger.h"
#include "tee/common/envelope.h"
#include "tee/common/error.h"
#include "tee/common/log.h"
#include "tee/common/rsa.h"
#include "tee/common/type.h"
#include "tee/trusted/trusted_pbcall.h"
#include "tee/trusted/utils/trusted_seal.h"

#include "./kubetee.pb.h"

#include "./enclave_service_t.h"

using tee::common::DigitalEnvelope;
using tee::trusted::TeeInstance;

#ifdef __cplusplus
extern "C" {
#endif

/// \brief This is demo trusted PbFunction to simple return the SHA256
///
/// To implement more complex PbFunctions, please refer to the header files
/// in sdk/include/tee folder
///
TeeErrorCode TeeGetSHA256(const std::string& req_str, std::string* res_str) {
  tee::PbGenericRequest req;
  tee::PbGenericResponse res;
  PB_PARSE(req, req_str);

  std::string data_str = req.argv()[0];
  if (data_str.empty()) {
    ELOG_ERROR("Empty data for getting SHA256");
    return TEE_ERROR_PARAMETERS;
  }

  tee::common::DataBytes data_bytes(data_str);
  res.add_result(data_bytes.ToSHA256().ToHexStr().GetStr());
  ELOG_DEBUG("SHA256 result: %s", data_bytes.GetStr().c_str());
  PB_SERIALIZE(res, res_str);
  return TEE_SUCCESS;
}

TeeErrorCode RegisterTrustedPbFunctionsEx() {
  ELOG_DEBUG("Register application trusted protobuf call functions");
  ADD_TRUSTED_PBCALL_FUNCTION(TeeGetSHA256);
  return TEE_SUCCESS;
}

#ifdef __cplusplus
}
#endif
