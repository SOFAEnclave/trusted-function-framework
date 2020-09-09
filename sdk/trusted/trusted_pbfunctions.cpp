#include <algorithm>
#include <map>
#include <string>
#include <vector>

#include "./sgx_trts.h"
#include "./sgx_utils.h"

#include "tee/common/bytes.h"
#include "tee/common/error.h"
#include "tee/common/log.h"
#include "tee/common/type.h"
#include "tee/trusted/trusted_instance.h"
#include "tee/trusted/trusted_pbcall.h"
#include "tee/trusted/trusted_pbfunctions.h"
#include "tee/trusted/utils/trusted_seal.h"

#include "./kubetee_t.h"

#ifdef __cplusplus
extern "C" {
#endif

using tee::trusted::TeeInstance;

TeeErrorCode TeeInitializeEnclave(const std::string& req_str,
                                  std::string* res_str) {
  tee::PbInitializeEnclaveRequest req;
  tee::PbInitializeEnclaveResponse res;
  PB_PARSE(req, req_str);

  TeeInstance& ti = TeeInstance::GetInstance();
  ti.SetEnclaveID(req.enclave_id());
  ti.SetEnclaveName(req.enclave_name());

  tee::trusted::Sealer sealer;
  std::string identity_str;
  if (!req.sealed_identity().empty()) {
    TEE_CHECK_RETURN(sealer.UnsealData(req.sealed_identity(), &identity_str));
    tee::KeyPair identity;
    PB_PARSE(identity, identity_str);
    TEE_CHECK_RETURN(ti.ImportIdentity(identity));
    ELOG_INFO("Reload local identity key pair successfully");
  } else {
    TEE_CHECK_RETURN(ti.CreateIdentity());
    std::string sealed_identity;
    PB_SERIALIZE(ti.GetIdentity(), &identity_str);
    TEE_CHECK_RETURN(sealer.SealSignerData(identity_str, &sealed_identity));
    res.set_enclave_identity(sealed_identity);
    ELOG_INFO("Generate new identity key pair successfully");
  }

  // Return identity public key by response
  res.set_enclave_public_key(ti.GetIdentity().public_key());
  // Create the enclave report and return by response
  TEE_CHECK_RETURN(ti.CreateReport(req.target_info(), req.user_data(),
                                   req.hex_spid(),
                                   res.mutable_enclave_report()));
  res.mutable_enclave_info()->CopyFrom(ti.GetEnclaveInfo());
  PB_SERIALIZE(res, res_str);
  return TEE_SUCCESS;
}

// Please register all above functions here
TeeErrorCode RegisterTrustedPbFunctionsInternal() {
  ADD_TRUSTED_PBCALL_FUNCTION(TeeInitializeEnclave);
  return TEE_SUCCESS;
}

#ifdef __cplusplus
}
#endif
