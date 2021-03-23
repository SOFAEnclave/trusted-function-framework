#include <unistd.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <typeinfo>
#include <vector>

#include "./sgx_urts.h"
#include "./sgx_utils.h"

#include "tee/common/bytes.h"
#include "tee/common/challenger.h"
#include "tee/common/error.h"
#include "tee/common/log.h"
#include "tee/common/type.h"
#include "tee/untrusted/enclave/untrusted_enclave.h"
#include "tee/untrusted/ra/untrusted_ias.h"
#include "tee/untrusted/untrusted_config.h"
#include "tee/untrusted/untrusted_pbcall.h"
#include "tee/untrusted/utils/untrusted_fs.h"

#include "./kubetee_u.h"

#ifdef __cplusplus
extern "C" {
#endif

TeeErrorCode __attribute__((weak)) RegisterUntrustedPbFunctionsEx() {
  // This week function may be overwritten in application enclave.
  TEE_LOG_INFO("[WEAK] Register application untrusted functions ...");
  return TEE_SUCCESS;
}

void ocall_PrintMessage(const char* message) {
  printf("\033[34m%s\033[0m", message);
  fflush(stdout);
}

#ifdef __cplusplus
}
#endif

namespace tee {
namespace untrusted {

EnclaveInstance::EnclaveInstance(const std::string& name,
                                 const std::string& filename) {
  // Initialize the enclave
  sgx_enclave_id_t eid = 0;
  TEE_LOG_INFO("SGX DEBUG MODE: %d", SGX_DEBUG_FLAG);
  TEE_LOG_DEBUG("Enclave file name: %s", filename.c_str());
  sgx_status_t ret = sgx_create_enclave(filename.c_str(), SGX_DEBUG_FLAG, NULL,
                                        NULL, &eid, NULL);
  if (ret != SGX_SUCCESS) {
    eid_ = 0;
    TEE_LOG_ERROR("Fail to create enclave: 0x%x!", ret);
  } else {
    eid_ = eid;
    enclave_name_ = name;
    TEE_LOG_INFO("Enclave %s is created, id:%ld", name.c_str(), eid_);
  }
}

EnclaveInstance::EnclaveInstance(const std::string& name,
                                 const std::string& filename,
                                 const uint8_t* sealed_key) {
  // Initialize the encrypted enclave
  sgx_enclave_id_t eid = 0;
  TEE_LOG_INFO("SGX DEBUG MODE: %d", SGX_DEBUG_FLAG);

  sgx_status_t ret =
      sgx_create_encrypted_enclave(filename.c_str(), SGX_DEBUG_FLAG, NULL, NULL,
                                   &eid, NULL, CCAST(uint8_t*, sealed_key));
  if (ret != SGX_SUCCESS) {
    eid_ = 0;
    TEE_LOG_ERROR("Fail to create enclave: 0x%x!", ret);
  } else {
    eid_ = eid;
    enclave_name_ = name;
    TEE_LOG_INFO("Enclave %s is created, id:%ld", name.c_str(), eid_);
  }
}

EnclaveInstance::~EnclaveInstance() {
  if (eid_) {
    TEE_LOG_INFO("Destroy enclave %s, id:%ld", enclave_name_.c_str(), eid_);
    sgx_destroy_enclave(eid_);
  }
}

TeeErrorCode EnclaveInstance::InitTargetInfo(std::string* target_info) {
  TeeErrorCode ec = TEE_ERROR_BUSY;
  int try_count = 5;
  while (try_count-- && (ec == TEE_ERROR_BUSY)) {
    ec = SCAST(TeeErrorCode, sgx_init_quote(&target_info_, &gid_));
    TEE_LOG_INFO("Initialize quote [%d]: %d", try_count, ec);
    if (ec == SGX_SUCCESS) {
      break;
    } else {
      sleep(1);
    }
  }
  if (ec != SGX_SUCCESS) {
    TEE_LOG_ERROR("Failed to initialize quote enclave: 0x%x", ec);
    return ec;
  }

#ifdef DEBUG
  tee::common::DataBytes gid_bytes(RCAST(uint8_t*, &gid_), sizeof(gid_));
  TEE_LOG_DEBUG("GID: %s", gid_bytes.ToHexStr().GetStr().c_str());
#endif
  target_info->assign(RCAST(char*, &target_info_), sizeof(sgx_target_info_t));
  return TEE_SUCCESS;
}

TeeErrorCode EnclaveInstance::Initialize() {
  // Load sealed enclave identity keypair, it may be empty on first time.
  std::string identity_cache = GET_CONF_STR(kConfIdentityCache);
  std::string identity_file = GET_CONF_STR(kConfIdentity) + "." + enclave_name_;
  std::string identity_sealed;
  if (identity_cache == kConfValueEnable) {
    TeeErrorCode ret = TEE_ERROR_GENERIC;
    ret = tee::untrusted::FsReadString(identity_file, &identity_sealed);
    if (ret != TEE_SUCCESS) {
      TEE_LOG_WARN("There is no cached identity key pair");
    }
  }

  TEE_CHECK_RETURN(Initialize(identity_sealed));
  return TEE_SUCCESS;
}

TeeErrorCode EnclaveInstance::Initialize(const std::string& identity_sealed) {
  if (eid_ == 0) {
    TEE_LOG_ERROR("Enclave has not been created successfully");
    return TEE_ERROR_RA_NOTINITIALIZED;
  }

  // Initialize the quote enclave and get the gid and target_info
  std::string target_info;
  TEE_CHECK_RETURN(InitTargetInfo(&target_info));

  // Check the user data, the report data has 64 bytes length,
  // the first 32 bytes will be filled with public key in enclave.
  // the second 32 bytes are filled by user data here.
  std::string user_data = GET_CONF_STR(kConfUserData);
  if ((sizeof(sgx_report_data_t) != (2 * SGX_HASH_SIZE)) ||
      (sizeof(sgx_measurement_t) != SGX_HASH_SIZE) ||
      (user_data.size() > SGX_HASH_SIZE)) {
    TEE_LOG_ERROR("Wrong size when prepare report data!");
    return TEE_ERROR_REPORT_DATA_SIZE;
  }

  // Initialize the enclave TEE instance and create the enclave report
  tee::PbInitializeEnclaveRequest req;
  tee::PbInitializeEnclaveResponse res;
  req.set_enclave_id(eid_);
  req.set_enclave_name(enclave_name_);
  req.set_sealed_identity(identity_sealed);
  req.set_target_info(target_info);
  req.set_user_data(user_data);
  req.set_hex_spid(GET_CONF_STR(kConfSPID));
  TEE_CHECK_RETURN(TeeRun("TeeInitializeEnclave", req, &res));
  std::string identity_cache = GET_CONF_STR(kConfIdentityCache);
  std::string identity_file = GET_CONF_STR(kConfIdentity) + "." + enclave_name_;
  if ((identity_cache == kConfValueEnable) && !res.enclave_identity().empty()) {
    TeeErrorCode ret = TEE_ERROR_GENERIC;
    ret = tee::untrusted::FsWriteString(identity_file, res.enclave_identity());
    if (ret != TEE_SUCCESS) {
      TEE_LOG_WARN("Fail to save new identity key pair");
      return ret;
    }
  }

  // Save the enclave identity public key and enclave report
  enclave_public_key_.assign(res.enclave_public_key());
  enclave_report_.assign(res.enclave_report());
  enclave_info_ = res.enclave_info();
  TEE_LOG_DEBUG("MRENCLAVE:%s", enclave_info_.hex_mrenclave().c_str());
  TEE_LOG_DEBUG("MRSIGNER:%s", enclave_info_.hex_mrsigner().c_str());
  TEE_LOG_DEBUG("PROD_ID:%s", enclave_info_.hex_prod_id().c_str());
  TEE_LOG_DEBUG("ISV_SVN:%s", enclave_info_.hex_min_isvsvn().c_str());
  TEE_LOG_DEBUG("USER_DATA:%s", enclave_info_.hex_user_data().c_str());
  TEE_LOG_DEBUG("SPID:%s", enclave_info_.hex_spid().c_str());

  TEE_LOG_INFO("Enclave has been initialized successfully");
  return TEE_SUCCESS;
}

TeeErrorCode EnclaveInstance::GetQuote(std::string* pquote_b64) {
  // Get the SigRL from IAS
  tee::untrusted::RaIasClient ias_client;
  DataBytes sigrl;
  uint8_t* psigrl = NULL;
  uint32_t sigrl_len = 0;
  TEE_LOG_DEBUG("Get Sigrl GID: %08x", *(RCAST(int*, &gid_)));
  TeeErrorCode ret = ias_client.GetSigRL(&gid_, &sigrl);
  if (ret == TEE_SUCCESS) {
    // SigRL may be empty, that's accepted case.
    if (!sigrl.empty()) {
      psigrl = sigrl.data();
      sigrl_len = sigrl.size();
    }
  } else {
    TEE_LOG_ERROR("Fail to get sigrl: %x", ret);
    return TEE_ERROR_IAS_CLIENT_GETSIGRL;
  }

  // Allocate the memory for quote
  uint32_t quote_size = 0;
  sgx_status_t ec = sgx_calc_quote_size(psigrl, sigrl_len, &quote_size);
  if (ec != SGX_SUCCESS) {
    TEE_LOG_ERROR("Failed to call sgx_calc_quote_size(): 0x%x", ec);
    return TEE_ERROR_CODE(ec);
  }
  TEE_LOG_DEBUG("quote_size=%d", quote_size);

  // Generate nonce
  sgx_quote_nonce_t nonce;
  ec = ecall_GetRand(eid_, &ret, RCAST(uint8_t*, &nonce),
                     sizeof(sgx_quote_nonce_t));
  if ((TEE_ERROR_MERGE(ec, ret)) != TEE_SUCCESS) {
    TEE_LOG_ERROR("Failed to call sgx_read_rand(): 0x%x/0x%x", ec, ret);
    return TEE_ERROR_MERGE(ec, ret);
  }
  TEE_LOG_BUFFER("NONCE", nonce.rand, sizeof(sgx_quote_nonce_t));

  // Get the SPID from configuration file
  tee::common::DataBytes spid_vec(GET_CONF_STR(kConfSPID));
  if (spid_vec.FromHexStr().size() != sizeof(sgx_spid_t)) {
    TEE_LOG_ERROR("Fail to get SPID from config file");
    return TEE_ERROR_PARSE_CONFIGURATIONS;
  }
  sgx_spid_t spid;
  std::copy(spid_vec.begin(), spid_vec.end(), spid.id);
  // Ready to get quote now
  // QE report is not used after get
  sgx_report_t qe_report;
  std::unique_ptr<sgx_quote_t, void (*)(void*)> quote_ptr(
      SCAST(sgx_quote_t*, malloc(quote_size)), free);
  sgx_report_t* preport = RCCAST(sgx_report_t*, enclave_report_.data());
  ec = sgx_get_quote(preport, quote_type_, &spid, &nonce, psigrl, sigrl_len,
                     &qe_report, quote_ptr.get(), quote_size);
  if (ec != SGX_SUCCESS) {
    TEE_LOG_ERROR("Fail to get enclave quote(): 0x%x", ec);
    return TEE_ERROR_CODE(ec);
  }
  ec = ecall_RaVerifyReport(eid_, &ret, &target_info_, &qe_report);
  if ((TEE_ERROR_MERGE(ec, ret)) != TEE_SUCCESS) {
    TEE_LOG_ERROR("Fail to verify QE report: 0x%x/0x%x", ret, ec);
    return TEE_ERROR_MERGE(ec, ret);
  }
  TEE_LOG_BUFFER("QUOTE", quote_ptr.get(), quote_size);

  tee::common::DataBytes quote(RCAST(uint8_t*, quote_ptr.get()),
                               SCAST(size_t, quote_size));
  pquote_b64->assign(quote.ToBase64().GetStr());
  TEE_LOG_DEBUG("QUOTE BASE64[%lu]: %s", pquote_b64->length(),
                pquote_b64->c_str());
  return TEE_SUCCESS;
}

TeeErrorCode EnclaveInstance::FetchQuote(std::string* pquote_b64) {
  // Make sure report is already created when initialize enclave
  if (enclave_public_key_.empty()) {
    TEE_LOG_ERROR("Enclave has not been initialized successfully");
    return TEE_ERROR_RA_NOTINITIALIZED;
  }

  return GetQuote(pquote_b64);
}

TeeErrorCode EnclaveInstance::FetchIasReport(bool use_cache) {
  TeeErrorCode ret = TEE_ERROR_GENERIC;

  // Make sure report is already created when initialize enclave
  if (enclave_public_key_.empty()) {
    TEE_LOG_ERROR("Enclave has not been initialized successfully");
    return TEE_ERROR_RA_NOTINITIALIZED;
  }

  // Try load cached RA report if required by both runtime and configuration
  std::string ias_report_cache = GET_CONF_STR(kConfIasResponseCache);
  std::string ias_report_path =
      GET_CONF_STR(kConfIasResponse) + "." + enclave_name_;
  std::string ias_report_str;
  if (use_cache && (ias_report_cache != kConfValueDisable)) {
    if (FsReadString(ias_report_path, &ias_report_str) == TEE_SUCCESS) {
      PB_PARSE(ias_report_, ias_report_str);
      TEE_LOG_WARN("Reload local report successfully");
      return TEE_SUCCESS;
    }
  }

  // Fetch it from IAS if there is no local IAS report or something wrong
  if (ret != TEE_SUCCESS) {
    std::string quote_b64;
    tee::untrusted::RaIasClient ias_client;
    TEE_CHECK_RETURN(GetQuote(&quote_b64));
    TEE_CHECK_RETURN(ias_client.FetchReport(quote_b64, &ias_report_));
  }

  // Verify the new RA report
  tee::EnclaveMatchRules rules;
  rules.add_entries()->CopyFrom(enclave_info_);
  tee::common::RaChallenger verifier(enclave_public_key_, rules);
  TEE_CHECK_RETURN(verifier.VerifyReport(ias_report_));

  // Save it in local cached file if required
  if (ias_report_cache != kConfValueDisable) {
    PB_SERIALIZE(ias_report_, &ias_report_str);
    TEE_CHECK_RETURN(FsWriteString(ias_report_path, ias_report_str));
    TEE_LOG_INFO("Save local report successfully");
  }

  return TEE_SUCCESS;
}

TeeErrorCode EnclaveInstance::TeeRun(const std::string& function_name,
                                     const google::protobuf::Message& request,
                                     google::protobuf::Message* response) {
  std::string attr_str;
  tee::PbCallAttributes attr;
  attr.set_enclave_id(eid_);
  attr.set_enclave_name(enclave_name_);
  attr.set_function_name(function_name);
  if (!attr.SerializeToString(&attr_str)) {
    TEE_LOG_ERROR("Fail to serialize the TeeRun attributes");
    return TEE_ERROR_PROTOBUF_SERIALIZE;
  }

  std::string req_str;
  if (!request.SerializeToString(&req_str)) {
    TEE_LOG_ERROR("Fail to serialize the TeeRun request");
    return TEE_ERROR_PROTOBUF_SERIALIZE;
  }

  char* res_buf = 0;
  size_t res_len = 0;
  TeeErrorCode ret = TEE_ERROR_GENERIC;
  sgx_status_t ec =
      ecall_TeeRun(eid_, &ret, attr_str.data(), attr_str.length(),
                   req_str.data(), req_str.length(), &res_buf, &res_len);
  if ((TEE_ERROR_MERGE(ec, ret)) != TEE_SUCCESS) {
    TEE_LOG_ERROR("Fail to do ecall_TeeRun: 0x%x/0x%x", ret, ec);
    return TEE_ERROR_MERGE(ec, ret);
  }
  if (res_buf) {
    bool parse_result = response->ParseFromArray(res_buf, SCAST(int, res_len));
    UntrustedMemoryFree(&res_buf);
    if (!parse_result) {
      TEE_LOG_ERROR("Fail to parse the TeeRun response");
      return TEE_ERROR_PROTOBUF_PARSE;
    }
  } else if (res_len) {
    // The res_buf and res_len may be zero when there is no response data
    // But the res_buf should not be NULL if res_len is not zero.
    TEE_LOG_ERROR("Invalid ecall_TeeRun buffer: %p/%ld", res_buf, res_len);
    return TEE_ERROR_UNEXPECTED;
  } else {
    TEE_LOG_DEBUG("No response for %s", function_name.c_str());
  }

  return TEE_SUCCESS;
}

// EnclavesManager Functions

EnclaveInstance* EnclavesManager::CreateEnclave(const std::string& name,
                                                const std::string& filename) {
  EnclaveInstancePtr enclave(new EnclaveInstance(name, filename));
  if (enclave.get()->Initialize() != TEE_SUCCESS) {
    TEE_LOG_ERROR("Fail to initialize enclave: %s", name.c_str());
    return nullptr;
  }
  enclaves_.emplace(enclave.get()->GetEnclaveID(), enclave);
  return enclave.get();
}

EnclaveInstance* EnclavesManager::CreateEnclave(const std::string& name,
                                                const std::string& filename,
                                                const uint8_t* sealed_key) {
  EnclaveInstancePtr enclave(new EnclaveInstance(name, filename, sealed_key));
  if (enclave.get()->Initialize() != TEE_SUCCESS) {
    TEE_LOG_ERROR("Fail to initialize protected enclave: %s", name.c_str());
    return nullptr;
  }

  enclaves_.emplace(enclave.get()->GetEnclaveID(), enclave);
  return enclave.get();
}

TeeErrorCode EnclavesManager::DestroyEnclave(EnclaveInstance* enclave) {
  EnclaveIdentity eid = enclave->GetEnclaveID();
  if (enclaves_.find(eid) == enclaves_.end()) {
    TEE_LOG_ERROR("Fail to find enclave %ld", eid);
    return TEE_ERROR_RA_NOTINITIALIZED;
  }
  enclaves_.erase(eid);
  return TEE_SUCCESS;
}

EnclaveInstance* EnclavesManager::GetEnclave(const EnclaveIdentity eid) {
  if (enclaves_.find(eid) == enclaves_.end()) {
    TEE_LOG_ERROR("Fail to find enclave %ld", eid);
    return nullptr;
  }
  return enclaves_[eid].get();
}

EnclaveInstance* EnclavesManager::GetEnclave(const std::string& name) {
  for (auto iter = enclaves_.begin(); iter != enclaves_.end(); iter++) {
    if ((iter->second).get()->GetEnclaveName() == name) {
      return (iter->second).get();
    }
  }
  TEE_LOG_ERROR("Fail to find enclave %s", name.c_str());
  return nullptr;
}

TeeErrorCode EnclavesManager::RegisterUntrustedPbFunctions() {
  if (is_functions_registed_) {
    return TEE_SUCCESS;
  }

  TEE_LOG_INFO("Register untrusted functions ...");
  // ADD_UNTRUSTED_PBCALL_FUNCTION(MyPbFunction);

  // Add extended trusted pbcall functions
  TEE_CHECK_RETURN(RegisterUntrustedPbFunctionsEx());

  is_functions_registed_ = true;
  return TEE_SUCCESS;
}

}  // namespace untrusted
}  // namespace tee
