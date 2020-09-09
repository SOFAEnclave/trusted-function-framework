#include <cstring>
#include <map>
#include <string>

#include "./sgx_trts.h"
#include "./sgx_utils.h"

#include "tee/common/aes.h"
#include "tee/common/bytes.h"
#include "tee/common/error.h"
#include "tee/common/log.h"
#include "tee/common/protobuf.h"
#include "tee/common/rsa.h"
#include "tee/common/type.h"
#include "tee/trusted/trusted_pbcall.h"
#include "tee/trusted/trusted_pbfunctions.h"

#include "./kubetee.pb.h"
#include "./kubetee_t.h"

namespace tee {
namespace trusted {

TeeErrorCode TeeInstance::RegisterTrustedPbFunctions() {
  if (is_functions_registed_) {
    return TEE_SUCCESS;
  }

  ELOG_DEBUG("Register trusted functions ...");
  TeeErrorCode ret = RegisterTrustedPbFunctionsInternal();
  if (ret != TEE_SUCCESS) {
    ELOG_ERROR_TRACE();
    return ret;
  }
  ret = RegisterTrustedPbFunctionsEx();
  if (ret != TEE_SUCCESS) {
    ELOG_ERROR_TRACE();
    return ret;
  }
  is_functions_registed_ = true;
  return TEE_SUCCESS;
}

TeeErrorCode TeeInstance::SetOrCheckAttr(const tee::PbCallAttributes& attr) {
  if (enclave_id_ == 0) {
    enclave_id_ = attr.enclave_id();
    enclave_name_ = attr.enclave_name();
  } else if (enclave_id_ != attr.enclave_id()) {
    ELOG_ERROR("Mismatched enclave ID: %ld", attr.enclave_id());
    return TEE_ERROR_PBCALL_ENCLAVE_ID;
  }
  return TEE_SUCCESS;
}

TeeErrorCode TeeInstance::ReeRun(const std::string& function_name,
                                 const google::protobuf::Message& request,
                                 google::protobuf::Message* response) {
  std::string attr_str;
  tee::PbCallAttributes attr;
  attr.set_enclave_id(enclave_id_);
  attr.set_enclave_name(enclave_name_);
  attr.set_function_name(function_name);
  PB_SERIALIZE(attr, &attr_str);

  std::string req_str;
  PB_SERIALIZE(request, &req_str);

  char* res_buf = 0;
  size_t res_len = 0;
  TeeErrorCode ret = TEE_ERROR_GENERIC;
  sgx_status_t oc = SGX_ERROR_UNEXPECTED;
  oc = ocall_ReeRun(&ret, attr_str.data(), attr_str.length(), req_str.data(),
                    req_str.size(), &res_buf, &res_len);
  if ((TEE_ERROR_MERGE(oc, ret)) != TEE_SUCCESS) {
    ELOG_ERROR("Fail to do ocall_ReeRun: 0x%x/0x%x", ret, oc);
    return TEE_ERROR_MERGE(oc, ret);
  }
  // The response may be empty
  if (res_buf && res_len) {
    std::string res_str(res_buf, res_len);
    PB_PARSE(*response, res_str);
    oc = ocall_UntrustedMemoryFree(&ret, &res_buf);
    if ((TEE_ERROR_MERGE(oc, ret)) != TEE_SUCCESS) {
      ELOG_ERROR("Fail to do ocall_UntrustedMemoryFree: 0x%x/0x%x", ret, oc);
      return TEE_ERROR_MERGE(oc, ret);
    }
  } else {
    ELOG_DEBUG("There is not response for ReeRun: %s", function_name.c_str());
  }

  return TEE_SUCCESS;
}

TeeErrorCode TeeInstance::CreateIdentity() {
  tee::common::RsaCrypto rsa;
  std::string* public_key = identity_keys_.mutable_public_key();
  std::string* private_key = identity_keys_.mutable_private_key();
  TeeErrorCode ret = rsa.GenerateKeyPair(public_key, private_key);
  if (ret != TEE_SUCCESS) {
    ELOG_ERROR("Fail to create identity RSA key pair");
    return ret;
  }

  size_t aes_key_size = tee::common::AesGcmCrypto::get_key_size();
  std::string* aes_key = identity_keys_.mutable_aes_key();
  aes_key->resize(aes_key_size, '\0');
  uint8_t* pdata = RCAST(uint8_t*, CCAST(char*, aes_key->data()));
  sgx_status_t sgx_ret = sgx_read_rand(pdata, aes_key->size());
  if (sgx_ret != SGX_SUCCESS) {
    ELOG_ERROR("Fail to create identity AES key");
    return TEE_ERROR_CODE(sgx_ret);
  }

  return TEE_SUCCESS;
}

TeeErrorCode TeeInstance::ImportIdentity(const tee::KeyPair& identity) {
  if (identity.public_key().empty() || identity.private_key().empty() ||
      identity.aes_key().empty()) {
    ELOG_ERROR("Invalid identity keys");
    return TEE_ERROR_PARAMETERS;
  }
  identity_keys_ = identity;
  return TEE_SUCCESS;
}

TeeErrorCode TeeInstance::CreateReport(const std::string& target_info,
                                       const std::string& user_data,
                                       const std::string& hex_spid,
                                       std::string* enclave_report) {
  // Get the enclave identity public key
  using tee::trusted::TeeInstance;
  TeeInstance& ti = TeeInstance::GetInstance();
  std::string enclave_public_key = ti.GetIdentity().public_key();
  if (enclave_public_key.empty()) {
    ELOG_ERROR("Invalid enclave identity public key, maybe not initialized.");
    return TEE_ERROR_RA_IDENTITY_NOTINITIALIZED;
  }

  // calculate the public SHA256 HASH and copy it to report data
  sgx_report_data_t report_data;
  memset(&report_data, 0, sizeof(sgx_report_data_t));
  tee::common::DataBytes pubkey_hash(enclave_public_key);
  if (pubkey_hash.ToSHA256().Export(report_data.d, SGX_HASH_SIZE).empty()) {
    ELOG_ERROR("Fail to compute sha256 for enclave public key");
    return pubkey_hash.GetError();
  }
  if (!user_data.empty() && (user_data.size() <= SGX_HASH_SIZE)) {
    memcpy(report_data.d + SGX_HASH_SIZE, user_data.data(), user_data.size());
  }

  // create the enclave report with target info and report_data
  sgx_target_info_t* pinfo = RCCAST(sgx_target_info_t*, target_info.data());
  sgx_report_t report;
  TeeErrorCode ret = sgx_create_report(pinfo, &report_data, &report);
  if (ret != TEE_SUCCESS) {
    ELOG_ERROR("Fail to create report");
    return ret;
  }

  // save the enclave information
  tee::common::DataBytes mrenclave(report.body.mr_enclave.m,
                                   sizeof(sgx_measurement_t));
  tee::common::DataBytes mrsigner(report.body.mr_signer.m,
                                  sizeof(sgx_measurement_t));
  enclave_info_.set_hex_mrenclave(mrenclave.ToHexStr().GetStr());
  enclave_info_.set_hex_mrsigner(mrsigner.ToHexStr().GetStr());
  enclave_info_.set_hex_prod_id(std::to_string(report.body.isv_prod_id));
  enclave_info_.set_hex_min_isvsvn(std::to_string(report.body.isv_svn));
  enclave_info_.set_hex_user_data(user_data);
  enclave_info_.set_hex_spid(hex_spid);

  // return the report
  enclave_report->assign(RCAST(char*, &report), sizeof(sgx_report_t));
  return TEE_SUCCESS;
}

}  // namespace trusted
}  // namespace tee
