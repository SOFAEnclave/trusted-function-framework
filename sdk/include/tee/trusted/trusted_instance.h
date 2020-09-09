#ifndef SDK_INCLUDE_TEE_TRUSTED_TRUSTED_INSTANCE_H_
#define SDK_INCLUDE_TEE_TRUSTED_TRUSTED_INSTANCE_H_

#include <map>
#include <string>

#include "tee/common/error.h"
#include "tee/common/log.h"
#include "tee/common/protobuf.h"
#include "tee/common/table.h"
#include "tee/common/type.h"

#include "./kubetee.pb.h"

namespace tee {
namespace trusted {

class TeeInstance {
 public:
  static TeeInstance& GetInstance() {
    static TeeInstance instance_;
    return instance_;
  }

  TeeErrorCode ReeRun(const std::string& function_name,
                      const google::protobuf::Message& request,
                      google::protobuf::Message* response);

  TeeErrorCode SetOrCheckAttr(const tee::PbCallAttributes& attr);

  int64_t GetEnclaveID() {
    return enclave_id_;
  }

  void SetEnclaveID(int64_t id) {
    enclave_id_ = id;
  }

  std::string GetEnclaveName() {
    return enclave_name_;
  }

  void SetEnclaveName(const std::string& name) {
    enclave_name_ = name;
  }

  tee::KeyPair& GetIdentity() {
    return identity_keys_;
  }

  tee::EnclaveInformation& GetEnclaveInfo() {
    return enclave_info_;
  }

  TeeErrorCode CreateIdentity();
  TeeErrorCode ImportIdentity(const tee::KeyPair& identity);
  TeeErrorCode CreateReport(const std::string& target_info,
                            const std::string& user_data,
                            const std::string& hex_spid,
                            std::string* enclave_report);

  tee::common::DataTable<PbFunction>& Functions() {
    return pb_ecall_functions_;
  }

  TeeErrorCode RegisterTrustedPbFunctions();

 private:
  // Hide construction functions
  TeeInstance() {
    is_functions_registed_ = false;
  }
  TeeInstance(const TeeInstance&);
  void operator=(TeeInstance const&);

  int64_t enclave_id_;
  std::string enclave_name_;
  bool is_functions_registed_;
  tee::KeyPair identity_keys_;
  tee::EnclaveInformation enclave_info_;
  tee::common::DataTable<PbFunction> pb_ecall_functions_;
};

}  // namespace trusted
}  // namespace tee

#endif  // SDK_INCLUDE_TEE_TRUSTED_TRUSTED_INSTANCE_H_
