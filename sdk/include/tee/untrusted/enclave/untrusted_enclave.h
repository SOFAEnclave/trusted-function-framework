#ifndef SDK_INCLUDE_TEE_UNTRUSTED_ENCLAVE_UNTRUSTED_ENCLAVE_H_
#define SDK_INCLUDE_TEE_UNTRUSTED_ENCLAVE_UNTRUSTED_ENCLAVE_H_

#include <map>
#include <memory>
#include <string>

#include "./sgx_uae_epid.h"
#include "./sgx_urts.h"
#include "./sgx_utils.h"

#include "tee/common/bytes.h"
#include "tee/common/error.h"
#include "tee/common/table.h"
#include "tee/common/type.h"

#include "./kubetee.pb.h"

namespace tee {
namespace untrusted {

// EnclaveInstance create one class instance for each enclave instance.
// enclave instance include untrusted part and trusted part, the trusted
// part is managed by TeeInstance
class EnclaveInstance {
 public:
  // Create the normal enclave by name
  EnclaveInstance(const std::string& name, const std::string& filename);

  // Create the Protected Code Loader mode encrypted enclave by name
  EnclaveInstance(const std::string& name, const std::string& filename,
                  const uint8_t* sealed_key);

  ~EnclaveInstance();

  // Initialize method creates the identity RSA key pair inside enclave
  // and also prepare the enclave information for generating quote later
  TeeErrorCode Initialize();

  // Initialize method with the cached identity RSA key pair.
  TeeErrorCode Initialize(const std::string& identity_sealed);

  // FetchQuote method is to get enclave quote
  // The result quote will be the input of the remote attestation.
  TeeErrorCode FetchQuote(std::string* pquote_b64);

  // Fetch RA report from Intel Attestation Service
  TeeErrorCode FetchIasReport(bool use_cache = true);

  // Run ECall Function based on serialized protobuf message parameters
  TeeErrorCode TeeRun(const std::string& function_name,
                      const google::protobuf::Message& request,
                      google::protobuf::Message* response);

  // Get the enclave EID, usually it's should be greater than 2
  EnclaveIdentity GetEnclaveID() {
    return eid_;
  }

  // Get the enclave name, the name should be unique, otherwise maybe the
  // wrong enclave instance will be found when GetEnclave(name)
  std::string GetEnclaveName() {
    return enclave_name_;
  }

  // Get the enclave identity public key, it should not be empty after
  // enclave instance is successfully initialized.
  std::string GetPublicKey() {
    return enclave_public_key_;
  }

  // Get the enclave information handler
  tee::EnclaveInformation& GetEnclaveInfo() {
    return enclave_info_;
  }

  // Get the local information handler
  tee::IasReport& GetLocalIasReport() {
    return ias_report_;
  }

 private:
  // service provider special settings
  const sgx_quote_sign_type_t quote_type_ = SGX_LINKABLE_SIGNATURE;

  // internal functions
  TeeErrorCode InitTargetInfo(std::string* target_info);
  TeeErrorCode GetQuote(std::string* pquote_b64);

  sgx_enclave_id_t eid_ = 0;
  sgx_epid_group_id_t gid_;
  sgx_target_info_t target_info_;
  std::string enclave_name_;
  std::string enclave_public_key_;
  std::string enclave_report_;
  tee::EnclaveInformation enclave_info_;
  tee::IasReport ias_report_;
};

typedef std::shared_ptr<EnclaveInstance> EnclaveInstancePtr;
typedef std::map<EnclaveIdentity, EnclaveInstancePtr> EnclaveInstancesMap;

// EnclavesManager is to manage enclaves instances together
class EnclavesManager {
 public:
  // Gets the singleton enclave manager instance handler
  static EnclavesManager& GetInstance() {
    static EnclavesManager instance_;
    return instance_;
  }

  /// Create a new enclave instance and return the handler which points to it
  ///
  /// @param name specifies the name of this enclave instance
  /// @param filename specifies the name of the enclave so file
  ///
  /// @return EnclaveInstance pointer, nullptr on fail
  EnclaveInstance* CreateEnclave(const std::string& name,
                                 const std::string& filename);

  /// @brief Load encrypted enclave so file and create the enclave instance
  ///
  /// This is for the Protected Code Loader mode enclave work flow.
  /// @param name specifies the name of this enclave instance
  /// @param filename specifies the name of the enclave so file
  /// @param sealed_key specifies the key to decrypt encrypted enclave file
  ///
  /// @return TeeErrorCode type error code, TEE_SUCCESS or other error
  EnclaveInstance* CreateEnclave(const std::string& name,
                                 const std::string& filename,
                                 const uint8_t* sealed_key);

  /// @brief Simply destroy the enclave instance via its EID
  ///
  /// @param enclave specifies the pointer of the enclave instance
  ///
  /// @return TeeErrorCode type error code, TEE_SUCCESS or other error
  TeeErrorCode DestroyEnclave(EnclaveInstance* enclave);

  /// @brief Get the enclave instance pointer via its EID
  ///
  /// @param eid specifies the successfully created enclave instance ID
  ///
  /// @return The pointer to EnclaveInstance or nullptr
  EnclaveInstance* GetEnclave(const EnclaveIdentity eid);

  /// @brief Get the enclave instance pointer via its EID
  ///
  /// @param name specifies the enclave name
  ///
  /// @return The pointer to EnclaveInstance or nullptr
  EnclaveInstance* GetEnclave(const std::string& name);

  /// Get the ocall functions table
  tee::common::DataTable<PbFunction>& Functions() {
    return pb_ocall_functions_;
  }

  /// Register all the untrusted PbFunctions (ocall functions)
  TeeErrorCode RegisterUntrustedPbFunctions();

 private:
  // Hide construction functions
  EnclavesManager() {
    is_functions_registed_ = false;
  }
  EnclavesManager(const EnclavesManager&);
  void operator=(EnclavesManager const&);

  EnclaveInstancesMap enclaves_;
  bool is_functions_registed_;
  tee::common::DataTable<PbFunction> pb_ocall_functions_;
};

}  // namespace untrusted
}  // namespace tee

using tee::untrusted::EnclaveInstance;
using tee::untrusted::EnclavesManager;

#endif  // SDK_INCLUDE_TEE_UNTRUSTED_ENCLAVE_UNTRUSTED_ENCLAVE_H_
