#ifndef SDK_INCLUDE_TEE_TRUSTED_UTILS_TRUSTED_SEAL_H_
#define SDK_INCLUDE_TEE_TRUSTED_UTILS_TRUSTED_SEAL_H_

#include <string>

#include "./sgx_attributes.h"
#include "./sgx_tseal.h"

#include "tee/common/error.h"

namespace tee {
namespace trusted {

// clang-format off

// Copy the following macros from SDK2.5 internal header files to use
// sgx_seal_data_ex with SGX_KEYPOLICY_MRENCLAVE policy. sgx_seal_data
// only support MISIGNER way, which will share data in all the enclaves
// with the same signing key. See also tseal_migration_attr.h
#define FLAGS_NON_SECURITY_BITS (0xFFFFFFFFFFFFC0ULL | \
                                 SGX_FLAGS_MODE64BIT | \
                                 SGX_FLAGS_PROVISION_KEY | \
                                 SGX_FLAGS_EINITTOKEN_KEY)
#define TSEAL_DEFAULT_FLAGSMASK (~FLAGS_NON_SECURITY_BITS)
#define KEY_POLICY_KSS (SGX_KEYPOLICY_CONFIGID | \
                        SGX_KEYPOLICY_ISVFAMILYID | \
                        SGX_KEYPOLICY_ISVEXTPRODID)
#define MISC_NON_SECURITY_BITS 0x0FFFFFFF
#define TSEAL_DEFAULT_MISCMASK (~MISC_NON_SECURITY_BITS)

// clang-format on

class Sealer {
 public:
  Sealer() {}

  // Seal data with SGX_KEYPOLICY_MRSIGNER policy, the sealed data
  // can be unsealed by all enclaves with same MRSINGER and ProdID value.
  TeeErrorCode SealSignerData(const std::string& data, std::string* sealed);

  // Seal data with SGX_KEYPOLICY_MRENCLAVE policy, the sealed data
  // can be unsealed only by enclaves with same MRENCLAVE value.
  TeeErrorCode SealEnclaveData(const std::string& data, std::string* sealed);
  TeeErrorCode UnsealData(const std::string& sealed, std::string* data);

 private:
  const sgx_attributes_t attributes_ = {TSEAL_DEFAULT_FLAGSMASK, 0x0};
  const sgx_misc_select_t misc_select_ = TSEAL_DEFAULT_MISCMASK;
};

}  // namespace trusted
}  // namespace tee

#endif  // SDK_INCLUDE_TEE_TRUSTED_UTILS_TRUSTED_SEAL_H_
