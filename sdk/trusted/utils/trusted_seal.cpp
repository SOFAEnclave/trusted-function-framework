#include <string>
#include <vector>

#include "./sgx_utils.h"

#include "tee/common/bytes.h"
#include "tee/common/error.h"
#include "tee/common/log.h"
#include "tee/common/type.h"
#include "tee/trusted/utils/trusted_seal.h"

namespace tee {
namespace trusted {

TeeErrorCode Sealer::SealSignerData(const std::string& data,
                                    std::string* sealed) {
  if (data.empty()) {
    ELOG_ERROR("Empty data to be sealed!");
    return TEE_ERROR_PARAMETERS;
  }

  // Allocate the sealed buffer
  uint32_t data_size = SCAST(uint32_t, data.size());
  uint32_t sealed_size = sgx_calc_sealed_data_size(0, data_size);
  sealed->resize(sealed_size);

  // Seal data
  uint8_t* pdata = RCAST(uint8_t*, CCAST(char*, data.data()));
  uint8_t* psealed = RCAST(uint8_t*, CCAST(char*, sealed->data()));
  sgx_status_t ret = sgx_seal_data(0, nullptr, data_size, pdata, sealed_size,
                                   RCAST(sgx_sealed_data_t*, psealed));
  if (ret != SGX_SUCCESS) {
    ELOG_ERROR("Failed to seal data of signer: 0x%x", ret);
    return TEE_ERROR_CODE(ret);
  }

  return TEE_SUCCESS;
}

TeeErrorCode Sealer::SealEnclaveData(const std::string& data,
                                     std::string* sealed) {
  if (data.empty()) {
    ELOG_ERROR("Empty data to be sealed!");
    return TEE_ERROR_PARAMETERS;
  }

  // Allocate the sealed buffer
  uint32_t data_size = SCAST(uint32_t, data.size());
  uint32_t sealed_size = sgx_calc_sealed_data_size(0, data_size);
  sealed->resize(sealed_size);

  // Seal data
  uint8_t* pdata = RCAST(uint8_t*, CCAST(char*, data.data()));
  uint8_t* psealed = RCAST(uint8_t*, CCAST(char*, sealed->data()));
  sgx_status_t ret = sgx_seal_data_ex(
      SGX_KEYPOLICY_MRENCLAVE, attributes_, misc_select_, 0, nullptr, data_size,
      pdata, sealed_size, RCAST(sgx_sealed_data_t*, psealed));
  if (ret != SGX_SUCCESS) {
    ELOG_ERROR("Failed to seal data of enclave: 0x%x", ret);
    return TEE_ERROR_CODE(ret);
  }

  return TEE_SUCCESS;
}

TeeErrorCode Sealer::UnsealData(const std::string& sealed, std::string* data) {
  if (sealed.empty()) {
    ELOG_ERROR("Empty sealed data to be unsealed!");
    return TEE_ERROR_PARAMETERS;
  }

  const sgx_sealed_data_t* psealed =
      RCAST(const sgx_sealed_data_t*, sealed.data());
  uint32_t data_size = sgx_get_encrypt_txt_len(psealed);
  data->resize(data_size);

  uint8_t* pdata = RCAST(uint8_t*, CCAST(char*, data->data()));
  uint32_t returned_size = data_size;
  sgx_status_t ret = sgx_unseal_data(psealed, NULL, 0, pdata, &returned_size);
  if ((ret != SGX_SUCCESS) || (data_size != returned_size)) {
    ELOG_ERROR("Fail to unseal data: 0x%x\n", ret);
    return TEE_ERROR_CODE(ret);
  }

  return TEE_SUCCESS;
}

}  // namespace trusted
}  // namespace tee
