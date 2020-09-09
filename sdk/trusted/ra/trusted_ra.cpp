#include <algorithm>
#include <cstdio>
#include <map>
#include <string>
#include <vector>

#include "./sgx_report.h"
#include "./sgx_trts.h"
#include "./sgx_utils.h"

#include "tee/common/bytes.h"
#include "tee/common/error.h"
#include "tee/common/log.h"
#include "tee/common/rsa.h"
#include "tee/common/type.h"
#include "tee/trusted/trusted_pbcall.h"
#include "tee/trusted/utils/trusted_seal.h"

#include "./kubetee_t.h"

#ifdef __cplusplus
extern "C" {
#endif

TeeErrorCode ecall_RaVerifyReport(sgx_target_info_t* target_info,
                                  sgx_report_t* target_report) {
  if (memcmp(target_info->mr_enclave.m, target_report->body.mr_enclave.m,
             sizeof(sgx_measurement_t)) != 0) {
    ELOG_ERROR("MRENCALVE mismatch when verify the target report");
    return TEE_ERROR_GENERIC;
  }
  sgx_status_t sgx_ret = sgx_verify_report(target_report);
  if (sgx_ret != SGX_SUCCESS) {
    ELOG_ERROR("Fail to verify the target report");
    return sgx_ret;
  }

  ELOG_DEBUG("Success to verify the target report");
  return sgx_ret;
}

#ifdef __cplusplus
}
#endif
