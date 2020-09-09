#ifndef SDK_INCLUDE_TEE_UNTRUSTED_RA_UNTRUSTED_CHALLENGER_H_
#define SDK_INCLUDE_TEE_UNTRUSTED_RA_UNTRUSTED_CHALLENGER_H_

#include <string>
#include <vector>

#include "./sgx_quote.h"
#include "./sgx_report.h"

#include "tee/common/challenger.h"
#include "tee/common/error.h"
#include "tee/common/type.h"

#include "./kubetee.pb.h"

#ifdef __cplusplus
extern "C" {
#endif

extern TeeErrorCode VerifyRaReport(const std::string& public_key,
                                   const tee::IasReport& ias_report);

#ifdef __cplusplus
}
#endif

#endif  // SDK_INCLUDE_TEE_UNTRUSTED_RA_UNTRUSTED_CHALLENGER_H_
