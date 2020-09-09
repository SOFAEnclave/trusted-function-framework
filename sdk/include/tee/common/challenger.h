#ifndef SDK_INCLUDE_TEE_COMMON_CHALLENGER_H_
#define SDK_INCLUDE_TEE_COMMON_CHALLENGER_H_

#include <string>
#include <vector>

#include "./sgx_quote.h"
#include "./sgx_report.h"

#include "tee/common/error.h"
#include "tee/common/type.h"

#include "./kubetee.pb.h"

namespace tee {
namespace common {

class RaChallenger {
 public:
  RaChallenger(const std::string& public_key,
               const tee::EnclaveMatchRules& verify_rules);

  // Verify the IAS report by the public key and verify rules
  TeeErrorCode VerifyReport(const tee::IasReport& ias_report);

  // Get the enclave related information from IAS report
  static TeeErrorCode GetEnclaveInfo(const tee::IasReport& ias_report,
                                     tee::EnclaveInformation* info);

 private:
  // internal functions
  TeeErrorCode CheckReportSignature(const tee::IasReport& ias_report);
  TeeErrorCode CheckReportQuoteStatus(const tee::IasReport& ias_report);
  TeeErrorCode CheckReportQuote(const tee::IasReport& ias_report);

  // Check quote
  TeeErrorCode CheckQuoteSignType(sgx_quote_t* pquote);
  TeeErrorCode CheckQuoteSPID(sgx_quote_t* pquote);
  TeeErrorCode CheckQuoteReportBody(sgx_quote_t* pquote);

  // Check report body
  TeeErrorCode CheckReportBodyMRENCLAVE(sgx_report_body_t* report_body);
  TeeErrorCode CheckReportBodyMRSIGNER(sgx_report_body_t* report_body);
  TeeErrorCode CheckReportBodyAttributes(sgx_report_body_t* report_body);
  TeeErrorCode CheckReportBodyIsvProd(sgx_report_body_t* report_body);
  TeeErrorCode CheckReportBodyIsvSvn(sgx_report_body_t* report_body);
  TeeErrorCode CheckReportBodyUserData(sgx_report_body_t* report_body);

  const std::string public_key_;
  const tee::EnclaveMatchRules& rules_;
  tee::EnclaveInformation* enclave_ = nullptr;
};

}  // namespace common
}  // namespace tee

#endif  // SDK_INCLUDE_TEE_COMMON_CHALLENGER_H_
