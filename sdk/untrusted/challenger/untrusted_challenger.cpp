#include <string>

#include "tee/common/challenger.h"
#include "tee/common/error.h"

#include "tee/untrusted/ra/untrusted_challenger.h"

#include "untrusted/challenger/untrusted_challenger_config.h"

#ifdef __cplusplus
extern "C" {
#endif

TeeErrorCode VerifyRaReport(const std::string& public_key,
                            const tee::IasReport& ias_report) {
  // Fill the match rules
  tee::EnclaveMatchRules rules;
  tee::EnclaveInformation* enclave_info = rules.add_entries();
  enclave_info->set_hex_mrenclave(VERIFY_CONF_STR(kConfVerifyMRENCLAVE));
  enclave_info->set_hex_mrsigner(VERIFY_CONF_STR(kConfVerifyMRSIGNER));
  enclave_info->set_hex_prod_id(VERIFY_CONF_STR(kConfVerifyProdID));
  enclave_info->set_hex_min_isvsvn(VERIFY_CONF_STR(kConfVerifySVN));
  enclave_info->set_hex_user_data(VERIFY_CONF_STR(kConfVerifyUserData));
  enclave_info->set_hex_spid(VERIFY_CONF_STR(kConfVerifySPID));

  // Verify the RA report
  tee::common::RaChallenger ch(public_key, rules);
  return ch.VerifyReport(ias_report);
}

#ifdef __cplusplus
}
#endif
