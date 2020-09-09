#ifndef SDK_UNTRUSTED_CHALLENGER_UNTRUSTED_CHALLENGER_CONFIG_H_
#define SDK_UNTRUSTED_CHALLENGER_UNTRUSTED_CHALLENGER_CONFIG_H_

#include <string>

#include "tee/common/error.h"
#include "tee/common/log.h"
#include "tee/untrusted/utils/untrusted_json.h"

constexpr char kVerifyConf[] = "kubetee.json";

constexpr char kConfVerifyMRENCLAVE[] = "verify_mrenclave";
constexpr char kConfVerifyMRSIGNER[] = "verify_mrsigner";
constexpr char kConfVerifySPID[] = "verify_spid";
constexpr char kConfVerifyUserData[] = "verify_user_hash";
constexpr char kConfVerifyProdID[] = "verify_prodid";
constexpr char kConfVerifySVN[] = "verify_min_svn";

#define VERIFY_CONF_STR(name) JSON_CONF_STR(kVerifyConf, (name))
#define VERIFY_CONF_INT(name, value) JSON_CONF_INT(kVerifyConf, (name), (value))
#define VERIFY_CONF_ARRARY(name, value) \
  JSON_CONF_ARRAY(kVerifyConf, (name), (value))

#endif  // SDK_UNTRUSTED_CHALLENGER_UNTRUSTED_CHALLENGER_CONFIG_H_
