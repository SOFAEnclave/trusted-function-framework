#ifndef SDK_INCLUDE_TEE_UNTRUSTED_UNTRUSTED_CONFIG_H_
#define SDK_INCLUDE_TEE_UNTRUSTED_UNTRUSTED_CONFIG_H_

#include <string>

#include "tee/common/error.h"
#include "tee/common/log.h"
#include "tee/untrusted/utils/untrusted_json.h"

namespace tee {
namespace untrusted {

constexpr char kConfFile[] = "kubetee.json";

constexpr char kConfIasURL[] = "ias_url";
constexpr char kConfIasAccessKey[] = "ias_access_key";
constexpr char kConfIasResponse[] = "ias_response_file";
constexpr char kConfIasResponseCache[] = "ias_response_cache";

constexpr char kConfSPID[] = "enclave_spid";
constexpr char kConfUserData[] = "enclave_user_data";
constexpr char kConfIdentity[] = "enclave_identity_file";
constexpr char kConfIdentityCache[] = "enclave_identity_cache";

constexpr char kConfRpcRemoteServer[] = "rpc_remote_server";
constexpr char kConfRpcRemotePort[] = "rpc_remote_port";
constexpr char kConfRpcServer[] = "rpc_server";
constexpr char kConfRpcPort[] = "rpc_port";
constexpr char kConfRpcCaPath[] = "rpc_ca_path";
constexpr char kConfRpcCertPath[] = "rpc_cert_path";
constexpr char kConfRpcKeyPath[] = "rpc_key_path";

}  // namespace untrusted
}  // namespace tee

#define GET_CONF_STR(name) JSON_CONF_STR(tee::untrusted::kConfFile, name)
#define GET_CONF_INT(name, value) \
  JSON_CONF_INT(tee::untrusted::kConfFile, name, value)
#define GET_CONF_ARRARY(name, value) \
  JSON_CONF_ARRAY(tee::untrusted::kConfFile, name, value)

#endif  // SDK_INCLUDE_TEE_UNTRUSTED_UNTRUSTED_CONFIG_H_
