#include <map>
#include <string>

#include "tee/common/bytes.h"
#include "tee/common/error.h"
#include "tee/common/log.h"
#include "tee/common/protobuf.h"
#include "tee/common/type.h"

#include "./kubetee.pb.h"
#include "./kubetee_t.h"

#include "tee/trusted/trusted_pbcall.h"
#include "tee/trusted/trusted_pbfunctions.h"

#ifdef __cplusplus
extern "C" {
#endif

// This week function may be overwritten in application enclave.
TeeErrorCode __attribute__((weak)) RegisterTrustedPbFunctionsEx() {
  TEE_LOG_INFO("[WEAK] Register application trusted functions ...");
  return TEE_SUCCESS;
}

TeeErrorCode ecall_TeeRun(const char* attr_buf, size_t attr_len,
                          const char* req_buf, size_t req_len, char** res_buf,
                          size_t* res_len) {
  // check and register functions firstly if they are not registered
  using tee::trusted::TeeInstance;
  TeeInstance& ti = TeeInstance::GetInstance();
  TeeErrorCode ret = ti.RegisterTrustedPbFunctions();
  if (ret != TEE_SUCCESS) {
    ELOG_ERROR_TRACE();
    return ret;
  }

  // Default response length is zero if there is any thing wrong.
  *res_len = 0;
  *res_buf = 0;

  // Get the ecall attributes
  std::string attr_str(attr_buf, attr_len);
  tee::PbCallAttributes attr;
  if (!attr.ParseFromString(attr_str)) {
    ELOG_ERROR("Fail to parse ecall attributes");
    return TEE_ERROR_PROTOBUF_PARSE;
  }

  // Get the ecall function handler
  ret = ti.SetOrCheckAttr(attr);
  if (ret != TEE_SUCCESS) {
    ELOG_ERROR_TRACE();
    return ret;
  }

  // Find the function handler
  PbFunction function = ti.Functions().Get(attr.function_name());
  if (!function) {
    ELOG_ERROR("Cannot find function: %s", attr.function_name().c_str());
    return TEE_ERROR_PBCALL_FUNCTION;
  }

  // Execute the protobuf ecall function
  std::string req_str(req_buf, req_len);
  std::string res_str;
  ret = (*function)(req_str, &res_str);
  if (ret != TEE_SUCCESS) {
    ELOG_ERROR_TRACE();
    return ret;
  }

  // Allocate the untrusted memory to return the response
  // !!! Need to free outside of enclave
  if (res_str.length()) {
    sgx_status_t sc = SGX_ERROR_UNEXPECTED;
    sc = ocall_UntrustedMemoryAlloc(&ret, res_str.length(), res_buf);
    if ((TEE_ERROR_MERGE(ret, sc) != TEE_SUCCESS) || !(*res_buf)) {
      ELOG_ERROR("Fail to allocate untrusted memory: len=%ld",
                 res_str.length());
      return TEE_ERROR_MERGE(ret, sc);
    }
    memcpy(*res_buf, res_str.data(), res_str.size());
  }

  *res_len = res_str.length();
  return TEE_SUCCESS;
}

#ifdef __cplusplus
}
#endif
