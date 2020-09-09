#include <string>

#include "./sgx_urts.h"
#include "./sgx_utils.h"

#include "tee/common/bytes.h"
#include "tee/common/error.h"
#include "tee/common/log.h"
#include "tee/common/type.h"

#include "./kubetee.pb.h"
#include "./kubetee_u.h"

#include "tee/untrusted/untrusted_pbcall.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef DEBUG
static size_t m_count = 0;
#endif

TeeErrorCode UntrustedMemoryAlloc(size_t size, char** buf) {
  if (size == 0) {
    return TEE_ERROR_PARAMETERS;
  }

  char* buf_allocated = static_cast<char*>(malloc(size));
  if (!buf_allocated) {
    TEE_LOG_ERROR("Fail to allocate memory: len=%ld", size);
    return TEE_ERROR_MALLOC;
  }

#ifdef DEBUG
  TEE_LOG_DEBUG("Untrusted Alloc[%ld]: +%p", ++m_count, buf_allocated);
#endif
  *buf = buf_allocated;
  return TEE_SUCCESS;
}

TeeErrorCode UntrustedMemoryFree(char** buf) {
  if (*buf == nullptr) {
    TEE_LOG_ERROR("Try to UntrustedMemoryFree nullptr");
    return TEE_ERROR_PARAMETERS;
  }

#ifdef DEBUG
  TEE_LOG_DEBUG("Untrusted Free[%ld]: -%p", --m_count, *buf);
#endif
  free(*buf);
  *buf = 0;
  return TEE_SUCCESS;
}

TeeErrorCode ocall_UntrustedMemoryAlloc(size_t size, char** buf) {
  return UntrustedMemoryAlloc(size, buf);
}

TeeErrorCode ocall_UntrustedMemoryFree(char** buf) {
  UntrustedMemoryFree(buf);
  return TEE_SUCCESS;
}

TeeErrorCode ocall_ReeRun(const char* attr_buf, size_t attr_len,
                          const char* req_buf, size_t req_len, char** res_buf,
                          size_t* res_len) {
  // Initialize the return buffer to be empty
  *res_buf = 0;
  *res_len = 0;

  // When the first time to call ReeRun, register all untrusted functions
  using tee::untrusted::EnclavesManager;
  EnclavesManager& em = EnclavesManager::GetInstance();
  TeeErrorCode ret = em.RegisterUntrustedPbFunctions();
  if (ret != TEE_SUCCESS) {
    TEE_LOG_ERROR_TRACE();
    return ret;
  }

  // Get the function name
  std::string attr_str(attr_buf, attr_len);
  tee::PbCallAttributes attr;
  PB_PARSE(attr, attr_str);
  PbFunction function = em.Functions().Get(attr.function_name());
  if (!function) {
    ELOG_ERROR("Cannot find function: %s", attr.function_name().c_str());
    return TEE_ERROR_PBCALL_FUNCTION;
  }

  // Execute the untrusted function
  std::string req_str(req_buf, req_len);
  std::string res_str;
  ret = (*function)(req_str, &res_str);
  if (ret != TEE_SUCCESS) {
    ELOG_ERROR_TRACE();
    return ret;
  }
  // And set the return buffer the response is not empty
  if (res_str.size()) {
    TEE_CHECK_RETURN(UntrustedMemoryAlloc(res_str.size(), res_buf));
    memcpy(*res_buf, res_str.data(), res_str.size());
    *res_len = res_str.size();
  }

  TEE_LOG_DEBUG("Ocall ReeRun, response addr/len=%p/%ld", *res_buf, *res_len);
  return TEE_SUCCESS;
}

#ifdef __cplusplus
}
#endif
