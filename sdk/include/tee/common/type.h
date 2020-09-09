#ifndef SDK_INCLUDE_TEE_COMMON_TYPE_H_
#define SDK_INCLUDE_TEE_COMMON_TYPE_H_

#include <string>
#include "tee/common/error.h"
#include "tee/common/log.h"

#define RCAST(t, v) reinterpret_cast<t>((v))
#define SCAST(t, v) static_cast<t>((v))
#define CCAST(t, v) const_cast<t>((v))
#define RCCAST(t, v) reinterpret_cast<t>(const_cast<char*>((v)))

// To ignore the parameters which is not used
#define TEE_UNREFERENCED_PARAMETER(p) \
  do {                                \
    static_cast<void>((p));           \
  } while (0)

// The template of one line code to check the function return value in
// TeeErrorCode type. Usage: TEE_CHECK_RETURN(functionName(arg-list));
#define TEE_CHECK_RETURN(r)   \
  do {                        \
    TeeErrorCode ret = (r);   \
    if (ret != TEE_SUCCESS) { \
      ELOG_ERROR_TRACE();     \
      return ret;             \
    }                         \
  } while (0)

typedef uint64_t EnclaveIdentity;

// Generic format of trusted/untrusted function with serialized
// protobuffer message type in/out parameters
typedef TeeErrorCode (*PbFunction)(const std::string& req_str,
                                   std::string* res_str);

#endif  // SDK_INCLUDE_TEE_COMMON_TYPE_H_
