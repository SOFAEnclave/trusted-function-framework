#ifndef SDK_INCLUDE_TEE_UNTRUSTED_UNTRUSTED_PBCALL_H_
#define SDK_INCLUDE_TEE_UNTRUSTED_UNTRUSTED_PBCALL_H_

#include <string>

#include "tee/common/error.h"
#include "tee/common/log.h"
#include "tee/common/protobuf.h"

#include "tee/untrusted/enclave/untrusted_enclave.h"

#define ADD_UNTRUSTED_PBCALL_FUNCTION(f) \
  tee::untrusted::EnclavesManager::GetInstance().Functions().Add(#f, f)

#ifdef __cplusplus
extern "C" {
#endif

extern TeeErrorCode RegisterUnTrustedPbFunctionsEx();
extern TeeErrorCode UntrustedMemoryMalloc(size_t size, char** buf);
extern TeeErrorCode UntrustedMemoryFree(char** buf);

#ifdef __cplusplus
}
#endif

#endif  // SDK_INCLUDE_TEE_UNTRUSTED_UNTRUSTED_PBCALL_H_
