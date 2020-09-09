#ifndef SDK_INCLUDE_TEE_TRUSTED_TRUSTED_PBFUNCTIONS_H_
#define SDK_INCLUDE_TEE_TRUSTED_TRUSTED_PBFUNCTIONS_H_

#include <string>

#include "tee/common/error.h"

#ifdef __cplusplus
extern "C" {
#endif

extern TeeErrorCode RegisterTrustedPbFunctionsInternal();
extern TeeErrorCode RegisterTrustedPbFunctionsEx();

#ifdef __cplusplus
}
#endif

#endif  // SDK_INCLUDE_TEE_TRUSTED_TRUSTED_PBFUNCTIONS_H_
