#ifndef SDK_INCLUDE_TEE_TRUSTED_TRUSTED_PBCALL_H_
#define SDK_INCLUDE_TEE_TRUSTED_TRUSTED_PBCALL_H_

#include "tee/trusted/trusted_instance.h"

#define ADD_TRUSTED_PBCALL_FUNCTION(f) \
  tee::trusted::TeeInstance::GetInstance().Functions().Add(#f, f)

#endif  // SDK_INCLUDE_TEE_TRUSTED_TRUSTED_PBCALL_H_
