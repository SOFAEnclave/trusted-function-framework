#include <cstdarg>
#include <cstdio>

#include "./kubetee_t.h"
#include "tee/common/log.h"

#ifdef __cplusplus
extern "C" {
#endif

int tee_printf(const char* fmt, ...) {
  constexpr size_t kMaxLogBufSzie = 4096;
  char buf[kMaxLogBufSzie] = {'\0'};
  va_list ap;

  va_start(ap, fmt);
  vsnprintf(buf, kMaxLogBufSzie, fmt, ap);
  va_end(ap);

  // Add the special suffix to notify the limitation of buffer length
  if (strlen(buf) >= (kMaxLogBufSzie - 4)) {
    buf[kMaxLogBufSzie - 4] = '.';
    buf[kMaxLogBufSzie - 3] = '.';
    buf[kMaxLogBufSzie - 2] = '.';
    buf[kMaxLogBufSzie - 1] = 0;
  }

  return ocall_PrintMessage(buf);
}

/// Because the protobuf files include the std headers and use printf
/// So there must be a implement of printf
int printf(const char* fmt, ...) {
  constexpr size_t kMaxLogBufSzie = 4096;
  char buf[kMaxLogBufSzie] = {'\0'};
  va_list ap;

  va_start(ap, fmt);
  vsnprintf(buf, kMaxLogBufSzie, fmt, ap);
  va_end(ap);

  // Add the special suffix to notify the limitation of buffer length
  if (strlen(buf) >= (kMaxLogBufSzie - 4)) {
    buf[kMaxLogBufSzie - 4] = '.';
    buf[kMaxLogBufSzie - 3] = '.';
    buf[kMaxLogBufSzie - 2] = '.';
    buf[kMaxLogBufSzie - 1] = 0;
  }

  return ocall_PrintMessage(buf);
}

#ifdef __cplusplus
}
#endif
