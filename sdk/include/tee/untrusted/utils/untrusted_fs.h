#ifndef SDK_INCLUDE_TEE_UNTRUSTED_UTILS_UNTRUSTED_FS_H_
#define SDK_INCLUDE_TEE_UNTRUSTED_UTILS_UNTRUSTED_FS_H_

#include <fstream>
#include <iostream>
#include <string>

#include "tee/common/error.h"

namespace tee {
namespace untrusted {

TeeErrorCode FsWriteString(const std::string& filename, const std::string& str);
TeeErrorCode FsReadString(const std::string& filename, std::string* str);
TeeErrorCode FsGetFileSize(const std::string& filename, size_t* size);
bool FsFileExists(const std::string& filename);
std::string GetFsString(const std::string& filename);

}  // namespace untrusted
}  // namespace tee

#endif  // SDK_INCLUDE_TEE_UNTRUSTED_UTILS_UNTRUSTED_FS_H_
