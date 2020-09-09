#ifndef SDK_INCLUDE_TEE_COMMON_AES_H_
#define SDK_INCLUDE_TEE_COMMON_AES_H_

#include <iostream>
#include <string>
#include <vector>

#include "tee/common/bytes.h"
#include "tee/common/error.h"
#include "tee/common/type.h"

#include "./kubetee.pb.h"

using tee::SymmetricKeyEncrypted;

namespace tee {
namespace common {

class AesGcmCrypto {
 public:
  AesGcmCrypto();  // Generate random key if it's not specified
  explicit AesGcmCrypto(const std::string& key) : key_(key) {}
  explicit AesGcmCrypto(const char* key) : key_(key) {}

  // Encrypt the plain string to cipher in SymmetricKeyEncrypted format
  TeeErrorCode Encrypt(const std::string& plain, SymmetricKeyEncrypted* cipher);
  // Decrypt the cipher in SymmetricKeyEncrypted format to plain string
  TeeErrorCode Decrypt(const SymmetricKeyEncrypted& cipher, std::string* plain);

  std::string GetKey() {
    return key_;
  }

  static size_t get_iv_size() {
    return kIvSize;
  }

  static size_t get_mac_size() {
    return kMacSize;
  }

  static size_t get_key_size() {
    return kKeySize;
  }

 private:
  static const size_t kKeySize = 32;  // AES256
  static const size_t kIvSize = 12;
  static const size_t kMacSize = 16;

  std::string key_;
};

}  // namespace common
}  // namespace tee

#endif  // SDK_INCLUDE_TEE_COMMON_AES_H_
