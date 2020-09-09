#ifndef SDK_INCLUDE_TEE_COMMON_ENVELOPE_H_
#define SDK_INCLUDE_TEE_COMMON_ENVELOPE_H_

#include <string>
#include <vector>

#include "tee/common/aes.h"
#include "tee/common/bytes.h"
#include "tee/common/error.h"
#include "tee/common/rsa.h"

using tee::DigitalEnvelopeEncrypted;

namespace tee {
namespace common {

class DigitalEnvelope {
 public:
  explicit DigitalEnvelope(const std::string& name) : name_(name) {}
  explicit DigitalEnvelope(const char* name) : name_(name) {}
  DigitalEnvelope() : name_("Enclave") {}  // with default envelope name

  // Before decrypt, you need to prepare the plain text and public key
  // AES AAD and IV is optional. The default AAD is envelope name, and
  // the default IV is random number generated when do AES encryption.
  TeeErrorCode Encrypt(const std::string& public_key, const std::string& plain,
                       DigitalEnvelopeEncrypted* envelope);

  // Before decrypt, you need to prepare the cipher envelope and private key
  TeeErrorCode Decrypt(const std::string& private_key,
                       const DigitalEnvelopeEncrypted& envelope,
                       std::string* plain);

  // Optional for add signature into the digital envelope
  TeeErrorCode Sign(const std::string& private_key, const std::string& plain,
                    DigitalEnvelopeEncrypted* envelope);

  // Verify the signature in the digital envelope if it exits
  TeeErrorCode Verify(const std::string& public_key, const std::string& plain,
                      const DigitalEnvelopeEncrypted& envelope);

 private:
  const std::string name_;
};

}  // namespace common
}  // namespace tee

#endif  // SDK_INCLUDE_TEE_COMMON_ENVELOPE_H_
