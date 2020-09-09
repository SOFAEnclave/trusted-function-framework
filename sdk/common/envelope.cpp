#include <string>
#include <vector>

#include "openssl/err.h"
#include "openssl/pem.h"
#include "openssl/rand.h"
#include "openssl/rsa.h"
#include "openssl/sha.h"

#include "tee/common/aes.h"
#include "tee/common/bytes.h"
#include "tee/common/error.h"
#include "tee/common/log.h"
#include "tee/common/rsa.h"
#include "tee/common/type.h"

#include "tee/common/envelope.h"

namespace tee {
namespace common {

TeeErrorCode DigitalEnvelope::Encrypt(const std::string& public_key,
                                      const std::string& plain,
                                      DigitalEnvelopeEncrypted* envelope) {
  ELOG_DEBUG("Encrypt secret to digital envelope: %s", name_.c_str());
  if (public_key.empty()) {
    ELOG_ERROR("RSA public key should not be empty.");
    return TEE_ERROR_PARAMETERS;
  }
  if (plain.empty()) {
    ELOG_ERROR("Input plain text should not be empty.");
    return TEE_ERROR_PARAMETERS;
  }

  // Set AAD to envelope name if it's not specified
  SymmetricKeyEncrypted* aes_cipher = envelope->mutable_aes_cipher();
  if (!name_.empty() && aes_cipher->aad().empty()) {
    aes_cipher->set_aad(name_);
  }

  // Do AES encryption
  AesGcmCrypto aes;
  TEE_CHECK_RETURN(aes.Encrypt(plain, aes_cipher));

  // Encrypt AES key by RSA public key
  tee::common::RsaCrypto rsa;
  TEE_CHECK_RETURN(
      rsa.Encrypt(public_key, aes.GetKey(), envelope->mutable_encrypted_key()));

  return TEE_SUCCESS;
}

TeeErrorCode DigitalEnvelope::Decrypt(const std::string& private_key,
                                      const DigitalEnvelopeEncrypted& envelope,
                                      std::string* plain) {
  ELOG_DEBUG("Decrypt secret in digital envelope: %s", name_.c_str());
  if (private_key.empty()) {
    ELOG_ERROR("RSA private key should not be empty.");
    return TEE_ERROR_PARAMETERS;
  }

  // Decrypt the AES key by RSA private key
  std::string aes_key;
  tee::common::RsaCrypto rsa;
  TEE_CHECK_RETURN(
      rsa.Decrypt(private_key, envelope.encrypted_key(), &aes_key));

  // Decrypt the secret data with AES key
  AesGcmCrypto aes(aes_key);
  TEE_CHECK_RETURN(aes.Decrypt(envelope.aes_cipher(), plain));

  return TEE_SUCCESS;
}

TeeErrorCode DigitalEnvelope::Sign(const std::string& private_key,
                                   const std::string& plain,
                                   DigitalEnvelopeEncrypted* envelope) {
  ELOG_DEBUG("Sign the digital envelope: %s", name_.c_str());

  // Set the HASH value
  std::string hash = DataBytes::SHA256HexStr(
      RCAST(uint8_t*, CCAST(char*, plain.data())), plain.size());
  envelope->set_plain_hash(hash);
  ELOG_DEBUG("Hash of envelope plain: %s", hash.c_str());

  // Sign and set the plain HASH value
  TEE_CHECK_RETURN(
      RsaCrypto::Sign(private_key, hash, envelope->mutable_plain_hash_sig()));

  return TEE_SUCCESS;
}

TeeErrorCode DigitalEnvelope::Verify(const std::string& public_key,
                                     const std::string& plain,
                                     const DigitalEnvelopeEncrypted& envelope) {
  ELOG_DEBUG("Verify the signature in digital envelope: %s", name_.c_str());

  if (envelope.plain_hash().empty() || envelope.plain_hash_sig().empty()) {
    ELOG_ERROR("Empty hash or signature value");
    return TEE_ERROR_PARAMETERS;
  }

  // Verify the HASH value
  std::string cal_hash = DataBytes::SHA256HexStr(
      RCAST(uint8_t*, CCAST(char*, plain.data())), plain.size());
  if (envelope.plain_hash() != cal_hash) {
    ELOG_ERROR("Fail to compare the hash value");
    ELOG_DEBUG("actual hash: %s", cal_hash.c_str());
    ELOG_DEBUG("expected hash: %s", envelope.plain_hash().c_str());
    return TEE_ERROR_UNEXPECTED;
  }

  // Verify the signature
  TEE_CHECK_RETURN(
      RsaCrypto::Verify(public_key, cal_hash, envelope.plain_hash_sig()));

  return TEE_SUCCESS;
}

}  // namespace common
}  // namespace tee
